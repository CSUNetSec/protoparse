package rib

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
	pbbgp "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
	pp "github.com/CSUNetSec/protoparse"
	bgp "github.com/CSUNetSec/protoparse/protocol/bgp"
	util "github.com/CSUNetSec/protoparse/util"
	"net"
	"time"
)

var (
	ERR_NOT_IMPLEMENTED = fmt.Errorf("Feature not yet implemented")
)

type ribBuf struct {
	dest    *pbbgp.RIB
	buf     []byte
	isv6    bool
	isIndex bool
	index   pp.PbVal
}

func NewRibIndexBuf(buf []byte) *ribBuf {
	return &ribBuf{
		dest:    new(pbbgp.RIB),
		buf:     buf,
		isIndex: true,
	}
}

func NewRibEntryBuf(buf []byte, subType int, index pp.PbVal) *ribBuf {
	return &ribBuf{
		dest:    new(pbbgp.RIB),
		buf:     buf,
		isIndex: false,
		index:   index,
		isv6:    subType == 4 || subType == 5,
	}
}

func (r *ribBuf) Parse() (pp.PbVal, error) {
	if r.isIndex {
		return r.parseIndexTable()
	} else {
		return r.parseRIB()
	}
	return nil, nil
}

// This function only parses AFI/SAFI-Specific RIB subtypes
func (r *ribBuf) parseRIB() (pp.PbVal, error) {

	if len(r.buf) < 5 {
		return nil, fmt.Errorf("rib: Buffer too small to read bitlen")
	}
	r.buf = r.buf[4:]
	bitlen := uint8(r.buf[0])
	r.buf = r.buf[1:]

	bytelen := int(bitlen+7) / 8
	if int(bytelen) > len(r.buf) {
		return nil, fmt.Errorf("Buffer too small to parse prefix. Buffer size:%d Prefix Size: %d\n", len(r.buf), bytelen)
	}

	pbuf := make([]byte, bytelen)
	prefWrapper := new(pbcom.PrefixWrapper)
	prefWrapper.Prefix = new(pbcom.IPAddressWrapper)

	if bytelen != 0 {
		copy(pbuf, r.buf[:bytelen])

		if bitlen%8 != 0 {
			mask := 0xff00 >> (bitlen % 8)
			last_byte_value := pbuf[bytelen-1] & byte(mask)
			pbuf[bytelen-1] = last_byte_value
		}

		var ipbuf []byte
		if r.isv6 {
			ipbuf = make([]byte, 16)
			copy(ipbuf, pbuf)
			prefWrapper.Prefix.Ipv6 = ipbuf
		} else {
			ipbuf = make([]byte, 4)
			copy(ipbuf, pbuf)
			prefWrapper.Prefix.Ipv4 = ipbuf
		}
		prefWrapper.Mask = uint32(bitlen)
		r.buf = r.buf[bytelen:]
	} else {
		if r.isv6 {
			prefWrapper.Prefix.Ipv6 = make([]byte, 16)
			prefWrapper.Mask = 0
		} else {
			prefWrapper.Prefix.Ipv4 = make([]byte, 4)
			prefWrapper.Mask = 0
		}
	}

	if len(r.buf) < 2 {
		return nil, fmt.Errorf("rib: Buffer too small to read entry count")
	}
	entryCount := int(binary.BigEndian.Uint16(r.buf[:2]))
	r.buf = r.buf[2:]

	routes := make([]*pbbgp.RIBEntry, entryCount)
	for i := 0; i < entryCount; i++ {
		re, err := r.parseRIBEntry(prefWrapper)
		routes[i] = re
		if err != nil {
			return nil, fmt.Errorf("Error parsing RIB entries: %s", err)
		}
	}
	r.dest.RouteEntry = routes
	return nil, nil
}

func (r *ribBuf) parseRIBEntry(pref *pbcom.PrefixWrapper) (*pbbgp.RIBEntry, error) {
	re := new(pbbgp.RIBEntry)
	re.Prefix = pref

	if len(r.buf) < 8 {
		return nil, fmt.Errorf("rib: Buffer too small to parse RIB entry header")
	}
	re.PeerIndex = uint32(binary.BigEndian.Uint16(r.buf[:2]))
	r.buf = r.buf[2:]

	re.Timestamp = binary.BigEndian.Uint32(r.buf[:4])
	r.buf = r.buf[4:]

	attrLen := int(binary.BigEndian.Uint16(r.buf[:2]))
	r.buf = r.buf[2:]

	if len(r.buf) < attrLen {
		return nil, fmt.Errorf("rib: Buffer too small to parse BGP attributes")
	}
	attrs, err, _, _ := bgp.ParseAttrs(r.buf[:attrLen], true, r.isv6)
	r.buf = r.buf[attrLen:]
	re.Attrs = attrs

	if err != nil {
		return nil, err
	}
	return re, nil
}

func (r *ribBuf) parseIndexTable() (pp.PbVal, error) {
	// buf[0:4] is Collector BGP ID

	if len(r.buf) < 6 {
		return nil, fmt.Errorf("rib: Buffer too small to read view length")
	}
	vLength := int(binary.BigEndian.Uint16(r.buf[4:6]))
	r.buf = r.buf[6:]

	if len(r.buf) < vLength {
		return nil, fmt.Errorf("rib: Buffer too small to read view name")
	}
	r.buf = r.buf[vLength:]

	if len(r.buf) < 2 {
		return nil, fmt.Errorf("rib: Buffer too small to read peer count")
	}
	peerCount := int(binary.BigEndian.Uint16(r.buf[:2]))
	r.buf = r.buf[2:]

	peers := make([]*pbbgp.PeerEntry, peerCount)
	for i := 0; i < peerCount; i++ {
		p, err := r.parsePeerEntry()
		if err != nil {
			return nil, err
		}
		peers[i] = p
	}
	r.dest.PeerEntry = peers
	return r, nil
}

func (r *ribBuf) parsePeerEntry() (*pbbgp.PeerEntry, error) {

	if len(r.buf) < 1 {
		return nil, fmt.Errorf("rib: Buffer too small to read peer type")
	}
	peerType := uint8(r.buf[0])
	r.buf = r.buf[1:]

	as4 := (peerType&0x2 != 0)
	ipv6 := (peerType&0x1 != 0)

	if len(r.buf) < 4 {
		return nil, fmt.Errorf("rib: Buffer too small to read BGP id")
	}
	id := binary.BigEndian.Uint32(r.buf[:4])
	r.buf = r.buf[4:]

	peerIP := new(pbcom.IPAddressWrapper)
	if ipv6 {
		ipbuf := make([]byte, 16)
		if len(r.buf) < 16 {
			return nil, fmt.Errorf("rib: Buffer too small to read peer ipv6")
		}
		copy(ipbuf, r.buf[:16])
		r.buf = r.buf[16:]
		peerIP.Ipv6 = ipbuf
	} else {
		ipbuf := make([]byte, 4)
		if len(r.buf) < 4 {
			return nil, fmt.Errorf("rib: Buffer too small to read peer ipv4")
		}
		copy(ipbuf, r.buf[:4])
		r.buf = r.buf[4:]
		peerIP.Ipv4 = ipbuf
	}

	var asNum uint32
	if as4 {
		asNum = binary.BigEndian.Uint32(r.buf[:4])
		r.buf = r.buf[4:]
	} else {
		asNum = uint32(binary.BigEndian.Uint16(r.buf[:2]))
		r.buf = r.buf[2:]
	}

	pe := new(pbbgp.PeerEntry)
	pe.PeerId = id
	pe.PeerAs = asNum
	pe.PeerIp = peerIP

	return pe, nil
}

func (r *ribBuf) GetHeader() *pbbgp.RIB {
	return r.dest
}

func (r *ribBuf) String() string {
	str := ""
	if r.isIndex {
		str += fmt.Sprintf("Peer Count: %d\n", len(r.dest.PeerEntry))
		str += "Peers:\n"
		for i := 0; i < len(r.dest.PeerEntry); i++ {
			str += peerToString(r.dest.PeerEntry[i]) + "\n"
		}
	} else {
		if len(r.dest.RouteEntry) > 0 {
			str += fmt.Sprintf("ENTRIES: %d\n", len(r.dest.RouteEntry))
			for i := 0; i < len(r.dest.RouteEntry); i++ {
				str += ribEntryToString(r.dest.RouteEntry[i], r.index) + "\n"
			}
		}
	}
	return str
}

func peerToString(p *pbbgp.PeerEntry) string {
	return fmt.Sprintf("%s AS%d", net.IP(util.GetIP(p.PeerIp)), p.PeerAs)
}

func ribEntryToString(r *pbbgp.RIBEntry, index pp.PbVal) string {
	ind := index.(*ribBuf)
	peer := ind.dest.PeerEntry[r.PeerIndex]
	pref := r.Prefix
	prefString := fmt.Sprintf("%s/%d", net.IP(util.GetIP(pref.GetPrefix())), pref.Mask)
	str := fmt.Sprintf("PREFIX: %s\n", prefString)
	str += fmt.Sprintf("FROM: %s\n", peerToString(peer))
	str += fmt.Sprintf("ORIGINATED: %s\n", time.Unix(int64(r.Timestamp), 0))
	str += bgp.AttrToString(r.Attrs)

	return str
}

func (r *ribBuf) MarshalJSON() ([]byte, error) {
	return json.Marshal(newribHeaderWrapper(r))
}

type ribHeaderWrapper struct {
	Prefix *bgp.PrefixWrapper
	Events []*ribEventWrapper
}

func newribHeaderWrapper(r *ribBuf) *ribHeaderWrapper {
	rh := ribHeaderWrapper{}
	rh.Prefix = bgp.NewPrefixWrapper(r.dest.RouteEntry[0].Prefix)
	rh.Events = make([]*ribEventWrapper, len(r.dest.RouteEntry))

	for i := 0; i < len(r.dest.RouteEntry); i++ {
		rh.Events[i] = newribEventWrapper(r.dest.RouteEntry[i], r.index.(*ribBuf))
	}
	return &rh
}

type ribEventWrapper struct {
	Peer       *ribPeerWrapper
	Originated time.Time
	Attrs      *bgp.AttrsWrapper
}

func newribEventWrapper(rib *pbbgp.RIBEntry, ind *ribBuf) *ribEventWrapper {
	rew := ribEventWrapper{}
	rew.Peer = newribPeerWrapper(ind.dest.PeerEntry[rib.PeerIndex])
	rew.Originated = time.Unix(int64(rib.Timestamp), 0)
	rew.Attrs = bgp.NewAttrsWrapper(rib.Attrs)
	return &rew
}

type ribPeerWrapper struct {
	*pbbgp.PeerEntry
	Peer_ip net.IP `json:"peer_ip"`
}

func newribPeerWrapper(p *pbbgp.PeerEntry) *ribPeerWrapper {
	rpw := ribPeerWrapper{}
	rpw.PeerEntry = p
	rpw.Peer_ip = net.IP(util.GetIP(p.PeerIp))
	return &rpw
}
