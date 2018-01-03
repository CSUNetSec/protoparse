package rib

import (
	"encoding/binary"
	"fmt"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
	pbbgp "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
	pp "github.com/CSUNetSec/protoparse"
	util "github.com/CSUNetSec/protoparse/util"
	"net"
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

	pos := 4
	bitlen := uint8(r.buf[pos])
	fmt.Printf("Buf: %v\n", r.buf)
	pos++
	bytelen := int(bitlen+7) / 8
	if int(bytelen) > len(r.buf) || int(bytelen) < 1 {
		return nil, fmt.Errorf("Buffer too small to parse prefix. Buffer size:%d Prefix Size: %d\n", len(r.buf), bytelen)
	}
	pbuf := make([]byte, bytelen)
	copy(pbuf, r.buf[pos:pos+bytelen])

	if bitlen%8 != 0 {
		mask := 0xff00 >> (bitlen % 8)
		last_byte_value := pbuf[bytelen-1] & byte(mask)
		pbuf[bytelen-1] = last_byte_value
	}
	var ipbuf []byte
	if r.isv6 {
		ipbuf = make([]byte, 16)
		copy(ipbuf, pbuf)
	} else {
		ipbuf = make([]byte, 4)
		copy(ipbuf, pbuf)
	}
	pos += bytelen
	entryCount := int(binary.BigEndian.Uint16(r.buf[pos : pos+2]))

	routes := make([]*pbbgp.RIBEntry, entryCount)
	for i := 0; i < entryCount; i++ {
		adv, re, err := r.parseRIBEntry(pos)
		routes[i] = re
		if err != nil {
			return nil, err
		}
		pos += adv
	}
	r.dest.RouteEntry = routes
	return nil, ERR_NOT_IMPLEMENTED
}

//TODO: Add buffer length checking to this method
func (r *ribBuf) parseRIBEntry(start int) (int, *pbbgp.RIBEntry, error) {
	re := new(pbbgp.RIBEntry)
	pos := start
	re.PeerIndex = uint32(binary.BigEndian.Uint16(r.buf[pos : pos+2]))
	pos += 2
	re.Timestamp = binary.BigEndian.Uint32(r.buf[pos : pos+4])
	pos += 4
	attrLen := int(binary.BigEndian.Uint16(r.buf[pos : pos+2]))
	pos += 2
	pos += attrLen
	return pos - start, re, nil
}

func (r *ribBuf) parseIndexTable() (pp.PbVal, error) {
	//If the buffer is too short to read View length
	bufLen := int(len(r.buf))
	if bufLen < 6 {
		return nil, fmt.Errorf("Buffer too small to read view length")
	}
	vLength := int(binary.BigEndian.Uint16(r.buf[4:6]))
	pos := 6 + vLength

	if bufLen < pos+2 {
		return nil, fmt.Errorf("Buffer too small to read peer count")
	}
	peerCount := int(binary.BigEndian.Uint16(r.buf[pos : pos+2]))
	pos += 2
	peers := make([]*pbbgp.PeerEntry, peerCount)
	for i := 0; i < peerCount; i++ {
		adv, p, err := r.parsePeerEntry(pos)
		if err != nil {
			return nil, err
		}
		pos += adv
		peers[i] = p
	}
	r.dest.PeerEntry = peers
	return r, nil
}

func (r *ribBuf) parsePeerEntry(start int) (int, *pbbgp.PeerEntry, error) {
	adv := start
	b := uint8(r.buf[start])
	adv++
	as4 := (b&0x2 != 0) //This might need to be 7 and 6, I'm not sure how the byte order will work
	ipv6 := (b&0x1 != 0)

	id := binary.BigEndian.Uint32(r.buf[adv : adv+4])
	adv += 4

	peerIP := new(pbcom.IPAddressWrapper)
	if ipv6 {
		ipbuf := make([]byte, 16)
		copy(ipbuf, r.buf[adv:adv+16])
		peerIP.Ipv4 = ipbuf
		adv += 16
	} else {
		ipbuf := make([]byte, 4)
		copy(ipbuf, r.buf[adv:adv+4])
		peerIP.Ipv6 = ipbuf
		adv += 4
	}

	var asNum uint32
	if as4 {
		asNum = binary.BigEndian.Uint32(r.buf[adv : adv+4])
		adv += 4
	} else {
		asNum = uint32(binary.BigEndian.Uint16(r.buf[adv : adv+2]))
		adv += 2
	}

	pe := new(pbbgp.PeerEntry)
	pe.PeerId = id
	pe.PeerAs = asNum
	pe.PeerIp = peerIP

	return adv - start, pe, nil

}

func (r *ribBuf) String() string {
	str := ""
	if r.isIndex {
		str += fmt.Sprintf("Collector ID: \nView Name: \nPeer Count: %d\n", len(r.dest.PeerEntry))
		str += "Peers:\n"
		for i := 0; i < len(r.dest.PeerEntry); i++ {
			str += peerToString(r.dest.PeerEntry[i])
		}
	} else {
		if len(r.dest.RouteEntry) > 0 {
			pref := r.dest.RouteEntry[0].Prefix
			str += fmt.Sprintf("Prefix: %s/%d\n", net.IP(util.GetIP(pref.GetPrefix())), pref.Mask)
		}
	}
	return str
}

func peerToString(p *pbbgp.PeerEntry) string {
	return fmt.Sprintf("ID: %d AS: %d IP: %s\n", p.PeerId, p.PeerAs, net.IP(util.GetIP(p.PeerIp)))
}
