package mrt

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	monpb "github.com/CSUNetSec/netsec-protobufs/bgpmon"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
	pbbgp "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
	"github.com/CSUNetSec/protoparse"
	pp "github.com/CSUNetSec/protoparse"
	bgp "github.com/CSUNetSec/protoparse/protocol/bgp"
	util "github.com/CSUNetSec/protoparse/util"
	"net"
	"time"
)

const (
	MRT_HEADER_LEN    = 12
	BGP4MP            = 16
	BGP4MP_ET         = 17
	MESSAGE           = 1
	MESSAGE_AS4       = 4
	MESSAGE_LOCAL     = 7
	MESSAGE_AS4_LOCAL = 7
)

type MrtBufferStack struct {
	MrthBuf   *pbbgp.MrtHeader `json:"mrt_header,omitempty"`
	Bgp4mpbuf protoparse.PbVal `json:"bgp4mp_header,omitempty"`
	Bgphbuf   protoparse.PbVal `json:"bgp_header,omitempty"`
	Bgpupbuf  protoparse.PbVal `json:"bgp_update,omitempty"`
}

func MrtToBGPCapture(data []byte) (*monpb.BGPCapture, error) {
	mrth := NewMrtHdrBuf(data)
	bgp4h, errmrt := mrth.Parse()
	if errmrt != nil {
		return nil, fmt.Errorf("Failed parsing MRT header:%s\n", errmrt)
	}
	bgph, errbgph := bgp4h.Parse()
	if errbgph != nil {
		return nil, fmt.Errorf("Failed parsing BGP4MP header:%s\n", errbgph)
	}
	bgpup, errbgpup := bgph.Parse()
	if errbgpup != nil {
		return nil, fmt.Errorf("Failed parsing BGP Header:%s\n", errbgpup)
	}
	_, errup := bgpup.Parse()
	if errup != nil {
		return nil, fmt.Errorf("Failed parsing BGP Update:%s\n", errup)
	}
	capture := new(monpb.BGPCapture)
	bgphpb := bgp4h.(pp.BGP4MPHeaderer).GetHeader()
	mrtpb := mrth.GetHeader()
	capture.Timestamp = mrtpb.Timestamp
	capture.PeerAs = bgphpb.PeerAs
	capture.LocalAs = bgphpb.LocalAs
	capture.InterfaceIndex = bgphpb.InterfaceIndex
	capture.AddressFamily = bgphpb.AddressFamily
	capture.PeerIp = bgphpb.PeerIp
	capture.LocalIp = bgphpb.LocalIp
	capture.Update = bgpup.(pp.BGPUpdater).GetUpdate()
	return capture, nil
}

type mrtHhdrBuf struct {
	dest *pbbgp.MrtHeader
	buf  []byte
}

type bgp4mpHdrBuf struct {
	dest  *pbbgp.BGP4MPHeader
	buf   []byte
	isv6  bool
	isAS4 bool
}

func NewMrtHdrBuf(buf []byte) *mrtHhdrBuf {
	return &mrtHhdrBuf{
		dest: new(pbbgp.MrtHeader),
		buf:  buf,
	}
}

func NewBgp4mpHdrBuf(buf []byte, as4 bool) *bgp4mpHdrBuf {
	return &bgp4mpHdrBuf{
		dest:  new(pbbgp.BGP4MPHeader),
		buf:   buf,
		isAS4: as4,
		isv6:  false,
	}
}

func (m *mrtHhdrBuf) String() string {
	return fmt.Sprintf("Timestamp:%v Type:%d Subtype:%d Len:%d", time.Unix(int64(m.dest.Timestamp), 0), m.dest.Type, m.dest.Subtype, m.dest.Len)
}

func (m *bgp4mpHdrBuf) String() string {
	formatstr := "peer_as:%d local_as:%d interface_index:%d address_family:%d peer_ip:%s local_ip:%s"
	return fmt.Sprintf(formatstr, m.dest.PeerAs, m.dest.LocalAs, m.dest.InterfaceIndex, m.dest.AddressFamily, net.IP(util.GetIP(m.dest.PeerIp)), net.IP(util.GetIP(m.dest.LocalIp)))
}

func (mhb *mrtHhdrBuf) Parse() (protoparse.PbVal, error) {
	if len(mhb.buf) < MRT_HEADER_LEN {
		return nil, errors.New("Not enough bytes in data slice to decode MRT header")
	}
	mhb.dest.Timestamp = binary.BigEndian.Uint32(mhb.buf[:4])
	u16type := binary.BigEndian.Uint16(mhb.buf[4:6])
	mhb.dest.Type = uint32(u16type)
	u16subtype := binary.BigEndian.Uint16(mhb.buf[6:8])
	mhb.dest.Subtype = uint32(u16subtype)
	mhb.dest.Len = binary.BigEndian.Uint32(mhb.buf[8:12])
	if len(mhb.buf[MRT_HEADER_LEN:]) < int(mhb.dest.Len) {
		return nil, fmt.Errorf("Not enough bytes in data slice for underlying message.len of buf:%d len parsed:%d", len(mhb.buf[MRT_HEADER_LEN:]), mhb.dest.Len)
	}
	if u16type == uint16(BGP4MP) || u16type == uint16(BGP4MP_ET) {
		if u16subtype == MESSAGE_AS4 || u16subtype == MESSAGE_AS4_LOCAL {
			return NewBgp4mpHdrBuf(mhb.buf[MRT_HEADER_LEN:], true), nil
		}
		if u16subtype == MESSAGE || u16subtype == MESSAGE_LOCAL {
			return NewBgp4mpHdrBuf(mhb.buf[MRT_HEADER_LEN:], false), nil
		}
		return nil, errors.New("unsupported MRT subtype")
	}
	return nil, errors.New("unsupported MRT type")
}

func (b4hdrb *bgp4mpHdrBuf) Parse() (protoparse.PbVal, error) {
	if len(b4hdrb.buf) < 20 { //PeerAs + Local As + interface ind + AF + 2*ipv4 addres
		return nil, errors.New("Not enough bytes in data slice to decode BGP4MP hdr")
	}
	if b4hdrb.isAS4 {
		b4hdrb.dest.PeerAs = binary.BigEndian.Uint32(b4hdrb.buf[:4])
		b4hdrb.dest.LocalAs = binary.BigEndian.Uint32(b4hdrb.buf[4:8])
		b4hdrb.buf = b4hdrb.buf[8:]
	} else {
		b4hdrb.dest.PeerAs = uint32(binary.BigEndian.Uint16(b4hdrb.buf[:2]))
		b4hdrb.dest.LocalAs = uint32(binary.BigEndian.Uint16(b4hdrb.buf[2:4]))
		b4hdrb.buf = b4hdrb.buf[4:]
	}
	b4hdrb.dest.InterfaceIndex = uint32(binary.BigEndian.Uint16(b4hdrb.buf[:2]))
	u16af := binary.BigEndian.Uint16(b4hdrb.buf[2:4])
	b4hdrb.dest.AddressFamily = uint32(u16af)
	pip, lip := new(pbcom.IPAddressWrapper), new(pbcom.IPAddressWrapper)
	switch u16af {
	case bgp.AFI_IP:
		pip.Ipv4 = b4hdrb.buf[4:8]
		lip.Ipv4 = b4hdrb.buf[8:12]
		b4hdrb.dest.PeerIp = pip
		b4hdrb.dest.LocalIp = lip
		b4hdrb.buf = b4hdrb.buf[12:]
	case bgp.AFI_IP6:
		b4hdrb.isv6 = true
		pip.Ipv6 = b4hdrb.buf[4:20]
		lip.Ipv6 = b4hdrb.buf[20:36]
		b4hdrb.dest.PeerIp = pip
		b4hdrb.dest.LocalIp = lip
		b4hdrb.buf = b4hdrb.buf[36:]
	default:
		return nil, errors.New("unsupported BGP4MP address family")
	}
	return bgp.NewBgpHeaderBuf(b4hdrb.buf, b4hdrb.isv6, b4hdrb.isAS4), nil
}

func SplitMrt(data []byte, atEOF bool) (advance int, token []byte, err error) {
	dataLen := len(data)
	if atEOF && dataLen == 0 {
		return 0, nil, nil
	}
	if atEOF { //if at EOF return the data
		return dataLen, data, nil
	}

	if cap(data) < MRT_HEADER_LEN { // read more
		return 0, nil, nil
	}
	if dataLen < MRT_HEADER_LEN {
		return 0, nil, errors.New("Data slice shorter than MRT header")
	}
	totlen := int(binary.BigEndian.Uint32(data[8:12])) + MRT_HEADER_LEN

	if dataLen < totlen { //need to read more
		return 0, nil, nil
	}
	return totlen, data[0:totlen], nil
}

func (m *mrtHhdrBuf) GetHeader() *pbbgp.MrtHeader {
	return m.dest
}

func (m *bgp4mpHdrBuf) GetHeader() *pbbgp.BGP4MPHeader {
	return m.dest
}

type bgp4mpHeaderWrapper struct {
	*pbbgp.BGP4MPHeader
	PeerIp  net.IP `json:"peer_ip,omitempty"`
	LocalIp net.IP `json:"local_ip,omitempty"`
}

func NewBGP4MPHeaderWrapper(dest *pbbgp.BGP4MPHeader) *bgp4mpHeaderWrapper {
	peer := net.IP(util.GetIP(dest.PeerIp))
	local := net.IP(util.GetIP(dest.LocalIp))
	return &bgp4mpHeaderWrapper{dest, peer, local}
}

func (m *bgp4mpHdrBuf) MarshalJSON() (data []byte, err error) {
	return json.Marshal(NewBGP4MPHeaderWrapper(m.dest))
}
