package mrt

import (
	"encoding/binary"
	"errors"
	"fmt"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
	pbbgp "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
	"github.com/CSUNetSec/protoparse"
	bgp "github.com/CSUNetSec/protoparse/protocol/bgp"
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
	if m.isv6 {
		return fmt.Sprintf(formatstr, m.dest.PeerAs, m.dest.LocalAs, m.dest.InterfaceIndex, m.dest.AddressFamily, net.IP(m.dest.PeerIp.Ipv6), net.IP(m.dest.LocalIp.Ipv6))
	}
	return fmt.Sprintf(formatstr, m.dest.PeerAs, m.dest.LocalAs, m.dest.InterfaceIndex, m.dest.AddressFamily, net.IP(m.dest.PeerIp.Ipv4).To4(), net.IP(m.dest.LocalIp.Ipv4).To4())
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
		pip.Ipv4 = b4hdrb.buf[4:20]
		lip.Ipv4 = b4hdrb.buf[20:36]
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
