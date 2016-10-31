package bgp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/CSUNetSec/protoparse"
	pb "github.com/CSUNetSec/protoparse/pb"
	"net"
)

const (
	AFI_IP  = 1
	AFI_IP6 = 2
)

type bgpHeaderBuf struct {
	dest  *pb.BGPHeader
	buf   []byte
	isv6  bool
	isAS4 bool
}

type bgpUpdateBuf struct {
	dest  *pb.BGPUpdate
	buf   []byte
	isv6  bool
	isAS4 bool
}

func NewBgpHeaderBuf(buf []byte, v6, as4 bool) *bgpHeaderBuf {
	return &bgpHeaderBuf{
		dest:  new(pb.BGPHeader),
		buf:   buf,
		isv6:  v6,
		isAS4: as4,
	}
}

func NewBgpUpdateBuf(buf []byte, v6, as4 bool) *bgpUpdateBuf {
	return &bgpUpdateBuf{
		buf:   buf,
		dest:  new(pb.BGPUpdate),
		isv6:  v6,
		isAS4: as4,
	}
}

func (b *bgpHeaderBuf) String() string {
	return b.dest.String()
}

func (b *bgpUpdateBuf) String() string {
	ret := ""
	if b.dest.WithdrawnRoutes != nil {
		if len(b.dest.WithdrawnRoutes.Prefixes) != 0 {
			ret += fmt.Sprintf(" Withdrawn Routes (%d):\n", len(b.dest.WithdrawnRoutes.Prefixes))
			for _, wr := range b.dest.WithdrawnRoutes.Prefixes {
				if b.isv6 {
					ret += fmt.Sprintf("%s/%d\n", net.IP(wr.Prefix.Ipv6), wr.Mask)
				} else {
					ret += fmt.Sprintf("%s/%d\n", net.IP(wr.Prefix.Ipv4).To4(), wr.Mask)
				}
			}
		}
	}
	if b.dest.AdvertizedRoutes != nil {
		if len(b.dest.AdvertizedRoutes.Prefixes) != 0 {
			ret += fmt.Sprintf(" Advertized Routes (%d):\n", len(b.dest.AdvertizedRoutes.Prefixes))
			for _, ar := range b.dest.AdvertizedRoutes.Prefixes {
				if b.isv6 {
					ret += fmt.Sprintf("%s/%d\n", net.IP(ar.Prefix.Ipv6), ar.Mask)
				} else {
					ret += fmt.Sprintf("%s/%d\n", net.IP(ar.Prefix.Ipv4).To4(), ar.Mask)
				}
			}
		}
	}
	if b.dest.Attrs != nil {
		for _, seg := range b.dest.Attrs.AsPath {
			ret += "AS-Path:"
			if seg.AsSeq != nil {
				ret += fmt.Sprintf(" (%v) ", seg.AsSeq)
			}
			if seg.AsSet != nil {
				ret += fmt.Sprintf(" {%v} ", seg.AsSet)
			}
		}
		if b.dest.Attrs.NextHop != nil {
			ret += "\nNext-Hop:"
			if b.isv6 {
				ret += fmt.Sprintf("%s", net.IP(b.dest.Attrs.NextHop.Ipv6))
			} else {
				ret += fmt.Sprintf("%s", net.IP(b.dest.Attrs.NextHop.Ipv4).To4())
			}
		}
		if b.dest.Attrs.AtomicAggregate {
			ret += "\nAtomic-Aggregate: true\n"
		}
		if b.dest.Attrs.Aggregator != nil {
			ret += "\nAggregator:"
			if b.isv6 {
				ret += fmt.Sprintf("AS:%d IP:%s", b.dest.Attrs.Aggregator.As, net.IP(b.dest.Attrs.Aggregator.Ip.Ipv6))
			} else {
				ret += fmt.Sprintf("AS:%d IP:%s", b.dest.Attrs.Aggregator.As, net.IP(b.dest.Attrs.Aggregator.Ip.Ipv4).To4())
			}
		}
		if b.dest.Attrs.Communities != nil {
			ret += "\nCommunities:"
			for _, com := range b.dest.Attrs.Communities.Communities {
				if com.ExtendedCommunity != nil {
					ret += fmt.Sprintf("Extended Community:%s\n", hex.EncodeToString(com.ExtendedCommunity))
				} else if com.Community != nil {
					ret += fmt.Sprintf("Community:%s\n", hex.EncodeToString(com.Community))
				}
			}
		}
		ret += "\n"
	}
	return ret
}

func (b *bgpHeaderBuf) Parse() (protoparse.PbVal, error) {
	if len(b.buf) < 19 {
		return nil, errors.New("not enough bytes to decode BGP header")
	}
	b.dest.Marker = b.buf[:16]
	b.dest.Length = uint32(binary.BigEndian.Uint16(b.buf[16:18]))
	b.dest.Type = uint32(b.buf[18])
	return NewBgpUpdateBuf(b.buf[19:], b.isv6, b.isAS4), nil
}

func itob(a uint8) bool {
	ret := false
	if a == 1 {
		ret = true
	}
	return ret
}

func readPrefix(buf []byte, v6 bool) []*pb.PrefixWrapper {
	wpslice := []*pb.PrefixWrapper{}

	//fmt.Printf("blen:%d buf:%+v\n", len(buf), buf)
	for len(buf) > 1 { //can read the bytelen
		route := new(pb.PrefixWrapper)
		addr := new(pb.IPAddressWrapper)
		//read pref mask in bits
		bitlen := uint8(buf[0])
		buf = buf[1:]
		bytelen := (bitlen + 7) / 8
		if int(bytelen) > len(buf) {
			fmt.Printf("error in readPrefix. bytelen requested is more than length of buffer")
			return wpslice
		}
		//fmt.Println("bitlen: ", bitlen, "bytelen ", bytelen)
		pbuf := make([]byte, bytelen)
		copy(pbuf, buf[:bytelen])
		// clear trailing bits in the last byte. rfc doesn't require
		// this but gobgp does it
		if bitlen%8 != 0 {
			mask := 0xff00 >> (bitlen % 8)
			last_byte_value := pbuf[bytelen-1] & byte(mask)
			pbuf[bytelen-1] = last_byte_value
		}
		if v6 {
			ipbuf := make([]byte, 16)
			copy(ipbuf, pbuf)
			addr.Ipv6 = ipbuf
		} else {
			ipbuf := make([]byte, 4)
			copy(ipbuf, pbuf)
			addr.Ipv4 = ipbuf
			//fmt.Printf(":ip:%s / %d:\n", net.IP(addr.Ipv4).To4().String(), bitlen)
		}
		route.Mask = uint32(bitlen)
		route.Prefix = addr
		wpslice = append(wpslice, route)
		buf = buf[bytelen:] //advance the buffer to the next withdrawn route
	}
	return wpslice
}

func readAttrs(buf []byte, as4, v6 bool) (*pb.BGPUpdate_Attributes, error) {
	attrs := new(pb.BGPUpdate_Attributes)
	var (
		attrlen uint16
		tempas  uint32
	)

	if len(buf) < 2 {
		//fmt.Printf(" ret here ")
		return attrs, errors.New("not enough bytes for attr flags and code")
	}
readattr:
	if len(buf) < 2 {
		return attrs, nil
	}
	flagbyte := uint8(buf[0])
	attrs.OptionalBit = itob(flagbyte & (1 << 0))
	attrs.TransitiveBit = itob(flagbyte & (1 << 1))
	attrs.PartialBit = itob(flagbyte & (1 << 2))
	attrs.ExtendedBit = itob(flagbyte & (1 << 3))
	typebyte := uint8(buf[1])
	//fmt.Printf(" TYPE %d ", typebyte)
	if attrs.ExtendedBit == true {
		if len(buf) < 4 {
			return nil, errors.New("not enough bytes for extended attribute")
		}
		attrlen = uint16(binary.BigEndian.Uint16(buf[2:4]))
		if int(attrlen+4) <= len(buf) {
			//buf = buf[attrlen+4:]
			buf = buf[4:]
		} else {
			//fmt.Printf(" ret here1 ")
			return attrs, nil
		}
	} else {
		if len(buf) < 3 {
			return nil, errors.New("not enough bytes for extended attribute")
		}
		attrlen = uint16(buf[2])
		if int(attrlen+3) <= len(buf) {
			//buf = buf[attrlen+3:]
			buf = buf[3:]
		} else {
			//fmt.Printf(" ret here2 attrlen:%d and lenbuf:%d", attrlen, len(buf))
			return attrs, nil
		}
	}
	if attrlen == 0 {
		//fmt.Printf("\n attren is 0 \n")
		//fmt.Printf(" ret here3 ")
		return attrs, nil
	}

	//fmt.Printf("attributes:%+v\n", attrs)
	//fmt.Printf(" [len:%d]  [val:%v] \n", attrlen, buf[:attrlen])
	totskip := 0
	switch typebyte {
	case 1:
		//fmt.Printf(" [origin] ")
		if attrlen != 1 {
			return nil, errors.New("origin attribute should be 1 byte long")
		}
		//attrs.Origin = new(pb.BGPUpdate_Attributes_Origin)
		attrs.Origin = pb.BGPUpdate_Attributes_Origin(buf[0])
		//fmt.Printf(" origin: %s ", attrs.Origin)
	case 2:
		//fmt.Printf(" [as-path] ")
		//reading  path segment type
	readseg:
		seg := new(pb.BGPUpdate_ASPathSegment)
		if len(buf) < 2 {
			return nil, errors.New("not enough bytes for path segment type and path length")
		}
		ptype := uint8(buf[0])
		setp := false
		switch ptype {
		case 1:
			setp = true
		case 2:
			setp = false
		default:
			//fmt.Printf("\n--err aspath--\n")
			return nil, fmt.Errorf("unknown path segment type %d", ptype)
		}
		plen := int(buf[1])
		buf = buf[2:]
		totskip += 2
		switch {
		case !as4 && len(buf) < int(plen)*2:
			return nil, fmt.Errorf("not enough bytes for an AS2 path segment of length %d", plen)
		case as4 && len(buf) < int(plen)*4:
			return nil, fmt.Errorf("not enough bytes for an AS4 path segment of length %d", plen)
		}

		for pind := 0; pind < plen; pind++ {
			if as4 {
				tempas = binary.BigEndian.Uint32(buf[:4])
				buf = buf[4:]
				totskip += 4
			} else {
				tempas = uint32(binary.BigEndian.Uint16(buf[:2]))
				buf = buf[2:]
				totskip += 2
			}
			if setp {
				seg.AsSet = append(seg.AsSet, tempas)
			} else {
				seg.AsSeq = append(seg.AsSeq, tempas)
			}
		}
		attrs.AsPath = append(attrs.AsPath, seg)
		if totskip < int(attrlen) { // XXX more as path segments?
			//fmt.Printf("jumping to readseg again until now read:%d attrlen:%d", totskip, attrlen)
			goto readseg
		}
	case 3:
		//fmt.Printf(" [next-hop] ", attrlen, v6)
		addr := new(pb.IPAddressWrapper)
		switch {
		case v6 == true && attrlen == 16:
			ipbuf := make([]byte, 16)
			copy(ipbuf, buf[:attrlen])
			//fmt.Sprintf("got v6 :%v", ipbuf)
			addr.Ipv6 = ipbuf
		case v6 == false && attrlen == 4:
			ipbuf := make([]byte, 4)
			copy(ipbuf, buf[:attrlen])
			//fmt.Sprintf("got v4 :%v", ipbuf)
			addr.Ipv4 = ipbuf
		default:
			//fmt.Sprintf("got fail")
			return nil, fmt.Errorf("nexthop ip bytes don't agree in length with function invocation ip type")
		}
		//fmt.Printf(":ip:%s / %d:\n", net.IP(addr.Ipv4).To4().String(), bitlen)
		attrs.NextHop = addr

	case 4:
		//fmt.Printf(" [multi-exit] ")
		if attrlen != 4 {
			return nil, fmt.Errorf("multi-exit discriminator should be 4 bytes")
		}
		me := binary.BigEndian.Uint32(buf[:attrlen])
		attrs.MultiExit = me
	case 5:
		//fmt.Printf(" [local-pref] ")
		if attrlen != 4 {
			return nil, fmt.Errorf("local-pref should be 4 bytes")
		}
		lp := binary.BigEndian.Uint32(buf[:attrlen])
		attrs.LocalPref = lp
	case 6:
		//fmt.Printf(" [atomic-aggregate] ")
		aa := true
		attrs.AtomicAggregate = aa
	case 7:
		//fmt.Printf(" [aggregator] ")
		addr := new(pb.IPAddressWrapper)
		aggr := new(pb.BGPUpdate_Aggregator)
		switch {
		case attrlen == 6: // 2 byte AS and 4 byte IP
			as := uint32(binary.BigEndian.Uint16(buf[:2]))
			aggr.As = as
			ipbuf := make([]byte, 4)
			copy(ipbuf, buf[2:6])
			addr.Ipv4 = ipbuf
		case attrlen == 8: // 4 byte AS and 4 byte IP
			as := binary.BigEndian.Uint32(buf[:4])
			aggr.As = as
			ipbuf := make([]byte, 4)
			copy(ipbuf, buf[4:8])
			addr.Ipv4 = ipbuf
		case attrlen == 18: // 2byte AS and 16 byte IP
			as := uint32(binary.BigEndian.Uint16(buf[:2]))
			aggr.As = as
			ipbuf := make([]byte, 16)
			copy(ipbuf, buf[2:18])
			addr.Ipv6 = ipbuf
		case attrlen == 20: // 2byte AS and 16 byte IP
			as := binary.BigEndian.Uint32(buf[:4])
			aggr.As = as
			ipbuf := make([]byte, 16)
			copy(ipbuf, buf[4:20])
			addr.Ipv6 = ipbuf
		default:
			return nil, fmt.Errorf("not correct amount of bytes for Aggregator Attribute")
		}
		aggr.Ip = addr
		attrs.Aggregator = aggr
	case 8:
		//fmt.Printf(" [community] ")
		//if communities is not set yet
		if attrs.Communities == nil {
			attrs.Communities = new(pb.BGPUpdate_Communities)
		}
		com := new(pb.BGPUpdate_Community)
		combuf := make([]byte, attrlen)
		copy(combuf, buf[:attrlen])
		com.Community = combuf
		attrs.Communities.Communities = append(attrs.Communities.Communities, com)
	case 16:
		//fmt.Printf(" [extended community] ")
		//if communities is not set yet
		if attrs.Communities == nil {
			attrs.Communities = new(pb.BGPUpdate_Communities)
		}
		com := new(pb.BGPUpdate_Community)
		combuf := make([]byte, attrlen)
		copy(combuf, buf[:attrlen])
		com.ExtendedCommunity = combuf
		attrs.Communities.Communities = append(attrs.Communities.Communities, com)
	case 17:
		//fmt.Printf(" [as4-path] ")
		//reading  path segment type
	readseg4:
		seg := new(pb.BGPUpdate_ASPathSegment)
		if len(buf) < 2 {
			return nil, errors.New("not enough bytes for path segment type and path length")
		}
		ptype := uint8(buf[0])
		setp := false
		switch ptype {
		case 1:
			setp = true
		case 2:
			setp = false
		default:
			return nil, fmt.Errorf("unknown path segment type %d", ptype)
		}
		plen := int(buf[1])
		buf = buf[2:]
		totskip += 2
		if len(buf) < int(plen)*4 {
			return nil, fmt.Errorf("not enough bytes for an AS4 path segment of length %d", plen)
		}
		for pind := 0; pind < plen; pind++ {
			as := binary.BigEndian.Uint32(buf[:4])
			if setp {
				seg.AsSet = append(seg.AsSet, as)
			} else {
				seg.AsSeq = append(seg.AsSeq, as)
			}
			buf = buf[4:]
			totskip += 4
		}
		attrs.AsPath = append(attrs.AsPath, seg)
		if totskip < int(attrlen) { // more as path segments?
			goto readseg4
		}
	case 18:
		//fmt.Printf(" [as4-aggregator] ")
	default:
		return attrs, fmt.Errorf(" [unknown type %d] ", typebyte)
	}
	buf = buf[int(attrlen)-totskip:]
	//fmt.Printf("\nattribute skipping %d bytes\n", int(attrlen)-totskip)
	goto readattr

	//NOTREACHED
	return attrs, nil
}

func (b *bgpUpdateBuf) Parse() (protoparse.PbVal, error) {
	if len(b.buf) < 2 {
		return nil, errors.New("not enough bytes to parse withdrawn routes length")
	}
	uplen := len(b.buf)
	wlen := int(binary.BigEndian.Uint16(b.buf[:2]))
	//log.Println("wlen:", wlen)
	if wlen == 0 {
		//fmt.Println("no withdrawn routes present")
		b.buf = b.buf[2:] // advance or die (fail or success)
	} else {
		if len(b.buf) < wlen {
			return nil, errors.New("not enough bytes for withdrawn routes")
		}
		b.buf = b.buf[2:] // advance or die

		wpslice := readPrefix(b.buf[:wlen], b.isv6)
		b.buf = b.buf[wlen:]

		b.dest.WithdrawnRoutes = new(pb.BGPUpdate_WithdrawnRoutes)
		b.dest.WithdrawnRoutes.Prefixes = wpslice
	}
	//read attr len
	attrlen := binary.BigEndian.Uint16(b.buf[:2])
	b.buf = b.buf[2:]
	if attrlen == 0 {
		//fmt.Println("no PathAttrs or NLRI present")
		return nil, nil
	} else {
		if len(b.buf) < int(attrlen) {
			return nil, errors.New("not enough bytes for attributes")
		}
		//XXX:parse them
		//attrtype := binary.BigEndian.Uint16(b.buf[:2])
		attrs, errattr := readAttrs(b.buf[:attrlen], b.isAS4, b.isv6)
		if errattr != nil {
			return nil, errattr
		}
		//fmt.Printf("attributes: %s\n", attrs)
		//XXX move over them for now
		b.buf = b.buf[attrlen:]
		b.dest.Attrs = attrs

		nlrilen := uplen - 4 - int(attrlen) - wlen
		if nlrilen == 0 || nlrilen < 0 {
			fmt.Println("no NLRI present")
			return nil, errors.New("negative or zero NLRI length")
		}
		//fmt.Println("nrlilen:", nlrilen)
		nlrislice := readPrefix(b.buf[:nlrilen], b.isv6)
		b.buf = b.buf[nlrilen:]
		b.dest.AdvertizedRoutes = new(pb.BGPUpdate_AdvertizedRoutes)
		b.dest.AdvertizedRoutes.Prefixes = nlrislice
	}

	return nil, nil
}
