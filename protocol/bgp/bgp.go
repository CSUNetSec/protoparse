package bgp

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
	pbbgp "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
	"github.com/CSUNetSec/protoparse"
	"github.com/CSUNetSec/protoparse/util"
	"log"
	"net"
)

const (
	AFI_IP  = 1
	AFI_IP6 = 2
)

type bgpHeaderBuf struct {
	dest  *pbbgp.BGPHeader
	buf   []byte
	isv6  bool
	isAS4 bool
}

type bgpUpdateBuf struct {
	dest  *pbbgp.BGPUpdate
	buf   []byte
	isv6  bool
	isAS4 bool
}

func NewBgpHeaderBuf(buf []byte, v6, as4 bool) *bgpHeaderBuf {
	return &bgpHeaderBuf{
		dest:  new(pbbgp.BGPHeader),
		buf:   buf,
		isv6:  v6,
		isAS4: as4,
	}
}

func NewBgpUpdateBuf(buf []byte, v6, as4 bool) *bgpUpdateBuf {
	return &bgpUpdateBuf{
		buf:   buf,
		dest:  new(pbbgp.BGPUpdate),
		isv6:  v6,
		isAS4: as4,
	}
}

func (bgph *bgpHeaderBuf) MarshalJSON() ([]byte, error) {
	return json.Marshal(bgph.dest)
}

func (bgpup *bgpUpdateBuf) MarshalJSON() ([]byte, error) {
	return json.Marshal(NewUpdateWrapper(bgpup.dest))
}

type UpdateWrapper struct {
	AdvertizedRoutes []*PrefixWrapper `json:"advertized_routes,omitempty"`
	WithdrawnRoutes  []*PrefixWrapper `json:"withdrawn_routes,omitempty"`
	Attrs            *AttrsWrapper    `json:"attrs,omitempty"`
}

func NewUpdateWrapper(update *pbbgp.BGPUpdate) *UpdateWrapper {
	ret := &UpdateWrapper{}
	if update.AdvertizedRoutes != nil {
		ret.AdvertizedRoutes = make([]*PrefixWrapper, len(update.AdvertizedRoutes.Prefixes))
		for ind, prefix := range update.AdvertizedRoutes.Prefixes {
			ret.AdvertizedRoutes[ind] = NewPrefixWrapper(prefix)
		}
	}

	if update.WithdrawnRoutes != nil {
		ret.WithdrawnRoutes = make([]*PrefixWrapper, len(update.WithdrawnRoutes.Prefixes))
		for ind, prefix := range update.WithdrawnRoutes.Prefixes {
			ret.WithdrawnRoutes[ind] = NewPrefixWrapper(prefix)
		}
	}

	if update.Attrs != nil {
		ret.Attrs = NewAttrsWrapper(update.Attrs)
	}

	return ret
}

// Neither of these fields should be omitted
type PrefixWrapper struct {
	Prefix net.IP `json:"prefix"`
	Mask   uint32 `json:"mask"`
}

func NewPrefixWrapper(pw *pbcom.PrefixWrapper) *PrefixWrapper {
	return &PrefixWrapper{net.IP(util.GetIP(pw.Prefix)), pw.Mask}
}

type AttrsWrapper struct {
	*pbbgp.BGPUpdate_Attributes
	NextHop    net.IP             `json:"next_hop,omitempty"`
	Aggregator *AggregatorWrapper `json:"aggregator,omitempty"`
}

func NewAttrsWrapper(base *pbbgp.BGPUpdate_Attributes) *AttrsWrapper {
	var nexthop net.IP
	if base.NextHop != nil {
		nexthop = net.IP(util.GetIP(base.NextHop))
	}
	return &AttrsWrapper{base, nexthop, NewAggregatorWrapper(base.Aggregator)}
}

type AggregatorWrapper struct {
	*pbbgp.BGPUpdate_Aggregator
	Ip net.IP `json:"ip,omitempty"`
}

func NewAggregatorWrapper(base *pbbgp.BGPUpdate_Aggregator) *AggregatorWrapper {
	if base == nil {
		return nil
	}
	ip := net.IP(util.GetIP(base.Ip))
	return &AggregatorWrapper{base, ip}
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
				ret += fmt.Sprintf("%s/%d\n", net.IP(util.GetIP(wr.GetPrefix())), wr.Mask)
			}
		}
	}
	if b.dest.AdvertizedRoutes != nil {
		if len(b.dest.AdvertizedRoutes.Prefixes) != 0 {
			ret += fmt.Sprintf(" Advertized Routes (%d):\n", len(b.dest.AdvertizedRoutes.Prefixes))
			for _, ar := range b.dest.AdvertizedRoutes.Prefixes {
				ret += fmt.Sprintf("%s/%d\n", net.IP(util.GetIP(ar.GetPrefix())), ar.Mask)
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
			ret += fmt.Sprintf("%s", net.IP(util.GetIP(b.dest.Attrs.NextHop)))
		}
		if b.dest.Attrs.AtomicAggregate {
			ret += "\nAtomic-Aggregate: true\n"
		}
		if b.dest.Attrs.Aggregator != nil {
			ret += "\nAggregator:"
			ret += fmt.Sprintf("AS:%d IP:%s", b.dest.Attrs.Aggregator.As, net.IP(util.GetIP(b.dest.Attrs.Aggregator.Ip)))
		}
		if b.dest.Attrs.Communities != nil {
			ret += "\nCommunities:"
			for _, com := range b.dest.Attrs.Communities.Communities {
				if com.ExtendedCommunity != nil {
					// Extended communities are 8 octet values
					ret += fmt.Sprintf("Extended Community:%s\n", hex.EncodeToString(com.ExtendedCommunity))
				} else if com.Community != nil {
					comStr := ""
					// Each community is described in 4 bytes
					for i := 0; i < len(com.Community); i += 4 {
						first := binary.BigEndian.Uint16(com.Community[i : i+2])
						sec := binary.BigEndian.Uint16(com.Community[i+2 : i+4])
						comStr += fmt.Sprintf(" %d:%d", first, sec)
					}
					ret += fmt.Sprintf("Community:%s", comStr)
				}
			}
		}
		ret += "\n"
	}
	return ret
}

func AttrToString(attrs *pbbgp.BGPUpdate_Attributes) string {
	ret := ""
	if attrs != nil {
		for _, seg := range attrs.AsPath {
			ret += "AS-Path:"
			if seg.AsSeq != nil {
				ret += fmt.Sprintf(" (%v) ", seg.AsSeq)
			}
			if seg.AsSet != nil {
				ret += fmt.Sprintf(" {%v} ", seg.AsSet)
			}
		}
		if attrs.NextHop != nil {
			ret += "\nNext-Hop:"
			ret += fmt.Sprintf("%s", net.IP(util.GetIP(attrs.NextHop)))
		}
		if attrs.AtomicAggregate {
			ret += "\nAtomic-Aggregate: true\n"
		}
		if attrs.Aggregator != nil {
			ret += "\nAggregator:"
			ret += fmt.Sprintf("AS:%d IP:%s", attrs.Aggregator.As, net.IP(util.GetIP(attrs.Aggregator.Ip)))
		}
		if attrs.Communities != nil {
			ret += "\nCommunities:"
			for _, com := range attrs.Communities.Communities {
				if com.ExtendedCommunity != nil {
					ret += fmt.Sprintf("Extended Community:%s\n", hex.EncodeToString(com.ExtendedCommunity))
				} else if com.Community != nil {
					comStr := ""
					// Each community is described in 4 bytes
					for i := 0; i < len(com.Community); i += 4 {
						first := binary.BigEndian.Uint16(com.Community[i : i+2])
						sec := binary.BigEndian.Uint16(com.Community[i+2 : i+4])
						comStr += fmt.Sprintf(" %d:%d", first, sec)
					}
					ret += fmt.Sprintf("Community:%s", comStr)
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
	if a != 0 {
		ret = true
	}
	return ret
}

func readPrefix(buf []byte, v6 bool) []*pbcom.PrefixWrapper {
	wpslice := []*pbcom.PrefixWrapper{}

	//fmt.Printf("blen:%d buf:%+v\n", len(buf), buf)
	for len(buf) > 1 { //can read the bytelen
		route := new(pbcom.PrefixWrapper)
		addr := new(pbcom.IPAddressWrapper)
		//read pref mask in bits
		bitlen := uint8(buf[0])
		buf = buf[1:]
		bytelen := (bitlen + 7) / 8
		if int(bytelen) > len(buf) || int(bytelen) < 1 {
			log.Printf("error in readPrefix [v6:%v].bytelen %d requested is more than length of buffer %d\n", v6, bytelen, len(buf))
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

func ParseAttrs(buf []byte, as4, v6 bool) (*pbbgp.BGPUpdate_Attributes, error, []*pbcom.PrefixWrapper, []*pbcom.PrefixWrapper) {
	return readAttrs(buf, as4, v6)
}

//this function returns the attributes but also the withdrawn prefixes or advertised prefixes found in MP_REACH/UNREACH
//because RFC2283 decided to shove that in the attributes. thanks ietf.
func readAttrs(buf []byte, as4, v6 bool) (*pbbgp.BGPUpdate_Attributes, error, []*pbcom.PrefixWrapper, []*pbcom.PrefixWrapper) {
	attrs := new(pbbgp.BGPUpdate_Attributes)
	var (
		attrlen uint16
		tempas  uint32
		mpadv   []*pbcom.PrefixWrapper
		mpwdr   []*pbcom.PrefixWrapper
	)
	//fmt.Printf("\ncalled with buflen:%d\n", len(buf))

	if len(buf) < 2 {
		//fmt.Printf(" ret here ")
		return attrs, errors.New("not enough bytes for attr flags and code"), nil, nil
	}
readattr:
	//fmt.Printf("\nreadattr buf %+v buflen:%d\n", buf, len(buf))
	if len(buf) < 2 {
		return attrs, nil, mpadv, mpwdr
	}
	flagbyte := uint8(buf[0])
	attrs.OptionalBit = itob(flagbyte & (1 << 7))
	attrs.TransitiveBit = itob(flagbyte & (1 << 6))
	attrs.PartialBit = itob(flagbyte & (1 << 5))
	attrs.ExtendedBit = itob(flagbyte & (1 << 4))
	typebyte := pbbgp.BGPUpdate_Attributes_Type(uint8(buf[1]))
	//fmt.Printf(" TYPE %d ", typebyte)
	if attrs.ExtendedBit == true {
		if len(buf) < 4 {
			return nil, errors.New("not enough bytes for extended attribute"), nil, nil
		}
		attrlen = uint16(binary.BigEndian.Uint16(buf[2:4]))
		//fmt.Printf("in attrlen ext. attrlen:%d\n", attrlen)
		if int(attrlen+4) <= len(buf) {
			//buf = buf[attrlen+4:]
			buf = buf[4:]
		} else {
			//fmt.Printf(" ret here1 ")
			return attrs, nil, mpadv, mpwdr
		}
	} else {
		if len(buf) < 3 {
			return nil, errors.New("not enough bytes for extended attribute"), nil, nil
		}
		attrlen = uint16(buf[2])
		//fmt.Printf("in attrlen. attrlen:%d\n", attrlen)
		if int(attrlen+3) <= len(buf) {
			//buf = buf[attrlen+3:]
			buf = buf[3:]
		} else {
			//fmt.Printf(" ret here2 attrlen:%d and lenbuf:%d", attrlen, len(buf))
			return attrs, nil, mpadv, mpwdr
		}
	}
	if attrlen == 0 {
		//fmt.Printf("\n attren is 0 \n")
		//fmt.Printf(" ret here3 ")
		return attrs, nil, mpadv, mpwdr
	}

	//fmt.Printf("attributes:%+v\n", attrs)
	//fmt.Printf(" [len:%d]  [val:%v] \n", attrlen, buf[:attrlen])
	totskip := 0
	switch typebyte {
	case pbbgp.BGPUpdate_Attributes_ORIGIN:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_ORIGIN)
		//fmt.Printf(" [origin] ")
		if attrlen != 1 {
			//XXX: when i have MP_REACH and unreach this is 2 bytes long. why?
			//maybe it's related to the stackoverflow attribute i commented on this patch...?
			return nil, fmt.Errorf("origin attribute should be 1 byte long and it is:%d", attrlen), nil, nil
		}
		//attrs.Origin = new(pb.BGPUpdate_Attributes_Origin)
		attrs.Origin = pbbgp.BGPUpdate_Attributes_Origin(buf[0])
		//fmt.Printf(" origin: %s ", attrs.Origin)
	case pbbgp.BGPUpdate_Attributes_AS_PATH:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_AS_PATH)
		//fmt.Printf(" [as-path] ")
		//reading  path segment type
	readseg:
		seg := new(pbbgp.BGPUpdate_ASPathSegment)
		if len(buf) < 2 {
			return nil, errors.New("not enough bytes for path segment type and path length"), nil, nil
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
			return nil, fmt.Errorf("unknown path segment type %d", ptype), nil, nil
		}
		plen := int(buf[1])
		buf = buf[2:]
		totskip += 2
		switch {
		case !as4 && len(buf) < int(plen)*2:
			return nil, fmt.Errorf("not enough bytes for an AS2 path segment of length %d", plen), nil, nil
		case as4 && len(buf) < int(plen)*4:
			return nil, fmt.Errorf("not enough bytes for an AS4 path segment of length %d", plen), nil, nil
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
	case pbbgp.BGPUpdate_Attributes_NEXT_HOP:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_NEXT_HOP)
		//fmt.Printf(" [next-hop] ", attrlen, v6)
		addr := new(pbcom.IPAddressWrapper)
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
			return nil, fmt.Errorf("nexthop ip bytes don't agree in length with function invocation ip type"), nil, nil
		}
		//fmt.Printf(":ip:%s / %d:\n", net.IP(addr.Ipv4).To4().String(), bitlen)
		attrs.NextHop = addr

	case pbbgp.BGPUpdate_Attributes_MULTI_EXIT:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_MULTI_EXIT)
		//fmt.Printf(" [multi-exit] ")
		if attrlen != 4 {
			return nil, fmt.Errorf("multi-exit discriminator should be 4 bytes"), nil, nil
		}
		me := binary.BigEndian.Uint32(buf[:attrlen])
		attrs.MultiExit = me
	case pbbgp.BGPUpdate_Attributes_LOCAL_PREF:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_LOCAL_PREF)
		//fmt.Printf(" [local-pref] ")
		if attrlen != 4 {
			return nil, fmt.Errorf("local-pref should be 4 bytes"), nil, nil
		}
		lp := binary.BigEndian.Uint32(buf[:attrlen])
		attrs.LocalPref = lp
	case pbbgp.BGPUpdate_Attributes_ATOMIC_AGGREGATE:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_ATOMIC_AGGREGATE)
		//fmt.Printf(" [atomic-aggregate] ")
		aa := true
		attrs.AtomicAggregate = aa
	case pbbgp.BGPUpdate_Attributes_AGGREGATOR:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_AGGREGATOR)
		//fmt.Printf(" [aggregator] ")
		addr := new(pbcom.IPAddressWrapper)
		aggr := new(pbbgp.BGPUpdate_Aggregator)
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
			return nil, fmt.Errorf("not correct amount of bytes for Aggregator Attribute"), nil, nil
		}
		aggr.Ip = addr
		attrs.Aggregator = aggr
	case pbbgp.BGPUpdate_Attributes_COMMUNITY:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_COMMUNITY)
		//fmt.Printf(" [community] ")
		//if communities is not set yet
		if attrs.Communities == nil {
			attrs.Communities = new(pbbgp.BGPUpdate_Communities)
		}
		com := new(pbbgp.BGPUpdate_Community)
		combuf := make([]byte, attrlen)
		copy(combuf, buf[:attrlen])
		com.Community = combuf
		attrs.Communities.Communities = append(attrs.Communities.Communities, com)
	case pbbgp.BGPUpdate_Attributes_MP_REACH_NLRI:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_MP_REACH_NLRI)

		if len(buf) < 4 {
			return nil, fmt.Errorf("not enough bytes for MP_REACH"), nil, nil
		}
		nhl := uint8(buf[3])
		buf = buf[4:] //skup over AFI SAFI and length of next hop
		totskip += 4
		if nhl > 0 && int(nhl) < len(buf) { //set next hop
			attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_NEXT_HOP)
			//fmt.Printf(" [next-hop] ", attrlen, v6)
			addr := new(pbcom.IPAddressWrapper)
			switch {
			case v6 == true && nhl == 16:
				ipbuf := make([]byte, 16)
				copy(ipbuf, buf[:nhl])
				//fmt.Sprintf("got v6 :%v", ipbuf)
				addr.Ipv6 = ipbuf
			//http://networkengineering.stackexchange.com/questions/12556/how-to-interpret-mp-reach-nlri-attribute-with-address-length-of-32-bytes-contain
			//this is the global ipv6 and the linklocal ipv6
			//RFC- 2545 Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing"
			case v6 == true && nhl == 32:
				ipbuf := make([]byte, 16)
				copy(ipbuf, buf[:16])
				addr.Ipv6 = ipbuf //XXX for now ignoring the link local ipv6
			case v6 == false && nhl == 4:
				ipbuf := make([]byte, 4)
				copy(ipbuf, buf[:nhl])
				//fmt.Sprintf("got v4 :%v", ipbuf)
				addr.Ipv4 = ipbuf
			default:
				//fmt.Sprintf("got fail")
				return nil, fmt.Errorf("nexthop ip bytes (%d) in MP_REACH don't agree in length with function invocation (v6:%v) ip type", nhl, v6), nil, nil
			}
			attrs.NextHop = addr //This next hop is prefered if it exists
		} else {
			return nil, fmt.Errorf("next hop length in MP_REACH is malformed"), nil, nil
		}
		buf = buf[nhl:]
		totskip += int(nhl)
		if len(buf) < 1 {
			return nil, fmt.Errorf("not enough space in MP_REACH for SNPA number info"), nil, nil
		}
		snpanum := uint8(buf[0]) //number of SNPAs
		buf = buf[1:]
		totskip += 1
		//they are now deprecated at the latest rfc (....)
		if snpanum > 0 { //XXX jump over them for now
			innerskip, snpal := 0, uint8(0)
			for i := 0; i < int(snpanum); i++ {
				if len(buf) < 1 {
					return nil, fmt.Errorf("not enough space in MP_REACH for SNPA length info"), nil, nil
				}
				snpal = uint8(buf[0])
				buf = buf[1:]
				innerskip += 1
				if int(snpal) > len(buf) {
					return nil, fmt.Errorf("not enough space in MP_REACH for SNPA info"), nil, nil
				}
				buf = buf[snpal:]
				innerskip += int(snpal)
			}
			totskip += innerskip
		}
		mpadv = readPrefix(buf, v6)
		//fmt.Printf(" [MP_REACH_NLRI] ")
	case pbbgp.BGPUpdate_Attributes_MP_UNREACH_NLRI:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_MP_UNREACH_NLRI)
		if len(buf) < 3 {
			return nil, fmt.Errorf("not enough bytes for MP unreach"), nil, nil
		}
		//XXX skip over AFI and SAFI
		buf = buf[3:]
		totskip += 3
		mpwdr = readPrefix(buf, v6)
		//fmt.Printf(" [MP_UNREACH_NLRI] ")
	case pbbgp.BGPUpdate_Attributes_EXTENDED_COMMUNITY:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_EXTENDED_COMMUNITY)
		//fmt.Printf(" [extended community] ")
		//if communities is not set yet
		if attrs.Communities == nil {
			attrs.Communities = new(pbbgp.BGPUpdate_Communities)
		}
		com := new(pbbgp.BGPUpdate_Community)
		combuf := make([]byte, attrlen)
		copy(combuf, buf[:attrlen])
		com.ExtendedCommunity = combuf
		attrs.Communities.Communities = append(attrs.Communities.Communities, com)
	case pbbgp.BGPUpdate_Attributes_AS4_PATH:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_AS4_PATH)
		//fmt.Printf(" [as4-path] ")
		//reading  path segment type
	readseg4:
		seg := new(pbbgp.BGPUpdate_ASPathSegment)
		if len(buf) < 2 {
			return nil, errors.New("not enough bytes for path segment type and path length"), nil, nil
		}
		ptype := uint8(buf[0])
		setp := false
		switch ptype {
		case 1:
			setp = true
		case 2:
			setp = false
		default:
			return nil, fmt.Errorf("unknown path segment type %d", ptype), nil, nil
		}
		plen := int(buf[1])
		buf = buf[2:]
		totskip += 2
		if len(buf) < int(plen)*4 {
			return nil, fmt.Errorf("not enough bytes for an AS4 path segment of length %d", plen), nil, nil
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
	case pbbgp.BGPUpdate_Attributes_AS4_AGGREGATOR:
		attrs.Types = append(attrs.Types, pbbgp.BGPUpdate_Attributes_AS4_AGGREGATOR)
		//fmt.Printf(" [as4-aggregator] ")
	case pbbgp.BGPUpdate_Attributes_IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITY:
		attrs.Types = append(attrs.Types, typebyte) // we just skip over the contents of the attribute for now.
		//fmt.Printf(" [IPV6 extended community] ")
		buf = buf[20:]
		totskip += 20
	case pbbgp.BGPUpdate_Attributes_ORIGINATOR_ID, pbbgp.BGPUpdate_Attributes_CLUSTER_LIST, pbbgp.BGPUpdate_Attributes_PMSI_TUNNEL, pbbgp.BGPUpdate_Attributes_TUNNEL_ENCAPSULATION_ATTRIBUTE, pbbgp.BGPUpdate_Attributes_TRAFFIC_ENGINEERING, pbbgp.BGPUpdate_Attributes_AIGP, pbbgp.BGPUpdate_Attributes_PE_DISTINGUISHER_LABELS, pbbgp.BGPUpdate_Attributes_BGP_LS_ATTRIBUTE, pbbgp.BGPUpdate_Attributes_LARGE_COMMUNITY, pbbgp.BGPUpdate_Attributes_BGPSEC_PATH, pbbgp.BGPUpdate_Attributes_ATTR_SET:
		attrs.Types = append(attrs.Types, typebyte)
	default:
		//fmt.Printf("\nunknown type!\n")
		return attrs, fmt.Errorf(" [unknown type %d] ", typebyte), nil, nil
	}
	buf = buf[int(attrlen)-totskip:]
	goto readattr

	//NOTREACHED
	return attrs, nil, mpadv, mpwdr
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

		b.dest.WithdrawnRoutes = new(pbbgp.BGPUpdate_WithdrawnRoutes)
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
		//attrtype := binary.BigEndian.Uint16(b.buf[:2])
		attrs, errattr, mpadv, mpwdr := readAttrs(b.buf[:attrlen], b.isAS4, b.isv6)
		if errattr != nil { //XXX log the error?
			return nil, errattr
		}
		//fmt.Printf("attributes: %s\n", attrs)
		b.buf = b.buf[attrlen:]
		b.dest.Attrs = attrs
		nlrilen := uplen - 4 - int(attrlen) - wlen
		if len(mpadv) != 0 { // we got advertised routes from mp_reach
			b.dest.AdvertizedRoutes = new(pbbgp.BGPUpdate_AdvertizedRoutes)
			b.dest.AdvertizedRoutes.Prefixes = mpadv
		}
		if len(mpwdr) != 0 {
			if b.dest.WithdrawnRoutes == nil { //make a new one
				b.dest.WithdrawnRoutes = new(pbbgp.BGPUpdate_WithdrawnRoutes)
				b.dest.WithdrawnRoutes.Prefixes = mpwdr
			} else { // append them
				b.dest.WithdrawnRoutes.Prefixes = append(b.dest.WithdrawnRoutes.Prefixes, mpwdr...)
			}
		}
		if nlrilen == 0 || nlrilen < 0 {
			return nil, nil //return. it might only have withdraws
		}
		//fmt.Println("nrlilen:", nlrilen)
		nlrislice := readPrefix(b.buf[:nlrilen], b.isv6)
		b.buf = b.buf[nlrilen:]
		if b.dest.AdvertizedRoutes == nil { // make a new one
			b.dest.AdvertizedRoutes = new(pbbgp.BGPUpdate_AdvertizedRoutes)
			b.dest.AdvertizedRoutes.Prefixes = nlrislice
		} else { // append them to the mp ones
			b.dest.AdvertizedRoutes.Prefixes = append(b.dest.AdvertizedRoutes.Prefixes, nlrislice...)
		}
	}

	return nil, nil
}

func (b *bgpUpdateBuf) GetUpdate() *pbbgp.BGPUpdate {
	return b.dest
}
