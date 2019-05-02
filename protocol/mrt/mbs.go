package mrt

import (
	"fmt"
	common "github.com/CSUNetSec/netsec-protobufs/common"
	pbbgp "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
	"github.com/CSUNetSec/protoparse"
	util "github.com/CSUNetSec/protoparse/util"
	"net"
	"time"
)

type MrtBufferStack struct {
	MrthBuf   protoparse.PbVal `json:"mrt_header,omitempty"`
	Bgp4mpbuf protoparse.PbVal `json:"bgp4mp_header,omitempty"`
	Bgphbuf   protoparse.PbVal `json:"bgp_header,omitempty"`
	Bgpupbuf  protoparse.PbVal `json:"bgp_update,omitempty"`

	Ribbuf protoparse.PbVal `json:"rib_entry,omitempty"`
}

func (mbs *MrtBufferStack) GetRawMessage() []byte {
	return mbs.MrthBuf.(*mrtHhdrBuf).buf
}

func (mbs *MrtBufferStack) IsRibStack() bool {
	return mbs.Ribbuf != nil
}

func ParseHeaders(data []byte, ind bool) (*MrtBufferStack, error) {
	mrth := NewMrtHdrBuf(data)
	bgp4h, err := mrth.Parse()
	if err != nil {
		return nil, fmt.Errorf("Failed parsing MRT header: %s\n", err)
	}

	if ind {
		_, err = bgp4h.Parse()
		if err != nil {
			return nil, fmt.Errorf("Failed parsing RIB header: %s\n", err)
		}

		return &MrtBufferStack{MrthBuf: mrth, Ribbuf: bgp4h}, nil
	} else {
		bgph, err := bgp4h.Parse()
		if err != nil {
			return nil, fmt.Errorf("Failed parsing BG4MP header: %s\n", err)
		}

		bgpup, err := bgph.Parse()
		if err != nil {
			return nil, fmt.Errorf("Failed parsing BGP header: %s\n", err)
		}

		_, err = bgpup.Parse()
		if err != nil {
			return nil, fmt.Errorf("Failed parsing BGP update: %s\n", err)
		}

		return &MrtBufferStack{MrthBuf: mrth, Bgp4mpbuf: bgp4h, Bgphbuf: bgph, Bgpupbuf: bgpup}, nil
	}
}

func ParseRibHeaders(data []byte, ind protoparse.PbVal) (*MrtBufferStack, error) {
	mrth := NewRIBMrtHdrBuf(data, ind)
	ribH, err := mrth.Parse()
	if err != nil {
		return nil, fmt.Errorf("Failed parsing MRT header: %s\n", err)
	}

	_, err = ribH.Parse()
	if err != nil {
		return nil, fmt.Errorf("Failed parsing RIB header: %s\n", err)
	}

	return &MrtBufferStack{MrthBuf: mrth, Ribbuf: ribH}, nil
}

// This code just converts the 32 bit timestamp inside
// an MRT header and converts it to a standard go time.Time
func GetTimestamp(mbs *MrtBufferStack) time.Time {
	mrth := mbs.MrthBuf.(protoparse.MRTHeaderer).GetHeader()
	ts := time.Unix(int64(mrth.Timestamp), 0)
	return ts
}

// This will return the full AS path listed on the mbs
// This does no length checking, so the returned path
// could be empty, under very weird circumstances
func GetASPath(mbs *MrtBufferStack) ([]uint32, error) {
	if mbs.IsRibStack() {
		var totalASlist []uint32
		rib := mbs.Ribbuf.(protoparse.RIBHeaderer).GetHeader()
		if rib == nil {
			return nil, fmt.Errorf("Error parsing AS path in rib header")
		}
		for _, ent := range rib.RouteEntry {
			if ent.Attrs != nil {
				entryAS := getASPathFromAttrs(ent.Attrs)
				totalASlist = append(totalASlist, entryAS...)
			}
		}
		return totalASlist, nil
	} else {
		update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()
		if update == nil || update.Attrs == nil {
			return nil, fmt.Errorf("Error parsing AS path in BGP update")
		}
		return getASPathFromAttrs(update.Attrs), nil
	}

}

func getASPathFromAttrs(attrs *pbbgp.BGPUpdate_Attributes) []uint32 {
	var ASlist []uint32
	for _, segment := range attrs.ASPath {
		if segment.ASSeq != nil && len(segment.ASSeq) > 0 {
			ASlist = append(ASlist, segment.ASSeq...)
		} else if segment.ASSet != nil && len(segment.ASSet) > 0 {
			ASlist = append(ASlist, segment.ASSet...)
		}
	}
	return ASlist
}

// This will get the collector IP that received the message from the
// BGP4MP header
func GetCollector(mbs *MrtBufferStack) net.IP {
	b4mph := mbs.Bgp4mpbuf.(protoparse.BGP4MPHeaderer).GetHeader()
	return net.IP(util.GetIP(b4mph.Local_IP))
}

type Route struct {
	IP   net.IP
	Mask uint8
}

func (r Route) String() string {
	return fmt.Sprintf("%s/%d", r.IP, r.Mask)
}

// This will return a list of prefixes <"IP/mask"> that appear in
// advertised routes
// Like getASPath, this does no length checking, and may return
// an empty array
func GetAdvertisedPrefixes(mbs *MrtBufferStack) ([]Route, error) {
	if mbs.IsRibStack() {
		rib := mbs.Ribbuf.(protoparse.RIBHeaderer).GetHeader()
		if rib == nil {
			return nil, fmt.Errorf("Error parsing withdrawn routes")
		}

		pref := rib.GetRouteEntry()[0].GetPrefix()
		r := Route{net.IP(util.GetIP(pref.GetPrefix())), uint8(pref.Mask)}
		return []Route{r}, nil
	} else {
		update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()

		if update == nil || update.AdvertisedRoutes == nil {
			return nil, fmt.Errorf("Error parsing advertised routes\n")
		}

		return getRoutes(update.AdvertisedRoutes.Prefixes), nil
	}
}

// This will return a list of prefixes that appear in withdrawn
// routes
func GetWithdrawnPrefixes(mbs *MrtBufferStack) ([]Route, error) {
	if mbs.IsRibStack() {
		rib := mbs.Ribbuf.(protoparse.RIBHeaderer).GetHeader()
		if rib == nil {
			return nil, fmt.Errorf("Error parsing withdrawn routes")
		}

		// Ribs don't have withdrawn prefixes
		return nil, nil
	} else {
		update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()

		if update == nil || update.WithdrawnRoutes == nil {
			return nil, fmt.Errorf("Error parsing withdrawn routes\n")
		}

		return getRoutes(update.WithdrawnRoutes.Prefixes), nil
	}
}

// This is just a convenience function for the getWithdrawn/Advertised routes, since
// they do essentially the same thing, but need to be separate
func getRoutes(prefixes []*common.PrefixWrapper) []Route {
	var rts []Route
	for _, pref := range prefixes {
		rts = append(rts, Route{net.IP(util.GetIP(pref.GetPrefix())), uint8(pref.Mask)})
	}
	return rts
}
