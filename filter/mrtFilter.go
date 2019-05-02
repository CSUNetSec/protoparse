package filter

// filters for BGP messages in MRT files
import (
	"fmt"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	pu "github.com/CSUNetSec/protoparse/util"
	"github.com/pkg/errors"
	"net"
	"strconv"
	"strings"
)

type Filter func(mbs *mrt.MrtBufferStack) bool

const (
	AdvPrefix = iota
	WdrPrefix
	AnyPrefix
)

type PrefixFilter struct {
	prefixes  []string
	pt        pu.PrefixTree
	prefixLoc int
}

func NewPrefixFilterFromString(raw string, sep string, loc int) (Filter, error) {
	prefstrings := strings.Split(raw, sep)
	return NewPrefixFilterFromSlice(prefstrings, loc)
}

func NewPrefixFilterFromSlice(prefstrings []string, loc int) (Filter, error) {
	pf := PrefixFilter{prefixLoc: loc}
	pf.pt = pu.NewPrefixTree()
	for _, p := range prefstrings {
		parts := strings.Split(p, "/")
		if len(parts) != 2 {
			return nil, errors.New("malformed prefix string")
		}
		mask, err := pu.MaskStrToUint8(parts[1])
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("can not parse mask:%s", parts[1]))
		}
		parsedIP := net.ParseIP(parts[0])
		if parsedIP == nil {
			return nil, errors.New(fmt.Sprintf("malformed IP address:%s", parts[0]))
		}
		pf.pt.Add(parsedIP, mask)
	}
	pf.prefixes = prefstrings
	return pf.filterBySeen, nil
}

func (pf PrefixFilter) filterBySeen(mbs *mrt.MrtBufferStack) bool {
	if pf.prefixLoc == AdvPrefix || pf.prefixLoc == AnyPrefix {
		advPrefs, err := mrt.GetAdvertisedPrefixes(mbs)
		if err == nil {
			for _, pref := range advPrefs {
				if pf.pt.ContainsIPMask(pref.IP, pref.Mask) {
					return true
				}
			}
		}
	}

	if pf.prefixLoc == WdrPrefix || pf.prefixLoc == AnyPrefix {
		wdnPrefs, err := mrt.GetWithdrawnPrefixes(mbs)
		if err == nil {
			for _, pref := range wdnPrefs {
				if pf.pt.ContainsIPMask(pref.IP, pref.Mask) {
					return true
				}
			}
		}
	}
	return false
}

type ASFilter struct {
	asList []uint32
}

type ASPosition uint32

const (
	AS_SOURCE = ASPosition(iota)
	AS_DESTINATION
	AS_MIDPATH
	AS_ANYWHERE
)

// Returns an AS filter with the list of AS's in the form "1,2,3,4"
// If src is true, filters messages by source AS number
// otherwise filters by destination AS number
func NewASFilter(list string, pos ASPosition) (Filter, error) {
	aslist, err := parseASList(list)
	if err != nil {
		return nil, err
	}
	return NewASFilterFromSlice(aslist, pos)
}

func NewASFilterFromSlice(aslist []uint32, pos ASPosition) (Filter, error) {
	asf := ASFilter{aslist}
	switch pos {
	case AS_SOURCE:
		return asf.FilterBySource, nil
	case AS_DESTINATION:
		return asf.FilterByDest, nil
	case AS_MIDPATH:
		return asf.FilterByMidPath, nil
	case AS_ANYWHERE:
		return asf.FilterByAnywhere, nil
	}
	return nil, errors.New("unsupported AS position argument")
}

func (asf ASFilter) FilterBySource(mbs *mrt.MrtBufferStack) bool {
	path, err := mrt.GetASPath(mbs)
	if err != nil || len(path) < 1 {
		return false
	}

	return asf.matchesOne(path[len(path)-1])
}

func (asf ASFilter) FilterByDest(mbs *mrt.MrtBufferStack) bool {
	path, err := mrt.GetASPath(mbs)
	if err != nil || len(path) < 1 {
		return false
	}

	return asf.matchesOne(path[0])
}

func (asf ASFilter) FilterByMidPath(mbs *mrt.MrtBufferStack) bool {
	path, err := mrt.GetASPath(mbs)
	if err != nil || len(path) < 3 {
		return false
	}

	for _, as := range path[1 : len(path)-1] {
		if asf.matchesOne(as) {
			return true
		}
	}

	return false
}

func (asf ASFilter) FilterByAnywhere(mbs *mrt.MrtBufferStack) bool {
	path, err := mrt.GetASPath(mbs)
	if err != nil || len(path) < 1 {
		return false
	}

	for _, as := range path {
		if asf.matchesOne(as) {
			return true
		}
	}

	return false
}

// Convenience function used by both FilterBySrc/Dest
func (asf ASFilter) matchesOne(comp uint32) bool {
	for _, asnum := range asf.asList {
		if asnum == comp {
			return true
		}
	}
	return false
}

func parseASList(str string) ([]uint32, error) {
	list := strings.Split(str, ",")
	aslist := make([]uint32, len(list))

	for i := 0; i < len(aslist); i++ {
		as, err := strconv.ParseUint(list[i], 10, 32)
		if err != nil {
			return nil, err
		}
		aslist[i] = uint32(as)
	}

	return aslist, nil
}

func FilterAll(filters []Filter, mbs *mrt.MrtBufferStack) bool {
	for _, fil := range filters {
		if fil != nil && !fil(mbs) {
			return false
		}
	}
	return true
}
