// This file defines all filters and convenience functions for filters.
// Should be functionally equivalent to stable gobgpdump
// Current Filter options:
// -Source AS number (NewASFilter("1,2,3", true))
// -Destination AS number (NewASFilter("1,2,3", false))

// TODO
// -Maybe a function to return an array of filters based on config
//	options?
// -Time filter
// -Filters based on other attributes (peers, prefixes seen, etc.)
package main

import (
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	"strconv"
	"strings"
)

type Filter func(mbs *mrt.MrtBufferStack) bool

type ASFilter struct {
	asList []uint32
}

// Returns an AS filter with the list of AS's in the form "1,2,3,4"
// If src is true, filters messages by source AS number
// otherwise filters by destination AS number
func NewASFilter(list string, src bool) (Filter, error) {
	aslist, err := parseASList(list)
	if err != nil {
		return nil, err
	}

	asf := ASFilter{aslist}
	if src {
		return asf.FilterBySource, nil
	} else {
		return asf.FilterByDest, nil
	}
}

func (asf ASFilter) FilterBySource(mbs *mrt.MrtBufferStack) bool {
	path, err := getASPath(mbs)
	if err != nil || len(path) < 1 {
		return false
	}

	return asf.matchesOne(path[len(path)-1])
}

func (asf ASFilter) FilterByDest(mbs *mrt.MrtBufferStack) bool {
	path, err := getASPath(mbs)
	if err != nil || len(path) < 1 {
		return false
	}

	return asf.matchesOne(path[0])
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

func filterAll(filters []Filter, mbs *mrt.MrtBufferStack) bool {
	for _, fil := range filters {
		if fil != nil && !fil(mbs) {
			return false
		}
	}
	return true
}
