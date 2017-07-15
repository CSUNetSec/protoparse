// Defines all formatters available to gobgpdump, and convenience
// functions for formatters.
// Current formatters:
// -TextFormatter (NewTextFormatter())
// -JSONFormatter (NewJSONFormatter())
// -IdentityFormatter (NewIdentityFormatter())

// Also very incomplete, and original gobgpdump has bugs in this
// area
package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	util "github.com/CSUNetSec/protoparse/util"
	radix "github.com/armon/go-radix"
	"os"
	"sync"
	"time"
)

// A Formatter takes the bufferstack and the underlying buffer
// and returns a representation of the data to be written to the
// dump file.
// The underlying buffer is necessary for the ID formatter
type Formatter interface {
	format(*mrt.MrtBufferStack, []byte) (string, error)
	summarize()
}

// -----------------------------------------------------------
// A simple text representation for the dump.
// The only formatter that needs the msgnum
type TextFormatter struct {
	msgNum int
}

func NewTextFormatter() *TextFormatter {
	return &TextFormatter{0}
}

func (t *TextFormatter) format(mbs *mrt.MrtBufferStack, _ []byte) (string, error) {
	ret := fmt.Sprintf("[%d] MRT Header: %s\n", t.msgNum, mbs.MrthBuf)
	ret += fmt.Sprintf("BGP4MP Header: %s\n", mbs.Bgp4mpbuf)
	ret += fmt.Sprintf("BGP Header: %s\n", mbs.Bgphbuf)
	ret += fmt.Sprintf("BGP Update: %s\n\n", mbs.Bgpupbuf)
	t.msgNum++
	return ret, nil
}

// The text formatter doesn't need to summarize
func (t *TextFormatter) summarize() {}

// ------------------------------------------------------------
// Formats each update as a JSON message
type JSONFormatter struct{}

func NewJSONFormatter() JSONFormatter {
	return JSONFormatter{}
}

func (j JSONFormatter) format(mbs *mrt.MrtBufferStack, _ []byte) (string, error) {
	mbsj, err := json.Marshal(mbs)
	return string(mbsj) + "\n", err
}

// The JSON formatter doesn't need to summarize
func (j JSONFormatter) summarize() {}

// -------------------------------------------------------------
// Applies no formatting to the data
// But data is decompressed, may need to fix that
// However, golang bz2 doesn't have compression features
type IdentityFormatter struct{}

func NewIdentityFormatter() IdentityFormatter {
	return IdentityFormatter{}
}

func (id IdentityFormatter) format(_ *mrt.MrtBufferStack, buf []byte) (string, error) {
	return string(buf), nil
}

// No summarization needed
func (id IdentityFormatter) summarize() {}

// -------------------------------------------------------------
type PrefixHistory struct {
	Pref   string
	Events []PrefixEvent
}

func NewPrefixHistory(pref string, firstTime time.Time, advert bool) *PrefixHistory {
	pe := PrefixEvent{firstTime, advert}
	return &PrefixHistory{pref, []PrefixEvent{pe}}
}

func (ph *PrefixHistory) addEvent(timestamp time.Time, advert bool) {
	ph.Events = append(ph.Events, PrefixEvent{timestamp, advert})
}

type PrefixEvent struct {
	Timestamp  time.Time
	Advertized bool
}

// ---------------------------------------------------------------
// In original gobgpdump, the List and Series are the same struct.
// Consider two separate structs

// UniquePrefixList will look at all incoming messages, and output
// only the top level prefixes seen.
type UniquePrefixList struct {
	output   *os.File // This should only be used in summarize
	mux      *sync.Mutex
	prefixes map[string]interface{}
}

func NewUniquePrefixList(fd *os.File) *UniquePrefixList {
	upl := UniquePrefixList{}
	upl.output = fd
	upl.mux = &sync.Mutex{}
	upl.prefixes = make(map[string]interface{})
	return &upl
}

func (upl *UniquePrefixList) format(mbs *mrt.MrtBufferStack, _ []byte) (string, error) {

	timestamp := getTimestamp(mbs)
	advRoutes, err := getAdvertizedPrefixes(mbs)
	// Do something with routes only if there is no error.
	// Otherwise, move on to withdrawn routes
	if err == nil {
		upl.addRoutes(advRoutes, timestamp, true)
	}

	wdnRoutes, err := getWithdrawnPrefixes(mbs)
	if err == nil {
		upl.addRoutes(wdnRoutes, timestamp, false)
	}
	return "", nil
}

// If this finds a Route that is not present in the prefixes map,
// adds it in. If it finds one, but these Routes have an earlier
// timestamp, it replaces the old one.
func (upl *UniquePrefixList) addRoutes(rts []Route, timestamp time.Time, advert bool) {
	for _, route := range rts {
		key := util.IpToRadixkey(route.IP, route.Mask)
		upl.mux.Lock()
		if upl.prefixes[key] == nil {
			upl.prefixes[key] = NewPrefixHistory(route.String(), timestamp, advert)
		} else {
			oldT := upl.prefixes[key].(*PrefixHistory).Events[0].Timestamp
			if oldT.After(timestamp) {
				upl.prefixes[key] = NewPrefixHistory(route.String(), timestamp, advert)
			}
		}
		upl.mux.Unlock()
	}
}

// All output is done in this function
func (upl *UniquePrefixList) summarize() {
	deleteChildPrefixes(upl.prefixes)

	// Whatever is left should be output
	for _, value := range upl.prefixes {
		ph := value.(*PrefixHistory)
		upl.output.WriteString(fmt.Sprintf("%s\n", ph.Pref))
	}
}

// -----------------------------------------------------------------
// UniquePrefixSeries does the same thing as UniquePrefixList, but
// rather than just a list, it will output a gob file containing each
// prefix and every event seen associated with that prefix
type UniquePrefixSeries struct {
	output   *os.File
	mux      *sync.Mutex
	prefixes map[string]interface{}
}

func NewUniquePrefixSeries(fd *os.File) *UniquePrefixSeries {
	ups := UniquePrefixSeries{}
	ups.output = fd
	ups.mux = &sync.Mutex{}
	ups.prefixes = make(map[string]interface{})
	return &ups
}

func (ups *UniquePrefixSeries) format(mbs *mrt.MrtBufferStack, _ []byte) (string, error) {
	timestamp := getTimestamp(mbs)

	advRoutes, err := getAdvertizedPrefixes(mbs)
	if err == nil {
		ups.addRoutes(advRoutes, timestamp, true)
	}

	wdnRoutes, err := getWithdrawnPrefixes(mbs)
	if err == nil {
		ups.addRoutes(wdnRoutes, timestamp, false)
	}
	return "", nil
}

func (ups *UniquePrefixSeries) addRoutes(rts []Route, timestamp time.Time, advert bool) {
	for _, route := range rts {
		key := util.IpToRadixkey(route.IP, route.Mask)
		ups.mux.Lock()
		if ups.prefixes[key] == nil {
			ups.prefixes[key] = NewPrefixHistory(route.String(), timestamp, advert)
		} else {
			ups.prefixes[key].(*PrefixHistory).addEvent(timestamp, advert)
		}
		ups.mux.Unlock()
	}
}

// All output is done here
func (ups *UniquePrefixSeries) summarize() {
	g := gob.NewEncoder(ups.output)

	deleteChildPrefixes(ups.prefixes)
	// Whatever is left are top-level prefixes and should be
	// encoded
	for _, value := range ups.prefixes {
		ph := value.(*PrefixHistory)
		g.Encode(ph)
	}
}

type PrefixWalker struct {
	top      bool
	prefixes map[string]interface{}
}

func (p *PrefixWalker) subWalk(s string, v interface{}) bool {
	if p.top {
		p.top = false
	} else {
		delete(p.prefixes, s)
	}
	return false
}

// This function will delete subprefixes from the provided map
func deleteChildPrefixes(pm map[string]interface{}) {
	pw := &PrefixWalker{false, pm}

	rTree := radix.New()
	for key, value := range pm {
		rTree.Insert(key, value)
	}

	rTree.Walk(func(s string, v interface{}) bool {
		pw.top = true
		rTree.WalkPrefix(s, pw.subWalk)
		return false
	})

}
