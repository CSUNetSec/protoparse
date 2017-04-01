package main

import (
	"bufio"
	"compress/bzip2"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/CSUNetSec/protoparse"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	util "github.com/CSUNetSec/protoparse/util"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

//accepts an error (can be nil which turns the func into a noop
//and variadic arguemnts that are fds to be closed before calling
//os.exit in case the error is not nil
func errx(e error, fds ...io.Closer) {
	if e == nil {
		return
	}
	log.Printf("error: %s\n", e)
	for _, fd := range fds {
		fd.Close()
	}
	os.Exit(-1)
}

func getScanner(file *os.File) (scanner *bufio.Scanner) {
	fname := file.Name()
	fext := filepath.Ext(fname)
	if fext == ".bz2" {
		bzreader := bzip2.NewReader(file)
		scanner = bufio.NewScanner(bzreader)
	} else {
		scanner = bufio.NewScanner(file)
	}
	scanner.Split(mrt.SplitMrt)
	scanbuffer := make([]byte, 2<<24) //an internal buffer for the large tokens (1M)
	scanner.Buffer(scanbuffer, cap(scanbuffer))
	return
}

var (
	pup    bool
	isJson bool
	destAs int
	srcAs  int
)

func init() {
	flag.BoolVar(&pup, "pup", false, "print every advertized prefix only once")
	flag.BoolVar(&isJson, "json", false, "print the output as json objects")
	flag.IntVar(&destAs, "destAs", -1, "filter by this destination AS")
	flag.IntVar(&srcAs, "srcAs", -1, "filter by this source AS")
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Println("mrt file not provided")
		os.Exit(-1)
	}
	var tf transformer
	if isJson {
		tf = jsontransformer
	} else if pup {
		upm := NewUniquePrefixMap()
		tf = upm.upmtransformer
	} else {
		tf = texttransformer
	}
	var vals []validator
	if destAs != -1 {
		av := NewAsValidator(destAs)
		vals = append(vals, av.validateDest)
	}
	if srcAs != -1 {
		av := NewAsValidator(srcAs)
		vals = append(vals, av.validateSrc)
	}

	mrtfd, err := os.Open(args[0])
	errx(err)
	defer mrtfd.Close()

	mrtScanner := getScanner(mrtfd)
	numentries := 0
	unfilteredct := 0
	totsz := 0
	t1 := time.Now()

	for mrtScanner.Scan() {
		ret := ""
		numentries++
		data := mrtScanner.Bytes()
		totsz += len(data)
		mrth := mrt.NewMrtHdrBuf(data)
		bgp4h, bgph, bgpup, err := parseHeaders(mrth, numentries)
		if err != nil {
			fmt.Printf("[%d] Error:%s\n", numentries, err)
			break
		}
		mbs := &mrt.MrtBufferStack{mrth, bgp4h, bgph, bgpup}
		if validateAll(vals, mbs) {
			unfilteredct++
			ret += tf(numentries, mbs)
			// I'm making transformers responsible for newlines, because
			// the upm doesn't need them
			fmt.Printf("%s", ret)
		}
	}

	if err := mrtScanner.Err(); err != nil {
		errx(err, mrtfd)
	}
	dt := time.Since(t1)
	log.Printf("Scanned: %d entries, %d passed filters, total size: %d bytes in %v\n", numentries, unfilteredct, totsz, dt)
}

func validateAll(vals []validator, mbs *mrt.MrtBufferStack) bool {
	for _, v := range vals {
		if v != nil && !v(mbs) {
			return false
		}
	}
	return true
}

// This could maybe not be a pointer
type validator func(*mrt.MrtBufferStack) bool

type AsValidator struct {
	as uint32
}

func NewAsValidator(i int) *AsValidator {
	return &AsValidator{uint32(i)}
}

// This checks the last AS in the ASPath,
// which should be where the update originated from
func (asval *AsValidator) validateSrc(mbs *mrt.MrtBufferStack) bool {
	update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()
	if update == nil || update.Attrs == nil {
		//This happens a lot
		//log.Printf("Error retrieving AS Path\n")
		return false
	}
	pathlen := len(update.Attrs.AsPath)
	if pathlen < 1 {
		// This happens sometimes
		//log.Printf("Error: empty AS Path\n")
		return false
	}

	lastseg := update.Attrs.AsPath[pathlen-1]

	var lastAs uint32 = 0
	if lastseg.AsSeq != nil && len(lastseg.AsSeq) > 0 {
		lastAs = lastseg.AsSeq[len(lastseg.AsSeq)-1]
	} else if lastseg.AsSet != nil && len(lastseg.AsSet) > 0 {
		lastAs = lastseg.AsSet[len(lastseg.AsSet)-1]
	} else {
		// Both are empty, not sure how thats possible, but return false
		return false
	}
	return lastAs == asval.as
}

func (asval *AsValidator) validateDest(mbs *mrt.MrtBufferStack) bool {
	update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()
	if update == nil || update.Attrs == nil {
		//This happens a lot
		//log.Printf("Error retrieving AS Path\n")
		return false
	}
	pathlen := len(update.Attrs.AsPath)
	if pathlen < 1 {
		// This happens sometimes
		//log.Printf("Error: empty AS Path\n")
		return false
	}

	lastseg := update.Attrs.AsPath[0]

	var firstAs uint32 = 0
	if lastseg.AsSeq != nil && len(lastseg.AsSeq) > 0 {
		firstAs = lastseg.AsSeq[0]
	} else if lastseg.AsSet != nil && len(lastseg.AsSet) > 0 {
		firstAs = lastseg.AsSet[0]
	} else {
		// Both are empty, not sure how thats possible, but return false
		return false
	}
	return firstAs == asval.as

}

type transformer func(int, *mrt.MrtBufferStack) string

type UniquePrefixMap struct {
	prefixes map[string]bool
}

func NewUniquePrefixMap() *UniquePrefixMap {
	upm := UniquePrefixMap{}
	upm.prefixes = make(map[string]bool)
	return &upm
}

func (upm *UniquePrefixMap) upmtransformer(msgNum int, mbs *mrt.MrtBufferStack) string {
	update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()

	//If there are no advertized routes
	if update.AdvertizedRoutes == nil || len(update.AdvertizedRoutes.Prefixes) == 0 {
		return ""
	}

	ret := ""
	for _, ar := range update.AdvertizedRoutes.Prefixes {
		ipstr := fmt.Sprintf("%s/%d", net.IP(util.GetIP(ar.GetPrefix())), ar.Mask)
		if !upm.prefixes[ipstr] {
			ret += ipstr + "\n"
			upm.prefixes[ipstr] = true
		}
	}

	return ret

}

func jsontransformer(msgNum int, mbs *mrt.MrtBufferStack) string {
	mbsj, err := json.Marshal(mbs)
	if err != nil {
		log.Printf("Error marshaling to json")
		return ""
	}
	return string(mbsj) + "\n"
}

func texttransformer(msgNum int, mbs *mrt.MrtBufferStack) string {
	ret := ""
	ret += fmt.Sprintf("[%d] MRT Header: %s\n", msgNum, mbs.MrthBuf)
	ret += fmt.Sprintf("BGP4MP Header:%s\n", mbs.Bgp4mpbuf)
	ret += fmt.Sprintf("BGP Header: %s\n", mbs.Bgphbuf)
	ret += fmt.Sprintf("BGP Update:%s\n", mbs.Bgpupbuf)
	return ret + "\n"
}

func parseHeaders(mrth protoparse.PbVal, entryCt int) (bgp4h, bgph, bgpup protoparse.PbVal, err error) {
	bgp4h, err = mrth.Parse()
	if err != nil {
		log.Printf("Failed parsing MRT header %d :%s", entryCt, err)
		return
	}

	bgph, err = bgp4h.Parse()
	if err != nil {
		log.Printf("Failed parsing BG4MP header %d :%s", entryCt, err)
		return
	}

	bgpup, err = bgph.Parse()
	if err != nil {
		log.Printf("Failed parsing BGP header %d :%s", entryCt, err)
		return
	}

	_, err = bgpup.Parse()
	if err != nil {
		log.Printf("Failed parsing BGP update %d :%s", entryCt, err)
		return
	}

	return
}
