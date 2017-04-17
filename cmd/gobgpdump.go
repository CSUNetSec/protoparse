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
	radix "github.com/armon/go-radix"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
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
	logout   string
	dumpout  string
	statout  string
	pup      bool
	isJson   bool
	parallel bool
	destAs   int
	srcAs    int
)

func init() {
	flag.StringVar(&logout, "lo", "stdout", "file to dump log output")
	flag.StringVar(&dumpout, "o", "stdout", "file to dump entries")
	flag.StringVar(&statout, "so", "stdout", "file to dump statistics output")
	flag.BoolVar(&parallel, "p", false, "dump files in parallel, may cause out of order output")
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

	if logout != "stdout" {
		lfd, _ := os.Create(logout)
		log.SetOutput(lfd)
		defer lfd.Close()
	}
	var statfd *os.File
	var dumpfd *os.File

	if statout != "stdout" {
		statfd, _ = os.Create(statout)
		defer statfd.Close()
	} else {
		statfd = os.Stdout
	}

	if dumpout != "stdout" {
		dumpfd, _ = os.Create(dumpout)
		defer dumpfd.Close()
	} else {
		dumpfd = os.Stdout
	}

	statstr := fmt.Sprintf("Dumping %d files\n", len(args))
	statfd.WriteString(statstr)

	var tf transformer
	if isJson {
		tf = jsonTransformer{}
	} else if pup {
		upm := NewUniquePrefixMap(dumpfd)
		tf = upm
	} else {
		tf = textTransformer{}
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

	wg := &sync.WaitGroup{}
	start := time.Now()
	// Each goroutine requires an fd,
	// I should consider adding a struct to
	// manage the number of fds consumed by the program
	for _, name := range args {
		if parallel && false {
			wg.Add(1)
			go dumpFile(name, tf, vals, dumpfd, statfd, wg)
		} else {
			dumpFile(name, tf, vals, dumpfd, statfd, nil)
		}
	}

	if parallel {
		wg.Wait()
	}
	tf.summarize()
	str := fmt.Sprintf("Total time taken: %s\n", time.Since(start))
	statfd.WriteString(str)
}

func dumpFile(fName string, tf transformer, vals []validator, dfd, sfd *os.File, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}
	mrtfd, err := os.Open(fName)
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
			log.Printf("[%d] Error:%s\n", numentries, err)
			break
		}
		mbs := &mrt.MrtBufferStack{mrth, bgp4h, bgph, bgpup}
		if validateAll(vals, mbs) {
			unfilteredct++
			ret += tf.transform(numentries, mbs)
			// I'm making transformers responsible for newlines, because
			// the upm doesn't need them
			dfd.WriteString(ret)
		}
	}

	if err := mrtScanner.Err(); err != nil {
		errx(err, mrtfd)
	}
	dt := time.Since(t1)
	statstr := fmt.Sprintf("Scanned %s: %d entries, %d passed filters, total size: %d bytes in %v\n", fName, numentries, unfilteredct, totsz, dt)
	sfd.WriteString(statstr)

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

type transformer interface {
	transform(int, *mrt.MrtBufferStack) string
	summarize()
}

type UniquePrefixMap struct {
	output    *os.File
	prefixes  map[string]bool
	radixTree *radix.Tree
	maplock   *sync.Mutex
}

func NewUniquePrefixMap(o *os.File) *UniquePrefixMap {
	upm := UniquePrefixMap{}
	upm.output = o
	upm.prefixes = make(map[string]bool)
	upm.radixTree = radix.New()
	upm.maplock = &sync.Mutex{}
	return &upm
}

type IPWrapper struct {
	ip string
}

func (upm *UniquePrefixMap) transform(msgNum int, mbs *mrt.MrtBufferStack) string {
	update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()

	//If there are no advertized routes
	if update.AdvertizedRoutes == nil || len(update.AdvertizedRoutes.Prefixes) == 0 {
		return ""
	}

	for _, ar := range update.AdvertizedRoutes.Prefixes {
		ipstr := fmt.Sprintf("%s/%d", net.IP(util.GetIP(ar.GetPrefix())), ar.Mask)
		upm.maplock.Lock()
		if !upm.prefixes[ipstr] {
			rkey := util.IpToRadixkey(util.GetIP(ar.GetPrefix()), uint8(ar.Mask))
			upm.radixTree.Insert(rkey, IPWrapper{ipstr})
			upm.prefixes[ipstr] = true
		}
		upm.maplock.Unlock()
	}

	return ""

}

func (upm *UniquePrefixMap) summarize() {
	upm.radixTree.Walk(upm.topWalk)
}

func (upm *UniquePrefixMap) topWalk(s string, v interface{}) bool {
	pref := v.(IPWrapper).ip
	if upm.prefixes[pref] {
		str := fmt.Sprintf("%s\n", pref)
		upm.output.WriteString(str)
		upm.radixTree.WalkPrefix(s, upm.subWalk)
	}
	return false
}

func (upm *UniquePrefixMap) subWalk(s string, v interface{}) bool {
	upm.prefixes[v.(IPWrapper).ip] = false
	return false
}

type jsonTransformer struct{}

func (j jsonTransformer) transform(msgNum int, mbs *mrt.MrtBufferStack) string {
	mbsj, err := json.Marshal(mbs)
	if err != nil {
		log.Printf("Error marshaling to json")
		return ""
	}
	return string(mbsj) + "\n"
}

func (j jsonTransformer) summarize() {}

type textTransformer struct{}

func (t textTransformer) transform(msgNum int, mbs *mrt.MrtBufferStack) string {
	ret := ""
	ret += fmt.Sprintf("[%d] MRT Header: %s\n", msgNum, mbs.MrthBuf)
	ret += fmt.Sprintf("BGP4MP Header:%s\n", mbs.Bgp4mpbuf)
	ret += fmt.Sprintf("BGP Header: %s\n", mbs.Bgphbuf)
	ret += fmt.Sprintf("BGP Update:%s\n", mbs.Bgpupbuf)
	return ret + "\n"
}

func (t textTransformer) summarize() {}

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
