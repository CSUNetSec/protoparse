package main

import (
	"bufio"
	"compress/bzip2"
	"encoding/gob"
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
	"strconv"
	"strings"
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
	logout     string
	dumpout    string
	statout    string
	pup        bool
	pts        bool
	isJson     bool
	parallel   bool
	destAsList string
	srcAsList  string
	confFiles  string
)

func init() {
	flag.StringVar(&logout, "lo", "stdout", "file to dump log output")
	flag.StringVar(&dumpout, "o", "stdout", "file to dump entries")
	flag.StringVar(&statout, "so", "stdout", "file to dump statistics output")
	flag.BoolVar(&parallel, "p", false, "dump files in parallel, may cause out of order output")
	flag.BoolVar(&pup, "pup", false, "print every advertized prefix only once")
	flag.BoolVar(&pts, "pts", false, "pup, but as a time series including withdrawals")
	flag.BoolVar(&isJson, "json", false, "print the output as json objects")
	flag.StringVar(&destAsList, "dest", "", "list of comma separated AS's (e.g. 1,2,3,4) to filter msg dest. by")
	flag.StringVar(&srcAsList, "src", "", "list of comma separated AS's (e.g. 1,2,3,4) to filter msg source by")
	flag.StringVar(&confFiles, "conf", "", "<collector format file>,<gobgpdump conf file>")
}

func main() {
	flag.Parse()

	var statfd *os.File
	var dumpfd *os.File
	var tf transformer
	var vals []validator
	args := flag.Args()

	var si stringiter
	si = &StringArray{args, 0}

	if len(args) == 0 {
		if confFiles == "" {
			log.Println("mrt file not provided")
			os.Exit(1)
		} else {
			parts := strings.Split(confFiles, ",")
			if len(parts) != 2 {
				log.Printf("Invalid configuration string\n")
				return
			}
			// This is weird, si, err := ... should work, but it redeclares si
			var err error
			si, err = parseConfiguration(parts[0], parts[1])
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				return
			}
		}
	}

	if logout != "stdout" {
		lfd, _ := os.Create(logout)
		log.SetOutput(lfd)
		defer lfd.Close()
	}

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

	if isJson {
		tf = jsonTransformer{}
	} else if pup || pts {
		upm := NewUniquePrefixMap(dumpfd, pts)
		tf = upm
	} else {
		tf = textTransformer{}
	}
	if destAsList != "" {
		aslist, err := parseAsList(destAsList)
		if err != nil {
			log.Printf("Error parsing as list: %s\n", err)
			return
		}

		av := NewAsValidator(aslist)
		vals = append(vals, av.validateDest)
	}
	if srcAsList != "" {
		aslist, err := parseAsList(srcAsList)
		if err != nil {
			log.Printf("Error parsing AS list: %s", err)
			return
		}

		av := NewAsValidator(aslist)
		vals = append(vals, av.validateSrc)
	}

	statstr := fmt.Sprintf("Dumping %d files\n", len(args))
	statfd.WriteString(statstr)

	wg := &sync.WaitGroup{}
	start := time.Now()
	// Each goroutine requires an fd,
	// I should consider adding a struct to
	// manage the number of fds consumed by the program
	name, serr := si.Next()
	for serr == nil {
		// This should only happen if it encounters a hidden file
		if name != "" {
			if parallel && false {
				wg.Add(1)
				go dumpFile(name, tf, vals, dumpfd, statfd, wg)
			} else {
				dumpFile(name, tf, vals, dumpfd, statfd, nil)
			}
		}
		name, serr = si.Next()
	}
	fmt.Println(serr)

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

type stringiter interface {
	Next() (string, error)
}

type StringArray struct {
	data []string
	cur  int
}

func (s *StringArray) Next() (string, error) {
	if s.cur >= len(s.data) {
		return "", fmt.Errorf("")
	}
	str := s.data[s.cur]
	s.cur++
	return str, nil
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
	asList []uint32
}

func NewAsValidator(asl []uint32) *AsValidator {
	return &AsValidator{asl}
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

	for i := 0; i < len(asval.asList); i++ {
		if lastAs == asval.asList[i] {
			return true
		}
	}
	return false
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

	for i := 0; i < len(asval.asList); i++ {
		if firstAs == asval.asList[i] {
			return true
		}
	}
	return false
}

type transformer interface {
	transform(int, *mrt.MrtBufferStack) string
	summarize()
}

type PrefixEvent struct {
	Timestamp  time.Time
	Advertized bool
}

type PrefixHistory struct {
	encoded bool
	Pref    string
	Events  []PrefixEvent
}

func NewPrefixHistory(pref string, firstTime time.Time, isAdvert bool) *PrefixHistory {
	firstEvent := PrefixEvent{firstTime, isAdvert}
	return &PrefixHistory{false, pref, []PrefixEvent{firstEvent}}
}

func (ph *PrefixHistory) add(t time.Time, adv bool) {
	ph.Events = append(ph.Events, PrefixEvent{t, adv})
}

func (ph *PrefixHistory) setEncoded(val bool) {
	ph.encoded = val
}

type UniquePrefixMap struct {
	output   *os.File
	prefixes map[string]interface{}
	maplock  *sync.Mutex
	isTS     bool
}

func NewUniquePrefixMap(o *os.File, pts bool) *UniquePrefixMap {
	upm := UniquePrefixMap{}
	upm.output = o
	upm.prefixes = make(map[string]interface{})
	upm.maplock = &sync.Mutex{}
	upm.isTS = pts
	return &upm
}

func (upm *UniquePrefixMap) transform(msgNum int, mbs *mrt.MrtBufferStack) string {
	update := mbs.Bgpupbuf.(protoparse.BGPUpdater).GetUpdate()
	timeint := mbs.MrthBuf.(protoparse.MRTHeaderer).GetHeader().Timestamp
	timestamp := time.Unix(int64(timeint), 0)

	//If there are no advertized routes
	if update.AdvertizedRoutes == nil || len(update.AdvertizedRoutes.Prefixes) == 0 {
		return ""
	}

	for _, ar := range update.AdvertizedRoutes.Prefixes {
		key := util.IpToRadixkey(util.GetIP(ar.GetPrefix()), uint8(ar.Mask))
		upm.maplock.Lock()
		if upm.prefixes[key] == nil {
			ipstr := fmt.Sprintf("%s/%d", net.IP(util.GetIP(ar.GetPrefix())), ar.Mask)
			upm.prefixes[key] = NewPrefixHistory(ipstr, timestamp, true)
		} else if upm.isTS {
			upm.prefixes[key].(*PrefixHistory).add(timestamp, true)
		}
		upm.maplock.Unlock()
	}

	if update.WithdrawnRoutes == nil || len(update.WithdrawnRoutes.Prefixes) == 0 {
		return ""
	}

	for _, ar := range update.WithdrawnRoutes.Prefixes {
		key := util.IpToRadixkey(util.GetIP(ar.GetPrefix()), uint8(ar.Mask))
		upm.maplock.Lock()
		if upm.prefixes[key] == nil {
			ipstr := fmt.Sprintf("%s/%d", net.IP(util.GetIP(ar.GetPrefix())), ar.Mask)
			upm.prefixes[key] = NewPrefixHistory(ipstr, timestamp, false)
		} else if upm.isTS {
			upm.prefixes[key].(*PrefixHistory).add(timestamp, false)
		}
		upm.maplock.Unlock()
	}

	return ""

}

func (upm *UniquePrefixMap) summarize() {
	var g *gob.Encoder
	if upm.isTS {
		g = gob.NewEncoder(upm.output)
	}

	rTree := radix.New()
	for key, value := range upm.prefixes {
		rTree.Insert(key, value)
	}

	// Access the map
	rTree.Walk(func(s string, v interface{}) bool {
		ph := upm.prefixes[s].(*PrefixHistory)
		// The following code should only run if the prefix hasn't been encoded,
		// meaning the prefix is a parent prefix
		if !ph.encoded {
			if upm.isTS {
				g.Encode(ph)
			} else {
				str := ph.Pref + " "
				if len(ph.Events) != 0 {
					str += fmt.Sprintf("%d\n", ph.Events[0].Timestamp.Unix())
				}
				upm.output.WriteString(str)
			}
			ph.setEncoded(true)
			// I am a humongous moron, ph.Pref is not a key in this tree,
			// beacuse I use the radix keys
			//rTree.WalkPrefix(ph.Pref, upm.subWalk)
			rTree.WalkPrefix(s, upm.subWalk)
		}
		return false
	})
}

func (upm *UniquePrefixMap) subWalk(s string, v interface{}) bool {
	// Set all child prefixes encoded value to true
	// because if this code is running, then their parent has been encoded
	ph := upm.prefixes[s].(*PrefixHistory)
	ph.setEncoded(true)
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

func parseAsList(liststr string) ([]uint32, error) {
	list := strings.Split(liststr, ",")
	aslist := make([]uint32, len(list))

	for i := 0; i < len(aslist); i++ {
		as, err := strconv.ParseUint(list[i], 10, 32)
		if err == nil {
			aslist[i] = uint32(as)
		} else {
			return nil, fmt.Errorf("Invalid AS: %s\n", list[i])
		}
	}
	return aslist, nil
}

type DumpList struct {
	ColList []string
	Start   string
	End     string
	Ofmt    string
	StFd    string
	DFd     string
	LFd     string
	SrcList string
	DstList string
}

type DumpIter struct {
	paths     []string
	pathNum   int
	curList   []os.FileInfo
	pathIndex int
}

func NewDumpIter(dl DumpList, fmts map[string]string) (*DumpIter, error) {
	di := DumpIter{}
	startT, err := time.Parse("2006.01", dl.Start)
	if err != nil {
		return nil, err
	}
	endT, err := time.Parse("2006.01", dl.End)
	if err != nil {
		return nil, err
	}

	// Add a day to the end so it should be a fully open interval
	for inc := startT; inc.Before(endT.AddDate(0, 0, 1)); inc = inc.AddDate(0, 1, 0) {
		for _, col := range dl.ColList {
			path, ok := fmts[col]
			if !ok {
				path = fmts["_default"]
				// Replace the placeholder with the name of the collector
				path = strings.Replace(path, "{x}", col, -1)
			}
			// Replace the time placeholder with inc
			path = strings.Replace(path, "{yyyy.mm}", inc.Format("2006.01"), -1)
			di.paths = append(di.paths, path)
			fmt.Printf("Adding path: %s\n", path)
		}
	}
	di.pathNum = 0
	di.pathIndex = 0
	di.curList = nil
	return &di, nil
}

func (di *DumpIter) Next() (string, error) {
	if di.curList == nil {
		if di.pathNum >= len(di.paths) {
			return "", fmt.Errorf("End of paths")
		}
		fddir, err := os.Open(di.paths[di.pathNum])
		if err != nil {
			return "", err
		}
		di.curList, err = fddir.Readdir(0)
		if err != nil {
			return "", err
		}
		fddir.Close()

		di.pathIndex = 0
	}

	ret := di.curList[di.pathIndex].Name()
	path := di.paths[di.pathNum]

	di.pathIndex++
	if di.pathIndex >= len(di.curList) {
		di.curList = nil
		di.pathNum++
	}
	if ret[0] == '.' {
		return "", nil
	}
	return path + ret, nil
}

func parseConfiguration(colfmt, conf string) (stringiter, error) {
	var dl DumpList
	fd, err := os.Open(conf)
	if err != nil {
		fmt.Printf("Error opening conf")
		return &StringArray{}, err
	}
	defer fd.Close()

	dec := json.NewDecoder(fd)
	err = dec.Decode(&dl)
	if err != nil {
		return &StringArray{}, err
	}
	// Load all the normal parameters from the config file
	switch dl.Ofmt {
	case "json":
		isJson = true
		pup = false
	case "pup":
		pup = true
		isJson = false
	case "pts":
		pts = true
		isJson = false
		pup = false
	case "":
		isJson = false
		pup = false
	default:
		return &StringArray{}, fmt.Errorf("Invalid format specified\n")
	}
	dumpout = dl.DFd
	statout = dl.StFd
	logout = dl.LFd
	srcAsList = dl.SrcList
	destAsList = dl.DstList

	fmts, err := parseCollectorFormat(colfmt)
	if err != nil {
		return &StringArray{}, err
	}

	di, err := NewDumpIter(dl, fmts)
	if err != nil {
		return &StringArray{}, err
	}

	return di, nil
}

func parseCollectorFormat(fname string) (map[string]string, error) {
	fd, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	reader := bufio.NewReader(fd)
	formats := make(map[string]string)

	str, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("Error reading collector file")
	}
	ok, base, err := readPair(str)
	if err != nil || ok != "{base}" {
		return nil, fmt.Errorf("Bad string formatting in collector file")
	}

	str, err = reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("Error reading collector file")
	}
	ok, def, err := readPair(str)
	if err != nil || ok != "{default}" {
		return nil, fmt.Errorf("Bad string formatting in collector file")
	}
	formats["_default"] = base + def

	for err == nil {
		str, err = reader.ReadString('\n')
		if err != nil {
			break
		}
		name, path, serr := readPair(str)
		if serr != nil {
			return nil, serr
		}
		formats[name] = base + path
	}

	return formats, nil
}

func readPair(str string) (string, string, error) {
	parts := strings.Split(str, " ")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Badly formatted string: %s\n", str)
	}
	ret2 := strings.Replace(parts[1], "\n", "", -1)
	return parts[0], ret2, nil
}
