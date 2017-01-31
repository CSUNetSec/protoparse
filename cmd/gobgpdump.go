package main

import (
	"bufio"
	"compress/bzip2"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/CSUNetSec/protoparse"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	"io"
	"log"
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

func main() {
	isJson := flag.Bool("json", false, "print the output as json objects")

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Println("mrt file not provided")
		os.Exit(-1)
	}

	mrtfd, err := os.Open(args[0])
	errx(err)
	defer mrtfd.Close()
	mrtScanner := getScanner(mrtfd)
	numentries := 0
	totsz := 0
	t1 := time.Now()
	for mrtScanner.Scan() {
		ret := ""
		numentries++
		data := mrtScanner.Bytes()
		totsz += len(data)
		mrth := mrt.NewMrtHdrBuf(data)
		bgp4h, bgph, bgpup := parseHeaders(mrth, numentries)
		mbs := &mrt.MrtBufferStack{mrth, bgp4h, bgph, bgpup}
		if *isJson {
			mbsj, err := json.Marshal(mbs)
			if err != nil {
				log.Printf("Error marshaling to json")
			}
			ret += string(mbsj)
		} else {
			ret += fmt.Sprintf("[%d] MRT Header: %s\n", numentries, mrth)
			ret += fmt.Sprintf("BGP4MP Header:%s\n", bgp4h)
			ret += fmt.Sprintf("BGP Header: %s\n", bgph)
			ret += fmt.Sprintf("BGP Update:%s\n", bgpup)
		}
		fmt.Printf("%s\n", ret)
	}

	if err := mrtScanner.Err(); err != nil {
		errx(err, mrtfd)
	}
	dt := time.Since(t1)
	log.Printf("Scanned: %d entries, total size: %d bytes in %v\n", numentries, totsz, dt)
}

func parseHeaders(mrth protoparse.PbVal, entryCt int) (bgp4h, bgph, bgpup protoparse.PbVal) {
	bgp4h, err := mrth.Parse()
	if err != nil {
		log.Printf("Failed parsing MRT header %d :%s", entryCt, err)
	}

	bgph, err = bgp4h.Parse()
	if err != nil {
		log.Printf("Failed parsing BG4MP header %d :%s", entryCt, err)
	}

	bgpup, err = bgph.Parse()
	if err != nil {
		log.Printf("Failed parsing BGP header %d :%s", entryCt, err)
	}

	_, err = bgpup.Parse()
	if err != nil {
		log.Printf("Failed parsing BGP update %d :%s", entryCt, err)
	}

	return
}
