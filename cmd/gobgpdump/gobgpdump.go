// This is the main logic of gobgpdump. Retrieves dump parameters
// from config.go, launches goroutines to parse and dump files.

package main

import (
	"bufio"
	"compress/bzip2"
	"fmt"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// This struct is the complete parameter set for a file
// dump. It is created and returned by the config.go code
type DumpConfig struct {
	workers int
	source  stringsource
	fmtr    Formatter
	filters []Filter
	dump    *MultiWriteFile
	log     *MultiWriteFile
	stat    *MultiWriteFile
}

func (dc *DumpConfig) CloseAll() {
	dc.dump.Close()
	dc.log.Close()
	dc.stat.Close()
}

func main() {
	// Get the config for this dump
	dc, err := getDumpConfig()
	if err != nil {
		fmt.Println(err)
		return
	}

	dumpStart := time.Now()
	wg := &sync.WaitGroup{}
	// Launch worker threads
	for w := 0; w < dc.workers; w++ {
		wg.Add(1)
		go worker(dc, wg)
	}

	wg.Wait()
	dc.fmtr.summarize()
	dc.stat.WriteString(fmt.Sprintf("Total time taken: %s\n", time.Since(dumpStart)))
	dc.CloseAll()
}

// Simple worker function, launched in a new goroutine.
// Reads from stringsource and launches dumpfile
func worker(dc *DumpConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	// dc.source must be thread safe
	name, serr := dc.source.Next()

	for serr == nil {
		dumpFile(name, dc)
		name, serr = dc.source.Next()
	}
	// On an unsuccessful dump, other threads should also stop
	// TODO: add context to DumpConfig
	if serr != EOP {
		fmt.Printf("Dump unsucessful: %s\n", serr)
	}
}

// Main compenent of the program. Opens a file, parses messages,
// filters them, formats them, and writes them to the dump file
func dumpFile(name string, dc *DumpConfig) {
	// At this point, we only want to read bzipped files
	if !isBz2(name) && false {
		dc.log.WriteString(fmt.Sprintf("Couldn't open: %s: not a bz2 file\n", name))
		return
	}

	mrtFile, err := os.Open(name)
	if err != nil {
		dc.log.WriteString("Error opening file: " + name + "\n")
		return
	}
	defer mrtFile.Close()

	scanner := getScanner(mrtFile)
	entryCt := 0
	passedCt := 0
	sz := 0
	start := time.Now()

	for scanner.Scan() {
		entryCt++
		data := scanner.Bytes()
		sz += len(data)
		mbs, err := parseHeaders(data)

		if err != nil {
			dc.log.WriteString(fmt.Sprintf("[%d] Error: %s\n", entryCt, err))
			break
		}

		if filterAll(dc.filters, mbs) {
			passedCt++
			output, err := dc.fmtr.format(mbs, NewMBSInfo(data, name, entryCt))
			if err != nil {
				dc.log.WriteString(fmt.Sprintf("%s\n", err))
			} else {
				dc.dump.WriteString(output)
			}
		}

	}

	if err = scanner.Err(); err != nil {
		dc.log.WriteString("Scanner returned an error.\n")
		return
	}

	dt := time.Since(start)
	statstr := fmt.Sprintf("Scanned %s: %d entries, %d passed filters, total size: %d bytes in %v\n", name, entryCt, passedCt, sz, dt)
	dc.stat.WriteString(statstr)

}

func getScanner(fd *os.File) (scanner *bufio.Scanner) {
	if isBz2(fd.Name()) {
		bzreader := bzip2.NewReader(fd)
		scanner = bufio.NewScanner(bzreader)
	} else {
		scanner = bufio.NewScanner(fd)
	}
	scanner.Split(mrt.SplitMrt)
	scanbuffer := make([]byte, 2<<24)
	scanner.Buffer(scanbuffer, cap(scanbuffer))
	return
}

func isBz2(fname string) bool {
	fext := filepath.Ext(fname)
	if fext == ".bz2" {
		return true
	}
	return false
}

// The dump, stat, and log files are all accessed by multiple
// goroutines. This is a simple file wrapper to lock on a write,
// and unlock once the write is complete
type MultiWriteFile struct {
	base *os.File
	mx   *sync.Mutex
}

func NewMultiWriteFile(fd *os.File) *MultiWriteFile {
	return &MultiWriteFile{fd, &sync.Mutex{}}
}

func (mwf *MultiWriteFile) WriteString(s string) (n int, err error) {
	mwf.mx.Lock()
	defer mwf.mx.Unlock()

	// This is to trash output if it's directed to a file that doesn't exist
	if mwf.base == nil {
		return 0, nil
	}
	return mwf.base.WriteString(s)
}

func (mwf *MultiWriteFile) Write(data []byte) (n int, err error) {
	mwf.mx.Lock()
	defer mwf.mx.Unlock()

	if mwf.base == nil {
		return 0, nil
	}
	return mwf.base.Write(data)
}

func (mwf *MultiWriteFile) Close() error {
	if mwf.base == nil {
		return nil
	}

	return mwf.base.Close()
}

func debugPrintf(format string, a ...interface{}) {
	if DEBUG {
		fmt.Printf(format, a)
	}
}

func debugSprintf(format string, a ...interface{}) string {
	if DEBUG {
		return fmt.Sprintf(format, a...)
	}
	return ""
}
