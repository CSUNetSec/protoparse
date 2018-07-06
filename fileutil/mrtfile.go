package fileutil

import (
	"bufio"
	"compress/bzip2"
	monpb "github.com/CSUNetSec/netsec-protobufs/bgpmon/v2"
	"github.com/CSUNetSec/protoparse/filter"
	"github.com/CSUNetSec/protoparse/protocol/mrt"
	"github.com/pkg/errors"
	"io"
	"os"
	"path/filepath"
)

type mrtReader struct {
	in         io.ReadCloser
	scanner    *bufio.Scanner
	filters    []filter.Filter
	err        error
	lastTok    *monpb.BGPCapture
	lastTokErr error
}

//NewMrtFileReader creates a wrapper around an open MRT file. After succesfull invocation
//the caller must call Close(). Entries are read using the Scan() method
//and any internal scanner errors are accessed using the Error() method.
func NewMrtFileReader(fname string, filters []filter.Filter) (*mrtReader, error) {
	if _, err := os.Stat(fname); err != nil {
		return nil, errors.Wrap(err, "stat")
	}
	if fp, err := os.Open(fname); err != nil {
		return nil, errors.Wrap(err, "open")
	} else {
		scanner := getScanner(fp)
		ret := &mrtReader{
			in:         fp,
			scanner:    scanner,
			filters:    filters,
			err:        nil,
			lastTok:    nil,
			lastTokErr: nil,
		}
		return ret, nil
	}
}

//Scan returns true if there is a next entry that can be returned as a BGP capture
//and passes filters. If there is a scanning error, Scan
//becomes a no op. If a message does not pass filters it scans
//until one that does.
func (m *mrtReader) Scan() bool {
	if m.err != nil { //make Scan a no op if there is an error
		return false
	}
rescan:
	if !m.scanner.Scan() { // internal scan finished? we finish too.
		return false
	}
	if m.err = m.scanner.Err(); m.err != nil {
		return false //this error will be checked on the Err() call
	}
	bytes := m.scanner.Bytes()
	if mbs, err := mrt.ParseHeaders(bytes, false); err != nil { //false for no rib.
		m.lastTok = nil
		m.lastTokErr = errors.Wrap(err, "parseHeaders")
	} else {
		if filter.FilterAll(m.filters, mbs) { //passes filters?
			if pb, err := mrt.MrtToBGPCapturev2(m.scanner.Bytes()); err != nil {
				m.lastTok = nil
				m.lastTokErr = errors.Wrap(err, "MrtToBGPCapture")
			} else {
				m.lastTok = pb // successfully got next token
				m.lastTokErr = nil
			}
		} else {
			goto rescan
		}
	}
	return true
}

//GetCapture returns the current scanned capture along with a possible error while
//unmarshalling it from the binary data.
func (m *mrtReader) GetCapture() (*monpb.BGPCapture, error) {
	return m.lastTok, m.lastTokErr
}

//Close closes the underlying reader
func (m *mrtReader) Close() {
	m.in.Close()
}

//Err shows errors that might have occured in the underlying bufio scanner.
//this errors would make Scan a no op.
func (m *mrtReader) Err() error {
	return m.err
}

//helper func to read bz2 files appropriately. maximum
//token size for an MRT entry is 1MB
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
	scanbuffer := make([]byte, 2<<20) //an internal buffer for the large tokens (1M)
	scanner.Buffer(scanbuffer, cap(scanbuffer))
	return
}
