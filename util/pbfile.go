// The protoparse util package deals with reading and writing
// protocol buffer encoded records in, for example, files.
// functions provided here should be thread safe.
// at any moment there can be only one writer or
// multiple readers.
package util

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
)

var (
	errNotOpen  = fmt.Errorf("underlying file pointer is nil")
	errOpen     = fmt.Errorf("underlying file pointer already open")
	errbufsiz   = fmt.Errorf("buffer sizes can't be negative")
	errbufsmall = fmt.Errorf("buffer for read is to small to accomodate the record")
)

const (
	RecordFile_Flat = iota
	RecordFile_Indexed
)

type RecordFiler interface {
	Version() int
	Fname() string
}

//A flat record file knows the number of records it has stored,
//every record is preceded by a 32bit unsigned value that is
//the length of that record in Big Endian and after that the
//bytes of the record
type FlatRecordFile struct {
	fname   string
	fp      *os.File
	writer  *bufio.Writer
	reader  *bufio.Reader
	Scanner *bufio.Scanner
	entries int64
	sz      int64
	mux     *sync.RWMutex
	wpend   bool
}

func NewFlatRecordFile(fname string) *FlatRecordFile {
	return &FlatRecordFile{
		fname:   fname,
		fp:      nil,
		writer:  nil,
		reader:  nil,
		Scanner: nil,
		entries: 0,
		sz:      0,
		mux:     &sync.RWMutex{},
		wpend:   false,
	}
}

func (p *FlatRecordFile) Version() int {
	return RecordFile_Flat
}

func (p *FlatRecordFile) Fname() string {
	return p.fname
}

func (p *FlatRecordFile) Open() error {
	return p.OpenWithBufferSizes(0, 0)
}

// Opens the underlying reader with buffer sizes specified in the arguments.
// useful for larger tokens than the default 64k
func (p *FlatRecordFile) OpenWithBufferSizes(readersize, writersize int) (err error) {
	if p.fp != nil {
		err = errOpen
	}
	if readersize < 0 || writersize < 0 {
		err = errbufsiz
	}
	p.fp, err = os.OpenFile(p.fname, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660)
	if err == nil {
		if writersize == 0 {
			p.writer = bufio.NewWriter(p)
		} else {
			p.writer = bufio.NewWriterSize(p, writersize)
		}
		if readersize == 0 {
			p.reader = bufio.NewReader(p)
		} else {
			p.reader = bufio.NewReaderSize(p, readersize)
		}
		p.Scanner = bufio.NewScanner(p.reader) //this should call our read
		p.Scanner.Split(splitRecord)
	}
	return
}

//implements io.Writer but enforces the bufio interfaces underneath
//bytes written here increase the recorded size of the file.
func (p *FlatRecordFile) Write(b []byte) (n int, err error) {
	if p.fp == nil {
		return 0, errNotOpen
	}
	p.mux.Lock()
	defer p.mux.Unlock()
	rlen := uint32(len(b))
	errind := binary.Write(p.writer, binary.BigEndian, rlen)
	if errind != nil {
		return 0, errind
	}
	nb, err := p.writer.Write(b)
	p.wpend = true //set the pending flag so that readers flush before
	if err != nil {
		return 0, err
	}
	p.sz += int64(nb)
	return nb, nil
}

func (p *FlatRecordFile) Read(b []byte) (int, error) {
	if p.fp == nil {
		return 0, errNotOpen
	}
	if p.wpend { //if there are writes pending flush the writer
		p.Flush()
	}
	p.mux.RLock()
	defer p.mux.RUnlock()
	return p.fp.Read(b)
}

func (p *FlatRecordFile) Flush() (err error) {
	if p.writer != nil {
		err = p.writer.Flush()
		if err == nil {
			p.wpend = false
		}
	}
	return
}

//implements io.Closer
func (p *FlatRecordFile) Close() error {
	p.Flush() // flush.
	if p.fp != nil {
		return p.fp.Close()
	}
	return errNotOpen
}

//a bufio scanner implementation that reads the record size and advances the reader.
func splitRecord(data []byte, atEOF bool) (advance int, token []byte, err error) {
	buf := bytes.NewBuffer(data)
	pbsize := uint32(0)
	if cap(data) < 4 || len(data) < 4 {
		return 0, nil, nil
	}
	binary.Read(buf, binary.BigEndian, &pbsize)
	if cap(data) < int(pbsize+4) || len(data) < int(pbsize+4) {
		return 0, nil, nil
	}
	return int(4 + pbsize), data[4 : pbsize+4], nil

}
