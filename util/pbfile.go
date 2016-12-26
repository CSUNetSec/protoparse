// The protoparse util package deals with reading and writing
// protocol buffer encoded records in, for example, files.
// functions provided here treat the underlying file as something
// that will be opened for either Reading or Writing (create or append)
package util

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var (
	errNotOpen   = fmt.Errorf("underlying file pointer is nil")
	errOpen      = fmt.Errorf("underlying file pointer already open")
	errbufsiz    = fmt.Errorf("buffer sizes can't be negative")
	errbufsmall  = fmt.Errorf("buffer for read is to small to accomodate the record")
	errnofoot    = fmt.Errorf("No header information")
	errnoentries = fmt.Errorf("No entries recorded in file")
	errfile      = fmt.Errorf("File given to Open() is not a regular file")
)

//this is the magin number that should be in
//the end of the file encoded in BigEndian
var magicbytes = uint32(118864)

const (
	RecordFile_Flat = iota
	RecordFile_Indexed
)

type RecordFiler interface {
	Version() int
	Fname() string
	Footer() (*Footer, error)
	Entries() (int64, error)
}

type FlatFootedRecordFile struct {
	*FlatRecordFile
	*Footer
}

func NewFlatFootedRecordFile(fname string) *FlatFootedRecordFile {
	abspath, _ := filepath.Abs(fname)
	return &FlatFootedRecordFile{
		NewFlatRecordFile(fname),
		&Footer{filedir: abspath, filename: filepath.Base(fname)},
	}
}

//A Footer is appended at the very end of a RecordFile
//(all types except the FlatRecordFile type )
//The end of a footer should always be the magicbytes uint32
//using that an application can easily see if a file is of our type
//Right before that the previous uint32 is the length of the footer
//bytes. The footer is a utf-8 encoded column separated string. it should be parsed
//after it is interpreted as a string. In a sense it is a reversed entry than the
//length prefixed records it follows. The length should not include the 4 magic bytes.
//so in the end the size of the file should be the sum of all the entry bytes +
//footer size + 4. Length in the end of the file should be encoded in BigEndian
type Footer struct {
	footlen  uint32 // the length does NOT INCLUDE the magicbytes
	entries  int64
	filever  int
	filedir  string
	filename string
}

func (f *Footer) String() string {
	return fmt.Sprintf("%d:%d:%s:%s", f.entries, f.filever, f.filedir, f.filename)
}

func MarshalBytes(a *Footer) []byte {
	fstr := a.String()
	buf := bytes.NewBufferString(fstr)
	binary.Write(buf, binary.BigEndian, uint32(buf.Len())) //write the length of the encoded string
	binary.Write(buf, binary.BigEndian, magicbytes)        //magic number to finish it off
	return buf.Bytes()
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
		wpend:   false,
	}
}

//Flat record files don't have headers.
func (p *FlatRecordFile) Footer() (*Footer, error) {
	return nil, errnofoot
}

//Entries in a flat record file are not guaranteed
//to be correct. they are dependant to the position
//of the writer.
func (p *FlatRecordFile) Entries() (int64, error) {
	if p.entries == 0 {
		return 0, errnoentries
	}
	return p.entries, nil
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
	if err == nil {
		if fi, errstat := os.Stat(p.fname); errstat == nil {
			if fi.IsDir() {
				return errfile
			}
			log.Printf("File already exists.opening for append")
			p.fp, err = os.OpenFile(p.fname, os.O_RDWR|os.O_APPEND, 0660)
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
	}
	return
}

//implements io.Writer but enforces the bufio interfaces underneath
//bytes written here increase the recorded size of the file.
func (p *FlatRecordFile) Write(b []byte) (n int, err error) {
	if p.fp == nil {
		return 0, errNotOpen
	}
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

func (p *FlatFootedRecordFile) Close() error {
	p.Write(MarshalBytes(p.Footer))
	p.Flush()
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
