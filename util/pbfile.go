// The protoparse util package deals with reading and writing
// protocol buffer encoded records in, for example, files.
// functions provided here treat the underlying file as something
// that will be opened for either Reading or Writing (create or append)
package util

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

var (
	errNotOpen   = fmt.Errorf("Underlying file pointer is nil")
	errOpen      = fmt.Errorf("Underlying file pointer already open")
	errbufsiz    = fmt.Errorf("Buffer sizes can't be negative")
	errbufsmall  = fmt.Errorf("Buffer for read is to small to accomodate the record")
	errnofoot    = fmt.Errorf("No footer information")
	errnoentries = fmt.Errorf("No entries recorded in file")
	errfile      = fmt.Errorf("File given to Open() is not a regular file")
	errexists    = fmt.Errorf("File exists")
	errmagic     = fmt.Errorf("Magic number in footer not detected")
	errreadfoot  = fmt.Errorf("Error reading footer")
	errcopytmp   = fmt.Errorf("Error copying to the temporary file and back")
)

//this is the magin number that should be in
//the end of the file encoded in BigEndian
var magicbytes = uint32(118864)

const (
	RecordFile_Flat = iota
	RecordFile_FlatFooted
	RecordFile_Indexed
)

const (
	OMode_Read = iota
	OMode_Write
)

type RecordFiler interface {
	Version() uint16
	Fname() string
	Footer() (*Footer, error)
	Entries() (uint64, error)
}

type FootedRecordFile struct {
	*RecordFile
	*Footer
	footoff int64 //offset of footer from the beginning of the file
}

func NewFootedRecordFile(fname string) *FootedRecordFile {
	return &FootedRecordFile{
		NewRecordFile(fname),
		nil,
		0,
	}
}

//A Footer is appended at the very end of a RecordFile
//(all types except the FlatRecordFile type )
//The end of a footer should always be the magicbytes uint32
//using that an application can easily see if a file is of our type
//Right before that the previous uint32 is the length of the footer
//bytes. The footer is a utf-8 encoded JSON string.In a sense it is a reversed entry than the
//length prefixed records it follows. The length should not include the 4 magic bytes.
//neither the 4 bytes of the footer length. it should be just the number of string bytes
//so in the end the size of the file should be the sum of all the entry bytes +
//footer size + 4. Length in the end of the file should be encoded in BigEndian
type Footer struct {
	Numentries uint64
	Filever    uint16
	Filedir    string
	Filename   string
	Sections   []Section
}

type Section struct {
	Compressed bool
	Secnum     uint32
	Start_off  uint64
	End_off    uint64
	Offsets    []Offset
}

type Offset struct {
	Recnum uint64
	Off    uint64
}

func (f *Footer) String() string {
	jb, _ := json.Marshal(f)
	return string(jb)
}

func ParseFooter(a []byte) (*Footer, error) {
	foot := &Footer{}
	if err := json.Unmarshal(a, foot); err != nil {
		return nil, err
	}
	return foot, nil
}

//MarshalBytes returns the bytes of
//[bytes of footer string][len of footer string][magic num]
//when this is writen to our underlying record file it is prepeneded
//by the length of the bytes mentioned above so this will appear as a
//normal record (but it won't parse normally)
func MarshalBytes(a *Footer) []byte {
	jb, err := json.Marshal(a)
	if err != nil {
		log.Printf("error marshaling footer bytes:%s", err)
	}
	buf := bytes.NewBuffer(jb)
	binary.Write(buf, binary.BigEndian, uint32(buf.Len())) //write the length of the encoded string
	binary.Write(buf, binary.BigEndian, magicbytes)        //magic number to finish it off
	return buf.Bytes()
}

//A record file knows the number of records it has stored,
//every record is preceded by a 32bit unsigned value that is
//the length of that record in Big Endian and after that the
//bytes of the record
type RecordFile struct {
	fname   string
	fp      *os.File
	writer  *bufio.Writer
	reader  *bufio.Reader
	Scanner *bufio.Scanner
	entries uint64
	sz      int64
}

func NewRecordFile(fname string) *RecordFile {
	return &RecordFile{
		fname:   fname,
		fp:      nil,
		writer:  nil,
		reader:  nil,
		Scanner: nil,
		entries: 0,
		sz:      0,
	}
}

//Seeks to the end of the file, validates the magic number,
//reads the bytes of the footer, reads the footer as a string
//and calls ParseFooter on it. the last argument it returns are the
//number of bytes of the footer
func (f *FootedRecordFile) ReadFooter() (*Footer, error) {
	if f.fp == nil {
		return nil, errfile
	}
	from := f.fp
	//Seek 4 bytes from the end of the file
	off, err := from.Seek(-4, 2) //2 is io.SeekEnd
	if err != nil {
		return nil, err
	}
	magic32 := uint32(0)
	binary.Read(from, binary.BigEndian, &magic32)
	if magic32 != magicbytes {
		return nil, errmagic
	}
	//seek to the length of the footer.
	off, err = from.Seek(-8, 2) //2 is io.SeekEnd
	if err != nil {
		return nil, err
	}
	fsz := uint32(0)
	binary.Read(from, binary.BigEndian, &fsz)
	if fsz == 0 || int64(fsz) > off { //something crazy happened. footer can't be bigger than file
		return nil, errnofoot
	}
	footof, err := from.Seek(-int64(fsz+8), 2) //2 is io.SeekEnd
	if err != nil {
		return nil, err
	}
	f.footoff = footof
	footbuf := make([]byte, fsz)
	nb, err := from.Read(footbuf)
	if nb != int(fsz) || err != nil {
		log.Printf("error: nb is %d  fsz is :%d footoffset: %d and err is:%s", nb, fsz, footof, err)
		return nil, errreadfoot
	}
	return ParseFooter(footbuf)
}

type FlatRecordFile struct {
	*RecordFile
}

func NewFlatRecordFile(fname string) *FlatRecordFile {
	return &FlatRecordFile{
		NewRecordFile(fname),
	}
}

//Flat record files don't have headers.
func (p *FlatRecordFile) Footer() (*Footer, error) {
	return nil, errnofoot
}

//Entries in a flat record file are not guaranteed
//to be correct. they are dependant to the position
//of the writer.
func (p *FlatRecordFile) Entries() (uint64, error) {
	if p.entries == 0 {
		return 0, errnoentries
	}
	return p.entries, nil
}

func (p *RecordFile) IncEntries(n uint64) {
	p.entries += n
}

func (p *FlatRecordFile) Version() uint16 {
	return RecordFile_Flat
}

func (p *RecordFile) Fname() string {
	return p.fname
}

func (p *RecordFile) OpenRead() error {
	err, _ := OpenWithBufferSizes(p, 0, 0, OMode_Read)
	return err
}

func (p *RecordFile) OpenWrite() error {
	err, _ := OpenWithBufferSizes(p, 0, 0, OMode_Write)
	return err
}

// Opens the underlying reader with buffer sizes specified in the arguments.
// useful for larger tokens than the default 64k
// returns if it created a new file or if it just opened an existing one
func OpenWithBufferSizes(p *RecordFile, readersize, writersize, openmode int) (err error, created bool) {
	created = false
	if p.fp != nil {
		err = errOpen
	}
	if readersize < 0 || writersize < 0 {
		err = errbufsiz
	}
	if err == nil {
		fi, errstat := os.Stat(p.fname)
		switch openmode {
		case OMode_Write:
			if errstat != nil { // file NX . create new
				log.Printf("creating new file :%s", p.fname)
				p.fp, err = os.OpenFile(p.fname, os.O_WRONLY|os.O_CREATE, 0660)
				created = true
			} else { //open for append
				if fi.IsDir() {
					err = errfile
					break
				}
				log.Printf("opening file :%s for append", p.fname)
				//we need to open as read too to check the footer
				p.fp, err = os.OpenFile(p.fname, os.O_RDWR, 0660)
			}
		case OMode_Read:
			if errstat == nil && fi.IsDir() {
				err = errfile
				break
			}
			log.Printf("opening file :%s for read", p.fname)
			p.fp, err = os.OpenFile(p.fname, os.O_RDONLY, 0660)
		}
		if err == nil {
			if openmode == OMode_Write {
				if writersize == 0 {
					p.writer = bufio.NewWriter(p.fp)
				} else {
					p.writer = bufio.NewWriterSize(p.fp, writersize)
				}
			} else {
				if readersize == 0 {
					p.reader = bufio.NewReader(p.fp)
				} else {
					p.reader = bufio.NewReaderSize(p.fp, readersize)
				}
				p.Scanner = bufio.NewScanner(p.reader) //this should call our read
				p.Scanner.Split(splitRecord)
			}
		}
	}
	return
}

//OpenRead will try to read the footer
func (p *FootedRecordFile) OpenRead() error {
	return p.OpenWithFooter(OMode_Read)
}

func (p *FootedRecordFile) OpenWithFooter(mode int) error {
	err, newfile := OpenWithBufferSizes(p.RecordFile, 0, 0, mode)
	if err != nil {
		return err
	}
	if !newfile {
		foot, err := p.ReadFooter()
		if err != nil {
			return err
		}
		if mode == OMode_Write {
			//create a new file and append everything up to the footer to it
			newfname := p.fname + ".temp"
			newf, err := os.OpenFile(newfname, os.O_RDWR|os.O_CREATE, 0660)
			if err != nil {
				return err
			}
			p.fp.Seek(0, 0)               //Seek to the start of the file in the source file
			endofdataoff := p.footoff - 4 //cause the footer is prepended by it's length in 4 bytes
			wb, err := io.CopyN(newf, p.fp, endofdataoff)
			if err != nil {
				return err
			}
			if wb != endofdataoff {
				log.Printf("did not copy the file to the temporary up to footer. wrote %d", wb)
				return errcopytmp
			}
			log.Printf("copied %d bytes from the source file to the tmp file", wb)
			//now truncate the original file and rewrite the bytes from the tmp
			p.fp, err = os.OpenFile(p.fname, os.O_WRONLY|os.O_CREATE, 0660)
			newf.Seek(0, 0) //Seek to the start of the file in the temp file
			if err != nil {
				return err
			}
			wb, err = io.CopyN(p.fp, newf, endofdataoff)
			if err != nil {
				return err
			}
			log.Printf("copied %d bytes from the temp file to the new source", wb)
			if wb != endofdataoff {
				log.Printf("did not copy the file from the temporary up to footer")
				return errcopytmp
			}
			//now we can seafely remove the temp file
			err = newf.Close()
			if err != nil {
				return err
			}
			err = os.Remove(p.fname + ".temp")
			if err != nil {
				log.Printf("error removing temp file")
			}
		}
		log.Printf("read footer :%s", foot)
		p.Footer = foot

	}
	return nil

}

//OpenWrite will try to read the footer
func (p *FootedRecordFile) OpenWrite() error {
	return p.OpenWithFooter(OMode_Write)
}

//implements io.Writer but enforces the bufio interfaces underneath
//bytes written here increase the recorded size of the file.
func (p *RecordFile) Write(b []byte) (n int, err error) {
	if p.fp == nil {
		return 0, errNotOpen
	}
	rlen := uint32(len(b))
	errind := binary.Write(p.writer, binary.BigEndian, rlen)
	if errind != nil {
		return 0, errind
	}
	nb, err := p.writer.Write(b)
	if err != nil {
		return 0, err
	}
	p.sz += int64(nb)
	return nb, nil
}

func (p *RecordFile) Read(b []byte) (int, error) {
	if p.fp == nil {
		return 0, errNotOpen
	}
	return p.fp.Read(b)
}

func (p *RecordFile) Flush() (err error) {
	if p.writer != nil {
		log.Printf("flushing writer")
		err = p.writer.Flush()
	}
	return
}

//implements io.Closer
func (p *RecordFile) Close() error {
	log.Printf("Record Close called")
	p.Flush() // flush.
	if p.fp != nil {
		err := p.fp.Close()
		p.fp = nil
		return err
	}
	return errNotOpen
}

func (p *FootedRecordFile) Close() error {
	log.Printf("FootedRecord Close called")
	p.Footer = p.MakeFooter()
	log.Printf("Footer is:%s", p.Footer)
	nb, err := p.Write(MarshalBytes(p.Footer))
	if err != nil {
		log.Printf("Error in close:%s", err)
		return err
	}
	log.Printf("wrote %d bytes", nb)
	return p.RecordFile.Close()
}

func (p *FootedRecordFile) MakeFooter() *Footer {
	return &Footer{
		Filedir:    filepath.Dir(p.fname),
		Filename:   filepath.Base(p.fname),
		Numentries: p.entries,
		Filever:    RecordFile_FlatFooted,
	}
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
