package magic

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"strconv"
)

var (
	ErrFileIsNotMIMEMagic = errors.New("File is not MIME Magic file")
)

type MagicReader struct {
	filename string
	isEOF    bool

	reader *bufio.Reader
	file   *os.File
}

type Section struct {
	Filetype string
	Priority uint
	Contents []*Content
}

type Content struct {
	Indent      uint
	Offset      uint
	Value       []byte
	Mask        []byte
	RangeLength uint
	WordSize    uint
}

func NewMagicReader() *MagicReader {
	r := new(MagicReader)

	r.filename = "/usr/share/mime/magic"
	r.isEOF = false

	return r
}

func (r *MagicReader) Open() error {
	f, err := os.Open(r.filename)
	if err != nil {
		return err
	}
	r.reader = bufio.NewReader(f)
	r.file = f
	return r.checkMagicHeader()
}

func (r *MagicReader) Close() error {
	return r.file.Close()
}

func (r *MagicReader) EOF() bool {
	return r.isEOF
}

func (r *MagicReader) ReadSection() *Section {
	sec := new(Section)

	r.findSectionStart()
	if !r.isEOF {
		sec.Priority = r.getUintToken(':')
		sec.Filetype = r.getStringToken(']')
		r.skipAfterNewline()
		sec.Contents = make([]*Content, 0, 2)

		con := new(Content)
		for r.checkSegmentEnd() {
			con.Indent = r.getUintToken('>')
			con.Offset = r.getUintToken('=')
			con.Value = r.readValue()
			con.Mask = r.getMask(len(con.Value))
			r.skipAfterNewline()
		}
		sec.Contents = append(sec.Contents, con)
	}

	return sec
}

func (r *MagicReader) findSectionStart() {
	var (
		c   byte
		err error
	)

	for err != nil && c != '[' {
		c, err = r.reader.ReadByte()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("[DEBUG] Failed to find sections in file")
			}
			r.isEOF = true
			return
		}
	}

	if _, err := r.reader.Discard(1); err != nil {
		r.isEOF = true
		return
	}
}

func (r *MagicReader) getUintToken(del byte) uint {
	buff, err := r.reader.ReadBytes(del)
	if err != nil {
		log.Printf("[DEBUG] Failed to read uint token")
	}

	if len(buff) <= 2 {
		return 0
	}

	buff = buff[:len(buff)-1]

	value, err := strconv.ParseUint(string(buff), 10, 32)
	if err != nil {
		log.Printf("[DEBUG] Failed to parse uint token. Got string = %q", string(buff))
		value = 0
	}

	return uint(value)
}

func (r *MagicReader) getStringToken(del byte) string {
	buff, err := r.reader.ReadBytes(del)
	if err != nil {
		if !errors.Is(err, os.ErrClosed) {
			log.Printf("[DEBUG] Failed to read string token. Err = %v", err)
		} else {
			r.isEOF = true
			return ""
		}
	}
	if len(buff) <= 2 {
		return ""
	}

	return string(buff[:len(buff)-1])
}

func (r *MagicReader) checkMagicHeader() error {
	sign := []byte("MIME-Magic\000\n")

	fileSign := make([]byte, len(sign))

	if _, err := r.reader.Read(fileSign); err != nil {
		return err
	}

	for i := range fileSign {
		if sign[i] != fileSign[i] {
			return ErrFileIsNotMIMEMagic
		}
	}

	return nil
}

func (r *MagicReader) readValue() []byte {
	buff := make([]byte, 2)
	_, err := r.reader.Read(buff)
	if err != nil {
		log.Printf("[DEBUG] Failed to read value size")
	}
	size := int(binary.BigEndian.Uint16(buff))

	buff = make([]byte, size)
	_, err = r.reader.Read(buff)
	if err != nil {
		log.Printf("[DEBUG] Failed to read value of size %d", size)
	}

	return buff
}

func (r *MagicReader) getMask(size int) []byte {
	buff := make([]byte, size)

	data, err := r.reader.Peek(1)
	if err != nil {
		log.Printf("[DEBUG] Failed to peek at next sym to get mask")
	} else if data[0] == '&' {
		_, err := r.reader.Discard(1)
		if err != nil {
			log.Printf("[DEBUG] Failed to read mask of size %d", size)
		}
		_, err = r.reader.Read(buff)
		if err != nil {
			log.Printf("[DEBUG] Failed to read mask of size %d", size)
		}
	}
	return buff
}

func (r *MagicReader) checkSegmentEnd() bool {
	data, err := r.reader.Peek(10)
	if err != nil {
		return false
	}
	bytes.TrimRight(data, " \n")
	if len(data) == 0 {
		return false
	}
	return data[0] != '['
}

func (r *MagicReader) skipAfterNewline() {
	_, err := r.reader.ReadBytes('\n')
	if err != nil {
		if !errors.Is(err, os.ErrClosed) {
			log.Printf("[DEBUG] Failed discard bytes before newline")
		}
	}
}
