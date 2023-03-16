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
	"unicode"

	"github.com/Pavel7004/goMimeMagic/pkg/domain"
)

var (
	ErrFileIsNotMIMEMagic = errors.New("File is not MIME Magic file")
	ErrHeaderCorrupted    = errors.New("Section header is not readable")
	ErrContentCorrupted   = errors.New("Section content is not readable")
)

type MagicReader struct {
	filename string
	isEOF    bool

	reader *bufio.Reader
	file   *os.File
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

func (r *MagicReader) ReadSections() ([]*domain.Section, error) {
	var (
		sec *domain.Section

		secs = make([]*domain.Section, 0, 10)
	)
	for {
		buff, err := r.reader.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				log.Printf("Failed to read from file. err = %v", err)
				return nil, err
			}
			break
		}

		log.Printf("Read buffer %q", string(buff))
		if buff[0] == '[' {
			// INFO: format - [priority : filetype]\n
			priority, filetype, ok := bytes.Cut(buff[1:len(buff)-2], []byte{':'})
			if !ok {
				log.Printf("Failed to read section header. buff = %q", string(buff))
				return nil, ErrHeaderCorrupted
			}

			num, err := strconv.ParseUint(string(priority), 10, 32)
			if err != nil {
				log.Printf("Failed to parse section priority in header. err = %v", err)
				return nil, ErrHeaderCorrupted
			}

			if sec != nil {
				secs = append(secs, sec)
			}

			sec = &domain.Section{
				Filetype: string(filetype),
				Priority: uint(num),
				Contents: make([]*domain.Content, 0, 2),
			}
		} else {
			// INFO: format - [indent] > [offset] = [2 byte value size][value]
			if sec == nil {
				log.Printf("Found content string, expected header.")
				return nil, ErrHeaderCorrupted
			}

			cont := new(domain.Content)

			indentBytes, buff, ok := bytes.Cut(buff, []byte{'>'})
			if !ok {
				log.Printf("Failed to read section content indent string. buff = %q", string(indentBytes))
				log.Printf("Section info: %q : %d ; %v", sec.Filetype, sec.Priority, sec.Contents)
				return nil, ErrContentCorrupted
			}
			if len(indentBytes) > 0 {
				indent, err := strconv.ParseUint(string(indentBytes), 10, 32)
				if err != nil {
					log.Printf("Failed to parse section content indent string. err = %v", err)
					return nil, ErrContentCorrupted
				}
				cont.Indent = uint(indent)
			}

			offsetBytes, buff, ok := bytes.Cut(buff, []byte{'='})
			if !ok {
				log.Printf("Failed to read section content offset string. buff = %q", string(offsetBytes))
				return nil, ErrContentCorrupted
			}
			offset, err := strconv.ParseUint(string(offsetBytes), 10, 32)
			if err != nil {
				log.Printf("Failed to parse section content offset string. err = %v", err)
				return nil, ErrContentCorrupted
			}
			cont.Offset = uint(offset)

			if len(buff) <= 3 {
				tmpBuff, err := r.reader.ReadBytes('\n')
				if err != nil {
					log.Printf("Failed to append next line to buff. err = %v", err)
					return nil, ErrContentCorrupted
				}

				log.Printf("Read first additional buff = %q", string(tmpBuff))
				buff = append(buff, tmpBuff...)
			}
			size := int(binary.BigEndian.Uint16(buff[:2]))
			buff = buff[2:]
			if len(buff) <= size {
				tmpBuff, err := r.reader.ReadBytes('\n')
				if err != nil {
					log.Printf("Failed to append next line to buff. err = %v", err)
					return nil, ErrContentCorrupted
				}

				log.Printf("Read second additional buff = %q", string(tmpBuff))
				buff = append(buff, tmpBuff...)

				c, err := r.reader.Peek(1)
				if err != nil {
					log.Printf("Failed to peek the next byte after reading additional buffer. err = %v", err)
					return nil, ErrContentCorrupted
				}
				if c[0] == '\n' {
					buff = append(buff, '\n')
					_, err := r.reader.Discard(1)
					if err != nil {
						log.Printf("Failed to discard byte after peek. err = %v", err)
						return nil, ErrContentCorrupted
					}
				}
			}

			cont.RangeLength = 1
			buff, rangeBytes, ok := bytes.Cut(buff[:len(buff)-1], []byte{'+'})
			if ok {
				if !unicode.IsDigit(rune(rangeBytes[0])) {
					buff = append(buff, rangeBytes...)
				} else {
					rangeLen, err := strconv.ParseUint(string(rangeBytes), 10, 32)
					if err != nil {
						log.Printf("Failed to parse section content range-length string. err = %v", err)
						return nil, ErrContentCorrupted
					}
					cont.RangeLength = uint(rangeLen)
				}
			}

			cont.WordSize = 1
			buff, wordSizeBytes, ok := bytes.Cut(buff, []byte{'~'})
			if ok {
				if !unicode.IsDigit(rune(wordSizeBytes[0])) {
					buff = append(buff, wordSizeBytes...)
				} else {
					wordSize, err := strconv.ParseUint(string(wordSizeBytes), 10, 32)
					if err != nil {
						log.Printf("Failed to parse section content word-size string. err = %v", err)
						return nil, ErrContentCorrupted
					}
					cont.WordSize = uint(wordSize)
				}
			}

			cont.Value, cont.Mask, ok = bytes.Cut(buff, []byte{'&'})
			if !ok {
				cont.Mask = make([]byte, size)
				for i := range cont.Mask {
					cont.Mask[i] = 0xff
				}
			}

			sec.Contents = append(sec.Contents, cont)
		}
	}

	return secs, nil
}

func (r *MagicReader) ReadSection() *domain.Section {
	sec := new(domain.Section)

	r.findSectionStart()
	if !r.isEOF {
		sec.Priority = r.getUintToken(':')
		sec.Filetype = r.getStringToken(']')
		r.skipAfterNewline()
		sec.Contents = make([]*domain.Content, 0, 2)

		con := new(domain.Content)
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
