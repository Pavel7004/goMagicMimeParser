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

	reader *bufio.Reader
	file   *os.File
}

func NewMagicReader() *MagicReader {
	r := new(MagicReader)

	r.filename = "/usr/share/mime/magic"

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

func (r *MagicReader) ReadSections() ([]*domain.Section, error) {
	secs := make([]*domain.Section, 0, 10)

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
			if sec, err := r.ReadHeader(buff); err != nil {
				return nil, err
			} else {
				secs = append(secs, sec)
			}
		} else {
			if len(secs) == 0 {
				log.Printf("Found content string, expected header.")
				return nil, ErrHeaderCorrupted
			}

			cont := new(domain.Content)

			// INFO: format - [indent] > [offset] = [2 byte value size][value]

			indentBytes, buff, ok := bytes.Cut(buff, []byte{'>'})
			if !ok {
				log.Printf("Failed to read section content indent string. buff = %q", string(indentBytes))
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

			secs[len(secs)-1].Contents = append(secs[len(secs)-1].Contents, cont)
		}
	}

	return secs, nil
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

func (r *MagicReader) ReadHeader(buff []byte) (*domain.Section, error) {
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

	return &domain.Section{
		Filetype: string(filetype),
		Priority: uint(num),
		Contents: make([]*domain.Content, 0, 2),
	}, nil
}
