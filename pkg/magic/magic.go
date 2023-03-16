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
	ErrTokenNotFound      = errors.New("Token not found")
)

type MagicReader struct {
	Filename string

	reader *bufio.Reader
	file   *os.File
}

func NewMagicReader() *MagicReader {
	return &MagicReader{
		Filename: "/usr/share/mime/magic",
	}
}

func (r *MagicReader) Open() error {
	f, err := os.Open(r.Filename)
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
			sec, err := r.readHeader(buff)
			if err != nil {
				return nil, err
			}

			secs = append(secs, sec)
		} else {
			if len(secs) == 0 {
				log.Printf("Found content string, expected header.")
				return nil, ErrHeaderCorrupted
			}

			con, err := r.readContent(buff)
			if err != nil {
				return nil, err
			}

			secs[len(secs)-1].Contents = append(secs[len(secs)-1].Contents, con)
		}
	}

	return secs, nil
}

func (r *MagicReader) checkMagicHeader() error {
	sign := []byte("MIME-Magic\x00\n")

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

func (r *MagicReader) readHeader(buff []byte) (*domain.Section, error) {
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

func (r *MagicReader) readContent(buff []byte) (*domain.Content, error) {
	indent, buff, err := r.getUintToken(buff, '>')
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return nil, err
	}

	offset, buff, err := r.getUintToken(buff, '=')
	if err != nil {
		return nil, err
	}

	size := 0
	if len(buff) >= 2 {
		size = int(binary.BigEndian.Uint16(buff[:2]))
		buff = buff[2:]
	}
	log.Printf("Size of value in content: %d, size of buff: %d", size, len(buff))

	for len(buff) <= size {
		tmpBuff, err := r.reader.ReadBytes('\n')
		if err != nil {
			log.Printf("Failed to append next line to buff. err = %v", err)
			return nil, ErrContentCorrupted
		}

		log.Printf("Read additional buff = %q", string(tmpBuff))
		buff = append(buff, tmpBuff...)
	}

	rangeLength, buff, err := r.getOptUintToken(buff[:len(buff)-1], '+')
	if err != nil {
		return nil, err
	}

	wordSize, buff, err := r.getOptUintToken(buff, '~')
	if err != nil {
		return nil, err
	}

	value, mask, ok := bytes.Cut(buff, []byte{'&'})
	if !ok {
		mask = make([]byte, size)
		for i := range mask {
			mask[i] = 0xff
		}
	}

	return &domain.Content{
		Indent:      indent,
		Offset:      offset,
		Value:       value,
		Mask:        mask,
		RangeLength: rangeLength,
		WordSize:    wordSize,
	}, nil
}

func (r *MagicReader) getUintToken(buff []byte, del byte) (uint, []byte, error) {
	tokenBytes, buff, ok := bytes.Cut(buff, []byte{del})
	if !ok {
		log.Printf("Failed to read section content  string. buff = %q", string(tokenBytes))
		return 0, nil, ErrContentCorrupted
	}
	if len(tokenBytes) == 0 {
		return 0, buff, ErrTokenNotFound
	}
	token, err := strconv.ParseUint(string(tokenBytes), 10, 32)
	if err != nil {
		log.Printf("Failed to parse section content indent string. err = %v", err)
		return 0, nil, ErrContentCorrupted
	}
	return uint(token), buff, nil
}

func (r *MagicReader) getOptUintToken(buff []byte, del byte) (uint, []byte, error) {
	var optVal uint = 1

	buff, optBytes, ok := bytes.Cut(buff, []byte{del})
	if ok {
		if !unicode.IsDigit(rune(optBytes[0])) {
			buff = append(buff, del)
			buff = append(buff, optBytes...)
		} else {
			rangeLen, err := strconv.ParseUint(string(optBytes), 10, 32)
			if err != nil {
				log.Printf("Failed to parse section optional content string. del = %c, err = %v", del, err)
				return 0, nil, ErrContentCorrupted
			}
			optVal = uint(rangeLen)
		}
	}

	return optVal, buff, nil
}
