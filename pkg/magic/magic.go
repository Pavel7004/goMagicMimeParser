package magic

import (
	"errors"
	"log"
	"os"
)

var (
	ErrFileIsNotMIMEMagic = errors.New("File is not MIME Magic db")
)

type MagicReader struct {
	filename string

	file *os.File
}

type Record struct {
	FileType string
	numbers  []byte
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
	r.file = f
	return r.checkMagicHeader()
}

func (r *MagicReader) Close() error {
	return r.file.Close()
}

func (r *MagicReader) ReadRecord() *Record {
	return nil
}

func (r *MagicReader) checkMagicHeader() error {
	sign := []byte("MIME-Magic\000\n")

	fileSign := make([]byte, len(sign))

	if _, err := r.file.Read(fileSign); err != nil {
		return err
	}

	log.Printf("Read signature: %v", fileSign)

	for i := range fileSign {
		if sign[i] != fileSign[i] {
			return ErrFileIsNotMIMEMagic
		}
	}

	return nil
}
