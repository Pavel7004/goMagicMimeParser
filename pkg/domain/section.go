package domain

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
