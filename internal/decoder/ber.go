package decoder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	TagBoolean         = 1
	TagInteger         = 2
	TagBitString       = 3
	TagOctetString     = 4
	TagNull            = 5
	TagObjectID        = 6
	TagSequence        = 16
	TagSet             = 17
	TagVisibleString   = 26
	TagGeneralizedTime = 24
	TagUTC             = 23
	TagUTCTime         = 23
	ClassContext       = 0x80
	ClassConstructed   = 0x20
)

var (
	ErrInvalidBER     = errors.New("invalid BER encoding")
	ErrTruncated      = errors.New("truncated data")
	ErrTagMismatch    = errors.New("tag mismatch")
	ErrLengthMismatch = errors.New("length mismatch")
)

type BERTag struct {
	Tag      byte
	Class    byte
	PC       byte
	TagNum   uint32
	Length   int
	Data     []byte
	FullData []byte
}

func ParseBER(data []byte) (*BERTag, error) {
	if len(data) < 2 {
		return nil, ErrTruncated
	}

	ber := &BERTag{
		FullData: data,
	}

	ber.Tag = data[0]
	ber.Class = data[0] & 0xC0
	ber.PC = data[0] & 0x20

	pos := 1

	if (data[0] & 0x1F) == 0x1F {
		var tagNum uint32
		for {
			if pos >= len(data) {
				return nil, ErrTruncated
			}
			tagNum = (tagNum << 7) | uint32(data[pos]&0x7F)
			if data[pos]&0x80 == 0 {
				pos++
				break
			}
			pos++
		}
		ber.TagNum = tagNum
	} else {
		ber.TagNum = uint32(data[0] & 0x1F)
	}

	if pos >= len(data) {
		return nil, ErrTruncated
	}

	lengthByte := data[pos]
	pos++

	if lengthByte&0x80 == 0 {
		ber.Length = int(lengthByte)
	} else {
		numBytes := int(lengthByte & 0x7F)
		if numBytes == 0 || numBytes > 4 {
			return nil, ErrInvalidBER
		}
		if pos+numBytes > len(data) {
			return nil, ErrTruncated
		}
		var length int
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[pos+i])
		}
		pos += numBytes
		ber.Length = length
	}

	if pos+ber.Length > len(data) {
		return nil, ErrTruncated
	}

	ber.Data = data[pos : pos+ber.Length]

	return ber, nil
}

func (b *BERTag) IsContextSpecific(tagNumber int) bool {
	return b.Class == ClassContext && int(b.TagNum) == tagNumber
}

func (b *BERTag) IsConstructed() bool {
	return b.PC == ClassConstructed
}

func DecodeBoolean(data []byte) (bool, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return false, err
	}
	if ber.TagNum != TagBoolean {
		return false, fmt.Errorf("%w: expected boolean tag %d, got %d", ErrTagMismatch, TagBoolean, ber.TagNum)
	}
	if ber.Length != 1 {
		return false, fmt.Errorf("%w: boolean length must be 1, got %d", ErrLengthMismatch, ber.Length)
	}
	return ber.Data[0] != 0, nil
}

func DecodeInteger(data []byte) (int64, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return 0, err
	}
	if ber.TagNum != TagInteger {
		return 0, fmt.Errorf("%w: expected integer tag %d, got %d", ErrTagMismatch, TagInteger, ber.TagNum)
	}
	if ber.Length == 0 || ber.Length > 8 {
		return 0, fmt.Errorf("%w: invalid integer length %d", ErrLengthMismatch, ber.Length)
	}

	var result int64
	if ber.Data[0]&0x80 != 0 {
		result = -1
	}
	for _, b := range ber.Data {
		result = (result << 8) | int64(b)
	}
	return result, nil
}

func DecodeUnsigned(data []byte) (uint64, error) {
	val, err := DecodeInteger(data)
	if err != nil {
		return 0, err
	}
	return uint64(val), nil
}

func DecodeBitString(data []byte) ([]byte, int, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return nil, 0, err
	}
	if ber.TagNum != TagBitString {
		return nil, 0, fmt.Errorf("%w: expected bit string tag %d, got %d", ErrTagMismatch, TagBitString, ber.TagNum)
	}
	if ber.Length < 1 {
		return nil, 0, fmt.Errorf("%w: bit string too short", ErrLengthMismatch)
	}
	unusedBits := int(ber.Data[0])
	bytes := ber.Data[1:]
	totalBits := len(bytes)*8 - unusedBits
	return bytes, totalBits, nil
}

func DecodeOctetString(data []byte) ([]byte, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return nil, err
	}
	if ber.TagNum != TagOctetString {
		return nil, fmt.Errorf("%w: expected octet string tag %d, got %d", ErrTagMismatch, TagOctetString, ber.TagNum)
	}
	return ber.Data, nil
}

func DecodeVisibleString(data []byte) (string, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return "", err
	}
	if ber.TagNum != TagVisibleString {
		return "", fmt.Errorf("%w: expected visible string tag %d, got %d", ErrTagMismatch, TagVisibleString, ber.TagNum)
	}
	return string(ber.Data), nil
}

func DecodeSequence(data []byte) ([]byte, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return nil, err
	}
	if ber.TagNum != TagSequence {
		return nil, fmt.Errorf("%w: expected sequence tag %d, got %d", ErrTagMismatch, TagSequence, ber.TagNum)
	}
	return ber.Data, nil
}

func DecodeContextSpecific(data []byte, expectedTag int) ([]byte, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return nil, err
	}
	if !ber.IsContextSpecific(expectedTag) {
		return nil, fmt.Errorf("%w: expected context tag [%d], got [%d]", ErrTagMismatch, expectedTag, ber.TagNum)
	}
	return ber.Data, nil
}

func SkipElement(data []byte) (int, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return 0, err
	}
	return len(data) - len(ber.Data), nil
}

func GetElementLength(data []byte) (int, int, error) {
	if len(data) < 2 {
		return 0, 0, ErrTruncated
	}

	pos := 1

	if (data[0] & 0x1F) == 0x1F {
		for {
			if pos >= len(data) {
				return 0, 0, ErrTruncated
			}
			if data[pos]&0x80 == 0 {
				pos++
				break
			}
			pos++
		}
	}

	if pos >= len(data) {
		return 0, 0, ErrTruncated
	}

	lengthByte := data[pos]
	pos++

	var length int
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		numBytes := int(lengthByte & 0x7F)
		if numBytes == 0 || numBytes > 4 {
			return 0, 0, ErrInvalidBER
		}
		if pos+numBytes > len(data) {
			return 0, 0, ErrTruncated
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[pos+i])
		}
		pos += numBytes
	}

	totalLen := pos + length
	return pos, totalLen, nil
}

func DecodeTimeStamp(data []byte) (time.Time, error) {
	ber, err := ParseBER(data)
	if err != nil {
		return time.Time{}, err
	}

	if len(ber.Data) < 8 {
		return time.Time{}, fmt.Errorf("%w: timestamp data too short", ErrLengthMismatch)
	}

	seconds := binary.BigEndian.Uint32(ber.Data[0:4])
	fractions := binary.BigEndian.Uint32(ber.Data[4:8])

	secs := int64(seconds)
	nanos := int64(fractions) * 1000 / 4294967

	return time.Unix(secs, nanos).UTC(), nil
}

type BERIterator struct {
	data  []byte
	index int
}

func NewBERIterator(data []byte) *BERIterator {
	return &BERIterator{
		data:  data,
		index: 0,
	}
}

func (it *BERIterator) Next() (*BERTag, error) {
	if it.index >= len(it.data) {
		return nil, nil
	}

	ber, err := ParseBER(it.data[it.index:])
	if err != nil {
		return nil, err
	}

	_, totalLen, err := GetElementLength(it.data[it.index:])
	if err != nil {
		return nil, err
	}

	it.index += totalLen
	return ber, nil
}

func (it *BERIterator) HasMore() bool {
	return it.index < len(it.data)
}

func (it *BERIterator) Pos() int {
	return it.index
}

func (it *BERIterator) Remaining() []byte {
	return it.data[it.index:]
}
