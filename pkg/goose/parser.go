package goose

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/smartgrid/relay-protect/internal/decoder"
)

const (
	EtherTypeGOOSE = 0x88B8
	GOOSEAPDUTag   = 0x61
)

var (
	ErrInvalidGOOSE     = errors.New("invalid GOOSE frame")
	ErrNotGOOSEFrame    = errors.New("not a GOOSE frame")
	ErrInvalidEtherType = errors.New("invalid ethernet type")
)

func ParseEthernetFrame(data []byte) (srcMAC, dstMAC []byte, etherType uint16, payload []byte, err error) {
	if len(data) < 14 {
		err = ErrInvalidGOOSE
		return
	}

	dstMAC = data[0:6]
	srcMAC = data[6:12]
	etherType = binary.BigEndian.Uint16(data[12:14])
	payload = data[14:]

	return
}

func ParseGOOSE(rawData []byte) (*GOOSEMessage, error) {
	srcMAC, _, etherType, payload, err := ParseEthernetFrame(rawData)
	if err != nil {
		return nil, err
	}

	if etherType != EtherTypeGOOSE {
		return nil, fmt.Errorf("%w: 0x%04x", ErrInvalidEtherType, etherType)
	}

	ber, err := decoder.ParseBER(payload)
	if err != nil {
		return nil, fmt.Errorf("parse GOOSE APDU: %w", err)
	}

	if ber.Tag != GOOSEAPDUTag {
		return nil, fmt.Errorf("%w: expected tag 0x%02x, got 0x%02x", ErrInvalidGOOSE, GOOSEAPDUTag, ber.Tag)
	}

	msg := &GOOSEMessage{
		RawData:       rawData,
		DataSetValues: make(map[string]bool),
		Timestamp:     time.Now(),
	}

	err = parseGOOSEPDU(ber.Data, msg)
	if err != nil {
		return nil, err
	}

	_ = srcMAC
	return msg, nil
}

func parseGOOSEPDU(data []byte, msg *GOOSEMessage) error {
	it := decoder.NewBERIterator(data)

	for it.HasMore() {
		ber, err := it.Next()
		if err != nil {
			return err
		}
		if ber == nil {
			break
		}

		if ber.Class != decoder.ClassContext {
			continue
		}

		switch ber.TagNum {
		case 0:
			msg.GOCBRef = string(ber.Data)
		case 1:
			msg.DatSet = string(ber.Data)
		case 2:
			msg.GoID = string(ber.Data)
		case 3:
			t, err := decoder.DecodeTimeStamp(ber.FullData)
			if err == nil {
				msg.T = t
			}
		case 4:
			stNum, err := decoder.DecodeUnsigned(ber.FullData)
			if err == nil {
				msg.StNum = uint32(stNum)
			}
		case 5:
			sqNum, err := decoder.DecodeUnsigned(ber.FullData)
			if err == nil {
				msg.SqNum = uint32(sqNum)
			}
		case 6:
			test, err := decoder.DecodeBoolean(ber.FullData)
			if err == nil {
				msg.Test = test
			}
		case 7:
			confRev, err := decoder.DecodeUnsigned(ber.FullData)
			if err == nil {
				msg.ConfRev = uint32(confRev)
			}
		case 8:
			ndsCom, err := decoder.DecodeBoolean(ber.FullData)
			if err == nil {
				msg.NdsCom = ndsCom
			}
		case 9:
			simulation, err := decoder.DecodeBoolean(ber.FullData)
			if err == nil {
				msg.Simulation = simulation
			}
		case 10:
			allData, err := parseAllData(ber.Data)
			if err == nil {
				msg.AllData = allData
			}
		}
	}

	return nil
}

func parseAllData(data []byte) ([]DataAttribute, error) {
	var attributes []DataAttribute
	it := decoder.NewBERIterator(data)

	for it.HasMore() {
		ber, err := it.Next()
		if err != nil {
			return nil, err
		}
		if ber == nil {
			break
		}

		attr, err := decodeDataAttribute(ber)
		if err != nil {
			continue
		}
		attributes = append(attributes, attr)
	}

	return attributes, nil
}

func decodeDataAttribute(ber *decoder.BERTag) (DataAttribute, error) {
	attr := DataAttribute{}

	switch ber.TagNum {
	case decoder.TagBoolean:
		attr.Type = TypeBoolean
		val, err := decoder.DecodeBoolean(ber.FullData)
		if err != nil {
			return attr, err
		}
		attr.Value = val

	case decoder.TagInteger:
		attr.Type = TypeInteger
		val, err := decoder.DecodeInteger(ber.FullData)
		if err != nil {
			return attr, err
		}
		attr.Value = val

	case decoder.TagBitString:
		attr.Type = TypeBitString
		bytes, bits, err := decoder.DecodeBitString(ber.FullData)
		if err != nil {
			return attr, err
		}
		attr.Value = map[string]interface{}{
			"bytes": bytes,
			"bits":  bits,
		}

	case decoder.TagOctetString:
		attr.Type = TypeOctetString
		val, err := decoder.DecodeOctetString(ber.FullData)
		if err != nil {
			return attr, err
		}
		attr.Value = val

	case decoder.TagVisibleString:
		attr.Type = TypeVisibleString
		val, err := decoder.DecodeVisibleString(ber.FullData)
		if err != nil {
			return attr, err
		}
		attr.Value = val

	case decoder.TagSequence:
		attr.Type = TypeStructure
		nested, err := parseAllData(ber.Data)
		if err != nil {
			return attr, err
		}
		attr.Value = nested

	default:
		if ber.Class == decoder.ClassContext {
			return decodeContextSpecificAttribute(ber)
		}
		return attr, fmt.Errorf("unsupported tag: %d", ber.TagNum)
	}

	return attr, nil
}

func decodeContextSpecificAttribute(ber *decoder.BERTag) (DataAttribute, error) {
	attr := DataAttribute{}

	switch ber.TagNum {
	case 0:
		attr.Type = TypeUnsigned
		val, err := decoder.DecodeUnsigned(ber.Data)
		if err != nil {
			return attr, err
		}
		attr.Value = val

	case 1:
		attr.Type = TypeInteger
		val, err := decoder.DecodeInteger(ber.Data)
		if err != nil {
			return attr, err
		}
		attr.Value = val

	case 2:
		attr.Type = TypeFloat
		if len(ber.Data) >= 4 {
			bits := binary.BigEndian.Uint32(ber.Data)
			attr.Value = float32FromBits(bits)
		}

	case 3:
		attr.Type = TypeOctetString
		attr.Value = ber.Data

	case 4:
		attr.Type = TypeBoolean
		if len(ber.Data) > 0 {
			attr.Value = ber.Data[0] != 0
		} else {
			attr.Value = false
		}

	case 5:
		attr.Type = TypeBitString
		if len(ber.Data) >= 1 {
			unusedBits := int(ber.Data[0])
			bytes := ber.Data[1:]
			totalBits := len(bytes)*8 - unusedBits
			attr.Value = map[string]interface{}{
				"bytes": bytes,
				"bits":  totalBits,
			}
		}

	case 7:
		attr.Type = TypeStructure
		nested, err := parseAllData(ber.Data)
		if err != nil {
			return attr, err
		}
		attr.Value = nested

	case 8:
		attr.Type = TypeTimeStamp
		if len(ber.Data) >= 8 {
			seconds := binary.BigEndian.Uint32(ber.Data[0:4])
			fractions := binary.BigEndian.Uint32(ber.Data[4:8])
			secs := int64(seconds)
			nanos := int64(fractions) * 1000 / 4294967
			attr.Value = time.Unix(secs, nanos).UTC()
		}

	default:
		return attr, fmt.Errorf("unsupported context tag [%d]", ber.TagNum)
	}

	return attr, nil
}

func float32FromBits(bits uint32) float32 {
	return float32(0)
}

func ExtractBooleanValues(attrs []DataAttribute, names []string) map[string]bool {
	result := make(map[string]bool)

	for i, attr := range attrs {
		if i >= len(names) {
			break
		}
		name := names[i]

		if attr.Type == TypeBoolean {
			if val, ok := attr.Value.(bool); ok {
				result[name] = val
			}
		} else if attr.Type == TypeStructure {
			if nested, ok := attr.Value.([]DataAttribute); ok && len(nested) > 0 {
				if nested[0].Type == TypeBoolean {
					if val, ok := nested[0].Value.(bool); ok {
						result[name] = val
					}
				}
			}
		}
	}

	return result
}

type GOOSEParser struct {
	dataSetNames map[string][]string
}

func NewGOOSEParser() *GOOSEParser {
	return &GOOSEParser{
		dataSetNames: make(map[string][]string),
	}
}

func (p *GOOSEParser) RegisterDataSet(dataset string, names []string) {
	p.dataSetNames[dataset] = names
}

func (p *GOOSEParser) Parse(rawData []byte) (*GOOSEMessage, error) {
	msg, err := ParseGOOSE(rawData)
	if err != nil {
		return nil, err
	}

	if names, ok := p.dataSetNames[msg.DatSet]; ok {
		msg.DataSetValues = ExtractBooleanValues(msg.AllData, names)
	}

	return msg, nil
}

func IsGOOSEMulticast(mac []byte) bool {
	if len(mac) < 6 {
		return false
	}
	return mac[0] == 0x01 && mac[1] == 0x0C && mac[2] == 0xCD &&
		(mac[3] == 0x01 || mac[3] == 0x00)
}
