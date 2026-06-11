package sv

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/smartgrid/relay-protect/internal/decoder"
)

type SVParser struct {
	channelMapping map[string][]string
}

func NewSVParser() *SVParser {
	return &SVParser{
		channelMapping: make(map[string][]string),
	}
}

func (p *SVParser) RegisterChannels(svid string, channels []string) {
	p.channelMapping[svid] = channels
}

func ParseSVEthernetFrame(data []byte) (srcMAC, dstMAC []byte, etherType uint16, payload []byte, err error) {
	if len(data) < 14 {
		err = fmt.Errorf("frame too short")
		return
	}

	dstMAC = data[0:6]
	srcMAC = data[6:12]
	etherType = binary.BigEndian.Uint16(data[12:14])
	payload = data[14:]

	return
}

func ParseSV(rawData []byte) (*SVData, error) {
	srcMAC, _, etherType, payload, err := ParseSVEthernetFrame(rawData)
	if err != nil {
		return nil, err
	}

	if etherType != EtherTypeSV {
		return nil, fmt.Errorf("not SV frame, ethertype=0x%04x", etherType)
	}

	_ = srcMAC

	ber, err := decoder.ParseBER(payload)
	if err != nil {
		return nil, fmt.Errorf("parse SV APDU: %w", err)
	}

	if ber.Tag != SVAPDUTag {
		return nil, fmt.Errorf("invalid SV APDU tag: 0x%02x", ber.Tag)
	}

	sv := &SVData{
		RawData:   rawData,
		Timestamp: time.Now(),
	}

	err = parseSVPDU(ber.Data, sv)
	if err != nil {
		return nil, err
	}

	return sv, nil
}

func parseSVPDU(data []byte, sv *SVData) error {
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
			sv.SVID = parseSVString(ber.Data)
		case 1:
			sv.SmpCnt = parseSVUint16(ber.Data)
		case 2:
			sv.ConfRev = parseSVUint32(ber.Data)
		case 3:
			refrTm, err := decoder.DecodeTimeStamp(ber.FullData)
			if err == nil {
				sv.RefrTm = refrTm
			}
		case 4:
			sv.SmpSync = parseSVUint8(ber.Data)
		case 5:
			sv.SmpRate = parseSVUint16(ber.Data)
		case 6:
			sv.DataSet = parseSVDataSet(ber.Data)
		case 7:
			sv.SmpMod = parseSVUint8(ber.Data)
		case 8:
			sv.SeqData = parseSVSequenceData(ber.Data)
		}
	}

	return nil
}

func parseSVString(data []byte) string {
	return string(data)
}

func parseSVUint8(data []byte) uint8 {
	if len(data) >= 1 {
		return data[0]
	}
	return 0
}

func parseSVUint16(data []byte) uint16 {
	if len(data) >= 2 {
		return binary.BigEndian.Uint16(data[0:2])
	}
	return 0
}

func parseSVUint32(data []byte) uint32 {
	if len(data) >= 4 {
		return binary.BigEndian.Uint32(data[0:4])
	}
	return 0
}

func parseSVInt32(data []byte) int32 {
	if len(data) >= 4 {
		return int32(binary.BigEndian.Uint32(data[0:4]))
	}
	return 0
}

func parseSVDataSet(data []byte) []PhyMeas {
	var measurements []PhyMeas
	it := decoder.NewBERIterator(data)

	for it.HasMore() {
		ber, err := it.Next()
		if err != nil || ber == nil {
			break
		}

		meas := PhyMeas{}

		if ber.Class == decoder.ClassContext && ber.TagNum == 0 {
			meas.InstMag = parseSVInt32(ber.Data)
			if len(ber.Data) == 4 {
				meas.InstMagF = float64(meas.InstMag)
				meas.HasFloat = false
			}
		}

		if ber.Class == decoder.ClassConstructed|decoder.ClassContext {
			innerIt := decoder.NewBERIterator(ber.Data)
			for innerIt.HasMore() {
				inner, err := innerIt.Next()
				if err != nil || inner == nil {
					break
				}
				switch inner.TagNum {
				case 0:
					meas.InstMag = parseSVInt32(inner.Data)
				case 1:
					if len(inner.Data) >= 4 {
						bits := binary.BigEndian.Uint32(inner.Data)
						meas.InstMagF = float64(mathFloat32frombits(bits))
						meas.HasFloat = true
					}
				case 2:
					meas.Range = parseSVUint16(inner.Data)
				case 3:
					meas.Quality = parseSVUint16(inner.Data)
				}
			}
		}

		measurements = append(measurements, meas)
	}

	return measurements
}

func parseSVSequenceData(data []byte) []int32 {
	var values []int32
	it := decoder.NewBERIterator(data)

	for it.HasMore() {
		ber, err := it.Next()
		if err != nil || ber == nil {
			break
		}

		if ber.Class == decoder.ClassContext && ber.TagNum == 0 {
			if len(ber.Data) == 4 {
				val := parseSVInt32(ber.Data)
				values = append(values, val)
			}
		}
	}

	return values
}

func mathFloat32frombits(b uint32) float32 {
	return float32FromBitsImpl(b)
}

func float32FromBitsImpl(b uint32) float32 {
	f := float32(0)
	bits := b

	if bits == 0 {
		return 0
	}
	if bits == 0x80000000 {
		return -0.0
	}

	sign := float32(1.0)
	if bits&0x80000000 != 0 {
		sign = -1.0
	}

	exponent := int((bits>>23)&0xFF) - 127
	mantissa := bits & 0x7FFFFF

	var fraction float32
	for i := 0; i < 23; i++ {
		if mantissa&(1<<uint(22-i)) != 0 {
			fraction += 1.0 / float32(uint32(1)<<uint(i+1))
		}
	}

	f = sign * (1.0 + fraction)
	if exponent >= 0 {
		for i := 0; i < exponent; i++ {
			f *= 2.0
		}
	} else {
		for i := 0; i < -exponent; i++ {
			f /= 2.0
		}
	}

	return f
}

func IsSVPacket(data []byte) bool {
	if len(data) < 14 {
		return false
	}
	etherType := uint16(data[12])<<8 | uint16(data[13])
	return etherType == EtherTypeSV
}

func IsSVMulticast(mac []byte) bool {
	if len(mac) < 6 {
		return false
	}
	return mac[0] == 0x01 && mac[1] == 0x0C && mac[2] == 0xCD &&
		(mac[3] == 0x02 || mac[3] == 0x01)
}

func ExtractAnalogValues(sv *SVData, scale float64) []float64 {
	values := make([]float64, 0, len(sv.DataSet)+len(sv.SeqData))

	for _, meas := range sv.DataSet {
		if meas.HasFloat {
			values = append(values, meas.InstMagF)
		} else {
			values = append(values, float64(meas.InstMag)*scale)
		}
	}

	for _, val := range sv.SeqData {
		values = append(values, float64(val)*scale)
	}

	return values
}

func BuildSVOnlyFilter() string {
	return "(ether[0:3] = 0x010ccd and ether proto 0x88ba)"
}
