package sv

import (
	"math"
	"time"
)

const (
	EtherTypeSV = 0x88BA
	SVAPDUTag   = 0x60
)

type DataType int

const (
	TypeInt8 DataType = iota
	TypeInt16
	TypeInt32
	TypeInt64
	TypeInt128
	TypeInt256
	TypeFloat32
	TypeFloat64
)

type PhyMeas struct {
	InstMag   int32
	InstMagF  float64
	Range     uint16
	Quality   uint16
	HasFloat  bool
}

type SVData struct {
	SVID          string
	SmpCnt        uint16
	ConfRev       uint32
	RefrTm        time.Time
	SmpSync       uint8
	SmpRate       uint16
	SmpMod        uint8
	DataSet       []PhyMeas
	SeqData       []int32
	SeqDataFloat  []float64
	RawData       []byte
	Timestamp     time.Time
}

type SVConfig struct {
	InterfaceName string
	Promiscuous   bool
	SnapLen       int32
	BufferSize    int
	BPFFilter     string
	SVIDs         []string
}

type Phasor struct {
	Real   float64
	Imag   float64
	Mag    float64
	Angle  float64
}

type SamplePoint struct {
	Value     float64
	Timestamp time.Time
	Index     uint32
}

type ChannelBuffer struct {
	Name        string
	Buffer      []float64
	BufferSize  int
	WriteIndex  int
	ReadIndex   int
	SampleRate  int
	Full        bool
}

type ZeroSequenceData struct {
	CurrentI0   *ChannelBuffer
	Side        string
	Phasor      Phasor
	LastUpdate  time.Time
}

type DifferentialData struct {
	Idiff       Phasor
	Ires        Phasor
	IdiffMag    float64
	IresMag     float64
	Slope       float64
	Trip        bool
	LastUpdate  time.Time
}

type DifferentialSettings struct {
	Iset1       float64
	Iset2       float64
	K1          float64
	K2          float64
	IresMin     float64
	CTRatio     float64
}

func DefaultDifferentialSettings() DifferentialSettings {
	return DifferentialSettings{
		Iset1:   0.2,
		Iset2:   1.5,
		K1:      0.3,
		K2:      0.5,
		IresMin: 0.5,
		CTRatio: 1.0,
	}
}

func NewPhasor(real, imag float64) Phasor {
	mag := math.Hypot(real, imag)
	angle := math.Atan2(imag, real)
	return Phasor{
		Real:  real,
		Imag:  imag,
		Mag:   mag,
		Angle: angle,
	}
}

func (p Phasor) Add(other Phasor) Phasor {
	return NewPhasor(p.Real+other.Real, p.Imag+other.Imag)
}

func (p Phasor) Sub(other Phasor) Phasor {
	return NewPhasor(p.Real-other.Real, p.Imag-other.Imag)
}

func (p Phasor) Scale(k float64) Phasor {
	return NewPhasor(p.Real*k, p.Imag*k)
}

func (p Phasor) Abs() float64 {
	return p.Mag
}
