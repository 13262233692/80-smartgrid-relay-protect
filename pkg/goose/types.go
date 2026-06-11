package goose

import "time"

type GOOSEMessage struct {
	GOCBRef         string
	DatSet          string
	GoID            string
	T               time.Time
	StNum           uint32
	SqNum           uint32
	Test            bool
	ConfRev         uint32
	NdsCom          bool
	Simulation      bool
	AllData         []DataAttribute
	DataSetValues   map[string]bool
	RawData         []byte
	Timestamp       time.Time
}

type DataAttribute struct {
	Type  DataType
	Value interface{}
}

type DataType int

const (
	TypeBoolean DataType = iota
	TypeBitString
	TypeInteger
	TypeUnsigned
	TypeFloat
	TypeOctetString
	TypeVisibleString
	TypeTimeStamp
	TypeStructure
)

type GOOSEConfig struct {
	InterfaceName   string
	FilterMAC       string
	Promiscuous     bool
	SnapLen         int32
	BufferSize      int
}

type DataSetValue struct {
	Name     string
	Value    bool
	Quality  uint16
	TimeTag  time.Time
}
