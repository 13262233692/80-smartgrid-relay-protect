package capture

import (
	"fmt"
	"strings"
)

const (
	GOOSEMulticastPrefix = "01:0c:cd"
	GOOSEEtherType       = "0x88b8"
)

type BPFBuilder struct {
	rules []string
}

func NewBPFBuilder() *BPFBuilder {
	return &BPFBuilder{}
}

func (b *BPFBuilder) AddRule(rule string) *BPFBuilder {
	b.rules = append(b.rules, rule)
	return b
}

func (b *BPFBuilder) EtherType(hexType string) *BPFBuilder {
	b.rules = append(b.rules, fmt.Sprintf("ether proto %s", hexType))
	return b
}

func (b *BPFBuilder) GOOSEEtherType() *BPFBuilder {
	return b.EtherType(GOOSEEtherType)
}

func (b *BPFBuilder) HostMAC(mac string) *BPFBuilder {
	b.rules = append(b.rules, fmt.Sprintf("ether host %s", mac))
	return b
}

func (b *BPFBuilder) DstMAC(mac string) *BPFBuilder {
	b.rules = append(b.rules, fmt.Sprintf("ether dst %s", mac))
	return b
}

func (b *BPFBuilder) SrcMAC(mac string) *BPFBuilder {
	b.rules = append(b.rules, fmt.Sprintf("ether src %s", mac))
	return b
}

func (b *BPFBuilder) Multicast() *BPFBuilder {
	b.rules = append(b.rules, "ether multicast")
	return b
}

func (b *BPFBuilder) MACPrefix(macPrefix string) *BPFBuilder {
	parts := strings.Split(macPrefix, ":")
	if len(parts) < 1 || len(parts) > 6 {
		return b
	}

	byteList := make([]byte, len(parts))
	for i, p := range parts {
		var val byte
		fmt.Sscanf(p, "%02x", &val)
		byteList[i] = val
	}

	hexStr := ""
	for _, v := range byteList {
		hexStr += fmt.Sprintf("%02x", v)
	}

	maskStr := ""
	for i := 0; i < len(parts); i++ {
		maskStr += "ff"
	}
	for i := len(parts); i < 6; i++ {
		maskStr += "00"
	}

	b.rules = append(b.rules, fmt.Sprintf("(ether[0:4] & 0x%s) = 0x%s", maskStr[:8], hexStr))
	return b
}

func (b *BPFBuilder) GOOSEMulticastPrefix() *BPFBuilder {
	return b.MACPrefix(GOOSEMulticastPrefix)
}

func (b *BPFBuilder) DstMACPrefix(macPrefix string) *BPFBuilder {
	parts := strings.Split(macPrefix, ":")
	if len(parts) < 1 || len(parts) > 6 {
		return b
	}

	byteList := make([]byte, len(parts))
	for i, p := range parts {
		var val byte
		fmt.Sscanf(p, "%02x", &val)
		byteList[i] = val
	}

	switch len(parts) {
	case 1:
		b.rules = append(b.rules, fmt.Sprintf("ether[0] = 0x%02x", byteList[0]))
	case 2:
		b.rules = append(b.rules, fmt.Sprintf("ether[0:2] = 0x%02x%02x", byteList[0], byteList[1]))
	case 3:
		b.rules = append(b.rules, fmt.Sprintf("ether[0:3] = 0x%02x%02x%02x", byteList[0], byteList[1], byteList[2]))
	case 4:
		b.rules = append(b.rules, fmt.Sprintf("ether[0:4] = 0x%02x%02x%02x%02x", byteList[0], byteList[1], byteList[2], byteList[3]))
	case 5:
		b.rules = append(b.rules, fmt.Sprintf("(ether[0:4] = 0x%02x%02x%02x%02x and ether[4] = 0x%02x)",
			byteList[0], byteList[1], byteList[2], byteList[3], byteList[4]))
	case 6:
		b.rules = append(b.rules, fmt.Sprintf("ether[0:4] = 0x%02x%02x%02x%02x and ether[4:2] = 0x%02x%02x",
			byteList[0], byteList[1], byteList[2], byteList[3], byteList[4], byteList[5]))
	}
	return b
}

func (b *BPFBuilder) SrcMACPrefix(macPrefix string) *BPFBuilder {
	parts := strings.Split(macPrefix, ":")
	if len(parts) < 1 || len(parts) > 6 {
		return b
	}

	byteList := make([]byte, len(parts))
	for i, p := range parts {
		var val byte
		fmt.Sscanf(p, "%02x", &val)
		byteList[i] = val
	}

	switch len(parts) {
	case 1:
		b.rules = append(b.rules, fmt.Sprintf("ether[6] = 0x%02x", byteList[0]))
	case 2:
		b.rules = append(b.rules, fmt.Sprintf("ether[6:2] = 0x%02x%02x", byteList[0], byteList[1]))
	case 3:
		b.rules = append(b.rules, fmt.Sprintf("ether[6:3] = 0x%02x%02x%02x", byteList[0], byteList[1], byteList[2]))
	case 4:
		b.rules = append(b.rules, fmt.Sprintf("ether[6:4] = 0x%02x%02x%02x%02x", byteList[0], byteList[1], byteList[2], byteList[3]))
	}
	return b
}

func (b *BPFBuilder) GreaterLength(length int) *BPFBuilder {
	b.rules = append(b.rules, fmt.Sprintf("greater %d", length))
	return b
}

func (b *BPFBuilder) LessLength(length int) *BPFBuilder {
	b.rules = append(b.rules, fmt.Sprintf("less %d", length))
	return b
}

func (b *BPFBuilder) And() *BPFBuilder {
	if len(b.rules) > 0 {
		last := b.rules[len(b.rules)-1]
		b.rules = b.rules[:len(b.rules)-1]
		combined := "(" + last + " and "
		b.rules = append(b.rules, combined)
	}
	return b
}

func (b *BPFBuilder) Or() *BPFBuilder {
	if len(b.rules) > 0 {
		last := b.rules[len(b.rules)-1]
		b.rules = b.rules[:len(b.rules)-1]
		combined := "(" + last + " or "
		b.rules = append(b.rules, combined)
	}
	return b
}

func (b *BPFBuilder) CloseParen() *BPFBuilder {
	if len(b.rules) > 0 {
		last := b.rules[len(b.rules)-1]
		b.rules = b.rules[:len(b.rules)-1]
		b.rules = append(b.rules, last+")")
	}
	return b
}

func (b *BPFBuilder) Build(joinOp string) string {
	if len(b.rules) == 0 {
		return ""
	}
	if joinOp == "" {
		joinOp = " and "
	}
	return strings.Join(b.rules, joinOp)
}

func (b *BPFBuilder) BuildAnd() string {
	return b.Build(" and ")
}

func (b *BPFBuilder) BuildOr() string {
	return b.Build(" or ")
}

func (b *BPFBuilder) Reset() *BPFBuilder {
	b.rules = b.rules[:0]
	return b
}

func BuildGOOSEOnlyFilter() string {
	return NewBPFBuilder().
		DstMACPrefix(GOOSEMulticastPrefix).
		GOOSEEtherType().
		BuildAnd()
}

func BuildGOOSEWithSrcFilter(srcMACs []string) string {
	b := NewBPFBuilder()

	b.AddRule("(")
	for i, mac := range srcMACs {
		if i > 0 {
			b.AddRule("or")
		}
		b.SrcMAC(mac)
	}
	b.CloseParen()

	b.GOOSEEtherType()
	b.DstMACPrefix(GOOSEMulticastPrefix)

	return b.BuildAnd()
}

func BuildGOOSEWithDstFilter(dstMACs []string) string {
	b := NewBPFBuilder()

	b.AddRule("(")
	for i, mac := range dstMACs {
		if i > 0 {
			b.AddRule("or")
		}
		b.DstMAC(mac)
	}
	b.CloseParen()

	b.GOOSEEtherType()

	return b.BuildAnd()
}

func BuildOptimizedGOOSEFilter(targetMACs []string) string {
	if len(targetMACs) == 0 {
		return BuildGOOSEOnlyFilter()
	}

	if len(targetMACs) <= 32 {
		return BuildGOOSEWithDstFilter(targetMACs)
	}

	return BuildGOOSEOnlyFilter()
}

type BPFProgram struct {
	Instructions []BPFInstruction
}

type BPFInstruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

const (
	BPF_LD    = 0x00
	BPF_LDX   = 0x01
	BPF_ST    = 0x02
	BPF_STX   = 0x03
	BPF_ALU   = 0x04
	BPF_JMP   = 0x05
	BPF_RET   = 0x06
	BPF_MISC  = 0x07

	BPF_W     = 0x00
	BPF_H     = 0x08
	BPF_B     = 0x10
	BPF_IMM   = 0x00
	BPF_ABS   = 0x20
	BPF_IND   = 0x40
	BPF_MEM   = 0x60
	BPF_LEN   = 0x80
	BPF_MSH   = 0xa0

	BPF_JA    = 0x00
	BPF_JEQ   = 0x10
	BPF_JGT   = 0x20
	BPF_JGE   = 0x30
	BPF_JSET  = 0x40

	BPF_K     = 0x00
	BPF_X     = 0x08
	BPF_A     = 0x10

	BPF_ADD   = 0x00
	BPF_SUB   = 0x10
	BPF_MUL   = 0x20
	BPF_DIV   = 0x30
	BPF_OR    = 0x40
	BPF_AND   = 0x50
	BPF_LSH   = 0x60
	BPF_RSH   = 0x70
	BPF_NEG   = 0x80
	BPF_MOD   = 0x90
	BPF_XOR   = 0xa0

	BPF_RET_K = 0x00
	BPF_RET_A = 0x10
)

func GenerateGOOSEBPF() *BPFProgram {
	return &BPFProgram{
		Instructions: []BPFInstruction{
			{BPF_LD | BPF_H | BPF_ABS, 0, 0, 12},
			{BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0x88B8},
			{BPF_LD | BPF_W | BPF_ABS, 0, 0, 0},
			{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x010CCD0C},
			{BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF},
			{BPF_RET | BPF_K, 0, 0, 0},
		},
	}
}

func OptimizedBPFString() string {
	return "(ether[0:3] = 0x010ccd and ether proto 0x88b8)"
}
