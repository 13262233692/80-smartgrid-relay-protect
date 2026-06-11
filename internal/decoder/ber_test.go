package decoder

import (
	"testing"
)

func TestParseBER_Boolean(t *testing.T) {
	data := []byte{0x01, 0x01, 0xFF}

	ber, err := ParseBER(data)
	if err != nil {
		t.Fatalf("ParseBER failed: %v", err)
	}

	if ber.TagNum != TagBoolean {
		t.Errorf("Expected tag %d (Boolean), got %d", TagBoolean, ber.TagNum)
	}

	if ber.Length != 1 {
		t.Errorf("Expected length 1, got %d", ber.Length)
	}

	if len(ber.Data) != 1 || ber.Data[0] != 0xFF {
		t.Errorf("Expected data [0xFF], got %v", ber.Data)
	}
}

func TestParseBER_Integer(t *testing.T) {
	data := []byte{0x02, 0x02, 0x01, 0x00}

	ber, err := ParseBER(data)
	if err != nil {
		t.Fatalf("ParseBER failed: %v", err)
	}

	if ber.TagNum != TagInteger {
		t.Errorf("Expected tag %d (Integer), got %d", TagInteger, ber.TagNum)
	}

	if ber.Length != 2 {
		t.Errorf("Expected length 2, got %d", ber.Length)
	}
}

func TestParseBER_Sequence(t *testing.T) {
	data := []byte{0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x05}

	ber, err := ParseBER(data)
	if err != nil {
		t.Fatalf("ParseBER failed: %v", err)
	}

	if ber.TagNum != TagSequence {
		t.Errorf("Expected tag %d (Sequence), got %d", TagSequence, ber.TagNum)
	}

	if !ber.IsConstructed() {
		t.Error("Expected constructed bit set")
	}

	if ber.Length != 6 {
		t.Errorf("Expected length 6, got %d", ber.Length)
	}
}

func TestParseBER_LongForm(t *testing.T) {
	data := []byte{0x02, 0x82, 0x01, 0x00}
	for i := 0; i < 256; i++ {
		data = append(data, 0x00)
	}

	ber, err := ParseBER(data)
	if err != nil {
		t.Fatalf("ParseBER failed: %v", err)
	}

	if ber.Length != 256 {
		t.Errorf("Expected length 256, got %d", ber.Length)
	}
}

func TestParseBER_ContextSpecific(t *testing.T) {
	data := []byte{0x80, 0x03, 0x66, 0x6F, 0x6F}

	ber, err := ParseBER(data)
	if err != nil {
		t.Fatalf("ParseBER failed: %v", err)
	}

	if !ber.IsContextSpecific(0) {
		t.Error("Expected context-specific tag [0]")
	}

	if ber.Length != 3 {
		t.Errorf("Expected length 3, got %d", ber.Length)
	}
}

func TestDecodeBoolean(t *testing.T) {
	tests := []struct {
		input    []byte
		expected bool
	}{
		{[]byte{0x01, 0x01, 0xFF}, true},
		{[]byte{0x01, 0x01, 0x01}, true},
		{[]byte{0x01, 0x01, 0x00}, false},
	}

	for i, tt := range tests {
		result, err := DecodeBoolean(tt.input)
		if err != nil {
			t.Errorf("Test case %d: unexpected error: %v", i, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("Test case %d: expected %v, got %v", i, tt.expected, result)
		}
	}
}

func TestDecodeInteger(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int64
	}{
		{[]byte{0x02, 0x01, 0x00}, 0},
		{[]byte{0x02, 0x01, 0x01}, 1},
		{[]byte{0x02, 0x01, 0x7F}, 127},
		{[]byte{0x02, 0x02, 0x00, 0xFF}, 255},
		{[]byte{0x02, 0x01, 0xFF}, -1},
		{[]byte{0x02, 0x02, 0xFF, 0xFE}, -2},
	}

	for i, tt := range tests {
		result, err := DecodeInteger(tt.input)
		if err != nil {
			t.Errorf("Test case %d: unexpected error: %v", i, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("Test case %d: expected %d, got %d", i, tt.expected, result)
		}
	}
}

func TestDecodeBitString(t *testing.T) {
	data := []byte{0x03, 0x03, 0x05, 0xFA, 0xA0}

	bytes, bits, err := DecodeBitString(data)
	if err != nil {
		t.Fatalf("DecodeBitString failed: %v", err)
	}

	if bits != 11 {
		t.Errorf("Expected 11 bits, got %d", bits)
	}

	if len(bytes) != 2 {
		t.Errorf("Expected 2 bytes, got %d", len(bytes))
	}
}

func TestDecodeOctetString(t *testing.T) {
	data := []byte{0x04, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F}

	result, err := DecodeOctetString(data)
	if err != nil {
		t.Fatalf("DecodeOctetString failed: %v", err)
	}

	if string(result) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(result))
	}
}

func TestBERIterator(t *testing.T) {
	data := []byte{
		0x01, 0x01, 0xFF,
		0x02, 0x01, 0x05,
		0x04, 0x03, 0x61, 0x62, 0x63,
	}

	it := NewBERIterator(data)

	count := 0
	for it.HasMore() {
		ber, err := it.Next()
		if err != nil {
			t.Fatalf("Iterator Next failed: %v", err)
		}
		if ber == nil {
			break
		}
		count++
	}

	if count != 3 {
		t.Errorf("Expected 3 elements, got %d", count)
	}
}

func TestDecodeSequence(t *testing.T) {
	data := []byte{
		0x30, 0x08,
		0x01, 0x01, 0xFF,
		0x02, 0x01, 0x05,
		0x04, 0x01, 0x61,
	}

	innerData, err := DecodeSequence(data)
	if err != nil {
		t.Fatalf("DecodeSequence failed: %v", err)
	}

	if len(innerData) != 8 {
		t.Errorf("Expected 8 bytes inner data, got %d", len(innerData))
	}
}

func TestGetElementLength(t *testing.T) {
	tests := []struct {
		input      []byte
		headerLen  int
		totalLen   int
		shouldFail bool
	}{
		{[]byte{0x01, 0x01, 0xFF}, 2, 3, false},
		{[]byte{0x02, 0x02, 0x01, 0x00}, 2, 4, false},
		{[]byte{0x30, 0x81, 0x0A}, 3, 13, false},
		{[]byte{0x00}, 0, 0, true},
	}

	for i, tt := range tests {
		headerLen, totalLen, err := GetElementLength(tt.input)

		if tt.shouldFail {
			if err == nil {
				t.Errorf("Test case %d: expected error, got nil", i)
			}
			continue
		}

		if err != nil {
			t.Errorf("Test case %d: unexpected error: %v", i, err)
			continue
		}

		if headerLen != tt.headerLen {
			t.Errorf("Test case %d: expected headerLen %d, got %d", i, tt.headerLen, headerLen)
		}

		if totalLen != tt.totalLen {
			t.Errorf("Test case %d: expected totalLen %d, got %d", i, tt.totalLen, totalLen)
		}
	}
}

func TestTruncatedData(t *testing.T) {
	tests := [][]byte{
		{0x01},
		{0x01, 0x05, 0x00},
		{},
	}

	for i, data := range tests {
		_, err := ParseBER(data)
		if err == nil {
			t.Errorf("Test case %d: expected error for truncated data", i)
		}
	}
}
