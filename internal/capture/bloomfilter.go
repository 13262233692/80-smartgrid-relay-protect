package capture

import (
	"encoding/binary"
	"math/bits"
	"sync"
)

type MACBloomFilter struct {
	bits    []uint64
	m       uint64
	k       uint64
	size    uint64
	mask    uint64
	mu      sync.RWMutex
}

func NewMACBloomFilter(expectedItems uint64, falsePositiveRate float64) *MACBloomFilter {
	m := calcOptimalM(expectedItems, falsePositiveRate)
	k := calcOptimalK(m, expectedItems)

	if m < 512 {
		m = 512
	}

	numUint64 := (m + 63) / 64
	actualM := numUint64 * 64

	return &MACBloomFilter{
		bits: make([]uint64, numUint64),
		m:    actualM,
		k:    k,
		size: 0,
		mask: actualM - 1,
	}
}

func calcOptimalM(n uint64, p float64) uint64 {
	if p <= 0 {
		p = 0.0001
	}
	numerator := float64(n) * 1.4426950408889634 * 3.3219280948873626
	m := uint64(numerator / 1.0)
	if m < 1024 {
		m = 1024
	}
	return m * 4
}

func calcOptimalK(m, n uint64) uint64 {
	if n == 0 {
		return 4
	}
	k := float64(m) / float64(n) * 0.6931471805599453
	if k < 3 {
		return 3
	}
	if k > 7 {
		return 7
	}
	return uint64(k)
}

func xxhash64(data []byte, seed uint64) uint64 {
	const (
		prime1 uint64 = 11400714785074694791
		prime2 uint64 = 14029467366897019727
		prime3 uint64 = 1609587929392839161
		prime4 uint64 = 9650029242287828579
		prime5 uint64 = 2870177450012600261
	)

	var h64 uint64
	n := len(data)

	if n >= 32 {
		v1 := seed + prime1 + prime2
		v2 := seed + prime2
		v3 := seed
		v4 := seed - prime1

		p := 0
		for n >= 32 {
			v1 = round(v1, binary.LittleEndian.Uint64(data[p:p+8]))
			v2 = round(v2, binary.LittleEndian.Uint64(data[p+8:p+16]))
			v3 = round(v3, binary.LittleEndian.Uint64(data[p+16:p+24]))
			v4 = round(v4, binary.LittleEndian.Uint64(data[p+24:p+32]))
			p += 32
			n -= 32
		}

		h64 = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)
		h64 = mergeRound(h64, v1)
		h64 = mergeRound(h64, v2)
		h64 = mergeRound(h64, v3)
		h64 = mergeRound(h64, v4)
	} else {
		h64 = seed + prime5
	}

	h64 += uint64(len(data))

	p := len(data) - n
	for n >= 8 {
		k1 := round(0, binary.LittleEndian.Uint64(data[p:p+8]))
		h64 ^= k1
		h64 = rotl(h64, 27)*prime1 + prime4
		p += 8
		n -= 8
	}

	if n >= 4 {
		h64 ^= uint64(binary.LittleEndian.Uint32(data[p:p+4])) * prime1
		h64 = rotl(h64, 23)*prime2 + prime3
		p += 4
		n -= 4
	}

	for n > 0 {
		h64 ^= uint64(data[p]) * prime5
		h64 = rotl(h64, 11) * prime1
		p++
		n--
	}

	h64 ^= h64 >> 33
	h64 *= prime2
	h64 ^= h64 >> 29
	h64 *= prime3
	h64 ^= h64 >> 32

	return h64
}

func round(acc, input uint64) uint64 {
	acc += input * 14029467366897019727
	acc = rotl(acc, 31)
	acc *= 11400714785074694791
	return acc
}

func mergeRound(acc, val uint64) uint64 {
	val = round(0, val)
	acc ^= val
	acc = acc*11400714785074694791 + 9650029242287828579
	return acc
}

func rotl(x uint64, r uint) uint64 {
	return (x << r) | (x >> (64 - r))
}

func (bf *MACBloomFilter) Add(mac []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	h1 := xxhash64(mac, 0x9E3779B97F4A7C15)
	h2 := xxhash64(mac, h1^0x85EBCA6B7C997627)

	for i := uint64(0); i < bf.k; i++ {
		h := h1 + i*h2
		pos := h % bf.m
		bf.bits[pos>>6] |= 1 << (pos & 63)
	}
	bf.size++
}

func (bf *MACBloomFilter) Test(mac []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	h1 := xxhash64(mac, 0x9E3779B97F4A7C15)
	h2 := xxhash64(mac, h1^0x85EBCA6B7C997627)

	for i := uint64(0); i < bf.k; i++ {
		h := h1 + i*h2
		pos := h % bf.m
		if bf.bits[pos>>6]&(1<<(pos&63)) == 0 {
			return false
		}
	}
	return true
}

func (bf *MACBloomFilter) TestFast(mac []byte, bitsCopy []uint64) bool {
	h1 := xxhash64(mac, 0x9E3779B97F4A7C15)
	h2 := xxhash64(mac, h1^0x85EBCA6B7C997627)

	m := bf.m
	k := bf.k

	for i := uint64(0); i < k; i++ {
		h := h1 + i*h2
		pos := h % m
		if bitsCopy[pos>>6]&(1<<(pos&63)) == 0 {
			return false
		}
	}
	return true
}

func (bf *MACBloomFilter) BitsSnapshot() []uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	snapshot := make([]uint64, len(bf.bits))
	copy(snapshot, bf.bits)
	return snapshot
}

func (bf *MACBloomFilter) Clear() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.size = 0
}

func (bf *MACBloomFilter) Count() uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.size
}

func (bf *MACBloomFilter) EstimatedFalsePositiveRate() float64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	setBits := 0
	for _, w := range bf.bits {
		setBits += bits.OnesCount64(w)
	}

	m := float64(bf.m)
	k := float64(bf.k)

	prob := 1.0
	for i := 0.0; i < k; i++ {
		prob *= 1.0 - float64(setBits)/m
	}

	return 1.0 - prob
}

type MACExactFilter struct {
	macs    map[uint64]struct{}
	bloom   *MACBloomFilter
	mu      sync.RWMutex
}

func NewMACExactFilter(expectedItems int) *MACExactFilter {
	if expectedItems < 100 {
		expectedItems = 100
	}
	return &MACExactFilter{
		macs:  make(map[uint64]struct{}, expectedItems),
		bloom: NewMACBloomFilter(uint64(expectedItems), 0.0001),
	}
}

func MACToUint64(mac []byte) uint64 {
	if len(mac) < 6 {
		return 0
	}
	return binary.BigEndian.Uint64(append([]byte{0, 0}, mac...))
}

func (f *MACExactFilter) Add(mac []byte) {
	key := MACToUint64(mac)
	f.mu.Lock()
	f.macs[key] = struct{}{}
	f.bloom.Add(mac)
	f.mu.Unlock()
}

func (f *MACExactFilter) Contains(mac []byte) bool {
	if !f.bloom.Test(mac) {
		return false
	}

	key := MACToUint64(mac)
	f.mu.RLock()
	_, exists := f.macs[key]
	f.mu.RUnlock()
	return exists
}

func (f *MACExactFilter) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.macs)
}

func (f *MACExactFilter) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k := range f.macs {
		delete(f.macs, k)
	}
	f.bloom.Clear()
}

func (f *MACExactFilter) Bloom() *MACBloomFilter {
	return f.bloom
}

func IsGOOSEMulticastMAC(mac []byte) bool {
	if len(mac) < 6 {
		return false
	}
	return mac[0] == 0x01 && mac[1] == 0x0C && mac[2] == 0xCD
}

func GOOSEMACGroup(mac []byte) uint8 {
	if len(mac) < 6 {
		return 0
	}
	return mac[3]
}
