package capture

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func generateGOOSEPacket(dstMAC []byte, srcMAC []byte) []byte {
	packet := make([]byte, 128)
	copy(packet[0:6], dstMAC)
	copy(packet[6:12], srcMAC)
	packet[12] = 0x88
	packet[13] = 0xB8
	return packet
}

func generateRandomMAC() []byte {
	mac := make([]byte, 6)
	for i := 0; i < 6; i++ {
		mac[i] = byte(rand.Intn(256))
	}
	return mac
}

func generateGOOSEMulticastMAC(group byte) []byte {
	mac := []byte{0x01, 0x0C, 0xCD, group,
		byte(rand.Intn(256)), byte(rand.Intn(256))}
	return mac
}

func generateNonGOOSEMAC() []byte {
	mac := make([]byte, 6)
	mac[0] = 0x00
	mac[1] = byte(rand.Intn(256))
	mac[2] = byte(rand.Intn(256))
	mac[3] = byte(rand.Intn(256))
	mac[4] = byte(rand.Intn(256))
	mac[5] = byte(rand.Intn(256))
	return mac
}

func BenchmarkBloomFilter_Add(b *testing.B) {
	bf := NewMACBloomFilter(1000, 0.0001)
	macs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		macs[i] = generateGOOSEMulticastMAC(byte(i % 256))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Add(macs[i])
	}
}

func BenchmarkBloomFilter_Test(b *testing.B) {
	bf := NewMACBloomFilter(1000, 0.0001)
	for i := 0; i < 500; i++ {
		bf.Add(generateGOOSEMulticastMAC(byte(i % 256)))
	}
	bits := bf.BitsSnapshot()
	macs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			macs[i] = generateGOOSEMulticastMAC(byte((i / 2) % 500))
		} else {
			macs[i] = generateNonGOOSEMAC()
		}
	}

	b.ResetTimer()
	hits := 0
	for i := 0; i < b.N; i++ {
		if bf.TestFast(macs[i], bits) {
			hits++
		}
	}
	b.ReportMetric(float64(hits)/float64(b.N), "hits/op")
}

func BenchmarkIsGOOSEPacket(b *testing.B) {
	packets := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			packets[i] = generateGOOSEPacket(
				generateGOOSEMulticastMAC(byte(i%256)),
				generateRandomMAC())
		} else {
			packets[i] = generateGOOSEPacket(
				generateNonGOOSEMAC(),
				generateRandomMAC())
			packets[i][12] = 0x08
			packets[i][13] = 0x00
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsGOOSEPacket(packets[i])
	}
}

func BenchmarkFastPreFilter(b *testing.B) {
	capture := &HighPerfGOOSECapture{
		useBloom: false,
	}

	packets := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		if i%3 == 0 {
			packets[i] = generateGOOSEPacket(
				generateGOOSEMulticastMAC(byte(i%256)),
				generateRandomMAC())
		} else if i%3 == 1 {
			packets[i] = generateGOOSEPacket(
				generateNonGOOSEMAC(),
				generateRandomMAC())
		} else {
			packets[i] = generateGOOSEPacket(
				generateGOOSEMulticastMAC(byte(i%256)),
				generateRandomMAC())
			packets[i][12] = 0x08
			packets[i][13] = 0x00
		}
	}

	b.ResetTimer()
	hits := 0
	for i := 0; i < b.N; i++ {
		if capture.fastPreFilter(packets[i]) {
			hits++
		}
	}
	b.ReportMetric(float64(hits)/float64(b.N), "hits/op")
}

func BenchmarkFastPreFilter_WithBloom(b *testing.B) {
	filter := NewMACExactFilter(500)
	for i := 0; i < 500; i++ {
		mac := generateGOOSEMulticastMAC(byte(i))
		filter.Add(mac)
	}

	capture := &HighPerfGOOSECapture{
		useBloom:      true,
		macFilter:     filter,
		bloomSnapshot: filter.Bloom().BitsSnapshot(),
	}

	packets := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			mac := generateGOOSEMulticastMAC(byte(i % 500))
			packets[i] = generateGOOSEPacket(mac, generateRandomMAC())
		} else {
			mac := generateGOOSEMulticastMAC(0xFF)
			packets[i] = generateGOOSEPacket(mac, generateRandomMAC())
		}
	}

	b.ResetTimer()
	hits := 0
	for i := 0; i < b.N; i++ {
		if capture.fastPreFilter(packets[i]) {
			hits++
		}
	}
	b.ReportMetric(float64(hits)/float64(b.N), "hits/op")
}

func BenchmarkLockFreeRingBuffer_Enqueue(b *testing.B) {
	rb := NewLockFreeRingBuffer(16384)
	data := make([]byte, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Enqueue(data, int64(i))
	}
}

func BenchmarkLockFreeRingBuffer_Dequeue(b *testing.B) {
	rb := NewLockFreeRingBuffer(16384)
	data := make([]byte, 128)
	for i := 0; i < b.N; i++ {
		rb.Enqueue(data, int64(i))
	}

	buf := PacketBuffer{Data: make([]byte, 2048)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Dequeue(&buf)
	}
}

func BenchmarkSPSCQueue_EnqueueDequeue(b *testing.B) {
	q := NewSPSCLockFreeQueue(16384)
	data := make([]byte, 128)
	buf := PacketBuffer{Data: make([]byte, 2048)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Enqueue(data, int64(i))
		q.Dequeue(&buf)
	}
}

func TestBloomFilter_FalsePositiveRate(t *testing.T) {
	itemCount := 500
	bf := NewMACBloomFilter(uint64(itemCount), 0.0001)

	added := make(map[string]bool)
	for i := 0; i < itemCount; i++ {
		mac := []byte{0x01, 0x0C, 0xCD,
			byte(i >> 16 & 0xFF), byte(i >> 8 & 0xFF), byte(i & 0xFF)}
		bf.Add(mac)
		added[hex.EncodeToString(mac)] = true
	}

	falsePositives := 0
	trueNegatives := 0
	totalTests := 100000

	for i := 0; i < totalTests; i++ {
		idx := itemCount + 10000 + i
		mac := []byte{0x01, 0x0C, 0xCD,
			byte(idx >> 16 & 0xFF), byte(idx >> 8 & 0xFF), byte(idx & 0xFF)}
		macStr := hex.EncodeToString(mac)
		if added[macStr] {
			continue
		}
		if bf.Test(mac) {
			falsePositives++
		} else {
			trueNegatives++
		}
	}

	fpRate := float64(falsePositives) / float64(falsePositives+trueNegatives)
	t.Logf("False positive rate: %.6f (%d/%d)",
		fpRate, falsePositives, falsePositives+trueNegatives)
	t.Logf("Estimated FP rate: %.6f", bf.EstimatedFalsePositiveRate())

	if fpRate > 0.01 {
		t.Errorf("False positive rate too high: %.6f", fpRate)
	}
}

func TestMACExactFilter_Integration(t *testing.T) {
	filter := NewMACExactFilter(100)

	for i := 0; i < 50; i++ {
		mac := generateGOOSEMulticastMAC(byte(i))
		filter.Add(mac)
		if !filter.Contains(mac) {
			t.Errorf("Added MAC %x not found in filter", mac)
		}
	}

	for i := 50; i < 100; i++ {
		mac := generateGOOSEMulticastMAC(byte(i + 100))
		if filter.Contains(mac) {
			t.Logf("False positive for MAC %x (acceptable)", mac)
		}
	}

	t.Logf("Filter count: %d", filter.Count())
	t.Logf("Bloom estimated FP: %.6f", filter.Bloom().EstimatedFalsePositiveRate())
}

func TestNetworkStormSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network storm simulation in short mode")
	}

	filter := NewMACExactFilter(500)
	targetMACs := make([][]byte, 500)
	for i := 0; i < 500; i++ {
		mac := []byte{0x01, 0x0C, 0xCD,
			byte(i >> 16 & 0xFF), byte(i >> 8 & 0xFF), byte(i & 0xFF)}
		targetMACs[i] = mac
		filter.Add(mac)
	}

	capture := &HighPerfGOOSECapture{
		useBloom:      true,
		macFilter:     filter,
		bloomSnapshot: filter.Bloom().BitsSnapshot(),
	}

	totalPackets := 100000
	filtered := 0
	passed := 0

	noiseMACs := make([][]byte, 500)
	for i := 0; i < 500; i++ {
		idx := i + 100000
		mac := []byte{0x01, 0x0C, 0xCD,
			byte(idx >> 16 & 0xFF), byte(idx >> 8 & 0xFF), byte(idx & 0xFF)}
		noiseMACs[i] = mac
	}

	start := time.Now()
	for i := 0; i < totalPackets; i++ {
		var pkt []byte
		if i%2 == 0 {
			src := generateRandomMAC()
			dst := targetMACs[rand.Intn(500)]
			pkt = generateGOOSEPacket(dst, src)
		} else {
			src := generateRandomMAC()
			dst := noiseMACs[rand.Intn(500)]
			pkt = generateGOOSEPacket(dst, src)
		}

		if capture.fastPreFilter(pkt) {
			passed++
		} else {
			filtered++
		}
	}
	duration := time.Since(start)

	pps := float64(totalPackets) / duration.Seconds()
	t.Logf("Processed %d packets in %v", totalPackets, duration)
	t.Logf("Throughput: %.0f packets/sec", pps)
	t.Logf("Passed: %d (%.1f%%)", passed, float64(passed)/float64(totalPackets)*100)
	t.Logf("Filtered: %d (%.1f%%)", filtered, float64(filtered)/float64(totalPackets)*100)

	fmt.Printf("\n=== Network Storm Simulation Results ===\n")
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Total Packets: %d\n", totalPackets)
	fmt.Printf("Throughput: %.2f Mpps\n", pps/1000000)
	fmt.Printf("Bloom Filter FP Rate: %.6f\n", filter.Bloom().EstimatedFalsePositiveRate())
	fmt.Printf("========================================\n\n")
}

func TestConcurrentRingBuffer(t *testing.T) {
	rb := NewLockFreeRingBuffer(65536)

	producers := 4
	consumers := 2
	packetsPerProducer := 100000

	var wg sync.WaitGroup
	var produced uint64
	var consumed uint64

	start := time.Now()

	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := make([]byte, 128)
			for i := 0; i < packetsPerProducer; i++ {
				if rb.Enqueue(data, int64(i)) {
					atomic.AddUint64(&produced, 1)
				}
			}
		}(p)
	}

	bufs := make([]PacketBuffer, consumers)
	for c := 0; c < consumers; c++ {
		bufs[c].Data = make([]byte, 2048)
	}

	for c := 0; c < consumers; c++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for atomic.LoadUint64(&produced) < uint64(producers*packetsPerProducer) {
				if rb.Dequeue(&bufs[id]) {
					atomic.AddUint64(&consumed, 1)
				} else {
					runtime.Gosched()
				}
			}
			for rb.Dequeue(&bufs[id]) {
				atomic.AddUint64(&consumed, 1)
			}
		}(c)
	}

	wg.Wait()
	duration := time.Since(start)

	t.Logf("Duration: %v", duration)
	t.Logf("Produced: %d", produced)
	t.Logf("Consumed: %d", consumed)
	t.Logf("Dropped: %d", rb.Dropped())
	t.Logf("Throughput: %.0f ops/sec",
		float64(produced+consumed)/duration.Seconds())

	if produced == 0 {
		t.Error("No packets produced")
	}
}

func TestBPFBuilder(t *testing.T) {
	filter := OptimizedBPFString()
	t.Logf("Optimized BPF filter: %s", filter)

	if len(filter) == 0 {
		t.Error("Empty BPF filter")
	}

	simple := BuildGOOSEOnlyFilter()
	t.Logf("Simple GOOSE BPF filter: %s", simple)

	macs := []string{
		"01:0c:cd:01:00:01",
		"01:0c:cd:01:00:02",
	}
	withFilter := BuildGOOSEWithDstFilter(macs)
	t.Logf("GOOSE with MAC filter: %s", withFilter)
}
