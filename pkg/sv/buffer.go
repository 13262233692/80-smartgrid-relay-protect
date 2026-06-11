package sv

import (
	"math"
	"sync"
	"time"
)

const (
	DefaultSampleRate = 4000
	DefaultSamplesPerCycle = 80
	DefaultBufferCycles     = 5
	DefaultBufferSize       = DefaultSamplesPerCycle * DefaultBufferCycles
)

func NewChannelBuffer(name string, sampleRate int) *ChannelBuffer {
	samplesPerCycle := sampleRate / 50
	bufferSize := samplesPerCycle * DefaultBufferCycles
	return &ChannelBuffer{
		Name:       name,
		Buffer:     make([]float64, bufferSize),
		BufferSize: bufferSize,
		SampleRate: sampleRate,
	}
}

func (cb *ChannelBuffer) Push(value float64) {
	cb.Buffer[cb.WriteIndex] = value
	cb.WriteIndex = (cb.WriteIndex + 1) % cb.BufferSize
	if cb.WriteIndex == 0 {
		cb.Full = true
	}
}

func (cb *ChannelBuffer) GetLastN(n int) []float64 {
	if n > cb.BufferSize {
		n = cb.BufferSize
	}

	result := make([]float64, n)
	start := (cb.WriteIndex - n + cb.BufferSize) % cb.BufferSize

	for i := 0; i < n; i++ {
		result[i] = cb.Buffer[(start+i)%cb.BufferSize]
	}

	return result
}

func (cb *ChannelBuffer) AvailableSamples() int {
	if cb.Full {
		return cb.BufferSize
	}
	return cb.WriteIndex
}

func (cb *ChannelBuffer) SamplesPerCycle() int {
	return cb.SampleRate / 50
}

func (cb *ChannelBuffer) Reset() {
	cb.WriteIndex = 0
	cb.ReadIndex = 0
	cb.Full = false
	for i := range cb.Buffer {
		cb.Buffer[i] = 0
	}
}

type SampleBufferPool struct {
	buffers map[string]*ChannelBuffer
	mu      sync.RWMutex
}

func NewSampleBufferPool() *SampleBufferPool {
	return &SampleBufferPool{
		buffers: make(map[string]*ChannelBuffer),
	}
}

func (pool *SampleBufferPool) GetOrCreate(name string, sampleRate int) *ChannelBuffer {
	pool.mu.RLock()
	if buf, ok := pool.buffers[name]; ok {
		pool.mu.RUnlock()
		return buf
	}
	pool.mu.RUnlock()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	if buf, ok := pool.buffers[name]; ok {
		return buf
	}

	buf := NewChannelBuffer(name, sampleRate)
	pool.buffers[name] = buf
	return buf
}

func (pool *SampleBufferPool) Get(name string) (*ChannelBuffer, bool) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	buf, ok := pool.buffers[name]
	return buf, ok
}

func (pool *SampleBufferPool) List() []string {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	names := make([]string, 0, len(pool.buffers))
	for k := range pool.buffers {
		names = append(names, k)
	}
	return names
}

func CalcZeroSequenceCurrent(Ia, Ib, Ic float64) float64 {
	return (Ia + Ib + Ic) / 3.0
}

type DFTProcessor struct {
	SampleRate    int
	SamplesPerCycle int
	cosTable      []float64
	sinTable      []float64
}

func NewDFTProcessor(sampleRate int) *DFTProcessor {
	spc := sampleRate / 50
	d := &DFTProcessor{
		SampleRate:      sampleRate,
		SamplesPerCycle: spc,
	}
	d.buildTables()
	return d
}

func (d *DFTProcessor) buildTables() {
	d.cosTable = make([]float64, d.SamplesPerCycle)
	d.sinTable = make([]float64, d.SamplesPerCycle)

	for i := 0; i < d.SamplesPerCycle; i++ {
		angle := 2.0 * math.Pi * float64(i) / float64(d.SamplesPerCycle)
		d.cosTable[i] = math.Cos(angle)
		d.sinTable[i] = math.Sin(angle)
	}
}

func (d *DFTProcessor) ComputePhasor(samples []float64) Phasor {
	n := d.SamplesPerCycle
	if len(samples) < n {
		return Phasor{}
	}

	var realPart, imagPart float64

	for k := 0; k < n; k++ {
		realPart += samples[k] * d.cosTable[k]
		imagPart += samples[k] * d.sinTable[k]
	}

	realPart *= 2.0 / float64(n)
	imagPart *= -2.0 / float64(n)

	return NewPhasor(realPart, imagPart)
}

func trapezoidalCorrection(samples []float64, table []float64, directSum float64, n float64) float64 {
	if len(samples) < 2 {
		return directSum
	}

	var trapSum float64
	for k := 0; k < len(samples)-1; k++ {
		avgSample := (samples[k] + samples[k+1]) / 2.0
		trapSum += avgSample * table[k]
	}

	return trapSum * 2.0 / n
}

func (d *DFTProcessor) ComputePhasorFromBuffer(buf *ChannelBuffer) Phasor {
	n := d.SamplesPerCycle
	if buf.AvailableSamples() < n {
		return Phasor{}
	}
	samples := buf.GetLastN(n)
	return d.ComputePhasor(samples)
}

type ZeroSequenceProcessor struct {
	BufferIa   *ChannelBuffer
	BufferIb   *ChannelBuffer
	BufferIc   *ChannelBuffer
	BufferI0   *ChannelBuffer
	DFT        *DFTProcessor
	LastPhasor Phasor
	LastUpdate time.Time
	mu         sync.Mutex
}

func NewZeroSequenceProcessor(name string, sampleRate int) *ZeroSequenceProcessor {
	prefix := name + "_"
	return &ZeroSequenceProcessor{
		BufferIa: NewChannelBuffer(prefix+"Ia", sampleRate),
		BufferIb: NewChannelBuffer(prefix+"Ib", sampleRate),
		BufferIc: NewChannelBuffer(prefix+"Ic", sampleRate),
		BufferI0: NewChannelBuffer(prefix+"I0", sampleRate),
		DFT:      NewDFTProcessor(sampleRate),
	}
}

func (z *ZeroSequenceProcessor) PushSamples(Ia, Ib, Ic float64) {
	z.mu.Lock()
	defer z.mu.Unlock()

	z.BufferIa.Push(Ia)
	z.BufferIb.Push(Ib)
	z.BufferIc.Push(Ic)

	I0 := CalcZeroSequenceCurrent(Ia, Ib, Ic)
	z.BufferI0.Push(I0)

	if z.BufferI0.AvailableSamples() >= z.DFT.SamplesPerCycle {
		z.LastPhasor = z.DFT.ComputePhasorFromBuffer(z.BufferI0)
		z.LastUpdate = time.Now()
	}
}

func (z *ZeroSequenceProcessor) GetI0Phasor() Phasor {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.LastPhasor
}

func (z *ZeroSequenceProcessor) GetI0RMS() float64 {
	return z.GetI0Phasor().Mag / math.Sqrt2
}

func (z *ZeroSequenceProcessor) Ready() bool {
	return z.BufferI0.AvailableSamples() >= z.DFT.SamplesPerCycle
}

type ThreePhaseSample struct {
	Ts time.Time
	Ia float64
	Ib float64
	Ic float64
	Ua float64
	Ub float64
	Uc float64
}

type ThreePhaseBuffer struct {
	Samples []ThreePhaseSample
	Size    int
	Head    int
	Count   int
	mu      sync.Mutex
}

func NewThreePhaseBuffer(size int) *ThreePhaseBuffer {
	return &ThreePhaseBuffer{
		Samples: make([]ThreePhaseSample, size),
		Size:    size,
	}
}

func (tb *ThreePhaseBuffer) Push(sample ThreePhaseSample) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.Samples[tb.Head] = sample
	tb.Head = (tb.Head + 1) % tb.Size
	if tb.Count < tb.Size {
		tb.Count++
	}
}

func (tb *ThreePhaseBuffer) GetLastN(n int) []ThreePhaseSample {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if n > tb.Count {
		n = tb.Count
	}

	result := make([]ThreePhaseSample, n)
	start := (tb.Head - n + tb.Size) % tb.Size

	for i := 0; i < n; i++ {
		result[i] = tb.Samples[(start+i)%tb.Size]
	}

	return result
}
