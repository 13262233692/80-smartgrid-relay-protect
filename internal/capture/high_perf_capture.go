package capture

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	DefaultRingBufferSize = 16384
	DefaultBatchSize      = 256
)

type HighPerfGOOSECapture struct {
	handle         *pcap.Handle
	config         GOOSEConfig
	macFilter      *MACExactFilter
	bloomSnapshot  []uint64
	ringBuffer     *LockFreeRingBuffer
	batchBuffer    *PacketBatch
	packetChan     chan []byte
	stopChan       chan struct{}
	wg             sync.WaitGroup
	running        bool
	mu             sync.Mutex
	stats          CaptureStats
	bloomRefresh   time.Duration
	lastBloomCheck time.Time
	useBloom       bool
	useKernelBPF   bool
	batchHandler   func([]PacketBuffer)
}

type CaptureStats struct {
	PacketsReceived uint64
	PacketsFiltered uint64
	PacketsDropped  uint64
	PacketsQueued   uint64
	PacketsSent     uint64
	BloomRejects    uint64
	KernelRejects   uint64
	LastUpdate      time.Time
}

type HighPerfConfig struct {
	InterfaceName    string
	Promiscuous      bool
	SnapLen          int32
	RingBufferSize   int
	BatchSize        int
	UseBloomFilter   bool
	UseKernelBPF     bool
	ExpectedMACCount int
	BloomRefresh     time.Duration
	BPFFilter        string
	TargetMACs       [][]byte
	ChannelSize      int
}

func DefaultHighPerfConfig() HighPerfConfig {
	return HighPerfConfig{
		InterfaceName:    "eth0",
		Promiscuous:      true,
		SnapLen:          65535,
		RingBufferSize:   DefaultRingBufferSize,
		BatchSize:        DefaultBatchSize,
		UseBloomFilter:   true,
		UseKernelBPF:     true,
		ExpectedMACCount: 1000,
		BloomRefresh:     100 * time.Millisecond,
		BPFFilter:        "",
		TargetMACs:       nil,
		ChannelSize:      4096,
	}
}

func NewHighPerfGOOSECapture(config HighPerfConfig) (*HighPerfGOOSECapture, error) {
	if config.SnapLen == 0 {
		config.SnapLen = 65535
	}
	if config.RingBufferSize == 0 {
		config.RingBufferSize = DefaultRingBufferSize
	}
	if config.BloomRefresh == 0 {
		config.BloomRefresh = 100 * time.Millisecond
	}

	capture := &HighPerfGOOSECapture{
		config: GOOSEConfig{
			InterfaceName: config.InterfaceName,
			Promiscuous:   config.Promiscuous,
			SnapLen:       config.SnapLen,
			BufferSize:    config.ChannelSize,
			BPFFilter:     config.BPFFilter,
		},
		macFilter:    NewMACExactFilter(config.ExpectedMACCount),
		ringBuffer:   NewLockFreeRingBuffer(config.RingBufferSize),
		batchBuffer:  NewPacketBatch(),
		bloomRefresh: config.BloomRefresh,
		useBloom:     config.UseBloomFilter,
		useKernelBPF: config.UseKernelBPF,
		stopChan:     make(chan struct{}),
	}

	if config.ChannelSize > 0 {
		capture.packetChan = make(chan []byte, config.ChannelSize)
	}

	for _, mac := range config.TargetMACs {
		capture.AddTargetMAC(mac)
	}

	return capture, nil
}

func (c *HighPerfGOOSECapture) AddTargetMAC(mac []byte) {
	if len(mac) != 6 {
		return
	}
	c.macFilter.Add(mac)
	c.refreshBloomSnapshot()
}

func (c *HighPerfGOOSECapture) refreshBloomSnapshot() {
	c.bloomSnapshot = c.macFilter.Bloom().BitsSnapshot()
	c.lastBloomCheck = time.Now()
}

func (c *HighPerfGOOSECapture) buildBPFFilter() string {
	if c.config.BPFFilter != "" {
		return c.config.BPFFilter
	}

	macCount := c.macFilter.Count()
	if macCount > 0 && macCount <= 32 && c.useKernelBPF {
		return BuildGOOSEOnlyFilter()
	}

	return OptimizedBPFString()
}

func (c *HighPerfGOOSECapture) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("capture already running")
	}

	inactive, err := pcap.NewInactiveHandle(c.config.InterfaceName)
	if err != nil {
		return fmt.Errorf("create inactive handle failed: %w", err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetSnapLen(int(c.config.SnapLen)); err != nil {
		return fmt.Errorf("set snaplen failed: %w", err)
	}

	if err = inactive.SetPromisc(c.config.Promiscuous); err != nil {
		return fmt.Errorf("set promiscuous failed: %w", err)
	}

	if err = inactive.SetTimeout(time.Millisecond * 1); err != nil {
		return fmt.Errorf("set timeout failed: %w", err)
	}

	if err = inactive.SetBufferSize(32 * 1024 * 1024); err != nil {
		return fmt.Errorf("set buffer size failed: %w", err)
	}

	if err = inactive.SetImmediateMode(true); err != nil {
	}

	handle, err := inactive.Activate()
	if err != nil {
		return fmt.Errorf("activate handle failed: %w", err)
	}

	bpfFilter := c.buildBPFFilter()
	if err = handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return fmt.Errorf("set BPF filter failed: %w", err)
	}

	c.handle = handle
	c.running = true

	c.refreshBloomSnapshot()

	c.wg.Add(1)
	go c.captureLoop()

	c.wg.Add(1)
	go c.dispatchLoop()

	return nil
}

func (c *HighPerfGOOSECapture) captureLoop() {
	defer c.wg.Done()

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packetSource.NoCopy = true
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	lastBloomRefresh := time.Now()

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			select {
			case <-c.stopChan:
				return
			default:
				continue
			}
		}

		atomic.AddUint64(&c.stats.PacketsReceived, 1)

		rawData := packet.Data()

		if !c.fastPreFilter(rawData) {
			atomic.AddUint64(&c.stats.PacketsFiltered, 1)
			continue
		}

		if !c.ringBuffer.Enqueue(rawData, 0) {
			atomic.AddUint64(&c.stats.PacketsDropped, 1)
			continue
		}

		atomic.AddUint64(&c.stats.PacketsQueued, 1)

		if time.Since(lastBloomRefresh) > c.bloomRefresh {
			c.refreshBloomSnapshot()
			lastBloomRefresh = time.Now()
		}
	}
}

func (c *HighPerfGOOSECapture) fastPreFilter(data []byte) bool {
	if len(data) < 14 {
		return false
	}

	if data[12] != 0x88 || data[13] != 0xB8 {
		return false
	}

	if data[0] != 0x01 || data[1] != 0x0C || data[2] != 0xCD {
		return false
	}

	if c.useBloom && len(c.bloomSnapshot) > 0 {
		dstMAC := data[0:6]
		if !c.macFilter.Bloom().TestFast(dstMAC, c.bloomSnapshot) {
			atomic.AddUint64(&c.stats.BloomRejects, 1)
			return false
		}
	}

	return true
}

func (c *HighPerfGOOSECapture) dispatchLoop() {
	defer c.wg.Done()

	batchBufs := make([]PacketBuffer, DefaultBatchSize)
	for i := range batchBufs {
		batchBufs[i].Data = make([]byte, 2048)
	}

	ticker := time.NewTicker(500 * time.Microsecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return

		case <-ticker.C:
			c.dispatchBatch(batchBufs)
		}
	}
}

func (c *HighPerfGOOSECapture) dispatchBatch(bufs []PacketBuffer) {
	count := c.ringBuffer.DequeueBatch(bufs)
	if count == 0 {
		return
	}

	for i := 0; i < count; i++ {
		pkt := &bufs[i]
		dataCopy := make([]byte, pkt.Length)
		copy(dataCopy, pkt.Data[:pkt.Length])

		select {
		case c.packetChan <- dataCopy:
			atomic.AddUint64(&c.stats.PacketsSent, 1)
		default:
			atomic.AddUint64(&c.stats.PacketsDropped, 1)
		}
	}
}

func (c *HighPerfGOOSECapture) SetBatchHandler(handler func([]PacketBuffer)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batchHandler = handler
}

func (c *HighPerfGOOSECapture) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	close(c.stopChan)
	c.running = false

	if c.handle != nil {
		c.handle.Close()
		c.handle = nil
	}

	c.wg.Wait()
}

func (c *HighPerfGOOSECapture) PacketChan() <-chan []byte {
	return c.packetChan
}

func (c *HighPerfGOOSECapture) GetStats() CaptureStats {
	return CaptureStats{
		PacketsReceived: atomic.LoadUint64(&c.stats.PacketsReceived),
		PacketsFiltered: atomic.LoadUint64(&c.stats.PacketsFiltered),
		PacketsDropped:  atomic.LoadUint64(&c.stats.PacketsDropped),
		PacketsQueued:   atomic.LoadUint64(&c.stats.PacketsQueued),
		PacketsSent:     atomic.LoadUint64(&c.stats.PacketsSent),
		BloomRejects:    atomic.LoadUint64(&c.stats.BloomRejects),
		KernelRejects:   atomic.LoadUint64(&c.stats.KernelRejects),
		LastUpdate:      time.Now(),
	}
}

func (c *HighPerfGOOSECapture) RingBufferStats() (size, capacity int, dropped, processed uint64) {
	size = c.ringBuffer.Size()
	capacity = c.ringBuffer.Capacity()
	dropped = c.ringBuffer.Dropped()
	processed = c.ringBuffer.Processed()
	return
}

func (c *HighPerfGOOSECapture) GetMACFilterCount() int {
	return c.macFilter.Count()
}

func (c *HighPerfGOOSECapture) EstimatedFalsePositiveRate() float64 {
	return c.macFilter.Bloom().EstimatedFalsePositiveRate()
}
