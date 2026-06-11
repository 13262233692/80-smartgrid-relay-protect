package capture

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartgrid/relay-protect/pkg/sv"
)

type SVCaptureConfig struct {
	InterfaceName    string
	Promiscuous      bool
	SnapLen          int32
	BufferSize       int
	UseBPF           bool
	UseBloom         bool
	MACFilterList    []string
	ChannelScale     float64
	HandleSV         func(data *sv.SVData)
}

type SVCaptureStats struct {
	PacketsReceived  uint64
	PacketsParsed    uint64
	PacketsDropped   uint64
	BPFRejects       uint64
	BloomRejects     uint64
	ParseErrors      uint64
	LastUpdate       time.Time
	mu               sync.Mutex
}

type HighPerfSVCapture struct {
	config           SVCaptureConfig
	stats            SVCaptureStats
	macFilter        *MACExactFilter
	bloomSnapshot    []uint64
	running          int32
	stopChan         chan struct{}
	mu               sync.Mutex
}

func DefaultSVCaptureConfig() SVCaptureConfig {
	return SVCaptureConfig{
		InterfaceName: "eth0",
		Promiscuous:   true,
		SnapLen:       65535,
		BufferSize:    32 * 1024 * 1024,
		UseBPF:        true,
		UseBloom:      true,
		ChannelScale:  0.001,
	}
}

func NewHighPerfSVCapture(cfg SVCaptureConfig) (*HighPerfSVCapture, error) {
	c := &HighPerfSVCapture{
		config:   cfg,
		stopChan: make(chan struct{}),
	}

	if cfg.UseBloom && len(cfg.MACFilterList) > 0 {
		filter := NewMACExactFilter(len(cfg.MACFilterList) * 2)
		for _, macStr := range cfg.MACFilterList {
			if mac := parseMACAddress(macStr); len(mac) == 6 {
				filter.Add(mac)
			}
		}
		c.macFilter = filter
		c.bloomSnapshot = filter.Bloom().BitsSnapshot()
	}

	return c, nil
}

func parseMACAddress(s string) []byte {
	mac := make([]byte, 6)
	n, _ := fmt.Sscanf(s, "%x:%x:%x:%x:%x:%x",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])
	if n == 6 {
		return mac
	}
	n, _ = fmt.Sscanf(s, "%x-%x-%x-%x-%x-%x",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])
	if n == 6 {
		return mac
	}
	return nil
}

func (c *HighPerfSVCapture) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if atomic.LoadInt32(&c.running) == 1 {
		return fmt.Errorf("SV capture already running")
	}

	atomic.StoreInt32(&c.running, 1)
	return nil
}

func (c *HighPerfSVCapture) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if atomic.CompareAndSwapInt32(&c.running, 1, 0) {
		close(c.stopChan)
	}
}

func (c *HighPerfSVCapture) IsRunning() bool {
	return atomic.LoadInt32(&c.running) == 1
}

func (c *HighPerfSVCapture) FastPreFilter(data []byte) bool {
	if len(data) < 14 {
		return false
	}

	if data[12] != 0x88 || data[13] != 0xBA {
		return false
	}

	if data[0] != 0x01 || data[1] != 0x0C || data[2] != 0xCD {
		return false
	}

	if c.config.UseBloom && c.macFilter != nil && len(c.bloomSnapshot) > 0 {
		dstMAC := data[0:6]
		if !c.macFilter.Bloom().TestFast(dstMAC, c.bloomSnapshot) {
			atomic.AddUint64(&c.stats.BloomRejects, 1)
			return false
		}
	}

	return true
}

func (c *HighPerfSVCapture) ProcessPacket(data []byte) {
	atomic.AddUint64(&c.stats.PacketsReceived, 1)

	if !c.FastPreFilter(data) {
		atomic.AddUint64(&c.stats.PacketsDropped, 1)
		return
	}

	svData, err := sv.ParseSV(data)
	if err != nil {
		atomic.AddUint64(&c.stats.ParseErrors, 1)
		return
	}

	atomic.AddUint64(&c.stats.PacketsParsed, 1)

	c.stats.mu.Lock()
	c.stats.LastUpdate = time.Now()
	c.stats.mu.Unlock()

	if c.config.HandleSV != nil {
		c.config.HandleSV(svData)
	}
}

func (c *HighPerfSVCapture) GetStats() SVCaptureStats {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	return SVCaptureStats{
		PacketsReceived: atomic.LoadUint64(&c.stats.PacketsReceived),
		PacketsParsed:   atomic.LoadUint64(&c.stats.PacketsParsed),
		PacketsDropped:  atomic.LoadUint64(&c.stats.PacketsDropped),
		BPFRejects:      atomic.LoadUint64(&c.stats.BPFRejects),
		BloomRejects:    atomic.LoadUint64(&c.stats.BloomRejects),
		ParseErrors:     atomic.LoadUint64(&c.stats.ParseErrors),
		LastUpdate:      c.stats.LastUpdate,
	}
}

func BuildSVBPFFilter() string {
	return BuildGOOSEOnlyFilter()
}

func OptimizedSVBPFString() string {
	return "(ether[0:3] = 0x010ccd and ether proto 0x88ba)"
}

type SVNetworkSimulator struct {
	capture       *HighPerfSVCapture
	packetRate    int
	running       bool
	stopChan      chan struct{}
	mu            sync.Mutex
}

func NewSVNetworkSimulator(capture *HighPerfSVCapture, packetRate int) *SVNetworkSimulator {
	return &SVNetworkSimulator{
		capture:    capture,
		packetRate: packetRate,
		stopChan:   make(chan struct{}),
	}
}

func (sim *SVNetworkSimulator) GeneratePacket(idx int, svid string, smpCnt uint16) []byte {
	frame := make([]byte, 128)

	frame[0] = 0x01
	frame[1] = 0x0C
	frame[2] = 0xCD
	frame[3] = 0x02
	frame[4] = byte(idx >> 8)
	frame[5] = byte(idx & 0xFF)

	for i := 6; i < 12; i++ {
		frame[i] = 0xAA
	}

	frame[12] = 0x88
	frame[13] = 0xBA

	return frame
}

func (sim *SVNetworkSimulator) Start() {
	sim.mu.Lock()
	if sim.running {
		sim.mu.Unlock()
		return
	}
	sim.running = true
	sim.stopChan = make(chan struct{})
	sim.mu.Unlock()

	interval := time.Second / time.Duration(sim.packetRate)
	ticker := time.NewTicker(interval)
	idx := 0

	go func() {
		for {
			select {
			case <-ticker.C:
				pkt := sim.GeneratePacket(idx, "SIM_SV01", uint16(idx))
				sim.capture.ProcessPacket(pkt)
				idx++
			case <-sim.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (sim *SVNetworkSimulator) Stop() {
	sim.mu.Lock()
	defer sim.mu.Unlock()
	if sim.running {
		close(sim.stopChan)
		sim.running = false
	}
}
