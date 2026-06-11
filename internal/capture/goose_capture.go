package capture

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type GOOSECapture struct {
	handle      *pcap.Handle
	config      GOOSEConfig
	packetChan  chan []byte
	stopChan    chan struct{}
	wg          sync.WaitGroup
	running     bool
	mu          sync.Mutex
}

type GOOSEConfig struct {
	InterfaceName string
	Promiscuous   bool
	SnapLen       int32
	BufferSize    int
	BPFFilter     string
}

func DefaultGOOSEConfig() GOOSEConfig {
	return GOOSEConfig{
		InterfaceName: "eth0",
		Promiscuous:   true,
		SnapLen:       65535,
		BufferSize:    1024,
		BPFFilter:     "ether proto 0x88B8",
	}
}

func NewGOOSECapture(config GOOSEConfig) (*GOOSECapture, error) {
	if config.SnapLen == 0 {
		config.SnapLen = 65535
	}
	if config.BPFFilter == "" {
		config.BPFFilter = "ether proto 0x88B8"
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1024
	}

	return &GOOSECapture{
		config:     config,
		packetChan: make(chan []byte, config.BufferSize),
		stopChan:   make(chan struct{}),
	}, nil
}

func (c *GOOSECapture) Start() error {
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

	if err = inactive.SetTimeout(time.Millisecond * 10); err != nil {
		return fmt.Errorf("set timeout failed: %w", err)
	}

	if err = inactive.SetBufferSize(2 * 1024 * 1024); err != nil {
		return fmt.Errorf("set buffer size failed: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return fmt.Errorf("activate handle failed: %w", err)
	}

	if err = handle.SetBPFFilter(c.config.BPFFilter); err != nil {
		handle.Close()
		return fmt.Errorf("set BPF filter failed: %w", err)
	}

	c.handle = handle
	c.running = true

	c.wg.Add(1)
	go c.captureLoop()

	return nil
}

func (c *GOOSECapture) captureLoop() {
	defer c.wg.Done()

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packetSource.NoCopy = true
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

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

		rawData := packet.Data()
		dataCopy := make([]byte, len(rawData))
		copy(dataCopy, rawData)

		select {
		case c.packetChan <- dataCopy:
		default:
		}
	}
}

func (c *GOOSECapture) Stop() {
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

func (c *GOOSECapture) PacketChan() <-chan []byte {
	return c.packetChan
}

func ListInterfaces() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(devices))
	for _, dev := range devices {
		names = append(names, dev.Name)
	}
	return names, nil
}

func IsGOOSEPacket(data []byte) bool {
	if len(data) < 14 {
		return false
	}
	etherType := uint16(data[12])<<8 | uint16(data[13])
	return etherType == 0x88B8
}

func ParseEthernetHeader(data []byte) (dstMAC, srcMAC []byte, etherType uint16, payload []byte) {
	if len(data) < 14 {
		return nil, nil, 0, nil
	}
	dstMAC = make([]byte, 6)
	copy(dstMAC, data[0:6])
	srcMAC = make([]byte, 6)
	copy(srcMAC, data[6:12])
	etherType = uint16(data[12])<<8 | uint16(data[13])
	payload = data[14:]
	return
}

func GetEthernetLayerInfo(packet gopacket.Packet) *layers.Ethernet {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth, _ := ethLayer.(*layers.Ethernet)
	return eth
}
