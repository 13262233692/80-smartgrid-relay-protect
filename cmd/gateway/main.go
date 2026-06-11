package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/smartgrid/relay-protect/internal/capture"
	"github.com/smartgrid/relay-protect/pkg/config"
	"github.com/smartgrid/relay-protect/pkg/goose"
	"github.com/smartgrid/relay-protect/pkg/grpcclient"
	"github.com/smartgrid/relay-protect/pkg/logic"
)

type RelayGateway struct {
	config        *config.GatewayConfig
	capture       *capture.GOOSECapture
	captureReady  bool
	gooseParser   *goose.GOOSEParser
	logicEngine   *logic.ProtectionEngine
	tripClient    grpcclient.TripClient
	wg            sync.WaitGroup
	stopChan      chan struct{}
	mu            sync.RWMutex
	running       bool
	stats         *GatewayStats
	signalMap     map[string]string
	deviceMap     map[string]string
}

type GatewayStats struct {
	PacketsReceived uint64
	GOOSEDecoded    uint64
	DecodeErrors    uint64
	LogicEvals      uint64
	TripCommands    uint64
	StartTime       time.Time
}

func NewRelayGateway(cfg *config.GatewayConfig) *RelayGateway {
	return &RelayGateway{
		config:    cfg,
		stopChan:  make(chan struct{}),
		stats:     &GatewayStats{StartTime: time.Now()},
		signalMap: make(map[string]string),
		deviceMap: make(map[string]string),
	}
}

func (g *RelayGateway) Initialize() error {
	var err error

	g.gooseParser = goose.NewGOOSEParser()

	graph := logic.NewLogicGraph()
	scheme := config.BuildOverCurrentProtection()

	for _, nodeDef := range scheme.Logic.Nodes {
		nodeType := parseNodeType(nodeDef.Type)
		node := logic.NewLogicNode(nodeDef.ID, nodeType, nodeDef.Name)
		node.Description = nodeDef.Description
		node.TripOutput = nodeDef.TripOutput
		node.DeviceID = nodeDef.DeviceID

		if nodeDef.Params.DelayOn > 0 {
			node.DelayOn = time.Duration(nodeDef.Params.DelayOn) * time.Millisecond
		}
		if nodeDef.Params.DelayOff > 0 {
			node.DelayOff = time.Duration(nodeDef.Params.DelayOff) * time.Millisecond
		}

		if err := graph.AddNode(node); err != nil {
			return fmt.Errorf("add node %s failed: %w", nodeDef.ID, err)
		}
	}

	for _, edge := range scheme.Logic.Edges {
		if err := graph.AddEdge(edge.From, edge.To); err != nil {
			return fmt.Errorf("add edge %s->%s failed: %w", edge.From, edge.To, err)
		}
	}

	g.logicEngine = logic.NewProtectionEngine(graph)

	g.logicEngine.AddTripHandler(func(signal logic.TripSignal) error {
		return g.handleTripSignal(signal)
	})

	for _, input := range scheme.Inputs {
		g.signalMap[input.LogicNodeID] = input.SignalName
	}

	for _, output := range scheme.Outputs {
		g.deviceMap[output.LogicNodeID] = output.DeviceID
	}

	captureConfig := capture.GOOSEConfig{
		InterfaceName: g.config.GOOSE.InterfaceName,
		Promiscuous:   g.config.GOOSE.Promiscuous,
		SnapLen:       g.config.GOOSE.SnapLen,
		BufferSize:    g.config.GOOSE.BufferSize,
		BPFFilter:     g.config.GOOSE.BPFFilter,
	}

	g.capture, err = capture.NewGOOSECapture(captureConfig)
	if err != nil {
		log.Printf("Warning: Create GOOSE capture failed: %v", err)
		log.Println("Running in simulation mode only")
	} else {
		g.captureReady = true
	}

	if g.config.GRPC.Enabled {
		mockClient := grpcclient.NewMockTripClient()
		g.tripClient = mockClient
	}

	return nil
}

func parseNodeType(typeStr string) logic.NodeType {
	switch typeStr {
	case "INPUT":
		return logic.NodeTypeInput
	case "AND":
		return logic.NodeTypeAND
	case "OR":
		return logic.NodeTypeOR
	case "NOT":
		return logic.NodeTypeNOT
	case "NAND":
		return logic.NodeTypeNAND
	case "NOR":
		return logic.NodeTypeNOR
	case "XOR":
		return logic.NodeTypeXOR
	case "TIMER":
		return logic.NodeTypeTimer
	case "LATCH":
		return logic.NodeTypeLatch
	case "OUTPUT":
		return logic.NodeTypeOutput
	default:
		return logic.NodeTypeInput
	}
}

func (g *RelayGateway) Start() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.running {
		return fmt.Errorf("gateway already running")
	}

	if err := g.logicEngine.Start(); err != nil {
		return fmt.Errorf("start logic engine failed: %w", err)
	}

	if g.captureReady {
		if err := g.capture.Start(); err != nil {
			log.Printf("Warning: Start GOOSE capture failed: %v", err)
			log.Println("Running in simulation mode only")
			g.captureReady = false
		} else {
			g.wg.Add(1)
			go g.packetProcessingLoop()
		}
	}

	g.running = true

	g.wg.Add(1)
	go g.statsReporter()

	log.Println("Relay gateway started successfully")
	if g.captureReady {
		log.Println("  - GOOSE capture: ACTIVE")
	} else {
		log.Println("  - GOOSE capture: SIMULATION MODE")
	}
	return nil
}

func (g *RelayGateway) packetProcessingLoop() {
	defer g.wg.Done()

	packetChan := g.capture.PacketChan()

	for {
		select {
		case <-g.stopChan:
			return

		case rawData := <-packetChan:
			g.processPacket(rawData)
		}
	}
}

func (g *RelayGateway) processPacket(rawData []byte) {
	g.stats.PacketsReceived++

	if !capture.IsGOOSEPacket(rawData) {
		return
	}

	msg, err := g.gooseParser.Parse(rawData)
	if err != nil {
		g.stats.DecodeErrors++
		return
	}

	g.stats.GOOSEDecoded++

	inputMap := make(map[string]bool)

	for signalName, value := range msg.DataSetValues {
		if nodeID, ok := g.signalMap[signalName]; ok {
			inputMap[nodeID] = value
		}
	}

	if len(inputMap) > 0 {
		if err := g.logicEngine.SetInputsBatch(inputMap); err != nil {
			log.Printf("Logic eval error: %v", err)
		}
		g.stats.LogicEvals++
	}
}

func (g *RelayGateway) handleTripSignal(signal logic.TripSignal) error {
	g.stats.TripCommands++

	log.Printf("TRIP SIGNAL: Device=%s, Node=%s, Time=%v",
		signal.DeviceID, signal.NodeName, signal.Timestamp)

	if g.tripClient != nil {
		cmd := &grpcclient.TripCommand{
			DeviceID:     signal.DeviceID,
			ProtectionID: signal.NodeID,
			TripType:     grpcclient.TripTypeTrip,
			Timestamp:    signal.Timestamp,
			Reason:       signal.NodeName,
			Priority:     grpcclient.PriorityUrgent,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		resp, err := g.tripClient.SendTrip(ctx, cmd)
		if err != nil {
			log.Printf("Trip command failed: %v", err)
			return err
		}

		if !resp.Success {
			log.Printf("Trip command rejected: %s", resp.ErrorMessage)
		}
	}

	return nil
}

func (g *RelayGateway) statsReporter() {
	defer g.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-g.stopChan:
			return

		case <-ticker.C:
			g.printStats()
		}
	}
}

func (g *RelayGateway) printStats() {
	engineStats := g.logicEngine.GetStats()

	uptime := time.Since(g.stats.StartTime)

	log.Printf("=== Gateway Stats ===")
	log.Printf("Uptime: %v", uptime)
	log.Printf("Packets received: %d", g.stats.PacketsReceived)
	log.Printf("GOOSE decoded: %d", g.stats.GOOSEDecoded)
	log.Printf("Decode errors: %d", g.stats.DecodeErrors)
	log.Printf("Logic evaluations: %d", engineStats.EvalCount)
	log.Printf("Trip commands: %d", engineStats.TripCount)
	log.Printf("Last eval time: %v", engineStats.LastEvalTime)
	log.Printf("Avg eval time: %v", engineStats.AvgEvalTime)
	log.Printf("Max eval time: %v", engineStats.MaxEvalTime)
	log.Printf("Nodes in graph: %d", engineStats.NodeCount)
	log.Printf("=====================")
}

func (g *RelayGateway) Stop() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return
	}

	log.Println("Stopping relay gateway...")

	close(g.stopChan)
	g.running = false

	if g.captureReady && g.capture != nil {
		g.capture.Stop()
	}

	g.logicEngine.Stop()

	g.wg.Wait()

	if g.tripClient != nil {
		g.tripClient.Close()
	}

	log.Println("Relay gateway stopped")
}

func (g *RelayGateway) SimulateInput(nodeID string, value bool) error {
	return g.logicEngine.SetInput(nodeID, value)
}

func (g *RelayGateway) GetStats() *GatewayStats {
	return g.stats
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := config.DefaultConfig()

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	gateway := NewRelayGateway(cfg)

	if err := gateway.Initialize(); err != nil {
		log.Fatalf("Initialize gateway failed: %v", err)
	}

	if err := gateway.Start(); err != nil {
		log.Fatalf("Start gateway failed: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Relay Protection Gateway started. Press Ctrl+C to stop.")
	log.Println("Simulating protection signals for demo...")

	go runSimulation(gateway)

	<-sigChan
	log.Println("Received shutdown signal")

	gateway.Stop()
	log.Println("Shutdown complete")
}

func runSimulation(gateway *RelayGateway) {
	time.Sleep(2 * time.Second)

	log.Println("[SIM] Simulating overcurrent start signal...")
	gateway.SimulateInput("in_i_start", true)
	time.Sleep(100 * time.Millisecond)

	log.Println("[SIM] Simulating Stage I protection operation...")
	gateway.SimulateInput("in_i1_oper", true)
	time.Sleep(2 * time.Second)

	log.Println("[SIM] Resetting Stage I...")
	gateway.SimulateInput("in_i1_oper", false)
	time.Sleep(500 * time.Millisecond)

	log.Println("[SIM] Simulating lockout signal...")
	gateway.SimulateInput("in_lockout", true)
	time.Sleep(100 * time.Millisecond)

	log.Println("[SIM] Simulating Stage II operation (should be locked out)...")
	gateway.SimulateInput("in_i2_oper", true)
	time.Sleep(2 * time.Second)

	log.Println("[SIM] Clearing lockout...")
	gateway.SimulateInput("in_lockout", false)
	time.Sleep(100 * time.Millisecond)

	log.Println("[SIM] Simulation cycle complete")
}
