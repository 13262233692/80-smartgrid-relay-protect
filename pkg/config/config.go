package config

import (
	"fmt"
	"time"
)

type GatewayConfig struct {
	NodeID       string      `yaml:"node_id"`
	SubstationID string      `yaml:"substation_id"`
	GOOSE        GOOSEConfig `yaml:"goose"`
	Logic        LogicConfig `yaml:"logic"`
	GRPC         GRPCConfig  `yaml:"grpc"`
	Logging      LogConfig   `yaml:"logging"`
}

type GOOSEConfig struct {
	InterfaceName string        `yaml:"interface_name"`
	Promiscuous   bool          `yaml:"promiscuous"`
	SnapLen       int32         `yaml:"snap_len"`
	BufferSize    int           `yaml:"buffer_size"`
	BPFFilter     string        `yaml:"bpf_filter"`
	DataSets      []DataSetDef  `yaml:"datasets"`
}

type DataSetDef struct {
	Name     string         `yaml:"name"`
	Ref      string         `yaml:"ref"`
	Signals  []SignalDef    `yaml:"signals"`
}

type SignalDef struct {
	Name  string `yaml:"name"`
	Label string `yaml:"label"`
	Type  string `yaml:"type"`
}

type LogicConfig struct {
	Nodes       []NodeDef    `yaml:"nodes"`
	Edges       []EdgeDef    `yaml:"edges"`
	Lockouts    []LockoutDef `yaml:"lockouts"`
}

type NodeDef struct {
	ID          string        `yaml:"id"`
	Type        string        `yaml:"type"`
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Params      NodeParams    `yaml:"params,omitempty"`
	DeviceID    string        `yaml:"device_id,omitempty"`
	TripOutput  bool          `yaml:"trip_output,omitempty"`
}

type NodeParams struct {
	DelayOn  int    `yaml:"delay_on_ms"`
	DelayOff int    `yaml:"delay_off_ms"`
	InitVal  bool   `yaml:"init_val"`
	DeviceID string `yaml:"device_id"`
}

type EdgeDef struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type LockoutDef struct {
	ID       string `yaml:"id"`
	Duration int    `yaml:"duration_ms"`
	DeviceID string `yaml:"device_id"`
}

type GRPCConfig struct {
	ServerAddress string        `yaml:"server_address"`
	Timeout       time.Duration `yaml:"timeout_ms"`
	MaxRetries    int           `yaml:"max_retries"`
	Enabled       bool          `yaml:"enabled"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file,omitempty"`
}

func DefaultConfig() *GatewayConfig {
	return &GatewayConfig{
		NodeID:       "relay-gateway-01",
		SubstationID: "substation-750kv-01",
		GOOSE: GOOSEConfig{
			InterfaceName: "eth0",
			Promiscuous:   true,
			SnapLen:       65535,
			BufferSize:    1024,
			BPFFilter:     "ether proto 0x88B8",
		},
		Logic: LogicConfig{},
		GRPC: GRPCConfig{
			ServerAddress: "localhost:50051",
			Timeout:       100 * time.Millisecond,
			MaxRetries:    3,
			Enabled:       true,
		},
		Logging: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

func (c *GatewayConfig) Validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}
	if c.GOOSE.InterfaceName == "" {
		return fmt.Errorf("goose.interface_name is required")
	}
	if c.GRPC.Enabled && c.GRPC.ServerAddress == "" {
		return fmt.Errorf("grpc.server_address is required when grpc is enabled")
	}
	return nil
}

type ProtectionScheme struct {
	Name        string
	Description string
	Inputs      []SignalMapping
	Outputs     []TripMapping
	Logic       LogicGraphDef
}

type SignalMapping struct {
	SignalName  string
	DataSet     string
	Position    int
	LogicNodeID string
}

type TripMapping struct {
	DeviceID    string
	LogicNodeID string
	Description string
}

type LogicGraphDef struct {
	Nodes []NodeDef
	Edges []EdgeDef
}

func BuildOverCurrentProtection() *ProtectionScheme {
	return &ProtectionScheme{
		Name:        "over_current_protection",
		Description: "三段式过流保护",
		Inputs: []SignalMapping{
			{SignalName: "I_start", DataSet: "ds_protection", Position: 0, LogicNodeID: "in_i_start"},
			{SignalName: "I段动作", DataSet: "ds_protection", Position: 1, LogicNodeID: "in_i1_oper"},
			{SignalName: "II段动作", DataSet: "ds_protection", Position: 2, LogicNodeID: "in_i2_oper"},
			{SignalName: "III段动作", DataSet: "ds_protection", Position: 3, LogicNodeID: "in_i3_oper"},
			{SignalName: "闭锁信号", DataSet: "ds_interlock", Position: 0, LogicNodeID: "in_lockout"},
		},
		Outputs: []TripMapping{
			{DeviceID: "breaker_A", LogicNodeID: "out_trip_A", Description: "A相断路器跳闸"},
			{DeviceID: "breaker_B", LogicNodeID: "out_trip_B", Description: "B相断路器跳闸"},
			{DeviceID: "breaker_C", LogicNodeID: "out_trip_C", Description: "C相断路器跳闸"},
		},
		Logic: LogicGraphDef{
			Nodes: []NodeDef{
				{ID: "in_i_start", Type: "INPUT", Name: "过流启动"},
				{ID: "in_i1_oper", Type: "INPUT", Name: "I段动作"},
				{ID: "in_i2_oper", Type: "INPUT", Name: "II段动作"},
				{ID: "in_i3_oper", Type: "INPUT", Name: "III段动作"},
				{ID: "in_lockout", Type: "INPUT", Name: "闭锁信号"},
				{ID: "not_lockout", Type: "NOT", Name: "非闭锁"},
				{ID: "trip_enable", Type: "AND", Name: "跳闸使能"},
				{ID: "timer_I", Type: "TIMER", Name: "I段延时", Params: NodeParams{DelayOn: 0}},
				{ID: "timer_II", Type: "TIMER", Name: "II段延时", Params: NodeParams{DelayOn: 500}},
				{ID: "timer_III", Type: "TIMER", Name: "III段延时", Params: NodeParams{DelayOn: 1500}},
				{ID: "trip_or", Type: "OR", Name: "跳闸条件或"},
				{ID: "trip_final", Type: "AND", Name: "最终跳闸"},
				{ID: "out_trip_A", Type: "OUTPUT", Name: "A相跳闸", TripOutput: true, DeviceID: "breaker_A"},
				{ID: "out_trip_B", Type: "OUTPUT", Name: "B相跳闸", TripOutput: true, DeviceID: "breaker_B"},
				{ID: "out_trip_C", Type: "OUTPUT", Name: "C相跳闸", TripOutput: true, DeviceID: "breaker_C"},
			},
			Edges: []EdgeDef{
				{From: "in_lockout", To: "not_lockout"},
				{From: "in_i_start", To: "trip_enable"},
				{From: "not_lockout", To: "trip_enable"},
				{From: "in_i1_oper", To: "timer_I"},
				{From: "in_i2_oper", To: "timer_II"},
				{From: "in_i3_oper", To: "timer_III"},
				{From: "timer_I", To: "trip_or"},
				{From: "timer_II", To: "trip_or"},
				{From: "timer_III", To: "trip_or"},
				{From: "trip_enable", To: "trip_final"},
				{From: "trip_or", To: "trip_final"},
				{From: "trip_final", To: "out_trip_A"},
				{From: "trip_final", To: "out_trip_B"},
				{From: "trip_final", To: "out_trip_C"},
			},
		},
	}
}
