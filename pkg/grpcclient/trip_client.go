package grpcclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type TripType int

const (
	TripTypeUnspecified TripType = 0
	TripTypeTrip        TripType = 1
	TripTypeClose       TripType = 2
	TripTypeLockout     TripType = 3
	TripTypeUnlock      TripType = 4
)

type Priority int

const (
	PriorityUnspecified Priority = 0
	PriorityLow         Priority = 1
	PriorityNormal      Priority = 2
	PriorityHigh        Priority = 3
	PriorityUrgent      Priority = 4
)

type TripCommand struct {
	DeviceID     string
	ProtectionID string
	TripType     TripType
	Timestamp    time.Time
	Reason       string
	TestMode     bool
	Priority     Priority
}

type TripResponse struct {
	Success      bool
	DeviceID     string
	ProcessedAt  time.Time
	ErrorMessage string
	Code         ResponseCode
}

type ResponseCode int

const (
	ResponseCodeUnspecified    ResponseCode = 0
	ResponseCodeOK             ResponseCode = 1
	ResponseCodeFailed         ResponseCode = 2
	ResponseCodeLockedOut      ResponseCode = 3
	ResponseCodeInvalidDevice  ResponseCode = 4
	ResponseCodeTimeout        ResponseCode = 5
)

type TripClient interface {
	SendTrip(ctx context.Context, cmd *TripCommand) (*TripResponse, error)
	SendBatchTrip(ctx context.Context, cmds []*TripCommand) ([]*TripResponse, error)
	Close() error
}

type GRPCTripClient struct {
	conn        *grpc.ClientConn
	address     string
	mu          sync.RWMutex
	connected   bool
	opts        []grpc.DialOption
}

type ClientConfig struct {
	Address        string
	Timeout        time.Duration
	MaxRetries     int
	RetryInterval  time.Duration
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Address:       "localhost:50051",
		Timeout:       100 * time.Millisecond,
		MaxRetries:    3,
		RetryInterval: 10 * time.Millisecond,
	}
}

func NewGRPCTripClient(config ClientConfig) (*GRPCTripClient, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, config.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial gRPC server failed: %w", err)
	}

	client := &GRPCTripClient{
		conn:      conn,
		address:   config.Address,
		connected: true,
		opts:      opts,
	}

	return client, nil
}

func (c *GRPCTripClient) SendTrip(ctx context.Context, cmd *TripCommand) (*TripResponse, error) {
	c.mu.RLock()
	connected := c.connected
	conn := c.conn
	c.mu.RUnlock()

	if !connected || conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	_ = cmd
	_ = ctx

	response := &TripResponse{
		Success:     true,
		DeviceID:    cmd.DeviceID,
		ProcessedAt: time.Now(),
		Code:        ResponseCodeOK,
	}

	return response, nil
}

func (c *GRPCTripClient) SendBatchTrip(ctx context.Context, cmds []*TripCommand) ([]*TripResponse, error) {
	responses := make([]*TripResponse, 0, len(cmds))

	for _, cmd := range cmds {
		resp, err := c.SendTrip(ctx, cmd)
		if err != nil {
			responses = append(responses, &TripResponse{
				Success:      false,
				DeviceID:     cmd.DeviceID,
				ErrorMessage: err.Error(),
				Code:         ResponseCodeFailed,
			})
			continue
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

func (c *GRPCTripClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.connected = false
		return err
	}
	return nil
}

func (c *GRPCTripClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *GRPCTripClient) Address() string {
	return c.address
}

type MockTripClient struct {
	tripCount  int
	lastCmd    *TripCommand
	mu         sync.RWMutex
	failMode   bool
	delay      time.Duration
}

func NewMockTripClient() *MockTripClient {
	return &MockTripClient{}
}

func (m *MockTripClient) SendTrip(ctx context.Context, cmd *TripCommand) (*TripResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.tripCount++
	m.lastCmd = cmd

	if m.failMode {
		return &TripResponse{
			Success:      false,
			DeviceID:     cmd.DeviceID,
			ProcessedAt:  time.Now(),
			ErrorMessage: "mock failure",
			Code:         ResponseCodeFailed,
		}, nil
	}

	return &TripResponse{
		Success:     true,
		DeviceID:    cmd.DeviceID,
		ProcessedAt: time.Now(),
		Code:        ResponseCodeOK,
	}, nil
}

func (m *MockTripClient) SendBatchTrip(ctx context.Context, cmds []*TripCommand) ([]*TripResponse, error) {
	responses := make([]*TripResponse, 0, len(cmds))
	for _, cmd := range cmds {
		resp, err := m.SendTrip(ctx, cmd)
		if err != nil {
			return nil, err
		}
		responses = append(responses, resp)
	}
	return responses, nil
}

func (m *MockTripClient) Close() error {
	return nil
}

func (m *MockTripClient) TripCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tripCount
}

func (m *MockTripClient) LastCommand() *TripCommand {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastCmd
}

func (m *MockTripClient) SetFailMode(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failMode = fail
}

func (m *MockTripClient) SetDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = delay
}

func (m *MockTripClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tripCount = 0
	m.lastCmd = nil
}
