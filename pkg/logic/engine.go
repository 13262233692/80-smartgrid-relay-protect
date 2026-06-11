package logic

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type ProtectionEngine struct {
	graph          *LogicGraph
	tripHandlers   []TripHandler
	lockoutStates  map[string]*LockoutState
	delayStates    map[string]*DelayState
	mu             sync.RWMutex
	running        bool
	eventChan      chan *ProtectionEvent
	stopChan       chan struct{}
	wg             sync.WaitGroup
	evalCount      uint64
	tripCount      uint64
	lastEvalTime   time.Duration
	maxEvalTime    time.Duration
	minEvalTime    time.Duration
	avgEvalTime    time.Duration
	totalEvalTime  time.Duration
}

type LockoutState struct {
	ID           string
	Active       bool
	StartTime    time.Time
	Duration     time.Duration
	Reason       string
}

type DelayState struct {
	ID            string
	StartTime     time.Time
	DelayDuration time.Duration
	Pending       bool
	Value         bool
}

type ProtectionEvent struct {
	Type      EventType
	NodeID    string
	Value     bool
	Timestamp time.Time
	Details   map[string]interface{}
}

type EventType int

const (
	EventInputChange EventType = iota
	EventTrip
	EventLockout
	EventEvalComplete
)

type TripHandler func(signal TripSignal) error

type EngineConfig struct {
	EventBufferSize int
}

func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		EventBufferSize: 1024,
	}
}

func NewProtectionEngine(graph *LogicGraph) *ProtectionEngine {
	config := DefaultEngineConfig()
	return &ProtectionEngine{
		graph:         graph,
		lockoutStates: make(map[string]*LockoutState),
		delayStates:   make(map[string]*DelayState),
		eventChan:     make(chan *ProtectionEvent, config.EventBufferSize),
		stopChan:      make(chan struct{}),
		minEvalTime:   time.Hour,
	}
}

func (e *ProtectionEngine) AddTripHandler(handler TripHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tripHandlers = append(e.tripHandlers, handler)
}

func (e *ProtectionEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("engine already running")
	}

	if err := e.graph.BuildTopology(); err != nil {
		return fmt.Errorf("build topology failed: %w", err)
	}

	e.running = true
	e.wg.Add(1)
	go e.eventLoop()

	return nil
}

func (e *ProtectionEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return
	}

	close(e.stopChan)
	e.running = false
	e.wg.Wait()
}

func (e *ProtectionEngine) eventLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopChan:
			return

		case event := <-e.eventChan:
			e.handleEvent(event)

		case <-ticker.C:
			e.checkTimers()
		}
	}
}

func (e *ProtectionEngine) handleEvent(event *ProtectionEvent) {
	switch event.Type {
	case EventInputChange:
		e.evaluateWithEvent(event)
	}
}

func (e *ProtectionEngine) checkTimers() {
	now := time.Now()

	e.mu.RLock()
	lockouts := make([]*LockoutState, 0, len(e.lockoutStates))
	for _, state := range e.lockoutStates {
		lockouts = append(lockouts, state)
	}
	e.mu.RUnlock()

	for _, state := range lockouts {
		if state.Active && now.Sub(state.StartTime) >= state.Duration {
			e.ClearLockout(state.ID)
		}
	}
}

func (e *ProtectionEngine) SetInput(nodeID string, value bool) error {
	event := &ProtectionEvent{
		Type:      EventInputChange,
		NodeID:    nodeID,
		Value:     value,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	select {
	case e.eventChan <- event:
		return nil
	default:
		return fmt.Errorf("event buffer full")
	}
}

func (e *ProtectionEngine) SetInputsBatch(inputs map[string]bool) error {
	for nodeID, value := range inputs {
		if err := e.graph.SetInput(nodeID, value); err != nil {
			return err
		}
	}

	result, err := e.graph.Evaluate()
	if err != nil {
		return err
	}

	e.recordEvalMetrics(result)

	if len(result.TripSignals) > 0 {
		e.dispatchTrips(result.TripSignals)
	}

	return nil
}

func (e *ProtectionEngine) evaluateWithEvent(event *ProtectionEvent) {
	if err := e.graph.SetInput(event.NodeID, event.Value); err != nil {
		return
	}

	result, err := e.graph.Evaluate()
	if err != nil {
		return
	}

	e.recordEvalMetrics(result)

	if len(result.TripSignals) > 0 {
		e.dispatchTrips(result.TripSignals)
	}
}

func (e *ProtectionEngine) recordEvalMetrics(result *EvaluationResult) {
	atomic.AddUint64(&e.evalCount, 1)

	e.mu.Lock()
	e.lastEvalTime = result.Duration
	e.totalEvalTime += result.Duration

	if result.Duration > e.maxEvalTime {
		e.maxEvalTime = result.Duration
	}
	if result.Duration < e.minEvalTime {
		e.minEvalTime = result.Duration
	}

	count := atomic.LoadUint64(&e.evalCount)
	if count > 0 {
		e.avgEvalTime = e.totalEvalTime / time.Duration(count)
	}
	e.mu.Unlock()
}

func (e *ProtectionEngine) dispatchTrips(signals []TripSignal) {
	e.mu.RLock()
	handlers := make([]TripHandler, len(e.tripHandlers))
	copy(handlers, e.tripHandlers)
	e.mu.RUnlock()

	for _, signal := range signals {
		if e.isLockedOut(signal.DeviceID) {
			continue
		}

		atomic.AddUint64(&e.tripCount, 1)

		for _, handler := range handlers {
			go func(h TripHandler, s TripSignal) {
				_ = h(s)
			}(handler, signal)
		}
	}
}

func (e *ProtectionEngine) SetLockout(id string, duration time.Duration, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lockoutStates[id] = &LockoutState{
		ID:       id,
		Active:   true,
		StartTime: time.Now(),
		Duration: duration,
		Reason:   reason,
	}
}

func (e *ProtectionEngine) ClearLockout(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if state, exists := e.lockoutStates[id]; exists {
		state.Active = false
	}
}

func (e *ProtectionEngine) isLockedOut(deviceID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if state, exists := e.lockoutStates[deviceID]; exists {
		return state.Active
	}
	return false
}

func (e *ProtectionEngine) IsLockedOut(deviceID string) bool {
	return e.isLockedOut(deviceID)
}

func (e *ProtectionEngine) GetStats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return EngineStats{
		EvalCount:     atomic.LoadUint64(&e.evalCount),
		TripCount:     atomic.LoadUint64(&e.tripCount),
		LastEvalTime:  e.lastEvalTime,
		MaxEvalTime:   e.maxEvalTime,
		MinEvalTime:   e.minEvalTime,
		AvgEvalTime:   e.avgEvalTime,
		NodeCount:     e.graph.NodeCount(),
		Running:       e.running,
	}
}

type EngineStats struct {
	EvalCount     uint64
	TripCount     uint64
	LastEvalTime  time.Duration
	MaxEvalTime   time.Duration
	MinEvalTime   time.Duration
	AvgEvalTime   time.Duration
	NodeCount     int
	Running       bool
}

func (e *ProtectionEngine) GetGraph() *LogicGraph {
	return e.graph
}

func (e *ProtectionEngine) GetAllInputs() map[string]bool {
	return e.graph.GetAllInputs()
}

func (e *ProtectionEngine) GetAllOutputs() map[string]bool {
	return e.graph.GetAllOutputs()
}
