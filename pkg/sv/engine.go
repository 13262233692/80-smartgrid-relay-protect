package sv

import (
	"fmt"
	"sync"
	"time"

	"github.com/smartgrid/relay-protect/pkg/logic"
)

type DifferentialEngineConfig struct {
	SampleRate       int
	TripSignalPrefix string
}

type DifferentialEngine struct {
	lines           map[string]*DifferentialProtection
	engine          *logic.ProtectionEngine
	tripSignalPrefix string
	sampleRate       int
	mu              sync.RWMutex
	stats           DifferentialEngineStats
}

type DifferentialEngineStats struct {
	TotalEvalCount   uint64
	TripCount        uint64
	SignalCount      uint64
	LastTripTime     time.Time
	LastEvalTime     time.Time
	mu               sync.Mutex
}

func NewDifferentialEngine(sampleRate int, eng *logic.ProtectionEngine) *DifferentialEngine {
	return &DifferentialEngine{
		lines:           make(map[string]*DifferentialProtection),
		engine:          eng,
		tripSignalPrefix: "DIFF_",
		sampleRate:       sampleRate,
	}
}

func (de *DifferentialEngine) AddLine(lineName string, settings DifferentialSettings) error {
	de.mu.Lock()
	defer de.mu.Unlock()

	if _, exists := de.lines[lineName]; exists {
		return fmt.Errorf("line %s already exists", lineName)
	}

	dp := NewDifferentialProtection(lineName, de.sampleRate)
	dp.Settings = settings
	dp.SetEventHandler(de.createEventHandler(lineName))

	de.lines[lineName] = dp

	tripSignal := de.tripSignalPrefix + lineName + "_TRIP"
	if de.engine != nil {
		_ = de.engine.UpsertInputNode(tripSignal, false)
	}

	return nil
}

func (de *DifferentialEngine) createEventHandler(lineName string) func(DifferentialEvent) {
	return func(event DifferentialEvent) {
		de.stats.mu.Lock()
		de.stats.TotalEvalCount++
		de.stats.LastEvalTime = event.Time
		if event.Trip {
			de.stats.TripCount++
			if event.Trip && !event.PrevTrip {
				de.stats.LastTripTime = event.Time
			}
		}
		de.stats.mu.Unlock()

		if de.engine != nil {
			tripSignal := de.tripSignalPrefix + lineName + "_TRIP"
			val := false
			if event.Trip {
				val = true
			}
			_ = de.engine.UpsertInputNode(tripSignal, val)
			de.stats.mu.Lock()
			de.stats.SignalCount++
			de.stats.mu.Unlock()
		}
	}
}

func (de *DifferentialEngine) GetLine(lineName string) (*DifferentialProtection, bool) {
	de.mu.RLock()
	defer de.mu.RUnlock()
	line, ok := de.lines[lineName]
	return line, ok
}

func (de *DifferentialEngine) PushSamples(lineName, side string, Ia, Ib, Ic float64) error {
	de.mu.RLock()
	line, ok := de.lines[lineName]
	de.mu.RUnlock()

	if !ok {
		return fmt.Errorf("line %s not found", lineName)
	}

	switch side {
	case "M":
		line.PushSideM(Ia, Ib, Ic)
	case "N":
		line.PushSideN(Ia, Ib, Ic)
	default:
		return fmt.Errorf("invalid side: %s (must be 'M' or 'N')", side)
	}

	return nil
}

func (de *DifferentialEngine) PushBothSides(lineName string, IaM, IbM, IcM, IaN, IbN, IcN float64) error {
	de.mu.RLock()
	line, ok := de.lines[lineName]
	de.mu.RUnlock()

	if !ok {
		return fmt.Errorf("line %s not found", lineName)
	}

	line.PushBothSides(IaM, IbM, IcM, IaN, IbN, IcN)
	return nil
}

func (de *DifferentialEngine) GetStatus(lineName string) (DifferentialData, error) {
	de.mu.RLock()
	line, ok := de.lines[lineName]
	de.mu.RUnlock()

	if !ok {
		return DifferentialData{}, fmt.Errorf("line %s not found", lineName)
	}

	return line.GetStatus(), nil
}

func (de *DifferentialEngine) IsTripping(lineName string) (bool, error) {
	status, err := de.GetStatus(lineName)
	if err != nil {
		return false, err
	}
	return status.Trip, nil
}

func (de *DifferentialEngine) ListLines() []string {
	de.mu.RLock()
	defer de.mu.RUnlock()
	names := make([]string, 0, len(de.lines))
	for k := range de.lines {
		names = append(names, k)
	}
	return names
}

func (de *DifferentialEngine) GetStats() DifferentialEngineStats {
	de.stats.mu.Lock()
	defer de.stats.mu.Unlock()
	return de.stats
}

type SVSimulator struct {
	engine     *DifferentialEngine
	sampleRate int
	running    bool
	stopChan   chan struct{}
	mu         sync.Mutex
	faults     map[string]*FaultCondition
}

type FaultCondition struct {
	LineName    string
	Active      bool
	I0Amplitude float64
	StartTime   time.Time
	side        string
}

func NewSVSimulator(engine *DifferentialEngine, sampleRate int) *SVSimulator {
	return &SVSimulator{
		engine:     engine,
		sampleRate: sampleRate,
		stopChan:   make(chan struct{}),
		faults:     make(map[string]*FaultCondition),
	}
}

func (sim *SVSimulator) SetFault(lineName string, I0Amp float64) {
	sim.mu.Lock()
	defer sim.mu.Unlock()

	if _, ok := sim.faults[lineName]; !ok {
		sim.faults[lineName] = &FaultCondition{
			LineName: lineName,
		}
	}

	sim.faults[lineName].Active = true
	sim.faults[lineName].I0Amplitude = I0Amp
	sim.faults[lineName].StartTime = time.Now()
}

func (sim *SVSimulator) ClearFault(lineName string) {
	sim.mu.Lock()
	defer sim.mu.Unlock()

	if f, ok := sim.faults[lineName]; ok {
		f.Active = false
	}
}

func (sim *SVSimulator) Step(idx int) {
	sim.mu.Lock()
	lines := sim.engine.ListLines()
	faultsCopy := make(map[string]*FaultCondition)
	for k, v := range sim.faults {
		faultsCopy[k] = &FaultCondition{
			LineName:    v.LineName,
			Active:      v.Active,
			I0Amplitude: v.I0Amplitude,
		}
	}
	sim.mu.Unlock()

	for _, lineName := range lines {
		loadCurrent := 1.0
		hasFault := false
		faultAmp := 0.0

		if f, ok := faultsCopy[lineName]; ok && f.Active {
			hasFault = true
			faultAmp = f.I0Amplitude
		}

		var IaM, IbM, IcM, IaN, IbN, IcN float64

		if hasFault {
			IaM, IbM, IcM = GenerateFaultThreePhase(loadCurrent, faultAmp, sim.sampleRate, idx)
			IaN, IbN, IcN = GenerateBalancedThreePhase(loadCurrent, sim.sampleRate, idx)
		} else {
			IaM, IbM, IcM = GenerateBalancedThreePhase(loadCurrent, sim.sampleRate, idx)
			IaN, IbN, IcN = GenerateBalancedThreePhase(loadCurrent, sim.sampleRate, idx)
		}

		_ = sim.engine.PushBothSides(lineName, IaM, IbM, IcM, IaN, IbN, IcN)
	}
}

func (sim *SVSimulator) Start() {
	sim.mu.Lock()
	if sim.running {
		sim.mu.Unlock()
		return
	}
	sim.running = true
	sim.stopChan = make(chan struct{})
	sim.mu.Unlock()

	interval := time.Second / time.Duration(sim.sampleRate)
	ticker := time.NewTicker(interval)
	idx := 0

	go func() {
		for {
			select {
			case <-ticker.C:
				sim.Step(idx)
				idx++
			case <-sim.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (sim *SVSimulator) Stop() {
	sim.mu.Lock()
	defer sim.mu.Unlock()
	if sim.running {
		close(sim.stopChan)
		sim.running = false
	}
}
