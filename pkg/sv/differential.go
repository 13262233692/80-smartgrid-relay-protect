package sv

import (
	"math"
	"sync"
	"time"
)

type RestraintCharacteristic struct {
	Breakpoint1 float64
	Breakpoint2 float64
	Slope1      float64
	Slope2      float64
	MinTrip     float64
}

func DefaultRestraintCharacteristic() RestraintCharacteristic {
	return RestraintCharacteristic{
		Breakpoint1: 0.5,
		Breakpoint2: 2.0,
		Slope1:      0.3,
		Slope2:      0.5,
		MinTrip:     0.2,
	}
}

func (rc RestraintCharacteristic) TripThreshold(IresMag float64) float64 {
	switch {
	case IresMag <= rc.Breakpoint1:
		return rc.MinTrip
	case IresMag <= rc.Breakpoint2:
		return rc.MinTrip + rc.Slope1*(IresMag-rc.Breakpoint1)
	default:
		thr1 := rc.MinTrip + rc.Slope1*(rc.Breakpoint2-rc.Breakpoint1)
		return thr1 + rc.Slope2*(IresMag-rc.Breakpoint2)
	}
}

func (rc RestraintCharacteristic) CheckRestraint(IdiffMag, IresMag float64) (bool, float64) {
	threshold := rc.TripThreshold(IresMag)
	slope := 0.0
	if IresMag > 0 {
		slope = IdiffMag / IresMag
	}
	return IdiffMag > threshold, slope
}

type DifferentialProtection struct {
	Name                 string
	Settings             DifferentialSettings
	Restraint            RestraintCharacteristic
	SideM                *ZeroSequenceProcessor
	SideN                *ZeroSequenceProcessor
	CurrentDifferential  Phasor
	CurrentRestraint     Phasor
	IdiffMag             float64
	IresMag              float64
	Slope                float64
	Trip                 bool
	TripCount            uint64
	LastEvalTime         time.Time
	LastTripTime         time.Time
	mu                   sync.Mutex
	eventHandler         func(event DifferentialEvent)
}

type DifferentialEvent struct {
	LineName      string
	Time          time.Time
	Idiff         Phasor
	Ires          Phasor
	IdiffMag      float64
	IresMag       float64
	Slope         float64
	Trip          bool
	PrevTrip      bool
}

func NewDifferentialProtection(name string, sampleRate int) *DifferentialProtection {
	return &DifferentialProtection{
		Name:      name,
		Settings:  DefaultDifferentialSettings(),
		Restraint: DefaultRestraintCharacteristic(),
		SideM:     NewZeroSequenceProcessor(name+"_M", sampleRate),
		SideN:     NewZeroSequenceProcessor(name+"_N", sampleRate),
	}
}

func (dp *DifferentialProtection) SetEventHandler(handler func(event DifferentialEvent)) {
	dp.eventHandler = handler
}

func (dp *DifferentialProtection) PushSideM(Ia, Ib, Ic float64) {
	dp.SideM.PushSamples(Ia, Ib, Ic)
	dp.evaluate()
}

func (dp *DifferentialProtection) PushSideN(Ia, Ib, Ic float64) {
	dp.SideN.PushSamples(Ia, Ib, Ic)
	dp.evaluate()
}

func (dp *DifferentialProtection) PushBothSides(IaM, IbM, IcM, IaN, IbN, IcN float64) {
	dp.SideM.PushSamples(IaM, IbM, IcM)
	dp.SideN.PushSamples(IaN, IbN, IcN)
	dp.evaluate()
}

func (dp *DifferentialProtection) evaluate() {
	if !dp.SideM.Ready() || !dp.SideN.Ready() {
		return
	}

	dp.mu.Lock()
	defer dp.mu.Unlock()

	phasorM := dp.SideM.GetI0Phasor()
	phasorN := dp.SideN.GetI0Phasor()

	Idiff := phasorM.Sub(phasorN)

	resMagM := phasorM.Mag
	resMagN := phasorN.Mag
	IresMag := (resMagM + resMagN) / 2.0

	IresReal := (phasorM.Real + phasorN.Real) / 2.0
	IresImag := (phasorM.Imag + phasorN.Imag) / 2.0
	Ires := NewPhasor(IresReal, IresImag)

	IdiffMag := Idiff.Mag * dp.Settings.CTRatio
	IresMagScaled := IresMag * dp.Settings.CTRatio

	dp.CurrentDifferential = Idiff
	dp.CurrentRestraint = Ires
	dp.IdiffMag = IdiffMag
	dp.IresMag = IresMagScaled

	prevTrip := dp.Trip

	trip, slope := dp.Restraint.CheckRestraint(IdiffMag, IresMagScaled)
	dp.Slope = slope
	dp.Trip = trip
	dp.LastEvalTime = time.Now()

	if trip && !prevTrip {
		dp.TripCount++
		dp.LastTripTime = time.Now()
	}

	if dp.eventHandler != nil {
		dp.eventHandler(DifferentialEvent{
			LineName: dp.Name,
			Time:     dp.LastEvalTime,
			Idiff:    Idiff,
			Ires:     Ires,
			IdiffMag: IdiffMag,
			IresMag:  IresMagScaled,
			Slope:    slope,
			Trip:     trip,
			PrevTrip: prevTrip,
		})
	}
}

func (dp *DifferentialProtection) GetStatus() DifferentialData {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	return DifferentialData{
		Idiff:      dp.CurrentDifferential,
		Ires:       dp.CurrentRestraint,
		IdiffMag:   dp.IdiffMag,
		IresMag:    dp.IresMag,
		Slope:      dp.Slope,
		Trip:       dp.Trip,
		LastUpdate: dp.LastEvalTime,
	}
}

func (dp *DifferentialProtection) Ready() bool {
	return dp.SideM.Ready() && dp.SideN.Ready()
}

func CalculateDifferentialCurrent(phasor1, phasor2 Phasor, ctRatio float64) Phasor {
	diff := phasor1.Sub(phasor2)
	return diff.Scale(ctRatio)
}

func CalculateRestraintCurrent(phasor1, phasor2 Phasor, ctRatio float64) (float64, Phasor) {
	avgReal := (phasor1.Real + phasor2.Real) / 2.0
	avgImag := (phasor1.Imag + phasor2.Imag) / 2.0
	phasor := NewPhasor(avgReal, avgImag)
	mag := (phasor1.Mag + phasor2.Mag) / 2.0
	return mag * ctRatio, phasor.Scale(ctRatio)
}

func CheckBiasedRestraint(IdiffMag, IresMag float64, settings DifferentialSettings) (bool, float64) {
	rc := RestraintCharacteristic{
		Breakpoint1: settings.IresMin,
		Breakpoint2: settings.Iset2,
		Slope1:      settings.K1,
		Slope2:      settings.K2,
		MinTrip:     settings.Iset1,
	}
	return rc.CheckRestraint(IdiffMag, IresMag)
}

func GenerateSineWave(amplitude, phaseDeg float64, sampleRate, sampleIndex int) float64 {
	phaseRad := phaseDeg * math.Pi / 180.0
	freq := 50.0
	t := float64(sampleIndex) / float64(sampleRate)
	return amplitude * math.Sin(2*math.Pi*freq*t+phaseRad)
}

func GenerateThreePhase(amplitudeAmp, phaseDegA, phaseDegB, phaseDegC float64, sampleRate, sampleIndex int) (float64, float64, float64) {
	Ia := GenerateSineWave(amplitudeAmp, phaseDegA, sampleRate, sampleIndex)
	Ib := GenerateSineWave(amplitudeAmp, phaseDegB, sampleRate, sampleIndex)
	Ic := GenerateSineWave(amplitudeAmp, phaseDegC, sampleRate, sampleIndex)
	return Ia, Ib, Ic
}

func GenerateBalancedThreePhase(amplitude float64, sampleRate, sampleIndex int) (float64, float64, float64) {
	return GenerateThreePhase(amplitude, 0, -120, 120, sampleRate, sampleIndex)
}

func GenerateFaultThreePhase(amplitude, I0Amp float64, sampleRate, sampleIndex int) (float64, float64, float64) {
	Ia, Ib, Ic := GenerateBalancedThreePhase(amplitude, sampleRate, sampleIndex)
	I0 := GenerateSineWave(I0Amp, 0, sampleRate, sampleIndex)
	Ia += I0
	Ib += I0
	Ic += I0
	return Ia, Ib, Ic
}
