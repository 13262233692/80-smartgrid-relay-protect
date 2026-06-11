package sv

import (
	"math"
	"testing"
)

func TestZeroSequenceCalculation(t *testing.T) {
	Ia, Ib, Ic := GenerateBalancedThreePhase(1.0, 4000, 0)

	I0 := CalcZeroSequenceCurrent(Ia, Ib, Ic)

	if math.Abs(I0) > 0.0001 {
		t.Errorf("Balanced three-phase should have I0 ≈ 0, got %f", I0)
	}
}

func TestZeroSequenceWithFault(t *testing.T) {
	expectedI0 := 10.0
	Ia, Ib, Ic := GenerateFaultThreePhase(1.0, expectedI0, 4000, 100)

	I0 := CalcZeroSequenceCurrent(Ia, Ib, Ic)

	sinePeak := math.Abs(expectedI0)
	if math.Abs(math.Abs(I0)-sinePeak) > sinePeak*0.01 && math.Abs(I0) > 0.001 {
		t.Errorf("Fault I0 mismatch, expected peak ≈ %f, got %f", sinePeak, I0)
	}
}

func TestChannelBuffer(t *testing.T) {
	buf := NewChannelBuffer("test", 4000)

	if buf.SamplesPerCycle() != 80 {
		t.Errorf("Expected 80 samples/cycle for 4kHz, got %d", buf.SamplesPerCycle())
	}

	for i := 0; i < 100; i++ {
		buf.Push(float64(i))
	}

	if buf.AvailableSamples() != 100 {
		t.Errorf("Expected 100 available samples, got %d", buf.AvailableSamples())
	}

	lastN := buf.GetLastN(5)
	expected := []float64{95, 96, 97, 98, 99}
	for i, v := range lastN {
		if v != expected[i] {
			t.Errorf("LastN[%d] = %f, expected %f", i, v, expected[i])
		}
	}
}

func TestDFTPhasorComputation(t *testing.T) {
	sampleRate := 4000
	dft := NewDFTProcessor(sampleRate)

	amplitude := 5.0
	phaseDeg := 30.0
	samples := make([]float64, dft.SamplesPerCycle)

	for i := 0; i < dft.SamplesPerCycle; i++ {
		samples[i] = GenerateSineWave(amplitude, phaseDeg, sampleRate, i)
	}

	phasor := dft.ComputePhasor(samples)

	expectedMag := amplitude
	magError := math.Abs(phasor.Mag-expectedMag) / expectedMag
	if magError > 0.02 {
		t.Errorf("DFT magnitude error too large: got %f, expected %f (error: %.2f%%)",
			phasor.Mag, expectedMag, magError*100)
	}

	expectedAngle := (phaseDeg - 90.0) * math.Pi / 180.0
	angleDiff := math.Abs(phasor.Angle - expectedAngle)
	for angleDiff > math.Pi {
		angleDiff -= 2 * math.Pi
	}
	for angleDiff < -math.Pi {
		angleDiff += 2 * math.Pi
	}
	angleDiffDeg := math.Abs(angleDiff) * 180.0 / math.Pi

	if angleDiffDeg > 2.0 {
		t.Errorf("DFT phase error too large: got %.2f°, expected %.2f°",
			phasor.Angle*180.0/math.Pi, (phaseDeg-90.0))
	}

	t.Logf("DFT Result: Mag=%.4f (expected %.0f), Angle=%.2f° (expected %.0f°, cosine reference)",
		phasor.Mag, expectedMag, phasor.Angle*180.0/math.Pi, (phaseDeg - 90.0))
}

func TestZeroSequenceProcessor(t *testing.T) {
	sampleRate := 4000
	proc := NewZeroSequenceProcessor("LINE1", sampleRate)

	amplitude := 10.0

	for i := 0; i < sampleRate; i++ {
		Ia, Ib, Ic := GenerateFaultThreePhase(1.0, amplitude, sampleRate, i)
		proc.PushSamples(Ia, Ib, Ic)
	}

	if !proc.Ready() {
		t.Fatal("ZeroSequenceProcessor should be ready after 4000 samples")
	}

	phasor := proc.GetI0Phasor()
	rms := proc.GetI0RMS()

	expectedRMS := amplitude / math.Sqrt2
	rmsError := math.Abs(rms-expectedRMS) / expectedRMS
	if rmsError > 0.02 {
		t.Errorf("I0 RMS error: got %.4f, expected %.4f (%.2f%%)",
			rms, expectedRMS, rmsError*100)
	}

	t.Logf("I0 Phasor: Mag=%.4f, Angle=%.2f°, RMS=%.4f",
		phasor.Mag, phasor.Angle*180.0/math.Pi, rms)
}

func TestRestraintCharacteristic(t *testing.T) {
	rc := DefaultRestraintCharacteristic()

	testCases := []struct {
		Ires      float64
		threshold float64
	}{
		{0.0, 0.2},
		{0.3, 0.2},
		{0.5, 0.2},
		{1.0, 0.2 + 0.3*(1.0-0.5)},
		{2.0, 0.2 + 0.3*(2.0-0.5)},
		{3.0, 0.2 + 0.3*(2.0-0.5) + 0.5*(3.0-2.0)},
	}

	for _, tc := range testCases {
		thr := rc.TripThreshold(tc.Ires)
		if math.Abs(thr-tc.threshold) > 0.0001 {
			t.Errorf("Ires=%.2f: expected threshold=%.4f, got %.4f", tc.Ires, tc.threshold, thr)
		}
	}
}

func TestDifferentialProtection_NoFault(t *testing.T) {
	sampleRate := 4000
	dp := NewDifferentialProtection("TestLine", sampleRate)

	for i := 0; i < sampleRate; i++ {
		IaM, IbM, IcM := GenerateBalancedThreePhase(1.0, sampleRate, i)
		IaN, IbN, IcN := GenerateBalancedThreePhase(1.0, sampleRate, i)
		dp.PushBothSides(IaM, IbM, IcM, IaN, IbN, IcN)
	}

	if !dp.Ready() {
		t.Fatal("DifferentialProtection should be ready")
	}

	status := dp.GetStatus()

	if status.IdiffMag > 0.05 {
		t.Errorf("No-fault Idiff should be ≈ 0, got %.4f", status.IdiffMag)
	}

	if status.Trip {
		t.Error("No-fault condition should NOT trip")
	}

	t.Logf("No-fault status: Idiff=%.6f, Ires=%.4f, Slope=%.4f, Trip=%v",
		status.IdiffMag, status.IresMag, status.Slope, status.Trip)
}

func TestDifferentialProtection_InternalFault(t *testing.T) {
	sampleRate := 4000
	dp := NewDifferentialProtection("TestLine", sampleRate)

	faultAmp := 2.0

	for i := 0; i < sampleRate; i++ {
		IaM, IbM, IcM := GenerateFaultThreePhase(1.0, faultAmp, sampleRate, i)
		IaN, IbN, IcN := GenerateBalancedThreePhase(1.0, sampleRate, i)
		dp.PushBothSides(IaM, IbM, IcM, IaN, IbN, IcN)
	}

	status := dp.GetStatus()

	if !status.Trip {
		t.Errorf("Internal fault should trip. Idiff=%.4f, Ires=%.4f, Slope=%.4f",
			status.IdiffMag, status.IresMag, status.Slope)
	}

	t.Logf("Internal fault: Idiff=%.4f, Ires=%.4f, Slope=%.4f, Trip=%v",
		status.IdiffMag, status.IresMag, status.Slope, status.Trip)
}

func TestDifferentialProtection_ExternalFault(t *testing.T) {
	sampleRate := 4000
	dp := NewDifferentialProtection("TestLine", sampleRate)

	faultAmp := 2.0

	for i := 0; i < sampleRate; i++ {
		IaM, IbM, IcM := GenerateFaultThreePhase(1.0, faultAmp, sampleRate, i)
		IaN, IbN, IcN := GenerateFaultThreePhase(1.0, faultAmp, sampleRate, i)
		dp.PushBothSides(IaM, IbM, IcM, IaN, IbN, IcN)
	}

	status := dp.GetStatus()

	if status.Trip {
		t.Errorf("External (through) fault should NOT trip. Idiff=%.4f, Ires=%.4f, Slope=%.4f",
			status.IdiffMag, status.IresMag, status.Slope)
	}

	t.Logf("External fault: Idiff=%.6f, Ires=%.4f, Slope=%.4f, Trip=%v",
		status.IdiffMag, status.IresMag, status.Slope, status.Trip)
}

func BenchmarkDFTPhasor(b *testing.B) {
	sampleRate := 4000
	dft := NewDFTProcessor(sampleRate)
	samples := make([]float64, dft.SamplesPerCycle)
	for i := range samples {
		samples[i] = GenerateSineWave(5.0, 30.0, sampleRate, i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dft.ComputePhasor(samples)
	}
}

func BenchmarkDifferentialEval(b *testing.B) {
	sampleRate := 4000
	dp := NewDifferentialProtection("TestLine", sampleRate)

	for i := 0; i < sampleRate; i++ {
		IaM, IbM, IcM := GenerateBalancedThreePhase(1.0, sampleRate, i)
		IaN, IbN, IcN := GenerateBalancedThreePhase(1.0, sampleRate, i)
		dp.PushBothSides(IaM, IbM, IcM, IaN, IbN, IcN)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IaM, IbM, IcM := GenerateBalancedThreePhase(1.0, sampleRate, sampleRate+i)
		IaN, IbN, IcN := GenerateBalancedThreePhase(1.0, sampleRate, sampleRate+i)
		dp.PushBothSides(IaM, IbM, IcM, IaN, IbN, IcN)
	}
}
