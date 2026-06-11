package logic

import (
	"testing"
	"time"
)

func TestNewLogicGraph(t *testing.T) {
	g := NewLogicGraph()
	if g == nil {
		t.Fatal("NewLogicGraph returned nil")
	}
	if g.NodeCount() != 0 {
		t.Errorf("Expected 0 nodes, got %d", g.NodeCount())
	}
}

func TestAddNode(t *testing.T) {
	g := NewLogicGraph()

	node := NewLogicNode("input1", NodeTypeInput, "Test Input")
	err := g.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	if g.NodeCount() != 1 {
		t.Errorf("Expected 1 node, got %d", g.NodeCount())
	}

	err = g.AddNode(node)
	if err == nil {
		t.Error("Expected error for duplicate node, got nil")
	}
}

func TestAddEdge(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Input 1")
	in2 := NewLogicNode("in2", NodeTypeInput, "Input 2")
	and1 := NewLogicNode("and1", NodeTypeAND, "AND Gate")

	g.AddNode(in1)
	g.AddNode(in2)
	g.AddNode(and1)

	err := g.AddEdge("in1", "and1")
	if err != nil {
		t.Fatalf("AddEdge failed: %v", err)
	}

	err = g.AddEdge("in2", "and1")
	if err != nil {
		t.Fatalf("AddEdge failed: %v", err)
	}

	if len(and1.Inputs) != 2 {
		t.Errorf("Expected 2 inputs on AND gate, got %d", len(and1.Inputs))
	}

	if len(in1.Outputs) != 1 {
		t.Errorf("Expected 1 output on input 1, got %d", len(in1.Outputs))
	}
}

func TestANDGate(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Input 1")
	in2 := NewLogicNode("in2", NodeTypeInput, "Input 2")
	and1 := NewLogicNode("and1", NodeTypeAND, "AND Gate")
	out1 := NewLogicNode("out1", NodeTypeOutput, "Output 1")

	g.AddNode(in1)
	g.AddNode(in2)
	g.AddNode(and1)
	g.AddNode(out1)

	g.AddEdge("in1", "and1")
	g.AddEdge("in2", "and1")
	g.AddEdge("and1", "out1")

	g.BuildTopology()

	tests := []struct {
		in1, in2 bool
		expected bool
	}{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{true, true, true},
	}

	for i, tt := range tests {
		g.SetInput("in1", tt.in1)
		g.SetInput("in2", tt.in2)

		result, err := g.Evaluate()
		if err != nil {
			t.Fatalf("Test case %d: Evaluate failed: %v", i, err)
		}

		actual := out1.GetValue()
		if actual != tt.expected {
			t.Errorf("Test case %d: AND(%v, %v) = %v, expected %v",
				i, tt.in1, tt.in2, actual, tt.expected)
		}
		_ = result
	}
}

func TestORGate(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Input 1")
	in2 := NewLogicNode("in2", NodeTypeInput, "Input 2")
	or1 := NewLogicNode("or1", NodeTypeOR, "OR Gate")
	out1 := NewLogicNode("out1", NodeTypeOutput, "Output 1")

	g.AddNode(in1)
	g.AddNode(in2)
	g.AddNode(or1)
	g.AddNode(out1)

	g.AddEdge("in1", "or1")
	g.AddEdge("in2", "or1")
	g.AddEdge("or1", "out1")

	g.BuildTopology()

	tests := []struct {
		in1, in2 bool
		expected bool
	}{
		{false, false, false},
		{true, false, true},
		{false, true, true},
		{true, true, true},
	}

	for i, tt := range tests {
		g.SetInput("in1", tt.in1)
		g.SetInput("in2", tt.in2)

		_, err := g.Evaluate()
		if err != nil {
			t.Fatalf("Test case %d: Evaluate failed: %v", i, err)
		}

		actual := out1.GetValue()
		if actual != tt.expected {
			t.Errorf("Test case %d: OR(%v, %v) = %v, expected %v",
				i, tt.in1, tt.in2, actual, tt.expected)
		}
	}
}

func TestNOTGate(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Input 1")
	not1 := NewLogicNode("not1", NodeTypeNOT, "NOT Gate")
	out1 := NewLogicNode("out1", NodeTypeOutput, "Output 1")

	g.AddNode(in1)
	g.AddNode(not1)
	g.AddNode(out1)

	g.AddEdge("in1", "not1")
	g.AddEdge("not1", "out1")

	g.BuildTopology()

	tests := []struct {
		in       bool
		expected bool
	}{
		{false, true},
		{true, false},
	}

	for i, tt := range tests {
		g.SetInput("in1", tt.in)

		_, err := g.Evaluate()
		if err != nil {
			t.Fatalf("Test case %d: Evaluate failed: %v", i, err)
		}

		actual := out1.GetValue()
		if actual != tt.expected {
			t.Errorf("Test case %d: NOT(%v) = %v, expected %v",
				i, tt.in, actual, tt.expected)
		}
	}
}

func TestTopologicalSort(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Input 1")
	in2 := NewLogicNode("in2", NodeTypeInput, "Input 2")
	and1 := NewLogicNode("and1", NodeTypeAND, "AND 1")
	or1 := NewLogicNode("or1", NodeTypeOR, "OR 1")
	out1 := NewLogicNode("out1", NodeTypeOutput, "Output 1")

	g.AddNode(in1)
	g.AddNode(in2)
	g.AddNode(and1)
	g.AddNode(or1)
	g.AddNode(out1)

	g.AddEdge("in1", "and1")
	g.AddEdge("in2", "and1")
	g.AddEdge("in1", "or1")
	g.AddEdge("and1", "or1")
	g.AddEdge("or1", "out1")

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort failed: %v", err)
	}

	if len(order) != 5 {
		t.Errorf("Expected 5 nodes in order, got %d", len(order))
	}

	pos := make(map[string]int)
	for i, node := range order {
		pos[node.ID] = i
	}

	if pos["in1"] > pos["and1"] {
		t.Error("in1 should come before and1")
	}
	if pos["in2"] > pos["and1"] {
		t.Error("in2 should come before and1")
	}
	if pos["and1"] > pos["or1"] {
		t.Error("and1 should come before or1")
	}
	if pos["or1"] > pos["out1"] {
		t.Error("or1 should come before out1")
	}
}

func TestTripDetection(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Protection Start")
	out1 := NewLogicNode("trip1", NodeTypeOutput, "Trip Output")
	out1.TripOutput = true
	out1.DeviceID = "breaker_1"

	g.AddNode(in1)
	g.AddNode(out1)

	g.AddEdge("in1", "trip1")

	g.BuildTopology()

	g.SetInput("in1", false)
	result, err := g.Evaluate()
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.TripSignals) != 0 {
		t.Errorf("Expected 0 trip signals, got %d", len(result.TripSignals))
	}

	g.SetInput("in1", true)
	result, err = g.Evaluate()
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.TripSignals) != 1 {
		t.Errorf("Expected 1 trip signal, got %d", len(result.TripSignals))
	}

	if len(result.TripSignals) > 0 {
		if result.TripSignals[0].DeviceID != "breaker_1" {
			t.Errorf("Expected device ID 'breaker_1', got '%s'", result.TripSignals[0].DeviceID)
		}
	}
}

func TestProtectionEngine(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Test Input")
	out1 := NewLogicNode("out1", NodeTypeOutput, "Test Output")
	out1.TripOutput = true
	out1.DeviceID = "test_device"

	g.AddNode(in1)
	g.AddNode(out1)
	g.AddEdge("in1", "out1")

	engine := NewProtectionEngine(g)

	tripCount := 0
	engine.AddTripHandler(func(signal TripSignal) error {
		tripCount++
		return nil
	})

	err := engine.Start()
	if err != nil {
		t.Fatalf("Engine Start failed: %v", err)
	}
	defer engine.Stop()

	err = engine.SetInputsBatch(map[string]bool{"in1": true})
	if err != nil {
		t.Fatalf("SetInputsBatch failed: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	stats := engine.GetStats()
	if stats.EvalCount < 1 {
		t.Errorf("Expected at least 1 eval, got %d", stats.EvalCount)
	}
}

func TestLatchNode(t *testing.T) {
	g := NewLogicGraph()

	in1 := NewLogicNode("in1", NodeTypeInput, "Trigger")
	latch := NewLogicNode("latch1", NodeTypeLatch, "Latch")
	out1 := NewLogicNode("out1", NodeTypeOutput, "Output")

	g.AddNode(in1)
	g.AddNode(latch)
	g.AddNode(out1)

	g.AddEdge("in1", "latch1")
	g.AddEdge("latch1", "out1")

	g.BuildTopology()

	g.SetInput("in1", false)
	g.Evaluate()
	if out1.GetValue() != false {
		t.Error("Latch should be false initially")
	}

	g.SetInput("in1", true)
	g.Evaluate()
	if out1.GetValue() != true {
		t.Error("Latch should be true after trigger")
	}

	g.SetInput("in1", false)
	g.Evaluate()
	if out1.GetValue() != true {
		t.Error("Latch should remain true after trigger removed")
	}

	g.ResetLatches()
	g.Evaluate()
	if out1.GetValue() != false {
		t.Error("Latch should be false after reset")
	}
}

func BenchmarkLogicEvaluation(b *testing.B) {
	g := NewLogicGraph()

	for i := 0; i < 10; i++ {
		node := NewLogicNode("in"+string(rune('0'+i)), NodeTypeInput, "Input")
		g.AddNode(node)
	}

	for i := 0; i < 5; i++ {
		and := NewLogicNode("and"+string(rune('0'+i)), NodeTypeAND, "AND")
		g.AddNode(and)
		g.AddEdge("in"+string(rune('0'+i*2)), "and"+string(rune('0'+i)))
		g.AddEdge("in"+string(rune('0'+i*2+1)), "and"+string(rune('0'+i)))
	}

	finalOr := NewLogicNode("final_or", NodeTypeOR, "Final OR")
	g.AddNode(finalOr)
	for i := 0; i < 5; i++ {
		g.AddEdge("and"+string(rune('0'+i)), "final_or")
	}

	out := NewLogicNode("out", NodeTypeOutput, "Output")
	out.TripOutput = true
	g.AddNode(out)
	g.AddEdge("final_or", "out")

	g.BuildTopology()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.SetInput("in0", i%2 == 0)
		g.SetInput("in1", i%3 == 0)
		g.Evaluate()
	}
}
