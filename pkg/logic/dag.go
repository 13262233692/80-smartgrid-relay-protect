package logic

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type NodeType int

const (
	NodeTypeInput NodeType = iota
	NodeTypeAND
	NodeTypeOR
	NodeTypeNOT
	NodeTypeNAND
	NodeTypeNOR
	NodeTypeXOR
	NodeTypeTimer
	NodeTypeLatch
	NodeTypeOutput
)

type LogicNode struct {
	ID          string
	Type        NodeType
	Name        string
	Description string
	Value       bool
	PrevValue   bool
	Inputs      []*LogicNode
	Outputs     []*LogicNode
	Params      map[string]interface{}
	LastChanged time.Time
	Latched     bool
	Lockout     bool
	DelayOn     time.Duration
	DelayOff    time.Duration
	TripOutput  bool
	DeviceID    string
	mu          sync.RWMutex
}

type LogicGraph struct {
	Nodes       map[string]*LogicNode
	InputNodes  []*LogicNode
	OutputNodes []*LogicNode
	topoOrder   []*LogicNode
	mu          sync.RWMutex
	evaluating  bool
}

type EvaluationResult struct {
	Changed     bool
	TripSignals []TripSignal
	Duration    time.Duration
	UpdatedAt   time.Time
}

type TripSignal struct {
	DeviceID  string
	NodeID    string
	NodeName  string
	Trip      bool
	Timestamp time.Time
}

var (
	ErrNodeNotFound    = errors.New("node not found")
	ErrCycleDetected   = errors.New("cycle detected in graph")
	ErrInvalidNodeType = errors.New("invalid node type")
	ErrEmptyGraph      = errors.New("empty logic graph")
)

func NewLogicNode(id string, nodeType NodeType, name string) *LogicNode {
	return &LogicNode{
		ID:          id,
		Type:        nodeType,
		Name:        name,
		Params:      make(map[string]interface{}),
		LastChanged: time.Now(),
	}
}

func NewLogicGraph() *LogicGraph {
	return &LogicGraph{
		Nodes: make(map[string]*LogicNode),
	}
}

func (g *LogicGraph) AddNode(node *LogicNode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.Nodes[node.ID]; exists {
		return fmt.Errorf("node %s already exists", node.ID)
	}

	g.Nodes[node.ID] = node

	switch node.Type {
	case NodeTypeInput:
		g.InputNodes = append(g.InputNodes, node)
	case NodeTypeOutput:
		g.OutputNodes = append(g.OutputNodes, node)
	}

	return nil
}

func (g *LogicGraph) AddEdge(fromID, toID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	fromNode, exists := g.Nodes[fromID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrNodeNotFound, fromID)
	}

	toNode, exists := g.Nodes[toID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrNodeNotFound, toID)
	}

	fromNode.Outputs = append(fromNode.Outputs, toNode)
	toNode.Inputs = append(toNode.Inputs, fromNode)

	return nil
}

func (g *LogicGraph) GetNode(id string) (*LogicNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, exists := g.Nodes[id]
	return node, exists
}

func (g *LogicGraph) TopologicalSort() ([]*LogicNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Nodes) == 0 {
		return nil, ErrEmptyGraph
	}

	inDegree := make(map[string]int)
	for id, node := range g.Nodes {
		inDegree[id] = len(node.Inputs)
	}

	var queue []*LogicNode
	for id, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, g.Nodes[id])
		}
	}

	var result []*LogicNode
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		for _, output := range node.Outputs {
			inDegree[output.ID]--
			if inDegree[output.ID] == 0 {
				queue = append(queue, output)
			}
		}
	}

	if len(result) != len(g.Nodes) {
		return nil, ErrCycleDetected
	}

	return result, nil
}

func (g *LogicGraph) BuildTopology() error {
	order, err := g.TopologicalSort()
	if err != nil {
		return err
	}

	g.mu.Lock()
	g.topoOrder = order
	g.mu.Unlock()

	return nil
}

func (n *LogicNode) evaluate() bool {
	switch n.Type {
	case NodeTypeInput:
		return n.Value

	case NodeTypeAND:
		if len(n.Inputs) == 0 {
			return false
		}
		result := true
		for _, input := range n.Inputs {
			if !input.Value {
				result = false
				break
			}
		}
		return result

	case NodeTypeOR:
		if len(n.Inputs) == 0 {
			return false
		}
		result := false
		for _, input := range n.Inputs {
			if input.Value {
				result = true
				break
			}
		}
		return result

	case NodeTypeNOT:
		if len(n.Inputs) == 0 {
			return false
		}
		return !n.Inputs[0].Value

	case NodeTypeNAND:
		if len(n.Inputs) == 0 {
			return true
		}
		allTrue := true
		for _, input := range n.Inputs {
			if !input.Value {
				allTrue = false
				break
			}
		}
		return !allTrue

	case NodeTypeNOR:
		if len(n.Inputs) == 0 {
			return true
		}
		anyTrue := false
		for _, input := range n.Inputs {
			if input.Value {
				anyTrue = true
				break
			}
		}
		return !anyTrue

	case NodeTypeXOR:
		if len(n.Inputs) < 2 {
			return false
		}
		result := false
		for _, input := range n.Inputs {
			result = result != input.Value
		}
		return result

	case NodeTypeLatch:
		if n.Latched {
			return n.Value
		}
		if len(n.Inputs) >= 1 && n.Inputs[0].Value {
			n.Latched = true
			return true
		}
		return false

	case NodeTypeTimer:
		return n.evaluateTimer()

	case NodeTypeOutput:
		if len(n.Inputs) == 0 {
			return false
		}
		return n.Inputs[0].Value

	default:
		return false
	}
}

func (n *LogicNode) evaluateTimer() bool {
	if len(n.Inputs) == 0 {
		return false
	}

	inputValue := n.Inputs[0].Value
	now := time.Now()

	if inputValue && !n.PrevValue {
		n.LastChanged = now
	}

	if !inputValue && n.PrevValue {
		n.LastChanged = now
	}

	elapsed := now.Sub(n.LastChanged)

	if inputValue {
		if n.DelayOn > 0 {
			if elapsed >= n.DelayOn {
				return true
			}
			return n.Value
		}
		return true
	} else {
		if n.DelayOff > 0 {
			if elapsed >= n.DelayOff {
				return false
			}
			return n.Value
		}
		return false
	}
}

func (n *LogicNode) SetInput(value bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.Type != NodeTypeInput {
		return
	}

	n.PrevValue = n.Value
	n.Value = value
	if n.Value != n.PrevValue {
		n.LastChanged = time.Now()
	}
}

func (n *LogicNode) GetValue() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.Value
}

func (g *LogicGraph) SetInput(id string, value bool) error {
	node, exists := g.GetNode(id)
	if !exists {
		return fmt.Errorf("%w: %s", ErrNodeNotFound, id)
	}

	if node.Type != NodeTypeInput {
		return fmt.Errorf("node %s is not an input node", id)
	}

	node.SetInput(value)
	return nil
}

func (g *LogicGraph) GetOrAddInputNode(id string) (*LogicNode, error) {
	if node, exists := g.GetNode(id); exists {
		if node.Type != NodeTypeInput {
			return nil, fmt.Errorf("node %s exists but is not an input node", id)
		}
		return node, nil
	}

	node := &LogicNode{
		ID:          id,
		Type:        NodeTypeInput,
		Name:        id,
		Description: "Auto-created input",
	}
	if err := g.AddNode(node); err != nil {
		return nil, err
	}
	return node, nil
}

func (g *LogicGraph) Evaluate() (*EvaluationResult, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.topoOrder == nil {
		return nil, errors.New("topology not built, call BuildTopology first")
	}

	start := time.Now()
	result := &EvaluationResult{
		Changed:     false,
		TripSignals: make([]TripSignal, 0),
		UpdatedAt:   start,
	}

	for _, node := range g.topoOrder {
		if node.Type == NodeTypeInput {
			continue
		}

		node.mu.Lock()
		oldValue := node.Value
		node.PrevValue = oldValue
		newValue := node.evaluate()
		node.Value = newValue

		if newValue != oldValue {
			node.LastChanged = start
			result.Changed = true
		}

		if node.Type == NodeTypeOutput && node.TripOutput && newValue {
			result.TripSignals = append(result.TripSignals, TripSignal{
				DeviceID:  node.DeviceID,
				NodeID:    node.ID,
				NodeName:  node.Name,
				Trip:      true,
				Timestamp: start,
			})
		}

		node.mu.Unlock()
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (g *LogicGraph) EvaluateIncremental(changedInputs map[string]bool) (*EvaluationResult, error) {
	for id, value := range changedInputs {
		if err := g.SetInput(id, value); err != nil {
			return nil, err
		}
	}

	return g.Evaluate()
}

func (g *LogicGraph) GetAllOutputs() map[string]bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	outputs := make(map[string]bool)
	for _, node := range g.OutputNodes {
		outputs[node.ID] = node.GetValue()
	}
	return outputs
}

func (g *LogicGraph) GetAllInputs() map[string]bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	inputs := make(map[string]bool)
	for _, node := range g.InputNodes {
		inputs[node.ID] = node.GetValue()
	}
	return inputs
}

func (g *LogicGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.Nodes)
}

func (g *LogicGraph) ResetLatches() {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, node := range g.Nodes {
		if node.Type == NodeTypeLatch {
			node.mu.Lock()
			node.Latched = false
			node.Value = false
			node.mu.Unlock()
		}
	}
}

func NodeTypeToString(nt NodeType) string {
	switch nt {
	case NodeTypeInput:
		return "INPUT"
	case NodeTypeAND:
		return "AND"
	case NodeTypeOR:
		return "OR"
	case NodeTypeNOT:
		return "NOT"
	case NodeTypeNAND:
		return "NAND"
	case NodeTypeNOR:
		return "NOR"
	case NodeTypeXOR:
		return "XOR"
	case NodeTypeTimer:
		return "TIMER"
	case NodeTypeLatch:
		return "LATCH"
	case NodeTypeOutput:
		return "OUTPUT"
	default:
		return "UNKNOWN"
	}
}
