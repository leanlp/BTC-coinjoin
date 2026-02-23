package heuristics

import (
	"testing"
	"time"
)

func TestComputeWindowedAnonSet_NoErosion(t *testing.T) {
	// A 5-person Whirlpool mix with no post-mix activity
	mixTime := time.Now().Add(-48 * time.Hour) // Mixed 2 days ago
	events := []ErosionEvent{}                  // No erosion events

	result := ComputeWindowedAnonSet(5, mixTime, events)

	if result.AnonSetLocal != 5 {
		t.Errorf("Expected AnonSetLocal=5, got %d", result.AnonSetLocal)
	}
	// After 1 day with no erosion, AnonSet should remain 5
	if result.AnonSet1d != 5 {
		t.Errorf("Expected AnonSet1d=5 (no erosion), got %d", result.AnonSet1d)
	}
}

func TestComputeWindowedAnonSet_WithErosion(t *testing.T) {
	// A 10-person mix where 3 participants interacted with exchanges within 7 days
	mixTime := time.Now().Add(-30 * 24 * time.Hour) // Mixed 30 days ago
	events := []ErosionEvent{
		{Timestamp: mixTime.Add(12 * time.Hour), EventType: ErosionExchangeDeposit, Severity: 0.3},
		{Timestamp: mixTime.Add(3 * 24 * time.Hour), EventType: ErosionChangeConsolidate, Severity: 0.2},
		{Timestamp: mixTime.Add(15 * 24 * time.Hour), EventType: ErosionAddressReuse, Severity: 0.1},
	}

	result := ComputeWindowedAnonSet(10, mixTime, events)

	// After 1d: only 1 event (severity 0.3) → 10 * 0.7 = 7
	if result.AnonSet1d != 7 {
		t.Errorf("Expected AnonSet1d=7, got %d", result.AnonSet1d)
	}

	// After 7d: 2 events (0.3 + 0.2) → 10 * 0.7 * 0.8 = 5.6 → 6
	if result.AnonSet7d != 6 {
		t.Errorf("Expected AnonSet7d=6, got %d", result.AnonSet7d)
	}

	// After 30d: 3 events (0.3 + 0.2 + 0.1) → 10 * 0.7 * 0.8 * 0.9 = 5.04 → 5
	if result.AnonSet30d != 5 {
		t.Errorf("Expected AnonSet30d=5, got %d", result.AnonSet30d)
	}
}

func TestSolveCPSAT_SmallWhirlpool(t *testing.T) {
	// 3 inputs, 3 identical outputs + 3 change outputs
	// The solver should find that each input maps to exactly one denomination + change
	inputs := []int64{150000, 200000, 120000}
	outputs := []int64{100000, 100000, 100000, 49000, 99000, 19000}

	result := SolveCPSAT(inputs, outputs, 2000)

	if result < 2 {
		t.Errorf("Expected CP-SAT to find at least 2 valid partitions. Got: %d", result)
	}
}

func TestSolveCPSAT_GuardrailRefuse(t *testing.T) {
	// 11 inputs x 10 outputs = 110 > 100 → should refuse
	inputs := make([]int64, 11)
	outputs := make([]int64, 10)
	for i := range inputs {
		inputs[i] = 100000
	}
	for i := range outputs {
		outputs[i] = 90000
	}

	result := SolveCPSAT(inputs, outputs, 1000)

	if result != 0 {
		t.Errorf("Expected CP-SAT to refuse large instance and return 0. Got: %d", result)
	}
}
