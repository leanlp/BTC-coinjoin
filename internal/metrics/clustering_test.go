package metrics

import (
	"math"
	"testing"
)

func TestAdjustedRandIndex_PerfectAgreement(t *testing.T) {
	predicted := []int{0, 0, 1, 1, 2, 2}
	groundTruth := []int{0, 0, 1, 1, 2, 2}

	ari := AdjustedRandIndex(predicted, groundTruth)

	if math.Abs(ari-1.0) > 0.01 {
		t.Errorf("Expected ARI=1.0 for perfect agreement. Got: %f", ari)
	}
}

func TestAdjustedRandIndex_RandomPartition(t *testing.T) {
	// Two very different partitions should yield ARI near 0
	predicted := []int{0, 0, 0, 1, 1, 1}
	groundTruth := []int{0, 1, 0, 1, 0, 1}

	ari := AdjustedRandIndex(predicted, groundTruth)

	if ari > 0.5 {
		t.Errorf("Expected ARI near 0 for dissimilar partitions. Got: %f", ari)
	}
}

func TestVariationOfInformation_Identical(t *testing.T) {
	predicted := []int{0, 0, 1, 1, 2, 2}
	groundTruth := []int{0, 0, 1, 1, 2, 2}

	vi := VariationOfInformation(predicted, groundTruth)

	if vi > 0.01 {
		t.Errorf("Expected VI=0.0 for identical partitions. Got: %f", vi)
	}
}

func TestVariationOfInformation_Different(t *testing.T) {
	predicted := []int{0, 0, 0, 1, 1, 1}
	groundTruth := []int{0, 1, 0, 1, 0, 1}

	vi := VariationOfInformation(predicted, groundTruth)

	if vi < 0.1 {
		t.Errorf("Expected VI > 0 for different partitions. Got: %f", vi)
	}
}
