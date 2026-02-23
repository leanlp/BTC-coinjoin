package metrics

import "math"

// AdjustedRandIndex computes the Adjusted Rand Index (ARI) between two cluster partitions.
// ARI evaluates how well predicted clusters partition the graph
// compared to ground truth, instantly exposing unforeseen cluster collapse.
//
// ARI = (RI - Expected_RI) / (Max_RI - Expected_RI)
// where RI = (a + b) / C(n, 2)
//   a = number of pairs in same cluster in both partitions
//   b = number of pairs in different clusters in both partitions
//
// Values range from -1 (worse than random) to 1 (perfect agreement). 0 = random.
func AdjustedRandIndex(predicted, groundTruth []int) float64 {
	n := len(predicted)
	if n != len(groundTruth) || n < 2 {
		return 0.0
	}

	// Build contingency table
	predLabels := uniqueLabels(predicted)
	gtLabels := uniqueLabels(groundTruth)

	// Map labels to indices
	predMap := make(map[int]int)
	for i, l := range predLabels {
		predMap[l] = i
	}
	gtMap := make(map[int]int)
	for i, l := range gtLabels {
		gtMap[l] = i
	}

	// Contingency matrix n_ij
	nij := make([][]int, len(predLabels))
	for i := range nij {
		nij[i] = make([]int, len(gtLabels))
	}

	for k := 0; k < n; k++ {
		pi := predMap[predicted[k]]
		gi := gtMap[groundTruth[k]]
		nij[pi][gi]++
	}

	// Row sums (a_i) and column sums (b_j)
	rowSums := make([]int, len(predLabels))
	colSums := make([]int, len(gtLabels))

	for i := range nij {
		for j := range nij[i] {
			rowSums[i] += nij[i][j]
			colSums[j] += nij[i][j]
		}
	}

	// Compute the index using combinatorial formula
	// sum of C(n_ij, 2)
	sumNijC2 := 0.0
	for i := range nij {
		for j := range nij[i] {
			sumNijC2 += comb2(nij[i][j])
		}
	}

	sumAiC2 := 0.0
	for _, a := range rowSums {
		sumAiC2 += comb2(a)
	}

	sumBjC2 := 0.0
	for _, b := range colSums {
		sumBjC2 += comb2(b)
	}

	nC2 := comb2(n)
	if nC2 == 0 {
		return 0.0
	}

	expectedIndex := (sumAiC2 * sumBjC2) / nC2
	maxIndex := 0.5 * (sumAiC2 + sumBjC2)

	denominator := maxIndex - expectedIndex
	if math.Abs(denominator) < 1e-12 {
		return 1.0 // Perfect agreement (both are 0)
	}

	return (sumNijC2 - expectedIndex) / denominator
}

// VariationOfInformation computes the VI distance between two partitions.
// VI is an information-theoretic metric that measures the
// amount of information lost and gained when transitioning from one clustering to another.
//
// VI(C, C') = H(C|C') + H(C'|C)
// where H is the conditional entropy.
//
// Lower is better. 0 = identical partitions.
func VariationOfInformation(predicted, groundTruth []int) float64 {
	n := len(predicted)
	if n != len(groundTruth) || n < 2 {
		return 0.0
	}

	nf := float64(n)

	// Build contingency
	predLabels := uniqueLabels(predicted)
	gtLabels := uniqueLabels(groundTruth)

	predMap := make(map[int]int)
	for i, l := range predLabels {
		predMap[l] = i
	}
	gtMap := make(map[int]int)
	for i, l := range gtLabels {
		gtMap[l] = i
	}

	nij := make([][]int, len(predLabels))
	for i := range nij {
		nij[i] = make([]int, len(gtLabels))
	}
	for k := 0; k < n; k++ {
		nij[predMap[predicted[k]]][gtMap[groundTruth[k]]]++
	}

	rowSums := make([]int, len(predLabels))
	colSums := make([]int, len(gtLabels))
	for i := range nij {
		for j := range nij[i] {
			rowSums[i] += nij[i][j]
			colSums[j] += nij[i][j]
		}
	}

	// H(C|C') = -sum_ij (n_ij/n) * log(n_ij / b_j)
	hCgivenCp := 0.0
	for i := range nij {
		for j := range nij[i] {
			if nij[i][j] > 0 && colSums[j] > 0 {
				pij := float64(nij[i][j]) / nf
				hCgivenCp -= pij * math.Log2(float64(nij[i][j])/float64(colSums[j]))
			}
		}
	}

	// H(C'|C) = -sum_ij (n_ij/n) * log(n_ij / a_i)
	hCpgivenC := 0.0
	for i := range nij {
		for j := range nij[i] {
			if nij[i][j] > 0 && rowSums[i] > 0 {
				pij := float64(nij[i][j]) / nf
				hCpgivenC -= pij * math.Log2(float64(nij[i][j])/float64(rowSums[i]))
			}
		}
	}

	return hCgivenCp + hCpgivenC
}

// comb2 computes C(n, 2) = n*(n-1)/2
func comb2(n int) float64 {
	if n < 2 {
		return 0
	}
	return float64(n) * float64(n-1) / 2.0
}

// uniqueLabels returns sorted unique labels from a slice
func uniqueLabels(labels []int) []int {
	seen := make(map[int]bool)
	var result []int
	for _, l := range labels {
		if !seen[l] {
			seen[l] = true
			result = append(result, l)
		}
	}
	return result
}
