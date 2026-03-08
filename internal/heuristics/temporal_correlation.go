package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Temporal Correlation Engine (Phase 18)
//
// Detects timing-based correlation patterns across transactions. When a
// CoinJoin mix concludes and a withdrawal occurs within a bounded temporal
// window, the linkage probability increases significantly.
//
// Detection modes:
//   - Periodic: Transactions at regular intervals (bot behavior)
//   - Burst: Multiple transactions in rapid succession
//   - Delayed-withdrawal: CoinJoin → spend within a tight window
//
// Time bucketing classifies transaction timing into behavioral windows:
//   - "business": 09:00-17:00 UTC (institutional activity)
//   - "evening":  17:00-00:00 UTC (retail activity)
//   - "overnight": 00:00-09:00 UTC (automated/bot activity)
//
// References:
//   - Biryukov & Tikhomirov, "Transaction Clustering Using Network Traffic
//     Analysis for Bitcoin and Derived Blockchains" (WPES 2019)
//   - Goldfeder et al., "When the cookie meets the blockchain" (IEEE S&P 2018)

const (
	// PeriodicThresholdCV is the coefficient of variation threshold below
	// which intervals are considered periodic (regular bot-like pattern).
	periodicThresholdCV = 0.25

	// BurstWindowSeconds defines the maximum gap between transactions in a burst.
	burstWindowSeconds = 30.0

	// DelayedWithdrawalMaxSeconds defines the max delay between a CoinJoin and
	// the subsequent spend to flag as correlated.
	delayedWithdrawalMaxSeconds = 3600.0 // 1 hour
)

// AnalyzeTemporalCorrelation detects timing patterns between a target
// transaction and a set of recent related transactions.
func AnalyzeTemporalCorrelation(tx models.Transaction, recentTxs []models.Transaction) models.TemporalCorrelationResult {
	result := models.TemporalCorrelationResult{
		PatternType: "none",
	}

	// 1. Calculate time bucket for the target transaction (always compute this)
	if tx.BlockTime > 0 {
		result.TimeBucket = classifyTimeBucket(tx.BlockTime)
	}

	if len(recentTxs) < 2 || tx.BlockTime == 0 {
		return result
	}

	// 2. Compute intervals between consecutive transactions
	timestamps := make([]int64, 0, len(recentTxs)+1)
	timestamps = append(timestamps, tx.BlockTime)
	for _, rtx := range recentTxs {
		if rtx.BlockTime > 0 {
			timestamps = append(timestamps, rtx.BlockTime)
		}
	}

	if len(timestamps) < 2 {
		return result
	}

	// Sort timestamps ascending
	sortInt64s(timestamps)

	intervals := make([]float64, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		intervals = append(intervals, float64(timestamps[i]-timestamps[i-1]))
	}

	if len(intervals) == 0 {
		return result
	}

	// 3. Calculate statistics
	avgInterval := mean(intervals)
	stdDev := stddev(intervals, avgInterval)
	result.IntervalSeconds = avgInterval

	// 4. Detect pattern type
	if avgInterval > 0 {
		cv := stdDev / avgInterval // Coefficient of variation

		if cv < periodicThresholdCV && avgInterval > 10 {
			// Low variation = regular intervals = automated/bot pattern
			result.HasTimingPattern = true
			result.PatternType = "periodic"
			result.Confidence = math.Max(0, 1.0-cv) // Higher CV = lower confidence
		} else if avgInterval < burstWindowSeconds {
			// All transactions within a tight window = burst pattern
			result.HasTimingPattern = true
			result.PatternType = "burst"
			result.Confidence = math.Min(1.0, burstWindowSeconds/avgInterval*0.5)
		}
	}

	// 5. Check for delayed-withdrawal pattern (CoinJoin → spend)
	for _, rtx := range recentTxs {
		if rtx.BlockTime == 0 || tx.BlockTime == 0 {
			continue
		}
		delay := math.Abs(float64(tx.BlockTime - rtx.BlockTime))
		if delay > 0 && delay <= delayedWithdrawalMaxSeconds {
			// Check if either tx is a CoinJoin (mix) and the other is a spend
			if isCoinJoinStructure(rtx) || isCoinJoinStructure(tx) {
				result.HasTimingPattern = true
				result.PatternType = "delayed-withdrawal"
				result.MixToWithdrawDelay = delay
				result.Confidence = math.Max(0.5, 1.0-delay/delayedWithdrawalMaxSeconds)
				result.CorrelatedTxids = append(result.CorrelatedTxids, rtx.Txid)
			}
		}
	}

	// Collect all correlated txids for periodic/burst patterns
	if result.HasTimingPattern && result.PatternType != "delayed-withdrawal" {
		for _, rtx := range recentTxs {
			result.CorrelatedTxids = append(result.CorrelatedTxids, rtx.Txid)
		}
	}

	return result
}

// classifyTimeBucket assigns a behavioral time window based on hour of day (UTC).
func classifyTimeBucket(unixSeconds int64) string {
	hour := (unixSeconds % 86400) / 3600 // Hour of day in UTC
	switch {
	case hour >= 9 && hour < 17:
		return "business"
	case hour >= 17 || hour < 0: // This condition `hour < 0` is always false for `hour` being a result of modulo and division on `unixSeconds`
		return "evening"
	default:
		return "overnight"
	}
}

// isCoinJoinStructure performs a quick structural check for CoinJoin-like topology.
func isCoinJoinStructure(tx models.Transaction) bool {
	if len(tx.Inputs) < 2 || len(tx.Outputs) < 3 {
		return false
	}

	// Count equal-value outputs (CoinJoin signature)
	valueCounts := make(map[int64]int)
	for _, out := range tx.Outputs {
		valueCounts[out.Value]++
	}
	for _, count := range valueCounts {
		if count >= 3 {
			return true
		}
	}
	return false
}

// sortInt64s sorts a slice of int64 in ascending order (simple insertion sort for small slices).
func sortInt64s(s []int64) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}

// mean computes the arithmetic mean of a slice.
func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// stddev computes the standard deviation given a pre-computed mean.
func stddev(vals []float64, avg float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	sumSq := 0.0
	for _, v := range vals {
		d := v - avg
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(vals)-1))
}
