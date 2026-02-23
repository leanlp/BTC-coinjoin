package heuristics

import (
	"math"
	"time"
)

// Pattern-of-Life Behavioral Analysis
//
// Transaction timing reveals behavioral fingerprints that are nearly
// impossible to fake. The analysis extracts:
//
//   1. Timezone inference: peak activity hours reveal UTC offset
//   2. Schedule detection: weekday vs weekend, business hours vs not
//   3. Regularity scoring: bots have high regularity (σ < 0.5h),
//      humans are moderate (σ = 2-6h), random = noise
//   4. Frequency: transactions per day reveals entity type
//
// Two entities with identical wallet fingerprints but activity in
// different timezones are provably distinct. This is the strongest
// evidence for splitting clusters.
//
// References:
//   - Biryukov & Pustogarov, "Bitcoin over Tor" (CCS 2015) — timing attacks
//   - Fistful of Bitcoins (2013) — temporal patterns of exchanges
//   - Nick (2015), "Data-Driven De-Anonymization in Bitcoin"

// BehavioralProfile holds temporal behavioral analysis results
type BehavioralProfile struct {
	InferredTimezone string  `json:"inferredTimezone"` // Estimated UTC offset (e.g., "UTC-5")
	PeakHourUTC      int     `json:"peakHourUTC"`      // Most active hour (0-23 UTC)
	WeekdayRatio     float64 `json:"weekdayRatio"`     // Fraction of txs on weekdays (Mon-Fri)
	Regularity       float64 `json:"regularity"`       // 0.0 (random) to 1.0 (perfectly regular)
	TxFrequency      float64 `json:"txFrequency"`      // Average transactions per day
	EntityType       string  `json:"entityType"`       // "bot"/"service"/"human"/"unknown"
	IsBot            bool    `json:"isBot"`            // High regularity + high frequency
}

// AnalyzeBehavioralPattern computes temporal behavioral profile
// from a set of transaction timestamps.
func AnalyzeBehavioralPattern(txTimes []time.Time) BehavioralProfile {
	profile := BehavioralProfile{
		InferredTimezone: "unknown",
		EntityType:       "unknown",
	}

	if len(txTimes) < 3 {
		return profile
	}

	// 1. Compute hour-of-day distribution
	hourCounts := make([]int, 24)
	weekdayCount := 0
	for _, t := range txTimes {
		hourCounts[t.UTC().Hour()]++
		if t.UTC().Weekday() >= time.Monday && t.UTC().Weekday() <= time.Friday {
			weekdayCount++
		}
	}

	// 2. Find peak hour
	maxCount := 0
	for h, count := range hourCounts {
		if count > maxCount {
			maxCount = count
			profile.PeakHourUTC = h
		}
	}

	// 3. Infer timezone from peak activity
	// Assume peak activity is during business hours (9-17 local time)
	// Center of business day = ~13:00 local → UTC offset = peakHour - 13
	profile.InferredTimezone = inferTimezoneFromPeak(profile.PeakHourUTC)

	// 4. Weekday ratio
	profile.WeekdayRatio = math.Round(float64(weekdayCount)*100/float64(len(txTimes))) / 100

	// 5. Regularity (coefficient of variation of inter-tx intervals)
	profile.Regularity = computeRegularity(txTimes)

	// 6. Frequency (txs per day)
	if len(txTimes) >= 2 {
		span := txTimes[len(txTimes)-1].Sub(txTimes[0])
		if span.Hours() > 0 {
			profile.TxFrequency = math.Round(float64(len(txTimes))*100/(span.Hours()/24)) / 100
		}
	}

	// 7. Entity classification
	profile.EntityType = classifyEntityFromBehavior(profile)
	profile.IsBot = profile.EntityType == "bot"

	return profile
}

// inferTimezoneFromPeak estimates UTC offset from peak activity hour.
// Assumption: most entities are active during 9-17 local time,
// with peak around 13:00 local.
func inferTimezoneFromPeak(peakHourUTC int) string {
	// Peak hour in UTC → estimated local 13:00
	offset := peakHourUTC - 13
	if offset > 12 {
		offset -= 24
	}
	if offset < -12 {
		offset += 24
	}

	if offset == 0 {
		return "UTC+0"
	} else if offset > 0 {
		return "UTC+" + itoa(offset)
	}
	return "UTC" + itoa(offset)
}

// itoa is a minimal int-to-string without importing strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	if neg {
		return "-" + digits
	}
	return digits
}

// computeRegularity computes how regular the transaction intervals are.
// Returns 0.0 (completely random) to 1.0 (perfectly periodic).
// Based on coefficient of variation (CV) of inter-tx intervals.
func computeRegularity(times []time.Time) float64 {
	if len(times) < 3 {
		return 0
	}

	// Compute inter-transaction intervals
	intervals := make([]float64, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals[i-1] = times[i].Sub(times[i-1]).Hours()
	}

	// Mean interval
	sum := 0.0
	for _, v := range intervals {
		sum += v
	}
	mean := sum / float64(len(intervals))

	if mean <= 0 {
		return 0
	}

	// Standard deviation
	varianceSum := 0.0
	for _, v := range intervals {
		diff := v - mean
		varianceSum += diff * diff
	}
	stddev := math.Sqrt(varianceSum / float64(len(intervals)))

	// CV = σ/μ → lower CV = more regular
	cv := stddev / mean

	// Convert to regularity: reg = 1 / (1 + CV)
	regularity := 1.0 / (1.0 + cv)

	return math.Round(regularity*100) / 100
}

// classifyEntityFromBehavior infers entity type from behavioral patterns
func classifyEntityFromBehavior(p BehavioralProfile) string {
	switch {
	case p.Regularity >= 0.8 && p.TxFrequency >= 10:
		return "bot" // High regularity + high frequency = automated
	case p.Regularity >= 0.6 && p.TxFrequency >= 5:
		return "service" // Moderate regularity + good frequency = payment processor
	case p.WeekdayRatio >= 0.8 && p.TxFrequency >= 1:
		return "business" // Strongly weekday-biased = business entity
	case p.TxFrequency >= 0.1:
		return "human" // Low frequency, irregular = individual
	default:
		return "unknown"
	}
}

// InferTimezone is a convenience function for single-tx timezone hints.
// Uses block time to estimate the local timezone of the transactor.
func InferTimezone(blockTimeUTC time.Time) string {
	return inferTimezoneFromPeak(blockTimeUTC.UTC().Hour())
}
