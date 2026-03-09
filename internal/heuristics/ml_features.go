package heuristics

import (
	"math"
	"sort"
	"sync"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// CoinJoin Feature Extractor (30+ features for ML classification)
// ═══════════════════════════════════════════════════════════════════════

// TxFeatureVector holds extracted features for ML classification
type TxFeatureVector struct {
	InputCount       int     `json:"inputCount"`
	OutputCount      int     `json:"outputCount"`
	IOProduct        int     `json:"ioProduct"`
	IORatio          float64 `json:"ioRatio"`
	TotalInputValue  int64   `json:"totalInputValue"`
	TotalOutputValue int64   `json:"totalOutputValue"`
	Fee              int64   `json:"fee"`
	FeeRate          float64 `json:"feeRate"`
	Vsize            int     `json:"vsize"`

	MaxEqualOutputs             int     `json:"maxEqualOutputs"`
	EqualOutputRatio            float64 `json:"equalOutputRatio"`
	OutputGini                  float64 `json:"outputGini"`
	OutputEntropy               float64 `json:"outputEntropy"`
	OutputStdDev                float64 `json:"outputStdDev"`
	OutputCoefficientOfVariation float64 `json:"outputCV"`

	SmallestOutput   int64   `json:"smallestOutput"`
	LargestOutput    int64   `json:"largestOutput"`
	MedianOutput     int64   `json:"medianOutput"`
	OutputRange      int64   `json:"outputRange"`
	RoundOutputRatio float64 `json:"roundOutputRatio"`

	UniqueScriptTypes int  `json:"uniqueScriptTypes"`
	HasSegWit         bool `json:"hasSegWit"`
	HasTaproot        bool `json:"hasTaproot"`
	MixedScriptTypes  bool `json:"mixedScriptTypes"`

	IsBIP69      bool   `json:"isBIP69"`
	InputsSorted bool   `json:"inputsSorted"`
	LockTime     uint32 `json:"lockTime"`
	Version      int32  `json:"version"`

	HasLikelyChange    bool    `json:"hasLikelyChange"`
	ChangeRatio        float64 `json:"changeRatio"`
	CoinJoinLikelihood float64 `json:"coinJoinLikelihood"`
}

// ExtractFeatures computes a full feature vector from a transaction
func ExtractFeatures(tx models.Transaction) TxFeatureVector {
	f := TxFeatureVector{
		InputCount: len(tx.Inputs), OutputCount: len(tx.Outputs),
		Fee: tx.Fee, Vsize: tx.Vsize, LockTime: tx.LockTime, Version: tx.Version,
	}
	if f.InputCount > 0 && f.OutputCount > 0 {
		f.IOProduct = f.InputCount * f.OutputCount
		f.IORatio = float64(f.InputCount) / float64(f.OutputCount)
	}
	if tx.Vsize > 0 {
		f.FeeRate = float64(tx.Fee) / float64(tx.Vsize)
	}

	for _, in := range tx.Inputs {
		f.TotalInputValue += in.Value
	}

	outputVals := make([]int64, len(tx.Outputs))
	valueCounts := make(map[int64]int)
	scriptTypes := make(map[string]bool)
	inputScriptTypes := make(map[string]bool)
	roundOutputs := 0

	for i, out := range tx.Outputs {
		outputVals[i] = out.Value
		f.TotalOutputValue += out.Value
		valueCounts[out.Value]++
		addrType := ClassifyAddressType(out.Address)
		scriptTypes[addrType] = true
		if addrType == "P2WPKH" || addrType == "P2WSH" {
			f.HasSegWit = true
		}
		if addrType == "P2TR" {
			f.HasTaproot = true
		}
		if out.Value > 0 && out.Value%100000 == 0 {
			roundOutputs++
		}
	}
	for _, in := range tx.Inputs {
		inputScriptTypes[ClassifyAddressType(in.Address)] = true
	}

	f.MixedScriptTypes = len(inputScriptTypes) > 1
	f.UniqueScriptTypes = len(scriptTypes)
	if len(tx.Outputs) > 0 {
		f.RoundOutputRatio = float64(roundOutputs) / float64(len(tx.Outputs))
	}

	maxEqual := 0
	for _, count := range valueCounts {
		if count > maxEqual {
			maxEqual = count
		}
	}
	f.MaxEqualOutputs = maxEqual
	if len(tx.Outputs) > 0 {
		f.EqualOutputRatio = float64(maxEqual) / float64(len(tx.Outputs))
	}

	sort.Slice(outputVals, func(i, j int) bool { return outputVals[i] < outputVals[j] })
	if len(outputVals) > 0 {
		f.SmallestOutput = outputVals[0]
		f.LargestOutput = outputVals[len(outputVals)-1]
		f.MedianOutput = outputVals[len(outputVals)/2]
		f.OutputRange = f.LargestOutput - f.SmallestOutput
	}

	f.OutputGini = computeGini(outputVals)
	f.OutputEntropy = computeShannonEntropy(outputVals)

	if len(outputVals) > 1 {
		mean := float64(f.TotalOutputValue) / float64(len(outputVals))
		sumSqDiff := 0.0
		for _, v := range outputVals {
			diff := float64(v) - mean
			sumSqDiff += diff * diff
		}
		f.OutputStdDev = math.Sqrt(sumSqDiff / float64(len(outputVals)))
		if mean > 0 {
			f.OutputCoefficientOfVariation = f.OutputStdDev / mean
		}
	}

	if len(tx.Outputs) == 2 {
		ratio := float64(f.SmallestOutput) / float64(f.LargestOutput)
		if ratio < 0.1 {
			f.HasLikelyChange = true
			f.ChangeRatio = ratio
		}
	}

	f.CoinJoinLikelihood = computeCoinJoinLikelihood(f)
	return f
}

func computeCoinJoinLikelihood(f TxFeatureVector) float64 {
	score := 0.0
	if f.EqualOutputRatio >= 0.5 && f.MaxEqualOutputs >= 3 {
		score += 0.40
	}
	if f.MixedScriptTypes {
		score += 0.15
	}
	if f.InputCount >= 3 && f.OutputCount >= 3 {
		score += 0.15
	}
	if f.OutputGini < 0.3 {
		score += 0.15
	}
	if f.IsBIP69 {
		score += 0.10
	}
	if f.OutputEntropy > 2.0 {
		score += 0.05
	}
	return math.Min(score, 1.0)
}

func computeGini(values []int64) float64 {
	n := len(values)
	if n <= 1 {
		return 0
	}
	sum := int64(0)
	for _, v := range values {
		sum += v
	}
	if sum == 0 {
		return 0
	}
	absSum := 0.0
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			diff := values[i] - values[j]
			if diff < 0 {
				diff = -diff
			}
			absSum += float64(diff)
		}
	}
	return absSum / (2.0 * float64(n) * float64(sum))
}

func computeShannonEntropy(values []int64) float64 {
	total := int64(0)
	for _, v := range values {
		total += v
	}
	if total == 0 {
		return 0
	}
	entropy := 0.0
	for _, v := range values {
		if v > 0 {
			p := float64(v) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// ═══════════════════════════════════════════════════════════════════════
// Statistical Anomaly Detector (Welford's online z-score)
// ═══════════════════════════════════════════════════════════════════════

type AnomalyResult struct {
	IsAnomaly    bool      `json:"isAnomaly"`
	AnomalyScore float64   `json:"anomalyScore"`
	Anomalies    []Anomaly `json:"anomalies"`
}

type Anomaly struct {
	Feature string  `json:"feature"`
	Value   float64 `json:"value"`
	ZScore  float64 `json:"zScore"`
}

type AnomalyDetector struct {
	mu    sync.RWMutex
	stats map[string]*runningStats
	count int
}

type runningStats struct {
	n    int
	mean float64
	m2   float64
}

var (
	globalAnomalyDetector *AnomalyDetector
	anomalyDetectorOnce   sync.Once
)

func GetGlobalAnomalyDetector() *AnomalyDetector {
	anomalyDetectorOnce.Do(func() {
		globalAnomalyDetector = &AnomalyDetector{stats: make(map[string]*runningStats)}
	})
	return globalAnomalyDetector
}

func (ad *AnomalyDetector) RecordFeatures(f TxFeatureVector) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.count++
	ad.updateStat("inputCount", float64(f.InputCount))
	ad.updateStat("outputCount", float64(f.OutputCount))
	ad.updateStat("fee", float64(f.Fee))
	ad.updateStat("feeRate", f.FeeRate)
	ad.updateStat("totalValue", float64(f.TotalOutputValue))
	ad.updateStat("outputGini", f.OutputGini)
	ad.updateStat("outputEntropy", f.OutputEntropy)
	ad.updateStat("ioRatio", f.IORatio)
}

func (ad *AnomalyDetector) updateStat(name string, value float64) {
	s, exists := ad.stats[name]
	if !exists {
		s = &runningStats{}
		ad.stats[name] = s
	}
	s.n++
	delta := value - s.mean
	s.mean += delta / float64(s.n)
	delta2 := value - s.mean
	s.m2 += delta * delta2
}

func (ad *AnomalyDetector) DetectAnomalies(f TxFeatureVector) AnomalyResult {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	result := AnomalyResult{}
	if ad.count < 100 {
		return result
	}

	threshold := 3.0
	checks := map[string]float64{
		"inputCount": float64(f.InputCount), "outputCount": float64(f.OutputCount),
		"fee": float64(f.Fee), "feeRate": f.FeeRate,
		"totalValue": float64(f.TotalOutputValue), "outputGini": f.OutputGini,
		"outputEntropy": f.OutputEntropy, "ioRatio": f.IORatio,
	}

	totalZ := 0.0
	anomalyCount := 0
	for name, value := range checks {
		s, exists := ad.stats[name]
		if !exists || s.n < 50 {
			continue
		}
		variance := s.m2 / float64(s.n)
		stdDev := math.Sqrt(variance)
		if stdDev == 0 {
			continue
		}
		zScore := math.Abs(value-s.mean) / stdDev
		totalZ += zScore
		if zScore > threshold {
			anomalyCount++
			result.Anomalies = append(result.Anomalies, Anomaly{Feature: name, Value: value, ZScore: zScore})
		}
	}

	if anomalyCount > 0 {
		result.IsAnomaly = true
		result.AnomalyScore = math.Min(totalZ/float64(len(checks)*3), 1.0)
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════
// Entity Behavior Tracker (long-term wallet profiling)
// ═══════════════════════════════════════════════════════════════════════

// EntityBehavior profiles an entity's long-term transaction behavior
type EntityBehavior struct {
	EntityID       string  `json:"entityId"`
	TxCount        int     `json:"txCount"`
	AvgInputCount  float64 `json:"avgInputCount"`
	AvgOutputCount float64 `json:"avgOutputCount"`
	AvgFeeRate     float64 `json:"avgFeeRate"`
	AvgValue       float64 `json:"avgValue"`
	UsesRBF        bool    `json:"usesRBF"`
	UsesBIP69      bool    `json:"usesBIP69"`
	UsesSegWit     bool    `json:"usesSegWit"`
	UsesTaproot    bool    `json:"usesTaproot"`
	Consistency    float64 `json:"consistency"`
}

type EntityTracker struct {
	mu       sync.RWMutex
	profiles map[string]*entityAccumulator
}

type entityAccumulator struct {
	txCount      int
	inputSum     int
	outputSum    int
	feeRateSum   float64
	valueSum     float64
	segwitCount  int
	taprootCount int
	bip69Count   int
	rbfCount     int
}

var (
	globalEntityTracker *EntityTracker
	entityTrackerOnce   sync.Once
)

func GetGlobalEntityTracker() *EntityTracker {
	entityTrackerOnce.Do(func() {
		globalEntityTracker = &EntityTracker{profiles: make(map[string]*entityAccumulator)}
	})
	return globalEntityTracker
}

func (et *EntityTracker) RecordBehavior(entityID string, f TxFeatureVector) {
	et.mu.Lock()
	defer et.mu.Unlock()
	acc, exists := et.profiles[entityID]
	if !exists {
		acc = &entityAccumulator{}
		et.profiles[entityID] = acc
	}
	acc.txCount++
	acc.inputSum += f.InputCount
	acc.outputSum += f.OutputCount
	acc.feeRateSum += f.FeeRate
	acc.valueSum += float64(f.TotalOutputValue)
	if f.HasSegWit {
		acc.segwitCount++
	}
	if f.HasTaproot {
		acc.taprootCount++
	}
	if f.IsBIP69 {
		acc.bip69Count++
	}
	if f.Version == 2 {
		acc.rbfCount++
	}
}

func (et *EntityTracker) GetBehavior(entityID string) *EntityBehavior {
	et.mu.RLock()
	defer et.mu.RUnlock()
	acc, exists := et.profiles[entityID]
	if !exists || acc.txCount == 0 {
		return nil
	}
	n := float64(acc.txCount)
	return &EntityBehavior{
		EntityID: entityID, TxCount: acc.txCount,
		AvgInputCount: float64(acc.inputSum) / n, AvgOutputCount: float64(acc.outputSum) / n,
		AvgFeeRate: acc.feeRateSum / n, AvgValue: acc.valueSum / n,
		UsesRBF: float64(acc.rbfCount)/n > 0.5, UsesBIP69: float64(acc.bip69Count)/n > 0.5,
		UsesSegWit: float64(acc.segwitCount)/n > 0.5, UsesTaproot: float64(acc.taprootCount)/n > 0.5,
		Consistency: entityConsistency(acc),
	}
}

func entityConsistency(acc *entityAccumulator) float64 {
	if acc.txCount < 5 {
		return 0
	}
	n := float64(acc.txCount)
	total := 0.0
	for _, ratio := range []float64{
		float64(acc.segwitCount) / n, float64(acc.bip69Count) / n, float64(acc.rbfCount) / n,
	} {
		if ratio > 0.8 || ratio < 0.2 {
			total += 1.0
		} else {
			total += 0.5
		}
	}
	return total / 3.0
}
