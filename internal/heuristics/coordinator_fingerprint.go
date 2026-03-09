package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// CoinJoin Coordinator Fingerprinting & Sybil Attack Detection
//
// T3: Different CoinJoin coordinators leave distinct on-chain signatures.
//     Identifying the protocol enables targeted deanonymization attacks.
//
// T4: If a single entity controls multiple inputs in a CoinJoin round,
//     they know which outputs belong to the OTHER participants.
//     This is the Sybil attack — and it's more common than people think.
//
// References:
//   - Ficsór et al., "WabiSabi" (2021) — Section 3 on coordinator design
//   - Goldfeder et al., "When the Cookie Meets the Blockchain" (IEEE S&P 2018)
//   - Atlas, "Applying Boltzmann to Wasabi 2.0" (2022)

// CoinJoinProtocol identifies the mixing protocol used
type CoinJoinProtocol string

const (
	ProtocolWhirlpool CoinJoinProtocol = "whirlpool"
	ProtocolWasabi1   CoinJoinProtocol = "wasabi_1.0"
	ProtocolWasabi2   CoinJoinProtocol = "wasabi_2.0"
	ProtocolJoinMarket CoinJoinProtocol = "joinmarket"
	ProtocolUnknown   CoinJoinProtocol = "unknown_coinjoin"
)

// CoordinatorFingerprint holds the protocol identification result
type CoordinatorFingerprint struct {
	Protocol        CoinJoinProtocol `json:"protocol"`
	Confidence      float64          `json:"confidence"`
	Signals         []string         `json:"signals"`          // Which features matched
	PoolDenom       int64            `json:"poolDenom,omitempty"` // For Whirlpool: pool denomination
	Vulnerability   string           `json:"vulnerability"`    // Known weaknesses of this protocol
}

// Whirlpool pool denominations (in sats)
var coordinatorWhirlpoolPools = map[int64]string{
	100000000: "pool_1_btc",
	50000000:  "pool_05_btc",
	5000000:   "pool_005_btc",
	1000000:   "pool_001_btc",
}

// IdentifyCoordinator determines which CoinJoin protocol was used
// by analyzing structural features of the transaction.
func IdentifyCoordinator(tx models.Transaction, isCoinJoin bool) CoordinatorFingerprint {
	result := CoordinatorFingerprint{
		Protocol: ProtocolUnknown,
	}

	if !isCoinJoin || len(tx.Inputs) < 2 || len(tx.Outputs) < 2 {
		return result
	}

	// ═══ Whirlpool Detection ═════════════════════════════════════════
	// Whirlpool signatures:
	//   1. Exactly N equal outputs (same denomination)
	//   2. Input count == output count (no change outputs in pool txs)
	//   3. Known pool denominations (0.01, 0.05, 0.5, 1.0 BTC)
	//   4. 5 participants typical (but can be higher in Tx0)
	//   5. nVersion = 1
	whirlpoolScore := 0.0
	var whirlpoolSignals []string

	equalOutputGroups := groupEqualOutputs(tx.Outputs)
	largestGroup := 0
	var largestDenom int64
	for denom, count := range equalOutputGroups {
		if count > largestGroup {
			largestGroup = count
			largestDenom = denom
		}
	}

	if largestGroup >= 5 && largestGroup == len(tx.Inputs) {
		whirlpoolScore += 0.30
		whirlpoolSignals = append(whirlpoolSignals, "equal_outputs_match_inputs")
	}

	if _, isPool := coordinatorWhirlpoolPools[largestDenom]; isPool {
		whirlpoolScore += 0.35
		whirlpoolSignals = append(whirlpoolSignals, "known_pool_denomination")
		result.PoolDenom = largestDenom
	}

	if len(tx.Outputs) == len(tx.Inputs) {
		whirlpoolScore += 0.15
		whirlpoolSignals = append(whirlpoolSignals, "no_change_outputs")
	}

	if tx.Version == 1 {
		whirlpoolScore += 0.10
		whirlpoolSignals = append(whirlpoolSignals, "nVersion=1")
	}

	// ═══ Wasabi 2.0 (WabiSabi) Detection ═════════════════════════════
	// WabiSabi signatures:
	//   1. Variable denominations (NOT all equal — key differentiator from Whirlpool)
	//   2. Large participant count (often 50-150 participants)
	//   3. Coordinator fee output (small, specific address)
	//   4. nVersion = 1, nLockTime = current height (anti-fee-sniping)
	//   5. Many outputs with "round" sub-BTC values
	wasabiScore := 0.0
	var wasabiSignals []string

	uniqueDenoms := len(equalOutputGroups)
	if uniqueDenoms > 5 && len(tx.Outputs) > 20 {
		wasabiScore += 0.30
		wasabiSignals = append(wasabiSignals, "variable_denominations")
	}

	if len(tx.Inputs) > 30 && len(tx.Outputs) > 30 {
		wasabiScore += 0.25
		wasabiSignals = append(wasabiSignals, "large_participant_count")
	}

	if tx.Version == 1 && tx.LockTime > 0 {
		wasabiScore += 0.20
		wasabiSignals = append(wasabiSignals, "nVersion=1+anti_fee_sniping")
	}

	// Check for coordinator fee output (small value output)
	hasSmallOutput := false
	for _, out := range tx.Outputs {
		if out.Value > 0 && out.Value < 50000 { // < 50k sats likely coordinator fee
			hasSmallOutput = true
			break
		}
	}
	if hasSmallOutput && len(tx.Outputs) > 20 {
		wasabiScore += 0.15
		wasabiSignals = append(wasabiSignals, "coordinator_fee_output")
	}

	// ═══ JoinMarket Detection ════════════════════════════════════════
	// JoinMarket signatures:
	//   1. Maker/taker structure: some outputs are equal (makers), taker has different amount
	//   2. Typically smaller (2-9 participants)
	//   3. Makers charge a fee (visible as value difference)
	//   4. More ad-hoc structure
	joinmarketScore := 0.0
	var joinmarketSignals []string

	if largestGroup >= 2 && largestGroup < len(tx.Outputs) {
		// Some equal outputs (makers) + some different (taker + change)
		nonEqualOutputs := len(tx.Outputs) - largestGroup
		if nonEqualOutputs >= 1 && nonEqualOutputs <= 3 && largestGroup <= 9 {
			joinmarketScore += 0.30
			joinmarketSignals = append(joinmarketSignals, "maker_taker_structure")
		}
	}

	if len(tx.Inputs) >= 2 && len(tx.Inputs) <= 12 {
		joinmarketScore += 0.15
		joinmarketSignals = append(joinmarketSignals, "small_participant_count")
	}

	// ═══ Select Best Match ═══════════════════════════════════════════
	type candidate struct {
		protocol CoinJoinProtocol
		score    float64
		signals  []string
		vuln     string
	}

	candidates := []candidate{
		{ProtocolWhirlpool, whirlpoolScore, whirlpoolSignals,
			"Fixed denomination enables intersection attacks across rounds. Tx0 structure reveals pre-mix UTXO ownership."},
		{ProtocolWasabi2, wasabiScore, wasabiSignals,
			"Variable denominations enable sub-transaction linking via Boltzmann analysis. Large rounds may contain Sybil participants."},
		{ProtocolJoinMarket, joinmarketScore, joinmarketSignals,
			"Maker/taker asymmetry reveals taker identity (the one with non-matching output). Small rounds have low anonymity sets."},
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.score > best.score {
			best = c
		}
	}

	if best.score >= 0.30 {
		result.Protocol = best.protocol
		result.Confidence = best.score
		result.Signals = best.signals
		result.Vulnerability = best.vuln
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════
// T4: Sybil Attack Detection on CoinJoin
// ═══════════════════════════════════════════════════════════════════════

// SybilAnalysis holds the result of Sybil detection on a CoinJoin round
type SybilAnalysis struct {
	IsSybilVulnerable bool    `json:"isSybilVulnerable"`
	SybilInputCount   int     `json:"sybilInputCount"`   // Inputs controlled by same entity
	TotalInputCount   int     `json:"totalInputCount"`
	SybilRatio        float64 `json:"sybilRatio"`        // sybilInputs / totalInputs
	AffectedAnonSet   int     `json:"affectedAnonSet"`   // Effective anonset after Sybil
	OriginalAnonSet   int     `json:"originalAnonSet"`
	LargestClusterSize int    `json:"largestClusterSize"` // Biggest group of same-entity inputs
	Confidence        float64 `json:"confidence"`
}

// DetectSybilAttack checks if a CoinJoin round has been compromised
// by a single entity controlling multiple inputs.
func DetectSybilAttack(tx models.Transaction, anonSet int) SybilAnalysis {
	result := SybilAnalysis{
		TotalInputCount: len(tx.Inputs),
		OriginalAnonSet: anonSet,
	}

	if len(tx.Inputs) < 3 {
		return result
	}

	clusterEngine := GetGlobalClusterEngine()
	if clusterEngine == nil {
		return result
	}

	// Group inputs by cluster root
	clusterGroups := make(map[string]int) // cluster root → count
	for _, in := range tx.Inputs {
		if in.Address == "" {
			continue
		}
		root := clusterEngine.Find(in.Address)
		clusterGroups[root]++
	}

	// Find the largest cluster group
	largestCluster := 0
	for _, count := range clusterGroups {
		if count > largestCluster {
			largestCluster = count
		}
	}
	result.LargestClusterSize = largestCluster

	// Count Sybil inputs: any cluster controlling >1 input
	sybilCount := 0
	for _, count := range clusterGroups {
		if count > 1 {
			sybilCount += count
		}
	}
	result.SybilInputCount = sybilCount

	if result.TotalInputCount > 0 {
		result.SybilRatio = float64(sybilCount) / float64(result.TotalInputCount)
	}

	// Effective anonset: reduce by the Sybil-controlled fraction
	// If entity controls 3 of 5 inputs → effective anonset = 5 - 3 + 1 = 3
	// (the entity knows its own 3 inputs, leaving 2 unknown + the entity itself)
	distinctEntities := len(clusterGroups)
	if distinctEntities < anonSet {
		result.AffectedAnonSet = distinctEntities
	} else {
		result.AffectedAnonSet = anonSet
	}

	// Vulnerability thresholds
	if result.SybilRatio > 0.5 {
		result.IsSybilVulnerable = true
		result.Confidence = 0.90
	} else if result.SybilRatio > 0.3 {
		result.IsSybilVulnerable = true
		result.Confidence = 0.70
	} else if largestCluster > 1 {
		result.IsSybilVulnerable = false // Some clustering but not majority
		result.Confidence = 0.40
	}

	return result
}

// groupEqualOutputs groups outputs by value and returns value → count
func groupEqualOutputs(outputs []models.TxOut) map[int64]int {
	groups := make(map[int64]int)
	for _, out := range outputs {
		groups[out.Value]++
	}
	return groups
}
