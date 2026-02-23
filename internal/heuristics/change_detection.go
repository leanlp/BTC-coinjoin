package heuristics

import (
	"math"
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ChangeDetectionResult captures the multi-heuristic change output analysis.
// Each sub-heuristic votes independently and the final determination
// uses a weighted majority voting scheme.
type ChangeDetectionResult struct {
	ChangeIndex     int     `json:"changeIndex"`     // -1 if no change detected
	Confidence      float64 `json:"confidence"`      // 0.0–1.0
	Method          string  `json:"method"`          // Which heuristic(s) agreed
	IsRoundPayment  bool    `json:"isRoundPayment"`  // The non-change output is a round number
	ScriptTypeMatch bool    `json:"scriptTypeMatch"` // Change matches input script type
}

// DetectChangeOutput implements 5 independent sub-heuristics used by
// Chainalysis, BlockSci, and OXT Research to identify which output
// returns change to the sender:
//
//  1. Optimal Change Heuristic (BlockSci) — the smallest output that is
//     less than any single input
//  2. Round Number Heuristic — payments are typically round numbers (e.g.,
//     0.01 BTC), change is not
//  3. Address/Script Type Matching — change output's address type matches
//     the dominant input address type
//  4. Address Reuse Avoidance — if one output reuses a known input address
//     it's the sender (not change in the traditional sense, but still linkable)
//  5. Shadow Change (Largest Remainder) — in 1-in-2-out transactions,
//     if fee + smaller output ≈ an input value, that smaller output is the change
//
// Returns the index of the most likely change output and a confidence score.
// Explicitly gates against CoinJoin transactions where change detection is meaningless.
func DetectChangeOutput(tx models.Transaction) ChangeDetectionResult {
	result := ChangeDetectionResult{ChangeIndex: -1}

	// Gate: Change detection is only meaningful for non-CoinJoin standard transactions
	if len(tx.Outputs) < 2 || len(tx.Outputs) > 5 {
		return result
	}

	type vote struct {
		index  int
		weight float64
		method string
	}
	var votes []vote

	// ─── Heuristic 1: Optimal Change ───────────────────────────────────
	// The change output is typically the smallest output that is strictly
	// less than the smallest input. This exploits the fact that wallets
	// construct change as the remainder after paying the exact amount.
	if len(tx.Inputs) > 0 {
		minInput := int64(math.MaxInt64)
		for _, in := range tx.Inputs {
			if in.Value > 0 && in.Value < minInput {
				minInput = in.Value
			}
		}

		smallestIdx := -1
		smallestVal := int64(math.MaxInt64)
		for i, out := range tx.Outputs {
			if out.Value > 0 && out.Value < smallestVal && out.Value < minInput {
				smallestVal = out.Value
				smallestIdx = i
			}
		}
		if smallestIdx >= 0 {
			votes = append(votes, vote{smallestIdx, 0.3, "optimal_change"})
		}
	}

	// ─── Heuristic 2: Round Number Detection ───────────────────────────
	// Humans pay in round numbers (0.01, 0.05, 0.1, 0.5, 1.0 BTC etc.)
	// Change is almost never a round number. If exactly one output is
	// non-round and one is round, the non-round one is likely change.
	roundOutputs := make([]bool, len(tx.Outputs))
	for i, out := range tx.Outputs {
		roundOutputs[i] = isRoundAmount(out.Value)
	}

	roundCount := 0
	nonRoundCount := 0
	lastNonRoundIdx := -1
	for i, isRound := range roundOutputs {
		if isRound {
			roundCount++
		} else {
			nonRoundCount++
			lastNonRoundIdx = i
		}
	}

	if roundCount >= 1 && nonRoundCount == 1 {
		votes = append(votes, vote{lastNonRoundIdx, 0.35, "round_number"})
		result.IsRoundPayment = true
	}

	// ─── Heuristic 3: Script/Address Type Matching ─────────────────────
	// Wallets typically generate change to the same address type as the
	// inputs. If inputs are P2WPKH (bc1q...) and one output is P2WPKH
	// while another is P2TR (bc1p...), the P2WPKH output is likely change.
	if len(tx.Inputs) > 0 {
		inputTypes := make(map[string]int)
		for _, in := range tx.Inputs {
			addrType := classifyAddressType(in.Address)
			if addrType != "" {
				inputTypes[addrType]++
			}
		}

		// Find dominant input type
		dominantType := ""
		maxCount := 0
		for t, c := range inputTypes {
			if c > maxCount {
				dominantType = t
				maxCount = c
			}
		}

		if dominantType != "" {
			matchingOutputs := []int{}
			for i, out := range tx.Outputs {
				if classifyAddressType(out.Address) == dominantType {
					matchingOutputs = append(matchingOutputs, i)
				}
			}

			// If exactly one output matches the input type and others don't, it's likely change
			if len(matchingOutputs) == 1 {
				votes = append(votes, vote{matchingOutputs[0], 0.25, "script_type_match"})
				result.ScriptTypeMatch = true
			}
		}
	}

	// ─── Heuristic 4: Address Reuse Check ──────────────────────────────
	// If an output address matches any input address, that output is
	// going back to the sender (self-spend, not typical change but linkable).
	inputAddrs := make(map[string]bool)
	for _, in := range tx.Inputs {
		if in.Address != "" {
			inputAddrs[in.Address] = true
		}
	}
	for i, out := range tx.Outputs {
		if out.Address != "" && inputAddrs[out.Address] {
			votes = append(votes, vote{i, 0.5, "address_reuse_self"})
		}
	}

	// ─── Heuristic 5: Shadow Change (Largest Remainder) ────────────────
	// For 1-in-2-out transactions: the output closest to (input - fee - other_output)
	// is the payment, meaning the other is change. This is essentially
	// fee subtraction analysis.
	if len(tx.Inputs) == 1 && len(tx.Outputs) == 2 {
		inputVal := tx.Inputs[0].Value
		fee := tx.Fee
		for i := range tx.Outputs {
			otherIdx := 1 - i
			expectedPayment := inputVal - fee - tx.Outputs[otherIdx].Value
			if expectedPayment == tx.Outputs[i].Value {
				// Output i is the payment, otherIdx is the change
				votes = append(votes, vote{otherIdx, 0.2, "shadow_change"})
			}
		}
	}

	// ─── Weighted Majority Vote ────────────────────────────────────────
	if len(votes) == 0 {
		return result
	}

	scoreByIndex := make(map[int]float64)
	methodsByIndex := make(map[int][]string)
	for _, v := range votes {
		scoreByIndex[v.index] += v.weight
		methodsByIndex[v.index] = append(methodsByIndex[v.index], v.method)
	}

	bestIdx := -1
	bestScore := 0.0
	for idx, score := range scoreByIndex {
		if score > bestScore {
			bestScore = score
			bestIdx = idx
		}
	}

	if bestIdx >= 0 && bestScore >= 0.25 { // Minimum confidence threshold
		result.ChangeIndex = bestIdx
		result.Confidence = math.Min(bestScore, 1.0)
		result.Method = strings.Join(methodsByIndex[bestIdx], "+")
	}

	return result
}

// isRoundAmount checks if a satoshi value represents a human "round" BTC amount.
// Round amounts: multiples of 0.001 BTC (100,000 sats), 0.01 BTC (1M sats),
// 0.1 BTC (10M sats), etc. Also catches common denominations like 0.0005 BTC.
func isRoundAmount(sats int64) bool {
	if sats <= 0 {
		return false
	}

	// Check common round denominations (in satoshis)
	roundDenominations := []int64{
		100000000, // 1.0 BTC
		50000000,  // 0.5 BTC
		10000000,  // 0.1 BTC
		5000000,   // 0.05 BTC
		1000000,   // 0.01 BTC
		500000,    // 0.005 BTC
		100000,    // 0.001 BTC
		50000,     // 0.0005 BTC
		10000,     // 0.0001 BTC
	}

	for _, denom := range roundDenominations {
		if sats%denom == 0 {
			return true
		}
	}
	return false
}

// classifyAddressType returns the address type based on prefix patterns.
// This is critical for script-type-match change detection.
func classifyAddressType(addr string) string {
	if addr == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(addr, "bc1p"):
		return "p2tr" // Taproot (BIP341)
	case strings.HasPrefix(addr, "bc1q"):
		return "p2wpkh" // Native SegWit (BIP84)
	case strings.HasPrefix(addr, "3"):
		return "p2sh" // Wrapped SegWit / Multisig (BIP49)
	case strings.HasPrefix(addr, "1"):
		return "p2pkh" // Legacy (BIP44)
	case strings.HasPrefix(addr, "tb1p"):
		return "p2tr" // Testnet Taproot
	case strings.HasPrefix(addr, "tb1q"):
		return "p2wpkh" // Testnet SegWit
	default:
		return "unknown"
	}
}
