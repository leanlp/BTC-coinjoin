package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Dust Attack Detection Module
//
// Dust attacks are an ACTIVE SURVEILLANCE technique: an adversary sends
// tiny UTXOs (546-1000 sats) to target addresses. When the victim's wallet
// automatically consolidates these dust inputs with its real UTXOs, the
// adversary links the otherwise-unconnected addresses together.
//
// This is the primary technique used by Chainalysis to bridge CoinJoin
// outputs back to known exchange deposit addresses.
//
// Dust thresholds (Bitcoin Core relay policy):
//   P2PKH:   546 sats (34-byte output)
//   P2SH:    540 sats (32-byte output)
//   P2WPKH:  294 sats (31-byte output)
//   P2WSH:   330 sats (43-byte output)
//   P2TR:    330 sats (43-byte output)
//
// References:
//   - de Balthasar & Hernandez-Castro, "An Analysis of Bitcoin Laundry Services" (2017)
//   - Möser & Narayanan, "Obfuscation in Bitcoin" (2017)
//   - Biryukov et al., "Deanonymisation of Clients in Bitcoin P2P Network" (CCS 2014)

// Dust threshold per output type (in satoshis)
const (
	DustThresholdP2PKH   = 546
	DustThresholdP2SH    = 540
	DustThresholdP2WPKH  = 294
	DustThresholdP2WSH   = 330
	DustThresholdP2TR    = 330
	DustThresholdGeneric = 546 // Conservative default
)

// DetectDustAttack analyzes a transaction for dust attack indicators.
// It checks both outputs (sending dust = potential attack) and inputs
// (spending dust = post-attack consolidation, the dangerous part).
func DetectDustAttack(tx models.Transaction) models.DustResult {
	result := models.DustResult{
		Intent:    "none",
		RiskLevel: "none",
	}

	// Analyze outputs for dust creation
	for _, out := range tx.Outputs {
		threshold := getDustThreshold(out.Address)
		if out.Value > 0 && out.Value <= threshold {
			result.HasDustOutputs = true
			result.DustOutputCount++
			result.TotalDustValue += out.Value
		}
	}

	// Analyze inputs for dust spending (consolidation)
	for _, in := range tx.Inputs {
		threshold := getDustThreshold(in.Address)
		if in.Value > 0 && in.Value <= threshold {
			result.HasDustInputs = true
			result.DustInputCount++
			result.TotalDustValue += in.Value
		}
	}

	// Classify intent
	result.Intent = classifyDustIntent(tx, result)
	result.RiskLevel = assessDustRisk(result)

	return result
}

// getDustThreshold returns the dust limit for a given address type
func getDustThreshold(addr string) int64 {
	addrType := detectAddressType(addr)
	switch addrType {
	case "taproot":
		return DustThresholdP2TR
	case "segwit":
		return DustThresholdP2WPKH
	case "p2sh-segwit":
		return DustThresholdP2SH
	case "legacy":
		return DustThresholdP2PKH
	default:
		return DustThresholdGeneric
	}
}

// classifyDustIntent determines the likely purpose of dust in a transaction.
//
//	"surveillance" — Many small outputs sent to diverse addresses (active attack)
//	"spam"         — Mass dust creation to many outputs (OP_RETURN spam, stress test)
//	"consolidation" — Dust inputs being swept alongside real UTXOs (victim response)
//	"none"          — No significant dust involvement
func classifyDustIntent(tx models.Transaction, dust models.DustResult) string {
	// Case 1: Creating dust outputs to many different addresses
	if dust.HasDustOutputs && dust.DustOutputCount >= 3 {
		// Multiple dust outputs to different addresses = surveillance
		uniqueAddrs := make(map[string]bool)
		for _, out := range tx.Outputs {
			threshold := getDustThreshold(out.Address)
			if out.Value > 0 && out.Value <= threshold {
				uniqueAddrs[out.Address] = true
			}
		}
		if len(uniqueAddrs) >= 3 {
			return "surveillance"
		}
		return "spam"
	}

	// Case 2: Spending dust inputs alongside real inputs (the dangerous consolidation)
	if dust.HasDustInputs && len(tx.Inputs) > dust.DustInputCount {
		// Mixing dust with non-dust inputs = consolidation trap sprung
		return "consolidation"
	}

	// Case 3: Single dust output (could be accidental or intentional probe)
	if dust.HasDustOutputs && dust.DustOutputCount == 1 {
		// Single dust output — possible targeted surveillance probe
		nonDustOutputs := 0
		for _, out := range tx.Outputs {
			threshold := getDustThreshold(out.Address)
			if out.Value > threshold {
				nonDustOutputs++
			}
		}
		if nonDustOutputs >= 1 {
			return "surveillance"
		}
	}

	return "none"
}

// assessDustRisk determines the severity of the dust threat
func assessDustRisk(dust models.DustResult) string {
	switch dust.Intent {
	case "consolidation":
		// Consolidating dust = the attack has succeeded
		if dust.DustInputCount >= 3 {
			return "critical" // Multiple dust sources consolidated
		}
		return "high"
	case "surveillance":
		if dust.DustOutputCount >= 5 {
			return "high" // Broad scatter indicates sophisticated adversary
		}
		return "medium"
	case "spam":
		return "low"
	default:
		return "none"
	}
}
