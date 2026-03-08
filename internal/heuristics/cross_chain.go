package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Cross-Chain Correlation Engine (Phase 18)
//
// Correlates transactions across different blockchains to detect
// cross-chain swaps, atomic swaps, DEX trades, and bridge transfers.
//
// Correlation methods:
//   - Temporal window matching: |t_out - t_in| < Δt_max
//   - Value matching: Value(in) × rate ≈ Value(out) ± tolerance
//   - Pattern matching: Known atomic swap HTLC structures
//
// Initially supports manual correlation via API input. The data model
// is designed to accommodate automated correlation via exchange API feeds.
//
// References:
//   - Herlihy, "Atomic Cross-Chain Swaps" (PODC 2018)
//   - Hoenisch & Del Pino, "Atomic Swaps between Bitcoin and Monero" (2020)

const (
	// crossChainMaxTimeDelta is the maximum acceptable time difference
	// between cross-chain correlated transactions (2 hours).
	crossChainMaxTimeDelta = 7200.0

	// crossChainValueTolerance is the acceptable deviation in value
	// matching after exchange rate conversion (±5%).
	crossChainValueTolerance = 0.05
)

// AnalyzeCrossChainSwap evaluates the correlation between two transactions
// potentially representing a cross-chain swap.
func AnalyzeCrossChainSwap(
	srcChain string, srcTxid string, srcValue int64, srcTimestamp int64,
	dstChain string, dstTxid string, dstValue int64, dstTimestamp int64,
	exchangeRate float64,
) models.CrossChainCorrelation {

	result := models.CrossChainCorrelation{
		SourceChain: srcChain,
		DestChain:   dstChain,
		SourceTxid:  srcTxid,
		DestTxid:    dstTxid,
		SourceValue: srcValue,
		DestValue:   dstValue,
		ExchangeRate: exchangeRate,
	}

	// 1. Temporal correlation
	timeDelta := math.Abs(float64(dstTimestamp - srcTimestamp))
	result.TimeDeltaSeconds = timeDelta

	if timeDelta > crossChainMaxTimeDelta {
		result.Confidence = 0
		result.SwapType = "none"
		return result
	}

	// 2. Value correlation (after exchange rate conversion)
	expectedDstValue := float64(srcValue) * exchangeRate
	if expectedDstValue > 0 {
		deviation := math.Abs(float64(dstValue)-expectedDstValue) / expectedDstValue
		result.ValueMatchScore = math.Max(0, 1.0-deviation/crossChainValueTolerance)
	}

	// 3. Classify swap type
	result.SwapType = classifySwapType(srcChain, dstChain, timeDelta)

	// 4. Compute overall confidence
	// Weighted: 40% value match + 30% time proximity + 30% swap type
	timeScore := math.Max(0, 1.0-timeDelta/crossChainMaxTimeDelta)

	swapTypeScore := 0.5 // default
	switch result.SwapType {
	case "atomic":
		swapTypeScore = 1.0
	case "exchange":
		swapTypeScore = 0.7
	case "dex":
		swapTypeScore = 0.8
	case "bridge":
		swapTypeScore = 0.6
	}

	result.Confidence = math.Round(
		(0.4*result.ValueMatchScore+0.3*timeScore+0.3*swapTypeScore)*10000) / 10000

	result.IsCorrelated = result.Confidence >= 0.5

	return result
}

// classifySwapType determines the likely swap mechanism based on chains and timing.
func classifySwapType(srcChain, dstChain string, timeDelta float64) string {
	// Atomic swaps: BTC ↔ LTC, BTC ↔ DCR (HTLC-based, very tight timing)
	atomicPairs := map[string]bool{
		"BTC-LTC": true, "LTC-BTC": true,
		"BTC-DCR": true, "DCR-BTC": true,
	}
	pair := srcChain + "-" + dstChain
	if atomicPairs[pair] && timeDelta < 600 {
		return "atomic"
	}

	// Cross-chain bridges: typically ETH ↔ BTC (wBTC), BSC ↔ ETH
	bridgePairs := map[string]bool{
		"BTC-ETH": true, "ETH-BTC": true,
		"ETH-BSC": true, "BSC-ETH": true,
	}
	if bridgePairs[pair] {
		return "bridge"
	}

	// DEX: usually involves XMR (privacy → public or vice versa)
	if srcChain == "XMR" || dstChain == "XMR" {
		return "dex"
	}

	// Default: centralized exchange
	return "exchange"
}
