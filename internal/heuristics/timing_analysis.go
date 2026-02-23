package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Timing & Temporal Analysis Module
//
// Temporal patterns reveal wallet and coordinator behavior that purely
// structural analysis cannot detect. Key signals:
//
//   - Batch payouts: exchanges send consolidated withdrawals every N minutes
//   - Coordinator rounds: Whirlpool runs 5-min rounds, WabiSabi ~10 min
//   - Human activity: payments cluster during business hours in the sender's timezone
//   - Auto-consolidation: wallets periodically merge UTXOs during low-fee windows
//
// These signals are particularly valuable for:
//   1. Exchange attribution (periodic batch withdrawals)
//   2. CoinJoin coordinator identification (round timing)
//   3. Timezone inference (activity hour distribution)
//   4. Bot detection (inhuman timing precision)
//
// References:
//   - Biryukov & Pustogarov, "Bitcoin over Tor isn't a Good Idea" (2015)
//   - Möser & Narayanan, "Anonymous Alone" (IEEE S&P 2017)
//   - Paquet-Clouston et al., "Ransomware Payments in the Bitcoin Ecosystem" (JCSS 2019)

// TimingSignal captures the temporal analysis result for a transaction
type TimingSignal struct {
	HasTimingAnomaly bool    `json:"hasTimingAnomaly"`
	AnomalyType      string  `json:"anomalyType"` // "batch_payout"/"coordinator_round"/"bot_timing"/"none"
	Confidence       float64 `json:"confidence"`
	NLockTimeSignal  string  `json:"nLockTimeSignal"` // "anti-fee-snipe"/"timelock"/"disabled"/"none"
	RBFSignaling     bool    `json:"rbfSignaling"`    // True if any input signals RBF (BIP125)
	VersionSignal    string  `json:"versionSignal"`   // "v1"/"v2-rbf"/"v2-csv"
}

// AnalyzeTimingSignals extracts temporal intelligence from transaction metadata.
// This includes nLockTime analysis, nSequence/RBF detection, and version signals
// that reveal wallet software and user intent.
func AnalyzeTimingSignals(tx models.Transaction) TimingSignal {
	result := TimingSignal{
		AnomalyType:     "none",
		NLockTimeSignal: "none",
		VersionSignal:   "v1",
	}

	// 1. nLockTime analysis
	result.NLockTimeSignal = analyzeNLockTime(tx)

	// 2. RBF signaling (BIP125): any input with nSequence < 0xFFFFFFFE
	result.RBFSignaling = detectRBFSignaling(tx)

	// 3. Transaction version analysis
	result.VersionSignal = analyzeVersion(tx)

	// 4. Detect timing anomalies from structural patterns
	anomaly := detectTimingAnomalies(tx)
	result.HasTimingAnomaly = anomaly.detected
	result.AnomalyType = anomaly.anomalyType
	result.Confidence = anomaly.confidence

	return result
}

// analyzeNLockTime classifies the nLockTime value into behavioral categories.
//
// Bitcoin Core anti-fee-sniping: sets nLockTime = current_block_height
// Timelock: nLockTime is a future block height or timestamp (>= 500_000_000 = Unix time)
// Disabled: nLockTime = 0 (most wallets except Core)
func analyzeNLockTime(tx models.Transaction) string {
	lt := tx.LockTime

	switch {
	case lt == 0:
		return "disabled" // Most non-Core wallets
	case lt >= 500_000_000:
		return "timelock" // Unix timestamp-based timelock
	case lt > 0 && lt < 500_000_000:
		// Block height-based locktime
		// Bitcoin Core sets this to current height for anti-fee-sniping
		if tx.BlockHeight > 0 {
			diff := int(lt) - tx.BlockHeight
			if diff >= -2 && diff <= 0 {
				return "anti-fee-snipe" // Core pattern: locktime ≈ block height
			}
		}
		// If we don't know the block height, assume it's anti-fee-sniping
		// if the value looks like a plausible recent block height
		if lt > 700_000 && lt < 1_000_000 {
			return "anti-fee-snipe"
		}
		return "height-lock"
	default:
		return "none"
	}
}

// detectRBFSignaling checks if any input signals Replace-By-Fee (BIP125).
// An input signals RBF when its nSequence < 0xFFFFFFFE.
// This is used by Bitcoin Core (random nSequence for anti-fee-sniping),
// Electrum (always signals RBF), and some privacy wallets.
func detectRBFSignaling(tx models.Transaction) bool {
	for _, in := range tx.Inputs {
		if in.Sequence > 0 && in.Sequence < 0xFFFFFFFE {
			return true
		}
	}
	return false
}

// analyzeVersion extracts version-based signals.
// Version 2 transactions enable relative timelocks (BIP68/CSV).
func analyzeVersion(tx models.Transaction) string {
	switch tx.Version {
	case 1:
		return "v1"
	case 2:
		// Check if any input uses relative timelock (BIP68)
		for _, in := range tx.Inputs {
			// BIP68: if sequence bit 31 is NOT set, it's a relative timelock
			if in.Sequence > 0 && in.Sequence < 0x80000000 {
				return "v2-csv" // Using CheckSequenceVerify relative locks
			}
		}
		if detectRBFSignaling(tx) {
			return "v2-rbf"
		}
		return "v2"
	default:
		return "unknown"
	}
}

// timingAnomaly holds the internal detection result
type timingAnomaly struct {
	detected    bool
	anomalyType string
	confidence  float64
}

// detectTimingAnomalies looks for structural patterns that correlate with
// specific temporal behaviors (batch payouts, coordinator rounds, bots).
func detectTimingAnomalies(tx models.Transaction) timingAnomaly {
	// Pattern 1: Batch payout (exchange)
	// Exchanges send batched withdrawals: 1 input, many outputs (>10)
	// All outputs are different values, often to different address types
	if len(tx.Inputs) <= 3 && len(tx.Outputs) >= 10 {
		// Check output diversity (exchanges pay to many different addresses)
		addressTypes := make(map[string]int)
		for _, out := range tx.Outputs {
			addressTypes[detectAddressType(out.Address)]++
		}
		if len(addressTypes) >= 2 {
			confidence := math.Min(0.9, 0.5+0.05*float64(len(tx.Outputs)))
			return timingAnomaly{
				detected:    true,
				anomalyType: "batch_payout",
				confidence:  confidence,
			}
		}
	}

	// Pattern 2: Coordinator round signature
	// CoinJoin coordinators create txs with very specific I/O counts
	// Whirlpool: exactly 5 inputs, 5 outputs, equal values
	// WabiSabi: 50-150 inputs, 50-300 outputs
	if len(tx.Inputs) >= 50 && len(tx.Outputs) >= 50 {
		return timingAnomaly{
			detected:    true,
			anomalyType: "coordinator_round",
			confidence:  0.85,
		}
	}

	// Pattern 3: Bot timing (inhuman precision)
	// Bots create transactions with perfectly consistent sizes and fee rates.
	// If all inputs have the same value AND all outputs have the same value
	// AND it's not a CoinJoin, it's likely automated.
	if len(tx.Inputs) >= 3 && len(tx.Outputs) >= 3 {
		allSameInput := true
		firstVal := tx.Inputs[0].Value
		for _, in := range tx.Inputs[1:] {
			if in.Value != firstVal {
				allSameInput = false
				break
			}
		}
		allSameOutput := true
		firstOut := tx.Outputs[0].Value
		for _, out := range tx.Outputs[1:] {
			if out.Value != firstOut {
				allSameOutput = false
				break
			}
		}
		if allSameInput && allSameOutput {
			return timingAnomaly{
				detected:    true,
				anomalyType: "bot_timing",
				confidence:  0.70,
			}
		}
	}

	return timingAnomaly{
		anomalyType: "none",
	}
}

// InferWalletFromTiming combines nLockTime, RBF, and version signals
// to enhance wallet family attribution.
//
//	Bitcoin Core: anti-fee-snipe + RBF + v2
//	Electrum:     disabled locktime + RBF + v2
//	Samourai:     disabled locktime + no RBF + v1
//	Green:        anti-fee-snipe + no RBF + v2 (CSV multisig)
func InferWalletFromTiming(signal TimingSignal) string {
	switch {
	case signal.NLockTimeSignal == "anti-fee-snipe" && signal.RBFSignaling:
		return "bitcoin-core"
	case signal.NLockTimeSignal == "disabled" && signal.RBFSignaling:
		return "electrum"
	case signal.NLockTimeSignal == "disabled" && !signal.RBFSignaling && signal.VersionSignal == "v1":
		return "samourai"
	case signal.NLockTimeSignal == "anti-fee-snipe" && signal.VersionSignal == "v2-csv":
		return "blockstream-green"
	default:
		return "unknown"
	}
}
