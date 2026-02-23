package heuristics

import (
	"log"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// WatchListMonitor tracks and gates transactions exhibiting signatures
// of new privacy-enhancing protocols (BIP352, BIP77, BIP324/330) that break
// traditional observation assumptions.
//
// If a transaction matches these signatures, it is assigned a Policy-Gated flag
// and explicitly walled off from naive deterministic clustering.
type WatchListMonitor struct {
	Active bool
}

func NewWatchListMonitor() *WatchListMonitor {
	return &WatchListMonitor{
		Active: true,
	}
}

// Evaluate checks a transaction against all active watch list heuristics.
func (w *WatchListMonitor) Evaluate(tx models.Transaction) uint64 {
	var flags uint64 = 0

	if !w.Active {
		return flags
	}

	flags |= w.detectSilentPayments(tx)
	flags |= w.detectPayJoinV3(tx)
	flags |= w.detectNetworkRoutingDrift(tx)
	flags |= w.detectJoinMarketBond(tx)

	if flags > 0 {
		log.Printf("[WatchList] Emerging protocol signature detected in Tx %s", tx.Txid)
	}

	return flags
}

// detectSilentPayments (BIP352)
// Silent payments use non-interactive Diffie-Hellman to generate unique outputs.
// Signatures: Taproot outputs where the sender has directly tweaked the public key.
// Without the scan key, it's indistinguishable from random Taproot outputs, but
// we may flag massive 1-in-N-out Taproot consolidation sweeping as suspicious.
func (w *WatchListMonitor) detectSilentPayments(tx models.Transaction) uint64 {
	// Stub: Actual detection requires tracking output distribution entropies.
	// If a transaction creates numerous distinct Taproot outputs that are never reused.
	if len(tx.Inputs) == 1 && len(tx.Outputs) >= 5 {
		allTaproot := true
		for _, out := range tx.Outputs {
			if detectAddressType(out.Address) != "taproot" {
				allTaproot = false
				break
			}
		}
		if allTaproot {
			return FlagIsSilentPayment
		}
	}
	return 0
}

// detectPayJoinV3 (BIP77)
// Async PayJoin breaks the assumption that all inputs belong to the sender.
// Signature: 2-input, 2-output transaction where outputs perfectly match input sums
// (or one matches one input, effectively making it a zero-fee transfer conceptually).
func (w *WatchListMonitor) detectPayJoinV3(tx models.Transaction) uint64 {
	if len(tx.Inputs) == 2 && len(tx.Outputs) == 2 {
		// Heuristic PayJoin detector is already in ssmp.go, but we formalize it here.
		if tx.Outputs[0].Value == tx.Inputs[0].Value || tx.Outputs[1].Value == tx.Inputs[1].Value {
			return FlagIsPayjoinSuspect
		}
	}
	return 0
}

// detectNetworkRoutingDrift (BIP324 v2 Transport / BIP330 Erlay)
// These protocols change mempool propagation timing (V2 is encrypted, Erlay batches announcements).
// This renders "First Seen" IP triangulation highly brittle.
// Note: As an analytics firm, we rely mostly on block-native data, but if we feed
// mempool timing into our models, we must discount it if we detect batched propagation.
func (w *WatchListMonitor) detectNetworkRoutingDrift(tx models.Transaction) uint64 {
	// Stub: Would require temporal analysis of mempool arrival times (e.g.
	// if multiple distinct txs arrive from a peer at exactly the same microsecond
	// indicating an Erlay reconciliation batch rather than natural propagation).
	return 0
}

// detectJoinMarketBond (BIP46)
// JoinMarket Fidelity Bonds sacrifice capital liquidity using OP_CHECKLOCKTIMEVERIFY.
// This is a direct corroboration signal for Maker nodes in mixing pools.
// We must gate these descendants so they aren't trivially clustered.
//
// On-chain fingerprint (P2WSH with OP_CLTV):
//
//	<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
//	Hex pattern:  04XXXXXXXX b1 75 21 <33-byte-pubkey> ac
//	OP_CLTV = 0xb1, OP_DROP = 0x75, OP_CHECKSIG = 0xac
func (w *WatchListMonitor) detectJoinMarketBond(tx models.Transaction) uint64 {
	for _, out := range tx.Outputs {
		hex := out.ScriptPubKey
		if len(hex) == 0 {
			continue
		}

		// P2WSH outputs start with 0020 (OP_0 PUSH32) and are 66 hex chars
		if len(hex) == 66 && hex[:4] == "0020" {
			// This is a P2WSH output — cannot read the redeemScript directly,
			// but the presence of P2WSH in a CoinJoin-like topology is suspicious.
			// JoinMarket Makers often use P2WSH for their timelocked bonds.
			continue
		}

		// For witness script data available in the hex (raw script body),
		// scan for the OP_CLTV + OP_DROP pattern
		if containsCLTVPattern(hex) {
			return FlagIsJoinMarketBond
		}
	}
	return 0
}

// containsCLTVPattern scans a hex-encoded script for the OP_CHECKLOCKTIMEVERIFY (b1)
// followed by OP_DROP (75) pattern that characterizes BIP46 fidelity bonds.
func containsCLTVPattern(hexScript string) bool {
	// OP_CLTV = b1, OP_DROP = 75
	// The pattern appears as "b175" in the hex encoding
	for i := 0; i < len(hexScript)-3; i += 2 {
		if hexScript[i:i+4] == "b175" {
			return true
		}
	}
	return false
}
