package heuristics

import (
	"math"
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// WBTC Mint/Burn Detection
// ═══════════════════════════════════════════════════════════════════════

// WBTCEvent describes a detected WBTC mint or burn
type WBTCEvent struct {
	EventType   string `json:"eventType"` // "mint_custody" or "burn_release"
	Value       int64  `json:"value"`
	CustodyAddr string `json:"custodyAddr"`
}

// Known WBTC custodian address patterns
var wbtcCustodians = []string{
	"3LYJfcfHPXYJreMsASk2jkn69LWEYKzexb",
	"bc1qa5wkgaew2dkv56kxvg2",
}

// DetectWBTCActivity checks for interactions with WBTC custody
func DetectWBTCActivity(tx models.Transaction) *WBTCEvent {
	for _, out := range tx.Outputs {
		for _, custodian := range wbtcCustodians {
			if out.Address == custodian || strings.HasPrefix(out.Address, custodian) {
				return &WBTCEvent{
					EventType: "mint_custody", Value: out.Value, CustodyAddr: out.Address,
				}
			}
		}
	}
	for _, in := range tx.Inputs {
		for _, custodian := range wbtcCustodians {
			if in.Address == custodian || strings.HasPrefix(in.Address, custodian) {
				return &WBTCEvent{
					EventType: "burn_release", Value: in.Value, CustodyAddr: in.Address,
				}
			}
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════
// Cross-Chain Value/Time Matching
// ═══════════════════════════════════════════════════════════════════════

// CrossChainMatch represents a potential cross-chain transaction match
type CrossChainMatch struct {
	BTCTxID   string  `json:"btcTxid"`
	OtherTxID string  `json:"otherTxid"`
	Value     int64   `json:"value"`
	TimeDelta int64   `json:"timeDelta"`
	Chain     string  `json:"chain"`
	Score     float64 `json:"score"`
}

type crossChainEvent struct {
	txid      string
	chain     string
	value     int64
	timestamp int64
}

// CrossChainMatcher looks for value+timing correlations
type CrossChainMatcher struct {
	events map[int64][]crossChainEvent
}

// NewCrossChainMatcher creates a new matcher
func NewCrossChainMatcher() *CrossChainMatcher {
	return &CrossChainMatcher{events: make(map[int64][]crossChainEvent)}
}

// AddExternalEvent records an event from another chain
func (ccm *CrossChainMatcher) AddExternalEvent(txid, chain string, value, timestamp int64) {
	key := value / 10000
	ccm.events[key] = append(ccm.events[key], crossChainEvent{
		txid: txid, chain: chain, value: value, timestamp: timestamp,
	})
}

// FindMatches looks for BTC outputs that match external chain events
func (ccm *CrossChainMatcher) FindMatches(tx models.Transaction, txTimestamp int64) []CrossChainMatch {
	var matches []CrossChainMatch
	maxTimeDelta := int64(3600)

	for _, out := range tx.Outputs {
		key := out.Value / 10000
		events := ccm.events[key]
		for _, evt := range events {
			delta := txTimestamp - evt.timestamp
			if delta < 0 {
				delta = -delta
			}
			if delta <= maxTimeDelta {
				valuePrecision := 1.0 - math.Abs(float64(out.Value-evt.value))/float64(out.Value)
				timingScore := 1.0 - float64(delta)/float64(maxTimeDelta)
				matches = append(matches, CrossChainMatch{
					BTCTxID: tx.Txid, OtherTxID: evt.txid, Value: out.Value,
					TimeDelta: delta, Chain: evt.chain,
					Score: valuePrecision*0.6 + timingScore*0.4,
				})
			}
		}
	}
	return matches
}
