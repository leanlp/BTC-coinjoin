package heuristics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Edge Types (Aligned with Postgres schema)
const (
	EdgeTypeCIOH              = 1  // Common-Input-Ownership Heuristic
	EdgeTypeChange            = 2  // Probabilistic Change Address Link
	EdgeTypeCIOHInvalidated   = 3  // Hard boundary (cioh_invalidated)
	EdgeTypeCoinjoinSuspected = 4  // Soft gating (coinjoin_suspected)
	EdgeTypePayJoinSuspect    = 5  // Low confidence, possible PayJoin
	EdgeTypePeelChain         = 6  // Sequential change-output linking
	EdgeTypeFeeCorrelation    = 7  // Same fee-rate profile across txs
	EdgeTypeDustLink          = 8  // Dust-based address linking
	EdgeTypeUnmixLink         = 9  // Deterministic CoinJoin unmixing
	EdgeTypeTransitive        = 10 // Multi-hop transitive evidence
)

// Dependency Groups (Used to discount overlapping heuristics to prevent Probability Mass explosion)
const (
	DepGroupNone              = 0 // Independent variable
	DepGroupScriptHomogeneity = 1 // Related to P2SH / P2WPKH clustering
	DepGroupValueConstraints  = 2 // Related to Round Numbers / Optimal Change
	DepGroupCoordination      = 3 // Related to Protocol Fingerprints
	DepGroupTemporalSignals   = 4 // Timing-based features
	DepGroupFeePatterns       = 5 // Fee-rate analysis features
	DepGroupTopology          = 6 // Graph structure features
)

// --- 3-Layer Signal Taxonomy Flags (Bitmask) ---

// Layer 1: Deterministic Facts (Ledger-Observable)
const (
	FlagIsSegWit          = 1 << 0 // BIP141 Weight/vsize definition applicable
	FlagIsTaproot         = 1 << 1 // BIP341/342 Key-path vs Script-path spend
	FlagHasSchnorrSig     = 1 << 2 // BIP340 standard auth (no signer cardinality)
	FlagIsWhirlpoolStruct = 1 << 3 // Deterministic 5x5 / Tx0 OP_RETURN structure
)

// Layer 2: Probabilistic Signals (Inference)
const (
	FlagLikelyChange          = 1 << 10 // Heuristic change output detection
	FlagLikelyCollabConstruct = 1 << 11 // Probable multi-party mix (IsCoinjoin)
	FlagAddressReuse          = 1 << 12 // Standard address reuse
	FlagHasRoundPayment       = 1 << 13 // Non-change output is a round BTC amount
	FlagIsConsolidation       = 1 << 14 // Many inputs → 1 output (UTXO cleanup)
	FlagIsBIP69               = 1 << 15 // BIP69 lexicographic input/output ordering
	FlagHighEntropy           = 1 << 16 // Boltzmann entropy > 4 bits (strong mix)
	FlagSuspiciousFeePattern  = 1 << 17 // Fee-rate anomaly (rounding, overpay)
	FlagIsPeelChain           = 1 << 18 // Serial 1-in-2-out change linking
	FlagTimingAnomaly         = 1 << 19 // Temporal coordination signature
)

// Layer 3: Policy-Gated Hypotheses (Brittle by design, used for gating)
const (
	FlagIsMuSig2Suspect  = 1 << 20 // BIP327 Hidden Multi-Party
	FlagIsPayjoinSuspect = 1 << 21 // BIP77 Async PayJoin (do not cluster naively)
	FlagIsSilentPayment  = 1 << 22 // BIP352 (breaks output scanning)
	FlagIsWasabiSuspect  = 1 << 23 // Extensive WabiSabi graph
	FlagIsJoinMarketBond = 1 << 24 // BIP46 OP_CHECKLOCKTIMEVERIFY timelock
)

// Layer 4: Forensic Intelligence (Phase 14 — Active threat signals)
const (
	FlagDustAttackSuspect = 1 << 25 // Dust surveillance UTXO detected
	FlagWeakMix           = 1 << 26 // CoinJoin with unmixable outputs
	FlagIsHubTransaction  = 1 << 27 // Hub/exchange-like fan-out pattern
	FlagDustConsolidation = 1 << 28 // Dust inputs consolidated (post-attack)
	FlagHighTraceability  = 1 << 29 // Calibrated traceability > 0.8
)

// Layer 5: Deep Intelligence (Phase 15 — Behavioral profiling & multi-hop)
const (
	FlagAncientUTXO         = 1 << 30 // Input UTXO > 1 year old (dormancy signal)
	FlagKnownServicePattern = 1 << 31 // Value matches known exchange/service fee
	FlagIsMultisig          = 1 << 32 // M-of-N multisig script detected
	FlagHasOPReturn         = 1 << 33 // OP_RETURN data payload present
)

// Layer 6: Operational Intelligence (Phase 16 — Entity resolution & risk)
const (
	FlagPostMixLeakage = 1 << 34 // Privacy destroyed after CoinJoin
	FlagBotBehavior    = 1 << 35 // Automated/bot transaction pattern
	FlagHighRisk       = 1 << 36 // Taint from known illicit source
)

// Layer 7: Next-Gen Threat Intelligence (Phase 17 — Infrastructure analysis)
const (
	FlagLightningChannel       = 1 << 37 // Lightning Network channel tx detected
	FlagIsCoinbase             = 1 << 38 // Coinbase (mining reward) transaction
	FlagStrategicConsolidation = 1 << 39 // Planned UTXO consolidation pattern
)

const CurrentSnapshotID = 202602235 // Version of the Heuristics Engine (Phase 17)

// ProbToLLR converts a real probability [0,1] into a Log-Likelihood Ratio.
// LLR = log10( P(E|H1) / P(E|H0) )
// For simplicity in this implementation, we convert the probability P directly into a weight logic.
// LLR = log10( P / (1-P) )
func ProbToLLR(probability float64) float64 {
	if probability >= 1.0 {
		return 999.0 // Infinite certainty
	}
	if probability <= 0.0 {
		return -999.0 // Infinite negative certainty
	}
	return math.Log10(probability / (1.0 - probability))
}

// GenerateCIOHEdges applies the Common-Input-Ownership Heuristic.
// If the transaction is NOT a CoinJoin, it binds all inputs together.
func GenerateCIOHEdges(tx models.Transaction, isCoinJoin bool, currentHeight int) []models.EvidenceEdge {
	var edges []models.EvidenceEdge

	if len(tx.Inputs) < 2 {
		return edges // Nothing to cluster
	}

	// 1. If it IS a CoinJoin, we must apply NEGATIVE Gating Edges to prevent
	//    CIOH clustering. Negative LLR = evidence AGAINST same-entity hypothesis.
	if isCoinJoin {
		for _, in := range tx.Inputs {
			// Hard negative edge: CIOH Invalidated
			// NEGATIVE LLR: pushes posterior AWAY from clustering
			edges = append(edges, createEdge(
				in.Address,
				"Mixer_Coordinator",
				EdgeTypeCIOHInvalidated,
				-ProbToLLR(0.99), // -2.0: strong evidence AGAINST clustering
				DepGroupCoordination,
				currentHeight,
			))
			// Soft gating edge: Coinjoin Suspected
			edges = append(edges, createEdge(
				in.Address,
				"Mixer_Coordinator",
				EdgeTypeCoinjoinSuspected,
				-ProbToLLR(0.85), // -0.75: moderate evidence AGAINST clustering
				DepGroupCoordination,
				currentHeight,
			))
		}
		return edges
	}

	// 2. If it is NOT a CoinJoin, apply Standard CIOH (Assume all inputs belong to 1 entity)
	// Factor Graph Math: We assign confidence based on script type homogeneity.
	primaryInput := tx.Inputs[0].Address

	// Check if all inputs are the same type (e.g. all Native Segwit)
	allSameType := true
	for i := 1; i < len(tx.Inputs); i++ {
		if detectAddressType(tx.Inputs[i].Address) != detectAddressType(primaryInput) {
			allSameType = false
			break
		}
	}

	for i := 1; i < len(tx.Inputs); i++ {
		// If they mix legacy and segwit, CIOH confidence drops significantly
		confidence := 0.95
		if !allSameType {
			confidence = 0.60
		}

		edges = append(edges, createEdge(
			primaryInput,
			tx.Inputs[i].Address,
			EdgeTypeCIOH,
			ProbToLLR(confidence),
			DepGroupScriptHomogeneity, // Prevents double-counting if we later add "round numbers"
			currentHeight,
		))
	}

	return edges
}

// Helper to instantiate an EvidenceEdge with Audit Hashing
func createEdge(src, dst string, edgeType int, llr float64, depGroup int, height int) models.EvidenceEdge {
	edgeID := uuid.New().String()

	// Create immutable audit hash representing this exact inference state
	hashPayload := fmt.Sprintf("%s|%s|%s|%d|%f|%d|%d", edgeID, src, dst, edgeType, llr, depGroup, CurrentSnapshotID)
	auditHash := sha256.Sum256([]byte(hashPayload))
	auditHashHex := hex.EncodeToString(auditHash[:])

	return models.EvidenceEdge{
		EdgeID:          edgeID,
		CreatedHeight:   height,
		SrcNodeID:       src,
		DstNodeID:       dst,
		EdgeType:        edgeType,
		LLRScore:        llr,
		DependencyGroup: depGroup,
		SnapshotID:      CurrentSnapshotID,
		AuditHash:       auditHashHex,
	}
}
