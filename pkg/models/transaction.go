package models

// TxIn represents a Bitcoin transaction input
type TxIn struct {
	Txid      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	Value     int64  `json:"value"` // in Satoshis
	Address   string `json:"address"`
	ScriptSig string `json:"scriptSig"`
	Sequence  uint32 `json:"sequence"` // nSequence: 0xFFFFFFFE = RBF (BIP125), 0xFFFFFFFF = final
}

// TxOut represents a Bitcoin transaction output
type TxOut struct {
	Value        int64  `json:"value"` // in Satoshis
	Address      string `json:"address"`
	ScriptPubKey string `json:"scriptPubKey"`
	IsChange     bool   `json:"isChange,omitempty"`
}

// Transaction represents a parsed Bitcoin transaction
type Transaction struct {
	Txid        string  `json:"txid"`
	Inputs      []TxIn  `json:"inputs"`
	Outputs     []TxOut `json:"outputs"`
	Fee         int64   `json:"fee"` // Calculated as Inputs - Outputs in Satoshis
	Weight      int     `json:"weight"`
	Vsize       int     `json:"vsize"`                 // BIP141 Virtual Size
	LockTime        uint32  `json:"locktime"`              // nLockTime: anti-fee-sniping or timelock
	Version         int32   `json:"version"`               // Tx version (1 or 2)
	BlockHeight     int     `json:"blockHeight,omitempty"` // Block height (0 for mempool)
	BlockTime       int64   `json:"blockTime,omitempty"`   // Block timestamp (unix seconds)
	MempoolFirstSeen int64  `json:"mempoolFirstSeen,omitempty"` // Unix ms when first observed in mempool
	BroadcastNodeIP  string `json:"broadcastNodeIP,omitempty"`  // IP of first broadcasting peer (if captured)
}

// EvidenceEdge represents a directional, probabilistic linkage in the UTXO graph.
type EvidenceEdge struct {
	EdgeID          string  `json:"edgeId"`
	CreatedHeight   int     `json:"createdHeight"`
	SrcNodeID       string  `json:"srcNodeId"`           // Origin Address
	DstNodeID       string  `json:"dstNodeId"`           // Destination Address
	EdgeType        int     `json:"edgeType"`            // 1=CIOH, 2=Change, 3=NegativeGating
	LLRScore        float64 `json:"llrScore"`            // Log-Likelihood Ratio
	DependencyGroup int     `json:"dependencyGroup"`     // To prevent double-counting correlated features
	SnapshotID      int     `json:"snapshotId"`          // Version of the heuristic engine that generated this
	AuditHash       string  `json:"auditHash,omitempty"` // SHA256 digest for immutability
}

// InferenceResult is the factor-graph posterior evaluation
type InferenceResult struct {
	PosteriorLLR     float64 `json:"posteriorLlr"`
	ConfidenceLevel  string  `json:"confidenceLevel"`
	DiscountedEdges  int     `json:"discountedEdges"`
	TotalEdges       int     `json:"totalEdges"`
	EffectiveFactors int     `json:"effectiveFactors"`
}

// PrivacyAnalysisResult holds the heuristics engine output
type PrivacyAnalysisResult struct {
	Txid           string              `json:"txid"`
	PrivacyScore   int                 `json:"privacyScore"`
	AnonSet        int                 `json:"anonSet"`
	HeuristicFlags uint64              `json:"heuristicFlags"`           // 64-bit Bitmask
	Edges          []EvidenceEdge      `json:"edges"`                    // Composable probabilistic edges
	Inference      *InferenceResult    `json:"inference,omitempty"`      // Factor-graph posterior (Phase 3)
	ChangeOutput   *ChangeOutput       `json:"changeOutput,omitempty"`   // Detected change output
	WalletFamily   string              `json:"walletFamily,omitempty"`   // Attributed wallet software
	WhirlpoolPool  string              `json:"whirlpoolPool,omitempty"`  // Specific pool denomination
	Entropy        *EntropyResult      `json:"entropy,omitempty"`        // Boltzmann entropy analysis
	FeeAnalysis    *FeeAnalysisResult  `json:"feeAnalysis,omitempty"`    // Fee-rate intelligence
	PeelChain      *PeelChainResult    `json:"peelChain,omitempty"`      // Peel chain detection
	DustAnalysis   *DustResult         `json:"dustAnalysis,omitempty"`   // Dust attack detection
	UnmixResult    *UnmixResult        `json:"unmixResult,omitempty"`    // CoinJoin unmixability
	Topology       *TopologyResult     `json:"topology,omitempty"`       // Graph topology metrics
	ScoreBreakdown *ScoreBreakdown     `json:"scoreBreakdown,omitempty"` // Calibrated score decomposition
	UTXOAge        *UTXOAgeResult      `json:"utxoAge,omitempty"`        // Input UTXO lifespan analysis
	ValuePattern   *ValuePatternResult `json:"valuePattern,omitempty"`   // Value fingerprinting
	ScriptInfo     *ScriptAnalysis     `json:"scriptInfo,omitempty"`     // Script template deep inspection
	// Phase 18: Advanced Forensics
	TaintAnalysis     *TaintResult               `json:"taintAnalysis,omitempty"`    // FIFO/LIFO taint propagation
	ScriptFingerprint *ScriptFingerprintResult    `json:"scriptFingerprint,omitempty"` // Deep script opcode analysis
	TemporalSignals   *TemporalCorrelationResult  `json:"temporalSignals,omitempty"`  // Timing correlation
	MempoolIntel      *MempoolIntelResult         `json:"mempoolIntel,omitempty"`     // Pre-confirmation intelligence
	TaintExposure     float64                     `json:"taintExposure,omitempty"`    // Weighted taint ratio [0,1]
}

// EntropyResult holds Boltzmann transaction entropy analysis
type EntropyResult struct {
	Entropy         float64 `json:"entropy"`         // log₂(interpretations) in bits
	MaxEntropy      float64 `json:"maxEntropy"`      // Maximum possible entropy for this I/O shape
	Efficiency      float64 `json:"efficiency"`      // Ratio: entropy / maxEntropy (0.0 - 1.0)
	Level           string  `json:"level"`           // "transparent"/"low"/"moderate"/"high"/"maximum"
	Interpretations int     `json:"interpretations"` // Number of valid I→O mappings
}

// FeeAnalysisResult holds fee-rate intelligence
type FeeAnalysisResult struct {
	FeeRate           float64 `json:"feeRate"`           // sat/vB
	FeeRateClass      string  `json:"feeRateClass"`      // "minimal"/"economic"/"normal"/"priority"/"urgent"
	RoundingPattern   string  `json:"roundingPattern"`   // "1sat"/"5sat"/"10sat"/"precise"/"none"
	WalletHint        string  `json:"walletHint"`        // Wallet family inferred from fee
	OverpayRatio      float64 `json:"overpayRatio"`      // Ratio vs estimated optimal fee
	UnnecessaryInputs int     `json:"unnecessaryInputs"` // Count of inputs not needed to cover outputs+fee
}

// PeelChainResult holds peel chain detection results
type PeelChainResult struct {
	IsChain      bool    `json:"isChain"`
	ChainLength  int     `json:"chainLength"`            // Number of linked peel steps
	Direction    string  `json:"direction"`              // "forward" (spending change) or "backward" (input is change)
	Confidence   float64 `json:"confidence"`             // 0.0 - 1.0
	PreviousTxid string  `json:"previousTxid,omitempty"` // The prior tx in the chain
	ChangeIndex  int     `json:"changeIndex"`            // Which output is the identified change
}

// DustResult holds dust attack detection results
type DustResult struct {
	HasDustOutputs  bool   `json:"hasDustOutputs"`  // Tx creates dust outputs (potential attack)
	HasDustInputs   bool   `json:"hasDustInputs"`   // Tx spends dust inputs (post-attack consolidation)
	DustOutputCount int    `json:"dustOutputCount"` // Number of dust-sized outputs
	DustInputCount  int    `json:"dustInputCount"`  // Number of dust-sized inputs
	TotalDustValue  int64  `json:"totalDustValue"`  // Combined value of all dust
	Intent          string `json:"intent"`          // "surveillance"/"spam"/"consolidation"/"none"
	RiskLevel       string `json:"riskLevel"`       // "critical"/"high"/"medium"/"low"/"none"
}

// UnmixResult holds CoinJoin unmixability analysis
type UnmixResult struct {
	UnmixableOutputs   int     `json:"unmixableOutputs"` // Outputs with unique values linkable to inputs
	TotalOutputs       int     `json:"totalOutputs"`
	DeterministicLinks int     `json:"deterministicLinks"` // I→O links that are 100% certain
	LinkabilityScore   float64 `json:"linkabilityScore"`   // 0.0 (perfect mix) to 1.0 (fully linkable)
	WeakParticipants   int     `json:"weakParticipants"`   // Number of participants with compromised privacy
	MixQuality         string  `json:"mixQuality"`         // "perfect"/"strong"/"moderate"/"weak"/"broken"
}

// TopologyResult holds UTXO graph topology metrics
type TopologyResult struct {
	Shape              string  `json:"shape"`              // "simple-payment"/"peel-step"/"consolidation"/"batch-payout"/"mixing"/"hub"
	FanIn              int     `json:"fanIn"`              // Number of inputs
	FanOut             int     `json:"fanOut"`             // Number of outputs
	IOSymmetry         float64 `json:"ioSymmetry"`         // |inputs-outputs|/max(inputs,outputs) → 0=symmetric
	GiniCoefficient    float64 `json:"giniCoefficient"`    // Output value dispersion: 0=equal, 1=concentrated
	IsHub              bool    `json:"isHub"`              // Transaction acts as hub (high fan-in or fan-out)
	ValueConcentration string  `json:"valueConcentration"` // "dispersed"/"moderate"/"concentrated"
}

// ScoreBreakdown decomposes the privacy score into individual signal contributions
type ScoreBreakdown struct {
	BaseScore        int     `json:"baseScore"`        // Starting score (100)
	AnonSetFactor    int     `json:"anonSetFactor"`    // From anonymity set size
	EntropyFactor    int     `json:"entropyFactor"`    // From Boltzmann entropy
	ChangeDetection  int     `json:"changeDetection"`  // Penalty from change output detection
	WalletLeakage    int     `json:"walletLeakage"`    // Penalty from wallet fingerprinting
	PeelChainPenalty int     `json:"peelChainPenalty"` // Penalty from peel chain
	DustRisk         int     `json:"dustRisk"`         // Penalty from dust analysis
	TopologyPenalty  int     `json:"topologyPenalty"`  // Penalty from unfavorable topology
	UnmixPenalty     int     `json:"unmixPenalty"`     // Penalty from CoinJoin unmixability
	AddressReuse     int     `json:"addressReuse"`     // Penalty from address reuse
	Traceability     float64 `json:"traceability"`     // Final traceability probability (0.0 - 1.0)
}

// ChangeOutput represents the detected change output for non-CoinJoin transactions
type ChangeOutput struct {
	Index          int     `json:"index"`
	Confidence     float64 `json:"confidence"`
	Method         string  `json:"method"`
	IsRoundPayment bool    `json:"isRoundPayment"`
}

// UTXOAgeResult holds input UTXO lifespan analysis
type UTXOAgeResult struct {
	AvgAgeDays        float64 `json:"avgAgeDays"`        // Average age of input UTXOs in days
	MaxAgeDays        float64 `json:"maxAgeDays"`        // Oldest input UTXO age
	MinAgeDays        float64 `json:"minAgeDays"`        // Youngest input UTXO age
	CoinDaysDestroyed float64 `json:"coinDaysDestroyed"` // Σ(value_i × age_i) / 1e8
	HoldingPattern    string  `json:"holdingPattern"`    // "hot-wallet"/"service"/"user"/"hodler"/"ancient"
	HasAncientUTXO    bool    `json:"hasAncientUTXO"`    // Any input > 365 days old
}

// ValuePatternResult holds value fingerprinting results
type ValuePatternResult struct {
	HasRoundBTC          bool    `json:"hasRoundBTC"`          // Output matches round BTC amounts
	HasRoundSats         bool    `json:"hasRoundSats"`         // Output matches round sat amounts
	KnownServiceFee      string  `json:"knownServiceFee"`      // Matched exchange fee pattern
	OutputValueEntropy   float64 `json:"outputValueEntropy"`   // Shannon entropy of output values
	DominantDenomination int64   `json:"dominantDenomination"` // Most common output value
	UniqueValueRatio     float64 `json:"uniqueValueRatio"`     // Fraction of outputs with unique values
}

// ScriptAnalysis holds deep script template inspection results
type ScriptAnalysis struct {
	HasMultisig      bool   `json:"hasMultisig"`      // M-of-N multisig detected
	MultisigM        int    `json:"multisigM"`        // M in M-of-N
	MultisigN        int    `json:"multisigN"`        // N in M-of-N
	HasHTLC          bool   `json:"hasHTLC"`          // Hash timelock contract (Lightning)
	HasOPReturn      bool   `json:"hasOPReturn"`      // OP_RETURN data present
	OPReturnProtocol string `json:"opReturnProtocol"` // "omni"/"openassets"/"unknown"
	OPReturnSize     int    `json:"opReturnSize"`     // Size of OP_RETURN data in bytes
	DominantWitness  string `json:"dominantWitness"`  // "v0"/"v1"/"legacy"
	TapscriptDepth   int    `json:"tapscriptDepth"`   // Tapscript tree depth (0 = key-path)
}

// ============================================================
// Phase 18: Advanced Forensics Models
// ============================================================

// TaintResult holds FIFO/LIFO taint flow accounting results
type TaintResult struct {
	Method          string             `json:"method"`          // "fifo"/"lifo"/"proportional"
	InputTaintLevel float64            `json:"inputTaintLevel"` // Aggregate taint of all inputs (0.0 - 1.0)
	OutputTaints    []OutputTaintEntry `json:"outputTaints"`    // Per-output taint breakdown
	TotalAbsorbed   float64            `json:"totalAbsorbed"`   // Total taint absorbed by this tx
	SourceLabels    []string           `json:"sourceLabels"`    // Known taint source labels
	HopsFromSource  int                `json:"hopsFromSource"`  // Minimum hops from nearest taint source
}

// OutputTaintEntry holds taint level for a specific output
type OutputTaintEntry struct {
	Index      int     `json:"index"`
	Address    string  `json:"address"`
	Value      int64   `json:"value"`
	TaintLevel float64 `json:"taintLevel"` // 0.0 (clean) to 1.0 (fully tainted)
}

// ScriptFingerprintResult holds deep opcode-level script fingerprinting
type ScriptFingerprintResult struct {
	InputScriptTypes    map[string]int `json:"inputScriptTypes"`    // Frequency map: "p2pkh"/"p2sh"/"p2wpkh"/"p2wsh"/"p2tr"
	OutputScriptTypes   map[string]int `json:"outputScriptTypes"`   // Same for outputs
	HasTimeLock         bool           `json:"hasTimeLock"`         // CLTV or CSV detected
	TimeLockType        string         `json:"timeLockType"`        // "cltv"/"csv"/"none"
	TimeLockValue       uint32         `json:"timeLockValue"`       // Lock height or time
	MultisigConfigs     []string       `json:"multisigConfigs"`     // e.g., ["2-of-3", "3-of-5"]
	WalletSignature     string         `json:"walletSignature"`     // Inferred wallet: "ledger"/"trezor"/"electrum"/"bitcoin-core"/"unknown"
	SignatureScheme     string         `json:"signatureScheme"`     // "ecdsa"/"schnorr"/"mixed"
	WitnessVersions     []int          `json:"witnessVersions"`     // SegWit witness versions found
	NonStandardScripts  int            `json:"nonStandardScripts"`  // Count of non-standard scripts
	OPReturnPayloads    []string       `json:"opReturnPayloads"`    // Hex-encoded OP_RETURN data
	NSequenceAnalysis   string         `json:"nSequenceAnalysis"`   // "rbf-enabled"/"final"/"timelock"/"mixed"
}

// TemporalCorrelationResult holds timing-based correlation signals
type TemporalCorrelationResult struct {
	HasTimingPattern    bool    `json:"hasTimingPattern"`    // Automated pattern detected
	PatternType         string  `json:"patternType"`         // "periodic"/"burst"/"delayed-withdrawal"/"none"
	IntervalSeconds     float64 `json:"intervalSeconds"`     // Average interval between correlated txs
	CorrelatedTxids     []string `json:"correlatedTxids"`    // Txids with temporal correlation
	MixToWithdrawDelay  float64 `json:"mixToWithdrawDelay"`  // Seconds between CoinJoin completion and spend
	Confidence          float64 `json:"confidence"`          // 0.0 - 1.0
	TimeBucket          string  `json:"timeBucket"`          // Hour-of-day cluster: "business"/"evening"/"overnight"
}

// MarkovScoreResult holds absorbing random walk taint scoring
type MarkovScoreResult struct {
	StartAddress        string             `json:"startAddress"`
	AbsorptionProbs     []AbsorptionTarget `json:"absorptionProbs"` // Probability of reaching each absorber
	MaxHopsTraversed    int                `json:"maxHopsTraversed"`
	TotalNodesVisited   int                `json:"totalNodesVisited"`
	ConvergenceReached  bool               `json:"convergenceReached"`
	PrimaryDestination  string             `json:"primaryDestination"`  // Highest-probability absorber
	PrimaryProbability  float64            `json:"primaryProbability"`  // Probability of primary destination
}

// AbsorptionTarget represents a known absorbing state in the Markov chain
type AbsorptionTarget struct {
	Address     string  `json:"address"`
	Label       string  `json:"label"`       // "binance"/"coinbase"/"mixer"/"darknet"/etc.
	Probability float64 `json:"probability"` // Absorption probability from start
	HopsAway    int     `json:"hopsAway"`    // Shortest path length
}

// CrossChainCorrelation holds cross-chain swap correlation data
type CrossChainCorrelation struct {
	IsCorrelated       bool    `json:"isCorrelated"`
	SourceChain        string  `json:"sourceChain"`        // "BTC"/"ETH"/"XMR"/etc.
	DestChain          string  `json:"destChain"`
	SourceTxid         string  `json:"sourceTxid"`
	DestTxid           string  `json:"destTxid"`
	SourceValue        int64   `json:"sourceValue"`        // In source chain's smallest unit
	DestValue          int64   `json:"destValue"`
	ExchangeRate       float64 `json:"exchangeRate"`       // Observed rate at correlation time
	TimeDeltaSeconds   float64 `json:"timeDeltaSeconds"`   // |t_out - t_in|
	ValueMatchScore    float64 `json:"valueMatchScore"`    // How well values match after rate conversion
	Confidence         float64 `json:"confidence"`         // 0.0 - 1.0
	SwapType           string  `json:"swapType"`           // "atomic"/"exchange"/"dex"/"bridge"
}

// MempoolIntelResult holds pre-confirmation intelligence
type MempoolIntelResult struct {
	FirstSeenUnixMs    int64   `json:"firstSeenUnixMs"`    // Millisecond precision first-seen
	ConfirmationDelay  float64 `json:"confirmationDelay"`  // Seconds from first-seen to block inclusion
	RBFAttempts        int     `json:"rbfAttempts"`        // Number of RBF replacements observed
	FeeBumpRatio       float64 `json:"feeBumpRatio"`       // Final fee / initial fee
	PropagationDelay   float64 `json:"propagationDelay"`   // Seconds between first and last node sighting
	InitialFeeRate     float64 `json:"initialFeeRate"`     // Original fee rate before RBF bumps
	WasMempoolEvicted  bool    `json:"wasMempoolEvicted"`  // Tx was evicted and rebroadcast
}
