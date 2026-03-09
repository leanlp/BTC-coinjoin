# RawBlock CoinJoin Forensics Engine

The most advanced open-source Bitcoin transaction forensics engine. 62 Go source files, 18,000+ lines of heuristic analysis, 52-step pipeline covering CoinJoin deanonymization, ML classification, scammer tracking, compliance automation, and financial crime detection.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    52-Step AnalyzeTx Pipeline                        │
├──────────────────────────────────────────────────────────────────────┤
│ Steps 1-28:  Core Heuristics                                        │
│  CIOH · Change Detection · BIP69 · AnonSet (Schroeppel-Shamir MitM) │
│  CP-SAT Solver · Script Analysis · Entropy (Boltzmann) · Fee Intel  │
│  Dust Detection · UTXO Age · Value Patterns · Topology Metrics      │
├──────────────────────────────────────────────────────────────────────┤
│ Steps 29-34: Advanced Analysis                                      │
│  Taint Propagation (FIFO/LIFO/Proportional) · Script Fingerprint    │
│  Temporal Correlation · Bot Detection · Markov Taint Scoring        │
│  Intersection Attack Engine                                          │
├──────────────────────────────────────────────────────────────────────┤
│ Steps 35-36: World-Class Forensics                                  │
│  Boltzmann P(i→j) Ownership Matrix · Bayesian Signal Fusion         │
├──────────────────────────────────────────────────────────────────────┤
│ Steps 37-44: Phase 20 — Scammer Tracking & Financial Crime          │
│  Compound Wallet Fingerprint · Coordinator ID · Sybil Detection     │
│  Consolidation Attack · Self-Spend · Dust Lifecycle Tracing         │
│  Laundering Patterns · Value Fingerprint · Address Poisoning        │
│  Post-Mix Effectiveness · Cross-Chain Bridge Detection              │
├──────────────────────────────────────────────────────────────────────┤
│ Steps 45-52: Phase 22 — ML, Enterprise & Compliance                 │
│  ML Feature Extraction (30+ features) · CoinJoin Classifier         │
│  Statistical Anomaly Detection (Welford z-score)                    │
│  Deposit Address Heuristic · Mixer Service Fingerprinting           │
│  Darknet Market Patterns · SIGHASH Flag Analysis                    │
│  Customizable Risk Engine (7 rules) · Real-Time Alert System        │
│  SAR Auto-Generation · FATF Jurisdiction Risk · Travel Rule Check   │
└──────────────────────────────────────────────────────────────────────┘
```

## Key Features

### Core Analysis (Steps 1-28)
- **Schroeppel-Shamir MitM Solver** — Fee-tolerant subset sum for CoinJoin unmixing
- **CP-SAT Boolean Constraint Solver** — Full ILP for large transactions (100×100)
- **Factor-Graph Inference** — Loopy Belief Propagation with composable evidence edges
- **Boltzmann Entropy Analysis** — Transaction interpretations and mixing efficiency
- **Time-Evolving Anonymity Sets** — Post-mix decay at 1d, 7d, 30d, 365d

### Advanced Forensics (Steps 29-36)
- **Multi-Mode Taint Propagation** — FIFO, LIFO, and proportional flow tracking
- **Bayesian Signal Fusion** — Combines 18 signal categories into calibrated probabilities
- **Boltzmann Ownership Matrix** — P(input_i → output_j) for every I/O pair
- **Intersection Attack Engine** — Cross-round CoinJoin linkage analysis

### Scammer Tracking (Steps 37-44)
- **Consolidation Timing Attack** — Catches cash-out moments
- **Velocity Pattern Classifier** — Auto-classifies: rug pull, pig butchering, ransomware, Ponzi, exit scam
- **CoinJoin Coordinator ID** — Identifies Whirlpool, Wasabi 2.0, JoinMarket protocols
- **Sybil Attack Detection** — Detects compromised CoinJoin rounds
- **Compound Wallet Fingerprint** — nVersion+nLockTime+nSequence identifies 10 wallet types
- **Dust Attack Full Tracing** — 3-phase lifecycle monitoring (deploy→consolidate→expose)
- **Cross-Chain Bridge Detection** — OP_RETURN, atomic swap, and HTLC patterns

### ML & Intelligence (Steps 45-52)
- **30+ ML Feature Extractor** — Structural, output distribution, script types, ordering, timing
- **CoinJoin ML Classifier** — Rule-based decision tree: coinjoin/payment/consolidation/batch_payout
- **Statistical Anomaly Detector** — Welford's online z-score (3σ threshold)
- **Entity Behavior Tracker** — Long-term wallet profiling (fee rate, script usage, RBF, consistency)
- **Deposit Address Heuristic** — Exchange deposit flow detection via one-time address patterns
- **Mixer Service Fingerprinting** — ChipMixer (power-of-2), Sinbad, Blender, generic tumbler detection
- **Darknet Market Pattern Detection** — Withdrawal fees, structured amounts, tumbler outputs
- **SIGHASH Flag Analysis** — Unusual signing patterns (ANYONECANPAY, NONE, SINGLE)

### Enterprise & Compliance
- **Customizable Risk Indicator Engine** — 7 default rules (sanctions, mixer, structuring, dust, consolidation)
- **Real-Time Alert System** — 4 alert levels (info/warning/high/critical) with configurable rules
- **SAR Auto-Generation** — FinCEN-compatible Suspicious Activity Reports with BSA activity codes
- **FATF Jurisdiction Risk Mapping** — 2025 grey/blacklist (Iran, North Korea, Myanmar + 18 grey-listed)
- **FATF Travel Rule Check** — Automated threshold compliance (>$1,000 USD)
- **WBTC Mint/Burn Tracker** — Custodian address monitoring
- **Cross-Chain Value/Time Matcher** — Correlates BTC outputs with external chain events

### Graph & Fund Flow
- **Full-Chain UTXO Backtracking** — BFS backward tracing with taint decay
- **Forward Flow Projection** — Source-to-destination fund tracing with proportional taint
- **Fund Flow Tracer** — Incident response DAG (theft → exchange exit) with CoinJoin penetration
- **Entity Attribution Registry** — OFAC/DOJ seed data, behavioral classification, cluster inheritance

## Getting Started

### Prerequisites

* Go 1.24 or higher
* A fully synced Bitcoin Core node with `txindex=1` (for live analysis)
* PostgreSQL (optional, for persistence)

### Installation

```bash
git clone 
cd coinjoin-engine
go mod tidy
go build -v ./...
go test -v -race -cover ./...
```

### Development Setup

```bash
# Install pre-commit hooks, linters, and security tools
chmod +x scripts/setup.sh && ./scripts/setup.sh
```

### Developer Commands

```bash
make build      # Compile all packages
make test       # Run tests with race detection
make lint       # Run golangci-lint
make coverage   # Check coverage threshold (25% min)
make security   # Run govulncheck
make check      # Run all checks (build + test + lint + vet)
make all        # Full CI pipeline locally
```

## Project Structure

```
cmd/engine/              Main entrypoint for the forensics API
internal/
  heuristics/            Core algorithms (62 Go source files)
    ssmp.go              52-step AnalyzeTx pipeline
    llr_engine.go        Log-Likelihood Ratio + 55-bit flag system (10 layers)
    cluster_engine.go    Union-Find address clustering (CIOH)
    signal_fusion.go     Bayesian multi-signal fusion
    scammer_behavior.go  Consolidation + velocity + self-spend
    coordinator_fingerprint.go  Protocol ID + Sybil detection
    laundering_detection.go     Financial crime patterns
    dust_tracer.go       Full dust attack lifecycle
    advanced_forensics.go       Peeling chain + timezone + RBF
    ml_features.go       30+ feature extractor + anomaly detector
    darknet_patterns.go  Darknet market + CoinJoin ML classifier
    alert_engine.go      Risk indicators + real-time alerts
    compliance_engine.go SAR generation + FATF jurisdiction risk
    graph_traversal.go   UTXO backtracking + forward flow
    deposit_heuristic.go Deposit address + SIGHASH + mixer fingerprint
    cross_chain_tracking.go  WBTC + cross-chain value/time matcher
    ...
  mempool/               Mempool monitoring and pre-confirmation intel
  scanner/               Block scanner and UTXO indexer
  shadow/                Shadow testing framework
  metrics/               ARI/VI clustering evaluation
pkg/models/              Transaction models and result types
scripts/
  pre-commit             Git pre-commit hook
  setup.sh               Development environment setup
```

## CI/CD

| Workflow | Purpose |
|----------|---------|
| `ci.yml` | Build + Test (race + coverage threshold) + Security (govulncheck + go vet) |
| `lint.yml` | golangci-lint with custom `.golangci.yml` config |

## Engine Stats

| Metric | Value |
|--------|-------|
| Go source files | 62 |
| Lines of code | 18,306 |
| Pipeline steps | 52 |
| Heuristic flag bits | 55 (10 layers) |
| Test files | 16 |
| Test coverage | 57.6% |
| Industry technique coverage | 74/102 (73%) |
| Engine version | Phase 22 (`202603082`) |

## Industry Coverage (73%)

| Category | Coverage |
|----------|:--------:|
| Clustering & Entity | 7/9 |
| CoinJoin Deanonymization | 15/15 |
| Graph & Flow Analysis | 13/13 |
| Wallet Fingerprinting | 11/11 |
| Scammer Tracking | 13/13 |
| ML/AI Classification | 5/8 |
| Cross-Chain & Lightning | 5/8 |
| Risk & Compliance | 5/6 |
| Data Sources | 2/9 |
| Network Layer | 3/10 |

## License

This project is licensed under the Apache 2.0 License — see the `LICENSE` file for details.
