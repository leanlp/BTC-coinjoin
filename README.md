# RawBlock CoinJoin Forensics Engine

The most advanced open-source Bitcoin transaction forensics engine. 87 Go files, 19,000+ lines of heuristic analysis, 44-step pipeline covering CoinJoin deanonymization, scammer tracking, and financial crime detection.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    44-Step AnalyzeTx Pipeline                        │
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
- **Peeling Chain Reconstruction** — BFS following change outputs with confidence decay
- **RBF Fee Bump Forensics** — Urgency scoring + double-spend detection
- **Timezone Profiling** — Infers entity location from broadcast hour histogram

### Financial Crime Detection
- **Money Laundering Pattern Detection** — Fan-out/fan-in/layering/structuring
- **CPFP Ownership Confirmation** — Proves address control via child-pays-for-parent
- **Value Fingerprint Registry** — Cross-TX linking via unique amounts
- **Address Poisoning Detection** — Lookalike address attack identification
- **Cross-Chain Bridge Detection** — OP_RETURN, atomic swap, and HTLC pattern analysis

## Getting Started

### Prerequisites

* Go 1.24 or higher
* A fully synced Bitcoin Core node with `txindex=1` (for live analysis)
* PostgreSQL (optional, for persistence)

### Installation

```bash
git clone https://github.com/rawblock/coinjoin-engine.git
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
  heuristics/            Core algorithms (87 Go files)
    ssmp.go              44-step AnalyzeTx pipeline
    llr_engine.go        Log-Likelihood Ratio + 51-bit flag system
    cluster_engine.go    Union-Find address clustering (CIOH)
    signal_fusion.go     Bayesian multi-signal fusion
    scammer_behavior.go  Consolidation + velocity + self-spend
    coordinator_fingerprint.go  Protocol ID + Sybil detection
    laundering_detection.go     Financial crime patterns
    dust_tracer.go       Full dust attack lifecycle
    advanced_forensics.go       Peeling chain + timezone + RBF
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
| `ci.yml` | Build + Test (race + coverage threshold) + Security (govulncheck) |
| `lint.yml` | golangci-lint with custom `.golangci.yml` config |

## Engine Stats

| Metric | Value |
|--------|-------|
| Go source files | 87 |
| Lines of code | 19,333 |
| Pipeline steps | 44 |
| Heuristic flag bits | 51 (9 layers) |
| Test count | 74 |
| Test coverage | 31.7% |
| Engine version | Phase 20 (`202603081`) |

## License

This project is licensed under the Apache 2.0 License — see the `LICENSE` file for details.
