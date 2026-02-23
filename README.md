# RawBlock Coinjoin Forensics Engine

The RawBlock Coinjoin Forensics Engine is a high-performance backend heuristics analyzer for Bitcoin transactions, specializing in uncovering privacy degradation, tracking time-evolving anonymity sets, and cluster inference using advanced algorithms like the Schroeppel-Shamir MitM solver and CP-SAT solvers.

## Overview

This repository powers the backend forensics analysis for the RawBlock project. It integrates deeply with a Bitcoin Core node and parses raw transaction graphs to de-anonymize transactions. 

### Key Features

1. **Schroeppel-Shamir Meet-in-the-Middle Solver**: Finds exact and fee-tolerant subset sums for CoinJoin unmixing. Uses Hash-and-Modulus pruning for early exits and supports early bailout for computationally unfeasible transactions.
2. **Time-Evolving Anonymity Sets**: Tracks post-mix erosion over time (1d, 7d, 30d, 365d) modeling how anonymity sets decay as UTXOs interact over time. 
3. **CP-SAT Boolean Constraint Solvers**: Uses Constraint Programming to model full ILP for large-scale matching problems (up to 100 inputs x outputs).
4. **Factor-Graph Inference Engine**: Applies probabilistic inference over transaction graphs using Loopy Belief Propagation via Composable Evidence Graphs.
5. **Clustering Metrics**: Analyzes heuristic performance with Adjusted Rand Index (ARI) and Variation of Information (VI) metrics against ground-truth labels.

## Getting Started

### Prerequisites

* Go 1.22 or higher
* PostgreSQL Database
* A fully synced Bitcoin Core node with txindex=1 (for live analysis)

### Installation

```bash
git clone https://github.com/rawblock/rawblockGolandCoinjoin.git
cd rawblockGolandCoinjoin
go mod tidy
go build -v ./...
go test -v ./...
```

## Architecture

The project is structured according to clean Go project layout standards:

* `cmd/engine/`: Main entrypoint for the forensics engine API and pipeline runner.
* `internal/db/`: Database schema, migrations, and ORM abstractions.
* `internal/heuristics/`: The core algorithms (MitM, CP-SAT, LLR, Factor Graph, Anonymity Sets).
* `internal/shadow/`: Framework for running new heuristics in parallel against production data without impacting the primary graph.
* `internal/metrics/`: Evaluation of heuristic accuracy (ARI/VI).

## License

This project is licensed under the Apache 2.0 License - see the `LICENSE` file for details.
