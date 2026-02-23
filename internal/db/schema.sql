-- internal/db/schema.sql

-- Evidence graph edges (Reversible, composable clustering)
-- This table is designed for high-scale temporal partitioning and BRIN indexing
CREATE TABLE IF NOT EXISTS evidence_edge (
    edge_id           BIGSERIAL PRIMARY KEY,
    created_height    INT NOT NULL,
    src_node_id       VARCHAR(255) NOT NULL,    -- Changed from BIGINT since Transaction models use Address strings
    dst_node_id       VARCHAR(255) NOT NULL,
    edge_type         SMALLINT NOT NULL,        -- 1=CIOH, 2=Change, 3=NegativeGating, 4=PayJoinSuspect
    llr_score         REAL NOT NULL,            -- Log-Likelihood Ratio (Calibrated Probability)
    dependency_group  INT NOT NULL,             -- Handles correlated feature discounting
    snapshot_id       BIGINT NOT NULL,          -- Tied to the specific heuristics version release
    audit_hash        VARCHAR(64) NOT NULL      -- Hex-encoded SHA256
);

-- BRIN Index for massive temporal scanning
CREATE INDEX IF NOT EXISTS idx_evidence_edge_height ON evidence_edge USING BRIN (created_height);
-- Partial B-Tree indexes for fast policy lookups
CREATE INDEX IF NOT EXISTS idx_evidence_edge_src_type ON evidence_edge (src_node_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_evidence_edge_dst_type ON evidence_edge (dst_node_id, edge_type);

-- Computed transaction heuristics for high-QPS filtering
CREATE TABLE IF NOT EXISTS tx_heuristics (
    block_height      INT NOT NULL,
    txid              VARCHAR(64) NOT NULL,
    heuristic_flags   BIGINT NOT NULL,          -- 64-bit Bitmask encoding binary flags
    anonset_local     SMALLINT NULL,            -- The derived AnonSet size (e.g. 5 for Whirlpool)
    PRIMARY KEY (block_height, txid)
);

-- ============================================================
-- Time-Evolving Anonymity Windows
-- ============================================================
-- Tracks post-mix AnonSet erosion over observation windows.
CREATE TABLE IF NOT EXISTS anonset_windows (
    txid            VARCHAR(64) NOT NULL,
    output_index    SMALLINT NOT NULL,
    anonset_local   SMALLINT NOT NULL,         -- A_0: transaction-local candidate pool
    anonset_1d      SMALLINT NULL,             -- A(T+1 day)
    anonset_7d      SMALLINT NULL,             -- A(T+7 days)
    anonset_30d     SMALLINT NULL,             -- A(T+30 days)
    anonset_365d    SMALLINT NULL,             -- A(T+365 days)
    last_updated    TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (txid, output_index)
);

CREATE INDEX IF NOT EXISTS idx_anonset_windows_txid ON anonset_windows (txid);

-- ============================================================
-- Shadow-Mode Deployment Framework
-- ============================================================
-- New heuristics run in shadow-mode writing here, never to evidence_edge.
CREATE TABLE IF NOT EXISTS shadow_results (
    shadow_id        BIGSERIAL PRIMARY KEY,
    txid             VARCHAR(64) NOT NULL,
    shadow_flags     BIGINT NOT NULL,           -- What the new heuristic *would* have flagged
    production_flags BIGINT NOT NULL,           -- What production currently flags
    delta_anonset    SMALLINT NULL,             -- Difference in AnonSet computation
    snapshot_id      BIGINT NOT NULL,           -- Shadow heuristic version
    created_at       TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shadow_results_txid ON shadow_results (txid);
