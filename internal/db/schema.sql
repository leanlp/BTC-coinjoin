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

-- ============================================================
-- Incident Response & Fund Tracking (Phase 18)
-- ============================================================

-- Investigation cases for incident response
CREATE TABLE IF NOT EXISTS investigations (
    id              SERIAL PRIMARY KEY,
    case_id         VARCHAR(64) UNIQUE NOT NULL,  -- External case reference
    name            TEXT NOT NULL,
    description     TEXT,
    status          VARCHAR(20) DEFAULT 'active', -- active/paused/completed/archived
    total_stolen    BIGINT DEFAULT 0,
    total_recovered BIGINT DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- Tagged addresses within investigations
CREATE TABLE IF NOT EXISTS investigation_addresses (
    id                SERIAL PRIMARY KEY,
    investigation_id  INT REFERENCES investigations(id) ON DELETE CASCADE,
    address           VARCHAR(255) NOT NULL,
    label             TEXT,
    role              VARCHAR(30) NOT NULL,  -- 'theft'/'intermediate'/'mixer'/'exchange'/'suspect'/'unknown'
    notes             TEXT,
    hop_number        INT DEFAULT 0,
    value_sats        BIGINT DEFAULT 0,
    tagged_by         VARCHAR(100),
    tagged_at         TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_addr_investigation ON investigation_addresses (investigation_id);
CREATE INDEX IF NOT EXISTS idx_inv_addr_address ON investigation_addresses (address);

-- Fund flow edges for tracing stolen funds
CREATE TABLE IF NOT EXISTS fund_flows (
    id                SERIAL PRIMARY KEY,
    investigation_id  INT REFERENCES investigations(id) ON DELETE CASCADE,
    from_address      VARCHAR(255),
    to_address        VARCHAR(255),
    txid              VARCHAR(64),
    value_sats        BIGINT,
    hop_number        INT,
    is_coinjoin       BOOLEAN DEFAULT FALSE,
    confidence        REAL DEFAULT 1.0,
    created_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fund_flows_investigation ON fund_flows (investigation_id);
CREATE INDEX IF NOT EXISTS idx_fund_flows_from ON fund_flows (from_address);
CREATE INDEX IF NOT EXISTS idx_fund_flows_to ON fund_flows (to_address);

-- ============================================================
-- Risk Assessments (Sprint 1 — persist ALL analyzed txs)
-- ============================================================
-- Every analyzed transaction gets a risk row, not just CoinJoins.
-- This enables scam investigation, taint tracking, and entity risk scoring.
CREATE TABLE IF NOT EXISTS risk_assessments (
    txid              VARCHAR(64) PRIMARY KEY,
    block_height      INT NOT NULL,
    risk_score        SMALLINT NOT NULL DEFAULT 0,   -- 0-100 composite threat score
    risk_level        VARCHAR(20) NOT NULL DEFAULT 'info',  -- info/low/medium/high/critical
    privacy_score     SMALLINT NOT NULL DEFAULT 50,  -- 0-100 privacy score from pipeline
    heuristic_flags   BIGINT NOT NULL DEFAULT 0,     -- Full 64-bit flag bitmask
    taint_level       REAL DEFAULT 0.0,              -- 0.0 (clean) to 1.0 (fully tainted)
    num_inputs        INT DEFAULT 0,
    num_outputs       INT DEFAULT 0,
    total_value_sats  BIGINT DEFAULT 0,
    analyzed_at       TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_level ON risk_assessments (risk_level);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_score ON risk_assessments (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_height ON risk_assessments USING BRIN (block_height);

-- ============================================================
-- Phase 18: Advanced Forensics Tables
-- ============================================================

-- Taint propagation flows (FIFO/LIFO/Proportional accounting)
CREATE TABLE IF NOT EXISTS taint_flows (
    id                BIGSERIAL PRIMARY KEY,
    txid              VARCHAR(64) NOT NULL,
    output_index      SMALLINT NOT NULL,
    output_address    VARCHAR(255) NOT NULL,
    taint_level       REAL NOT NULL,               -- 0.0 (clean) to 1.0 (fully tainted)
    accounting_method VARCHAR(20) NOT NULL,         -- 'fifo'/'lifo'/'proportional'
    source_label      TEXT,                         -- Taint origin label
    hops_from_source  INT DEFAULT 0,
    created_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_taint_flows_txid ON taint_flows (txid);
CREATE INDEX IF NOT EXISTS idx_taint_flows_address ON taint_flows (output_address);
CREATE INDEX IF NOT EXISTS idx_taint_flows_level ON taint_flows (taint_level DESC);

-- Script fingerprint signatures (wallet identification)
CREATE TABLE IF NOT EXISTS script_fingerprints (
    id                BIGSERIAL PRIMARY KEY,
    txid              VARCHAR(64) NOT NULL,
    wallet_signature  VARCHAR(50),                  -- 'ledger'/'trezor'/'electrum'/'bitcoin-core'
    signature_scheme  VARCHAR(20),                  -- 'ecdsa'/'schnorr'/'mixed'
    has_timelock      BOOLEAN DEFAULT FALSE,
    timelock_type     VARCHAR(10),                  -- 'cltv'/'csv'/null
    multisig_configs  TEXT[],                       -- Array: '2-of-3', '3-of-5'
    nsequence_pattern VARCHAR(20),                  -- 'rbf-enabled'/'final'/'timelock'/'mixed'
    non_standard_count SMALLINT DEFAULT 0,
    created_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_script_fp_txid ON script_fingerprints (txid);
CREATE INDEX IF NOT EXISTS idx_script_fp_wallet ON script_fingerprints (wallet_signature);

-- Mempool telemetry (pre-confirmation intelligence)
CREATE TABLE IF NOT EXISTS mempool_telemetry (
    txid               VARCHAR(64) PRIMARY KEY,
    first_seen_ms      BIGINT NOT NULL,             -- Unix milliseconds when first observed
    confirmed_at_ms    BIGINT,                      -- Unix milliseconds when confirmed in block
    confirmation_delay REAL,                        -- Seconds from first-seen to confirmation
    initial_fee_rate   REAL,                        -- Original fee rate (sat/vB)
    final_fee_rate     REAL,                        -- Fee rate after any RBF bumps
    rbf_attempts       SMALLINT DEFAULT 0,          -- Number of RBF replacements observed
    fee_bump_ratio     REAL DEFAULT 1.0,            -- final_fee / initial_fee
    was_evicted        BOOLEAN DEFAULT FALSE,
    block_height       INT
);

CREATE INDEX IF NOT EXISTS idx_mempool_tel_height ON mempool_telemetry USING BRIN (block_height);

-- Cross-chain correlation events (atomic swaps, DEX, bridges)
CREATE TABLE IF NOT EXISTS cross_chain_events (
    id                BIGSERIAL PRIMARY KEY,
    source_chain      VARCHAR(10) NOT NULL,         -- 'BTC'/'ETH'/'XMR'
    dest_chain        VARCHAR(10) NOT NULL,
    source_txid       VARCHAR(128) NOT NULL,
    dest_txid         VARCHAR(128),
    source_value      BIGINT,
    dest_value        BIGINT,
    exchange_rate     REAL,
    time_delta_secs   REAL,
    value_match_score REAL,
    confidence        REAL,
    swap_type         VARCHAR(20),                  -- 'atomic'/'exchange'/'dex'/'bridge'
    investigation_id  INT REFERENCES investigations(id) ON DELETE SET NULL,
    created_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cross_chain_source ON cross_chain_events (source_txid);
CREATE INDEX IF NOT EXISTS idx_cross_chain_dest ON cross_chain_events (dest_txid);

-- Temporal correlation signals (timing analysis)
CREATE TABLE IF NOT EXISTS temporal_signals (
    id                BIGSERIAL PRIMARY KEY,
    txid              VARCHAR(64) NOT NULL,
    pattern_type      VARCHAR(30),                  -- 'periodic'/'burst'/'delayed-withdrawal'
    interval_seconds  REAL,
    correlated_txids  TEXT[],                       -- Array of correlated transaction IDs
    confidence        REAL,
    time_bucket       VARCHAR(20),                  -- 'business'/'evening'/'overnight'
    created_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_temporal_txid ON temporal_signals (txid);
CREATE INDEX IF NOT EXISTS idx_temporal_pattern ON temporal_signals (pattern_type);
