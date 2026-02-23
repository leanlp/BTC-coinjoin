package db

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

// Connect initializes the connection pool to PostgreSQL using pgx
func Connect(connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %v", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping failed: %v", err)
	}

	log.Println("Successfully connected to PostgreSQL for Forensics Engine")
	return &PostgresStore{pool: pool}, nil
}

// Close gracefully closes the connection pool
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// InitSchema loads and executes the schema.sql file
func (s *PostgresStore) InitSchema() error {
	schemaBytes, err := os.ReadFile("internal/db/schema.sql")
	if err != nil {
		return fmt.Errorf("failed to read schema file: %v", err)
	}

	_, err = s.pool.Exec(context.Background(), string(schemaBytes))
	if err != nil {
		return fmt.Errorf("failed to execute schema migrations: %v", err)
	}

	log.Println("Coinjoin Forensics Schema initialized")
	return nil
}

// SaveAnalysisResult persists the computed heuristics and the evidence graph
func (s *PostgresStore) SaveAnalysisResult(ctx context.Context, blockHeight int, result models.PrivacyAnalysisResult) error {
	// 1. Begin Transaction
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 2. Insert main heuristic row
	insertHeuristicSQL := `
		INSERT INTO tx_heuristics (block_height, txid, heuristic_flags, anonset_local)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (block_height, txid) DO UPDATE 
		SET heuristic_flags = EXCLUDED.heuristic_flags, anonset_local = EXCLUDED.anonset_local;
	`
	_, err = tx.Exec(ctx, insertHeuristicSQL, blockHeight, result.Txid, result.HeuristicFlags, result.AnonSet)
	if err != nil {
		return fmt.Errorf("failed to insert tx_heuristics: %v", err)
	}

	// 3. Batch insert the evidence edges
	if len(result.Edges) > 0 {
		insertEdgeSQL := `
			INSERT INTO evidence_edge 
			(created_height, src_node_id, dst_node_id, edge_type, llr_score, dependency_group, snapshot_id, audit_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
		`
		for _, edge := range result.Edges {
			// Extracting the Hex string from our uuid implementation, normally this would be BYTEA
			_, err = tx.Exec(ctx, insertEdgeSQL,
				blockHeight,
				edge.SrcNodeID,
				edge.DstNodeID,
				edge.EdgeType,
				edge.LLRScore,
				edge.DependencyGroup,
				edge.SnapshotID,
				edge.EdgeID, // Using edgeID string as the placeholder for the sha256 byte array in this implementation
			)
			if err != nil {
				return fmt.Errorf("failed to insert evidence edge: %v", err)
			}
		}
	}

	// 4. Commit transaction
	return tx.Commit(ctx)
}

// SaveAnonSetWindow persists the time-evolving anonymity set windows
func (s *PostgresStore) SaveAnonSetWindow(ctx context.Context, txid string, outputIndex int, anonsetLocal int) error {
	sql := `
		INSERT INTO anonset_windows (txid, output_index, anonset_local)
		VALUES ($1, $2, $3)
		ON CONFLICT (txid, output_index) DO UPDATE
		SET anonset_local = EXCLUDED.anonset_local, last_updated = NOW();
	`
	_, err := s.pool.Exec(ctx, sql, txid, outputIndex, anonsetLocal)
	return err
}

// UpdateAnonSetWindows updates a specific time window column for an output
func (s *PostgresStore) UpdateAnonSetWindows(ctx context.Context, txid string, outputIndex int, window string, value int) error {
	// Validate the window parameter to prevent SQL injection
	validWindows := map[string]bool{
		"anonset_1d": true, "anonset_7d": true, "anonset_30d": true, "anonset_365d": true,
	}
	if !validWindows[window] {
		return fmt.Errorf("invalid window: %s", window)
	}

	sql := fmt.Sprintf("UPDATE anonset_windows SET %s = $1, last_updated = NOW() WHERE txid = $2 AND output_index = $3", window)
	_, err := s.pool.Exec(ctx, sql, value, txid, outputIndex)
	return err
}

// GetMixers queries the heuristics table for any known CoinJoin transactions.
// It uses bitwise operations to match FlagIsWhirlpoolStruct (8) and FlagIsWasabiSuspect (8388608).
type MixerInfo struct {
	BlockHeight    int    `json:"blockHeight"`
	Txid           string `json:"txid"`
	HeuristicFlags int64  `json:"heuristicFlags"`
	AnonsetLocal   int    `json:"anonsetLocal"`
	MixerType      string `json:"mixerType"`
}

func (s *PostgresStore) GetMixers(ctx context.Context, page int, limit int) ([]MixerInfo, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit

	// Get total count first
	var totalCount int
	countSQL := `SELECT COUNT(*) FROM tx_heuristics WHERE (heuristic_flags & 8) > 0 OR (heuristic_flags & 8388608) > 0`
	err := s.pool.QueryRow(ctx, countSQL).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	dataSQL := `
		SELECT block_height, txid, heuristic_flags, anonset_local
		FROM tx_heuristics 
		WHERE (heuristic_flags & 8) > 0 OR (heuristic_flags & 8388608) > 0
		ORDER BY block_height DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, dataSQL, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var mixers []MixerInfo
	for rows.Next() {
		var m MixerInfo
		var anonset *int
		err := rows.Scan(&m.BlockHeight, &m.Txid, &m.HeuristicFlags, &anonset)
		if err != nil {
			return nil, 0, err
		}
		if anonset != nil {
			m.AnonsetLocal = *anonset
		}

		if (m.HeuristicFlags & 8) > 0 {
			m.MixerType = "Whirlpool"
		} else if (m.HeuristicFlags & 8388608) > 0 {
			m.MixerType = "WabiSabi"
		} else {
			m.MixerType = "CoinJoin"
		}
		mixers = append(mixers, m)
	}
	if mixers == nil {
		mixers = []MixerInfo{}
	}
	return mixers, totalCount, nil
}

// GetPool exposes the connection pool for the shadow runner and other subsystems
func (s *PostgresStore) GetPool() *pgxpool.Pool {
	return s.pool
}
