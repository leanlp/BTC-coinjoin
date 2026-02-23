package main

import (
	"context"
	"log"
	"os"

	"github.com/rawblock/coinjoin-engine/internal/api"
	"github.com/rawblock/coinjoin-engine/internal/bitcoin"
	"github.com/rawblock/coinjoin-engine/internal/db"
	"github.com/rawblock/coinjoin-engine/internal/mempool"
	"github.com/rawblock/coinjoin-engine/internal/scanner"
)

func main() {
	log.Println("Starting RawBlock Coinjoin Heuristics Engine (Microservice: btc-coinjoin-cuda-analytics)...")
	log.Println("Initializing Anonymity Set Matchers and Bloom Filters...")

	// ─── Required Environment Variables ─────────────────────────────────
	// All credentials MUST come from environment variables. No fallback
	// defaults for security-sensitive values. Use a .env file for local
	// development: cp .env.example .env && edit .env
	// ────────────────────────────────────────────────────────────────────

	dbUrl := requireEnv("DATABASE_URL")

	dbConn, err := db.Connect(dbUrl)
	if err != nil {
		log.Printf("Warning: Failed to connect to PostgreSQL, continuing without persisting forensics data. Error: %v", err)
	} else {
		defer dbConn.Close()
		if err := dbConn.InitSchema(); err != nil {
			log.Printf("Warning: DB schema init failed: %v", err)
		}
	}

	btcHost := getEnvOrDefault("BTC_RPC_HOST", "localhost:8332")
	btcUser := requireEnv("BTC_RPC_USER")
	btcPass := requireEnv("BTC_RPC_PASS")

	cfg := bitcoin.Config{
		Host: btcHost,
		User: btcUser,
		Pass: btcPass,
	}
	btcClient, err := bitcoin.NewClient(cfg)
	if err != nil {
		log.Printf("Warning: Failed to connect to Bitcoin RPC: %v", err)
	} else {
		defer btcClient.Shutdown()
	}

	// Setup WebSocket Hub
	wsHub := api.NewHub()
	go wsHub.Run()

	// Setup and start the Mempool Poller
	poller := mempool.NewPoller(btcClient, wsHub, dbConn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go poller.Run(ctx)

	// Create the Historical Block Scanner with real-time WebSocket alert broadcasting
	blockScanner := scanner.NewBlockScanner(btcClient, dbConn, api.BroadcastCoinJoinAlert(wsHub))

	// Setup the Gin Router
	r := api.SetupRouter(dbConn, btcClient, wsHub, blockScanner)

	port := getEnvOrDefault("PORT", "5339")

	// Start the server
	log.Printf("Engine running on :%s (API Node: btc-coinjoin-cuda-analytics)\n", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// requireEnv reads a required environment variable and exits if it is not set.
// This prevents the binary from starting with missing critical configuration.
func requireEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("FATAL: Required environment variable %s is not set. "+
			"Copy .env.example to .env and fill in your values: cp .env.example .env", key)
	}
	return val
}

// getEnvOrDefault returns the env var value or a safe default for non-secret settings.
func getEnvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
