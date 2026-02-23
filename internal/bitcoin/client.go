package bitcoin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
)

type Client struct {
	RPC       *rpcclient.Client
	WalletRPC *rpcclient.Client
	Config    Config
}

type Config struct {
	Host string
	User string
	Pass string
}

func NewClient(cfg Config) (*Client, error) {
	connCfg := &rpcclient.ConnConfig{
		Host:         cfg.Host,
		User:         cfg.User,
		Pass:         cfg.Pass,
		HTTPPostMode: true, // Bitcoin Core only supports HTTP POST mode
		DisableTLS:   true, // Assuming local node without TLS for this setup
	}

	log.Printf("Connecting to Bitcoin RPC at %s...", cfg.Host)
	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		return nil, err
	}

	// Verify connection
	blockCount, err := client.GetBlockCount()
	if err != nil {
		client.Shutdown()
		return nil, err
	}

	log.Printf("Connected to Bitcoin Node. Current Block Height: %d", blockCount)

	c := &Client{RPC: client, Config: cfg}

	// Ensure a wallet is loaded for watch-only operations
	if err := c.InitializeWallet(); err != nil {
		log.Printf("Warning: Failed to initialize wallet: %v. Watch-only features might fail.", err)
	} else {
		log.Println("Wallet initialized successfully.")
	}

	return c, nil
}

func (c *Client) Shutdown() {
	c.RPC.Shutdown()
}

// --- RPC Wrappers ---

func (c *Client) GetRawMempool() ([]string, error) {
	// Verbose=false returns []*chainhash.Hash
	hashes, err := c.RPC.GetRawMempool()
	if err != nil {
		return nil, err
	}

	// Convert to strings
	result := make([]string, len(hashes))
	for i, hash := range hashes {
		result[i] = hash.String()
	}
	return result, nil
}

func (c *Client) GetRawMempoolVerbose() (map[string]btcjson.GetRawMempoolVerboseResult, error) {
	// btcjson.GetRawMempoolVerboseResult expects `fee`, while modern Bitcoin Core
	// often returns `fees.base`. Decode raw JSON and backfill Fee from fees.base so
	// downstream fee-rate math remains accurate.
	rawResp, err := c.RPC.RawRequest("getrawmempool", []json.RawMessage{
		json.RawMessage(`true`), // verbose=true
	})
	if err != nil {
		return nil, err
	}

	verbose := make(map[string]btcjson.GetRawMempoolVerboseResult)
	if err := json.Unmarshal(rawResp, &verbose); err != nil {
		return nil, err
	}

	var modern map[string]struct {
		Fee  float64 `json:"fee"`
		Fees struct {
			Base float64 `json:"base"`
		} `json:"fees"`
	}
	if err := json.Unmarshal(rawResp, &modern); err == nil {
		for txid, entry := range verbose {
			if entry.Fee > 0 {
				continue
			}
			raw := modern[txid]
			switch {
			case raw.Fees.Base > 0:
				entry.Fee = raw.Fees.Base
			case raw.Fee > 0:
				entry.Fee = raw.Fee
			}
			verbose[txid] = entry
		}
	}

	return verbose, nil
}

func (c *Client) GetBlockTemplate(rules []string) (*btcjson.GetBlockTemplateResult, error) {
	// btcd rpcclient's GetBlockTemplate takes a request object, but standard one might be simpler.
	// We'll use the raw 'getblocktemplate' request if the wrapper is strict.
	// rpcclient.GetBlockTemplateRequest matches
	req := btcjson.TemplateRequest{
		Rules: rules,
	}
	return c.RPC.GetBlockTemplate(&req)
}

func (c *Client) GetRawTransaction(txHash *chainhash.Hash) (*btcjson.TxRawResult, error) {
	// Returns Verbose result
	return c.RPC.GetRawTransactionVerbose(txHash)
}

// ScanTxOutset is complex, usually takes a descriptor.
// btcd might default to specific types.
// We'll use RawRequest for flexibility if needed, but let's try strict first.
// Custom struct since btcjson might be missing this specific one or named differently
type ScanTxOutResult struct {
	Success     bool        `json:"success"`
	TxOuts      int64       `json:"txouts"`
	Height      int64       `json:"height"`
	BestBlock   string      `json:"bestblock"`
	Unspents    []ScanTxOut `json:"unspents"`
	TotalAmount float64     `json:"total_amount"`
}

type ScanTxOut struct {
	TxID         string  `json:"txid"`
	Vout         uint32  `json:"vout"`
	ScriptPubKey string  `json:"scriptPubKey"`
	Amount       float64 `json:"amount"`
	Height       int64   `json:"height"`
	Desc         string  `json:"desc,omitempty"`
}

// GetMempoolInfo returns the result of the getmempoolinfo RPC call
func (c *Client) GetMempoolInfo() (*btcjson.GetMempoolInfoResult, error) {
	rawResp, err := c.RPC.RawRequest("getmempoolinfo", nil)
	if err != nil {
		return nil, err
	}

	var res btcjson.GetMempoolInfoResult
	if err := json.Unmarshal(rawResp, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

// --- Wallet Management ---

// --- Wallet Management ---

func (c *Client) CreateWallet(name string) error {
	// Explicitly create LEGACY wallet (descriptors=false) because importaddress is not supported on descriptor wallets
	// Args: wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup
	// We want: disable_private_keys=true, descriptors=false

	// Since rpcclient helpers might not expose descriptors opt easily in all versions, we use RawRequest.
	// createwallet "name" true false "" false false true
	params := []interface{}{
		name,  // name
		true,  // disable_private_keys
		false, // blank
		"",    // passphrase
		false, // avoid_reuse
		false, // descriptors
		true,  // load_on_startup
	}

	// Convert to []json.RawMessage
	rawParams := make([]json.RawMessage, len(params))
	for i, v := range params {
		marshaled, err := json.Marshal(v)
		if err != nil {
			return err
		}
		rawParams[i] = marshaled
	}

	_, err := c.RPC.RawRequest("createwallet", rawParams)
	return err
}

func (c *Client) LoadWallet(name string) error {
	_, err := c.RPC.LoadWallet(name)
	return err
}

func (c *Client) ListWallets() ([]string, error) {
	// rpcclient might be missing ListWallets in this version, using RawRequest
	rawResp, err := c.RPC.RawRequest("listwallets", nil)
	if err != nil {
		return nil, err
	}

	var wallets []string
	if err := json.Unmarshal(rawResp, &wallets); err != nil {
		return nil, err
	}
	return wallets, nil
}

// InitializeWallet ensures a wallet exists and is loaded for watch-only operations
func (c *Client) InitializeWallet() error {
	wallets, err := c.ListWallets()
	if err != nil {
		return err
	}

	const walletName = "watcher_legacy_v2"

	// If wallet is already loaded, we are good
	for _, w := range wallets {
		if w == walletName || w == "" { // "" is default wallet
			return nil
		}
	}

	// Try to load it
	if err := c.LoadWallet(walletName); err != nil {
		// If load failed, assume it doesn't exist and create it
		if err := c.CreateWallet(walletName); err != nil {
			return err
		}
	}

	// Initialize WalletRPC
	walletConnCfg := &rpcclient.ConnConfig{
		Host:         c.Config.Host + "/wallet/" + walletName,
		User:         c.Config.User,
		Pass:         c.Config.Pass,
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	walletClient, err := rpcclient.New(walletConnCfg, nil)
	if err != nil {
		return err
	}
	c.WalletRPC = walletClient
	return nil
}

// ImportAddress imports a script (address) into the wallet as watch-only
// Uses importdescriptors (modern) to support descriptor wallets
func (c *Client) ImportAddress(address string, label string, rescan bool) error {
	return c.ImportAddressDescriptor(address, label, rescan)
}

type DescriptorRequest struct {
	Desc      string      `json:"desc"`
	Active    bool        `json:"active"`
	Timestamp interface{} `json:"timestamp"` // "now" or 0
	Label     string      `json:"label"`
}

func (c *Client) ImportAddressDescriptor(address string, label string, rescan bool) error {
	client := c.RPC
	if c.WalletRPC != nil {
		client = c.WalletRPC
	}

	// 1. Get Descriptor Info (checksum)
	// getdescriptorinfo "addr(ADDRESS)"
	descStr := "addr(" + address + ")"
	descParam, err := json.Marshal(descStr)
	if err != nil {
		return err
	}

	resp, err := client.RawRequest("getdescriptorinfo", []json.RawMessage{descParam})
	if err != nil {
		return err
	}

	var info struct {
		Descriptor string `json:"descriptor"` // canonical desc with checksum
	}
	if err := json.Unmarshal(resp, &info); err != nil {
		return err
	}

	// 2. Import
	req := DescriptorRequest{
		Desc:   info.Descriptor,
		Active: false, // addr() descriptor cannot be active? Or true? Usually true for watch-only.
		// For addr(), "active" means it's added to the wallet's active set?
		// "The descriptor must be solvable if 'active' is true" -> addr() is solvable?
		// Wait. addr(X) is not solvable (no keys).
		// But importaddress makes it watch-only.
		// "Active descriptors are those that the wallet watches and uses..."
		// For watch-only wallet, we want active=true?
		// Let's try active=true. If error says "not solvable", we try false?
		// Actually, standard practice for watch-only address is active=false on descriptor wallet?
		// No, if active=false, it might just store it but not track balance?
		// Let's allow fallback or try simple approach.
		// NOTE: "importdescriptors" documentation:
		// "If 'active' is true, the descriptor must be solvable".
		// addr(X) is NOT solvable. So we must set active=false?
		// But then how do we watch it?
		// Maybe we need combo(pkh(X))? No.
		// Wait. importaddress (legacy) makes it watch-only.
		// importdescriptors with addr(X) adds it.
		// If active=false, does it scan?
		// "Importing descriptors ... active=false ... will just add them to the wallet."
		// Does ListUnspent find them? Yes, if we scan.
		Timestamp: "now",
		Label:     label,
	}
	if rescan {
		req.Timestamp = 0
	}

	reqBytes, err := json.Marshal([]DescriptorRequest{req})
	if err != nil {
		return err
	}

	// Returns array of results
	_, err = client.RawRequest("importdescriptors", []json.RawMessage{reqBytes})
	return err
}

// ListUnspent returns UTXOs for specific addresses
func (c *Client) ListUnspent(addresses []string) ([]btcjson.ListUnspentResult, error) {
	// Convert strings to btcutil.Address
	decodedAddrs := make([]btcutil.Address, 0, len(addresses))
	for _, addr := range addresses {
		decoded, err := btcutil.DecodeAddress(addr, &chaincfg.MainNetParams)
		if err != nil {
			return nil, err
		}
		decodedAddrs = append(decodedAddrs, decoded)
	}

	// minConf=0, maxConf=9999999
	if c.WalletRPC != nil {
		return c.WalletRPC.ListUnspentMinMaxAddresses(0, 9999999, decodedAddrs)
	}
	return c.RPC.ListUnspentMinMaxAddresses(0, 9999999, decodedAddrs)
}

func (c *Client) ScanTxOutset(action string, descriptors []string) (*ScanTxOutResult, error) {
	// Build JSON-RPC params
	param1, _ := json.Marshal(action)
	params := []json.RawMessage{param1}

	if len(descriptors) > 0 {
		descObjects := make([]map[string]string, len(descriptors))
		for i, d := range descriptors {
			descObjects[i] = map[string]string{"desc": d}
		}
		param2, _ := json.Marshal(descObjects)
		params = append(params, param2)
	}

	// Use a direct HTTP POST with a 5-minute timeout.
	// The default rpcclient timeout is 60s which is too short for scantxoutset;
	// it causes a timeout + automatic retry that triggers "-8: Scan already in progress".
	type jsonRPCRequest struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      int               `json:"id"`
		Method  string            `json:"method"`
		Params  []json.RawMessage `json:"params"`
	}
	reqBody, _ := json.Marshal(jsonRPCRequest{
		JSONRPC: "1.0",
		ID:      1,
		Method:  "scantxoutset",
		Params:  params,
	})

	url := fmt.Sprintf("http://%s", c.Config.Host)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("scantxoutset: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(c.Config.User, c.Config.Pass)

	httpClient := &http.Client{Timeout: 5 * time.Minute}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("scantxoutset: http request: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("scantxoutset: read body: %w", err)
	}

	type jsonRPCResponse struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("scantxoutset: unmarshal rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("%d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var res ScanTxOutResult
	if err := json.Unmarshal(rpcResp.Result, &res); err != nil {
		return nil, fmt.Errorf("scantxoutset: unmarshal result: %w", err)
	}

	return &res, nil
}

func (c *Client) GetPeerInfo() ([]btcjson.GetPeerInfoResult, error) {
	return c.RPC.GetPeerInfo()
}

// GetTxOutSetInfoLong calls gettxoutsetinfo with a 3-minute timeout.
// The default rpcclient timeout (60s) is too short for this expensive RPC.
func (c *Client) GetTxOutSetInfoLong() (json.RawMessage, error) {
	type jsonRPCRequest struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      int               `json:"id"`
		Method  string            `json:"method"`
		Params  []json.RawMessage `json:"params"`
	}
	reqBody, _ := json.Marshal(jsonRPCRequest{
		JSONRPC: "1.0",
		ID:      1,
		Method:  "gettxoutsetinfo",
		Params:  []json.RawMessage{},
	})

	url := fmt.Sprintf("http://%s", c.Config.Host)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("gettxoutsetinfo: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(c.Config.User, c.Config.Pass)

	httpClient := &http.Client{Timeout: 3 * time.Minute}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gettxoutsetinfo: http request: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("gettxoutsetinfo: read body: %w", err)
	}

	type jsonRPCResponse struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("gettxoutsetinfo: unmarshal rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("%d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func (c *Client) estimateSmartFeeByMode(confTarget int64, mode *btcjson.EstimateSmartFeeMode) (float64, error) {
	res, err := c.RPC.EstimateSmartFee(confTarget, mode)
	if err != nil {
		return 0, err
	}
	if res == nil || res.FeeRate == nil {
		return 0, nil
	}
	if !isFinitePositive(*res.FeeRate) {
		return 0, nil
	}
	return *res.FeeRate, nil
}

func (c *Client) getMempoolFeeFloorBTCPerKVb() (float64, error) {
	rawResp, err := c.RPC.RawRequest("getmempoolinfo", nil)
	if err != nil {
		return 0, err
	}

	var mempool struct {
		MempoolMinFee float64 `json:"mempoolminfee"`
		MinRelayTxFee float64 `json:"minrelaytxfee"`
	}
	if err := json.Unmarshal(rawResp, &mempool); err != nil {
		return 0, err
	}

	floor := mempool.MempoolMinFee
	if mempool.MinRelayTxFee > floor {
		floor = mempool.MinRelayTxFee
	}
	if !isFinitePositive(floor) {
		return 0, nil
	}
	return floor, nil
}

func isFinitePositive(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0
}

func BTCPerKVbToSatPerVB(v float64) float64 {
	return v * 100_000
}

func (c *Client) EstimateSmartFee(confTarget int64) (float64, error) {
	// BTC/kvB smart fee estimate with fallback chain:
	// CONSERVATIVE -> ECONOMICAL -> mempool floor.
	conservative := btcjson.EstimateModeConservative
	if fee, err := c.estimateSmartFeeByMode(confTarget, &conservative); err == nil && fee > 0 {
		return fee, nil
	}

	economical := btcjson.EstimateModeEconomical
	if fee, err := c.estimateSmartFeeByMode(confTarget, &economical); err == nil && fee > 0 {
		return fee, nil
	}

	return c.getMempoolFeeFloorBTCPerKVb()
}

func (c *Client) EstimateSmartFeeSatVB(confTarget int64) (float64, error) {
	feeBTCPerKVb, err := c.EstimateSmartFee(confTarget)
	if err != nil {
		return 0, err
	}
	return BTCPerKVbToSatPerVB(feeBTCPerKVb), nil
}

func (c *Client) GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error) {
	return c.RPC.GetBlockChainInfo()
}

func (c *Client) GetBlockVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseResult, error) {
	return c.RPC.GetBlockVerbose(blockHash)
}

func (c *Client) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	return c.RPC.GetBlockHash(blockHeight)
}

// ListTransactions returns the most recent transactions for the wallet
func (c *Client) ListTransactions(pattern string, count int, skip int, watchOnly bool) ([]btcjson.ListTransactionsResult, error) {
	client := c.RPC
	if c.WalletRPC != nil {
		client = c.WalletRPC
	}

	// listtransactions "label" count skip watchonly
	// default label="*"
	params := []interface{}{
		pattern,
		count,
		skip,
		watchOnly,
	}

	rawParams := make([]json.RawMessage, len(params))
	for i, v := range params {
		marshaled, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		rawParams[i] = marshaled
	}

	rawResp, err := client.RawRequest("listtransactions", rawParams)
	if err != nil {
		return nil, err
	}

	var res []btcjson.ListTransactionsResult
	if err := json.Unmarshal(rawResp, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// GetNetworkInfo returns network info
func (c *Client) GetNetworkInfo() (*btcjson.GetNetworkInfoResult, error) {
	return c.RPC.GetNetworkInfo()
}

// GetMiningInfo returns mining info
func (c *Client) GetMiningInfo() (*btcjson.GetMiningInfoResult, error) {
	return c.RPC.GetMiningInfo()
}

// GetKnownNodes returns known node addresses from addrman
func (c *Client) GetKnownNodes(count int32) ([]btcjson.GetNodeAddressesResult, error) {
	return c.RPC.GetNodeAddresses(&count)
}
