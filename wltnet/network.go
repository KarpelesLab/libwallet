package wltnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/ethrpc/chains"
	"github.com/KarpelesLab/libwallet/wltasset"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltnft"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

var (
	networkCache   = make(map[xuid.XUID]*Network)
	networkCacheLk sync.Mutex
)

const ModChainApiKey = "crapi-nx4p6j-ifez-cjli-p5wj-uml43cte"

type Network struct {
	TableName        psql.Name      `sql:"Network"`
	Id               *xuid.XUID     `sql:",key=PRIMARY"`
	Type             string         `sql:",type=VARCHAR,size=255,key=UNIQUE:typeChain"` // evm | bitcoin
	ChainId          string         `sql:",type=VARCHAR,size=255,key=UNIQUE:typeChain"` // for Type=evm, the chain id from chainlist. For Type=bitcoin, chain key is included here
	Name             string         `sql:",type=VARCHAR,size=255"`                      // name, automatic if empty
	RPC              string         `sql:",type=TEXT"`                                  // rpc url, automatic if empty
	validRPC         ethrpc.Handler `sql:"-"`                                           // general-purpose RPC (eth_*, etc.); freshness-picked on mainnet
	modchainRPC      ethrpc.Handler `sql:"-"`                                           // direct modchain endpoint for `modchain_*` proprietary methods; nil when the chain has no modchain node
	CurrencySymbol   string         `sql:",type=VARCHAR,size=255"`                      // currency symbol, automatic if empty
	CurrencyDecimals int            `sql:",type=INT"`                                   // decimals, automatic if zero
	BlockExplorer    string         `sql:",type=TEXT"`                                  // explorer, automatic if empty
	TestNet          bool           `sql:",type=TINYINT,size=1"`                        // is this a testnet?
	Priority         int            `sql:",type=INT"`                                   // display priority
	Created          time.Time      `sql:",type=DATETIME"`                              // Creation timestamp
	Updated          time.Time      `sql:",type=DATETIME"`                              // Last update timestamp
}

type NativeCurrencyObject struct {
	Decimals int    `json:"decimals"`
	Name     string `json:"name"`
	Symbol   string `json:"symbol"`
}

type AddEthereumChainParameter struct {
	ChainId           string               `json:"chainId"` // The chain ID as a 0x-prefixed hexadecimal string
	BlockExplorerUrls []string             `json:"blockExplorerUrls"`
	ChainName         string               `json:"chainName"`
	IconUrls          []string             `json:"iconUrls"`
	NativeCurrency    NativeCurrencyObject `json:"nativeCurrency"`
	RPCUrls           []string             `json:"rpcUrls"`
}

func (a *AddEthereumChainParameter) Validate() error {
	if !strings.HasPrefix(a.ChainId, "0x") {
		return &apirouter.Error{Code: -32602, Message: "Expected 0x-prefixed, unpadded, non-zero hexadecimal string 'chainId'."}
	}
	bigV, ok := new(big.Int).SetString(a.ChainId, 0)
	if !ok || "0x"+bigV.Text(16) != a.ChainId {
		return &apirouter.Error{Code: -32602, Message: "Expected 0x-prefixed, unpadded, non-zero hexadecimal string 'chainId'."}
	}
	if len(a.ChainName) < 3 {
		return &apirouter.Error{Code: -32602, Message: "Expected chainName"}
	}
	if n := len(a.NativeCurrency.Symbol); n < 2 || n > 6 {
		return &apirouter.Error{Code: -32602, Message: "Expected 2-6 character string 'nativeCurrency.symbol'."}
	}
	// TODO add more checks?

	return nil
}

func (a *AddEthereumChainParameter) AsNetwork() *Network {
	bigV, _ := new(big.Int).SetString(a.ChainId, 0)
	if len(a.RPCUrls) == 0 {
		a.RPCUrls = []string{"auto"}
	}

	net := &Network{
		Id:               NetworkIdForTypeAndChainId("evm", bigV.Text(10)),
		Type:             "evm",
		ChainId:          bigV.Text(10),
		Name:             a.ChainName,
		RPC:              "auto",
		CurrencySymbol:   a.NativeCurrency.Symbol,
		CurrencyDecimals: a.NativeCurrency.Decimals,
		BlockExplorer:    "auto",
	}
	if len(a.RPCUrls) > 0 {
		net.RPC = a.RPCUrls[0]
	}
	if len(a.BlockExplorerUrls) > 0 {
		net.BlockExplorer = a.BlockExplorerUrls[0]
	}
	return net
}

func (n *Network) check() error {
	// check network status and fill anything missing
	switch n.Type {
	case "evm":
		// ok
	case "bitcoin":
		switch n.ChainId {
		case "bitcoin":
			if n.Name == "" {
				n.Name = "Bitcoin"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "BTC"
			}
		case "bitcoin-cash":
			if n.Name == "" {
				n.Name = "Bitcoin Cash"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "BCH"
			}
		case "litecoin":
			if n.Name == "" {
				n.Name = "Litecoin"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "LTC"
			}
		case "dogecoin":
			if n.Name == "" {
				n.Name = "Dogecoin"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "DOGE"
			}
		case "monacoin":
			if n.Name == "" {
				n.Name = "Monacoin"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "MONA"
			}
		case "namecoin":
			if n.Name == "" {
				n.Name = "Namecoin"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "NMC"
			}
		case "electraproto":
			if n.Name == "" {
				n.Name = "Electra Protocol"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "XEP"
			}
		default:
			return fmt.Errorf("invalid network type %s/%s", n.Type, n.ChainId)
		}
	case "solana":
		switch n.ChainId {
		case "mainnet":
			if n.Name == "" {
				n.Name = "Solana"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "SOL"
			}
		case "devnet":
			if n.Name == "" {
				n.Name = "Solana Devnet"
			}
			if n.CurrencySymbol == "" {
				n.CurrencySymbol = "SOL"
			}
			n.TestNet = true
		default:
			return fmt.Errorf("invalid network type %s/%s", n.Type, n.ChainId)
		}
		if n.CurrencyDecimals == 0 {
			n.CurrencyDecimals = 9
		}
		if n.RPC == "" {
			n.RPC = "auto"
		}
		if n.BlockExplorer == "" {
			n.BlockExplorer = "auto"
		}
		return nil
	default:
		return fmt.Errorf("invalid network type %s", n.Type)
	}
	info, err := n.GetChainInfo()
	if err != nil {
		// ignore fetch failed but do not input anything either
		return nil
	}
	if info.ChainId == 137 && n.CurrencySymbol == "MATIC" {
		n.CurrencySymbol = "POL"
	}
	if n.Name == "" {
		n.Name = info.Name
	}
	if n.RPC == "" {
		n.RPC = "auto"
	}
	if n.CurrencySymbol == "" {
		n.CurrencySymbol = info.NativeCurrency.Symbol
	}
	if n.BlockExplorer == "" {
		n.BlockExplorer = "auto"
	}
	return nil
}

func (n *Network) Save(e wltintf.Env) error {
	if n.Id == nil {
		// compute id
		n.Id = xuid.Must(xuid.FromKeyPrefix(n.Type+"."+n.ChainId, "net"))
	}
	now := time.Now()
	if n.Created.IsZero() {
		n.Created = now
	}
	n.Updated = now
	return psql.Replace(e, n)
}

func NetworkIdForTypeAndChainId(typ, chainId string) *xuid.XUID {
	return xuid.Must(xuid.FromKeyPrefix(typ+"."+chainId, "net"))
}

func (n *Network) addToCache() {
	networkCacheLk.Lock()
	defer networkCacheLk.Unlock()

	networkCache[*n.Id] = n
}

func networkFromCache(id *xuid.XUID) *Network {
	networkCacheLk.Lock()
	defer networkCacheLk.Unlock()
	k, ok := networkCache[*id]
	if ok {
		return k
	}
	return nil
}

func (n *Network) SetCurrent(e wltintf.Env) error {
	// broadcast change
	go wltutil.BroadcastMsg("js:chainChanged", map[string]any{"chainId": n.ChainId})
	return e.SetCurrent("network", n.Id.String())
}

func (n *Network) MarshalJSON() ([]byte, error) {
	res := map[string]any{
		"Id":             n.Id,
		"Type":           n.Type,
		"ChainId":        n.ChainId,
		"Name":           n.Name,
		"RPC":            n.RPC,
		"CurrencySymbol": n.CurrencySymbol,
		"BlockExplorer":  n.BlockExplorer,
		"TestNet":        n.TestNet,
		"Created":        n.Created,
		"Updated":        n.Updated,
	}

	switch n.Type {
	case "evm":
		res["EVM_Info"], _ = n.GetChainInfo()
		return json.Marshal(res)
	default:
		return json.Marshal(res)
	}
}

func (n *Network) String() string {
	return n.Type + "." + n.ChainId
}

func (n *Network) GetChainInfo() (*chains.ChainInfo, error) {
	if n.Type != "evm" {
		return nil, errors.New("unsupported for this network Type")
	}
	idN, err := strconv.ParseUint(n.ChainId, 0, 64)
	if err != nil {
		return nil, err
	}
	info := chains.Get(idN)
	if info == nil {
		return nil, fmt.Errorf("unknown net id %d", idN)
	}
	return info, nil
}

func (n *Network) NativeSymbol() (string, error) {
	switch n.Type {
	case "evm":
		info, err := n.GetChainInfo()
		if err != nil {
			return "", err
		}
		return info.NativeCurrency.Symbol, nil
	case "bitcoin":
		switch n.ChainId {
		case "bitcoin":
			return "BTC", nil
		case "bitcoin-cash":
			return "BCH", nil
		case "litecoin":
			return "LTC", nil
		case "dogecoin":
			return "DOGE", nil
		default:
			return "", fmt.Errorf("unsupported bitcoin chain type %s", n.ChainId)
		}
	case "solana":
		return "SOL", nil
	default:
		return "", errors.New("symbol not available (not supported type)")
	}
}

func (n *Network) TransactionUrl(txHash string) string {
	if n.Type == "solana" {
		if e := n.BlockExplorer; e != "" && e != "auto" {
			return fmt.Sprintf("%s/tx/%s", e, txHash)
		}
		return fmt.Sprintf("https://explorer.solana.com/tx/%s", txHash)
	}
	if e := n.BlockExplorer; e != "" && e != "auto" {
		return fmt.Sprintf("%s/tx/%s", e, txHash)
	}
	info, err := n.GetChainInfo()
	if err != nil {
		return ""
	}
	return info.TransactionUrl(txHash)
}

func (n *Network) getRPC() (ethrpc.Handler, error) {
	if n.Type == "solana" {
		if n.validRPC != nil {
			return n.validRPC, nil
		}
		if n.RPC != "" && n.RPC != "auto" {
			n.validRPC = ethrpc.New(n.RPC)
			return n.validRPC, nil
		}
		// Route to the correct Helius endpoint based on chain
		switch n.ChainId {
		case "devnet":
			n.validRPC = ethrpc.New("https://trudie-xvrnf4-fast-devnet.helius-rpc.com")
		default: // mainnet
			n.validRPC = ethrpc.New("https://kristi-cykm4t-fast-mainnet.helius-rpc.com")
		}
		return n.validRPC, nil
	}
	if n.Type == "bitcoin" {
		if n.validRPC != nil {
			return n.validRPC, nil
		}
		// Bitcoin family always goes through modchain — both standard
		// (sendrawtransaction etc.) and proprietary modchain_* calls
		// resolve against the same handle.
		h := ethrpc.New("https://rpc.modchain.net/api/" + ModChainApiKey + "/" + n.ChainId + "/rpc")
		n.validRPC = h
		n.modchainRPC = h
		return n.validRPC, nil
	}
	if n.RPC != "" && n.RPC != "auto" {
		return ethrpc.New(n.RPC), nil
	}
	if n.validRPC != nil {
		return n.validRPC, nil
	}

	// get RPC servers and select the best one
	info, err := n.GetChainInfo()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var rpcList []string

	// Ethereum mainnet: prefer the dedicated modchain RPC, but fall
	// back to the chain-info RPC pool whenever modchain is more than
	// ~100 blocks behind the network head (≈20 min on Ethereum). A
	// recent incident had modchain serving ~23 days stale data —
	// returning 0x0 balances for accounts funded after its last sync
	// — and the previous unconditional pin gave us no way to detect
	// or escape that. The freshness-aware picker keeps modchain the
	// preferred endpoint when healthy and routes around it otherwise.
	//
	// Polygon (chainId 137) used to pin modchain too; the modchain
	// operator removed the polygon node, so polygon falls through to
	// the standard chain-info Evaluate path below.
	if info.ChainId == 1 {
		// Ethereum mainnet has TWO different needs:
		//   - Standard methods (eth_getBalance etc.) want the freshest
		//     responder — modchain when healthy, anything else when
		//     modchain falls behind.
		//   - Proprietary modchain_* methods (modchain_assets,
		//     modchain_lookupTxoBIP32, modchain_historyByAddress)
		//     ONLY work on the modchain endpoint, regardless of how
		//     stale its general-purpose state is. Stale modchain_assets
		//     just means "missing recently-acquired NFTs" which is
		//     much less harmful than a stale balance.
		// So we set both handles independently — DoRPCCtx routes by
		// method prefix to the right one.
		modchainURL := "https://rpc.modchain.net/api/" + ModChainApiKey + "/ethereum/rpc"
		n.modchainRPC = ethrpc.New(modchainURL)
		candidates := []string{modchainURL}
		for _, r := range info.RPC {
			r = strings.ReplaceAll(r, "${INFURA_API_KEY}", infuraKey)
			if strings.Contains(r, "${") {
				continue
			}
			candidates = append(candidates, r)
		}
		picked, err := pickFreshestRPC(ctx, 100, candidates...)
		if err != nil {
			return nil, err
		}
		n.validRPC = picked
		return picked, nil
	}

	for _, r := range info.RPC {
		r = strings.ReplaceAll(r, "${INFURA_API_KEY}", infuraKey)
		if strings.Contains(r, "${") {
			continue
		}
		rpcList = append(rpcList, r)
	}

	list, err := ethrpc.Evaluate(ctx, rpcList...)
	if err != nil {
		return nil, err
	}

	n.validRPC = list
	return list, nil
}

// pickFreshestRPC returns the first RPC in `candidates` whose head
// block is within `maxLag` of the highest head observed across all
// candidates. The candidate order encodes preference — the caller
// typically lists the favored endpoint first, and pickFreshestRPC
// keeps using it as long as it stays "fresh enough", silently
// routing around it when it falls behind.
//
// Why not just take the highest-block responder: a primary endpoint
// might be marginally behind a CDN-fronted competitor by a block or
// two during normal operation, and we don't want to flap between
// them. The lag tolerance window absorbs that noise; only meaningful
// staleness (the modchain "23 days behind" incident the existing
// chainId 1 case was added to handle) trips the fallback.
//
// Returns the first responder if every candidate errored or none
// passed the freshness check, falling back rather than failing the
// whole call — at worst the caller sees a stale balance, the same
// behavior the old unconditional pin produced.
func pickFreshestRPC(ctx context.Context, maxLag uint64, candidates ...string) (ethrpc.Handler, error) {
	if len(candidates) == 0 {
		return nil, errors.New("pickFreshestRPC: no candidates")
	}
	if len(candidates) == 1 {
		return ethrpc.New(candidates[0]), nil
	}

	type result struct {
		rpc   ethrpc.Handler
		block uint64
		err   error
	}
	results := make([]result, len(candidates))
	var wg sync.WaitGroup
	for i, url := range candidates {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			r := ethrpc.New(url)
			block, err := ethrpc.ReadUint64(r.DoCtx(ctx, "eth_blockNumber"))
			results[i] = result{rpc: r, block: block, err: err}
		}(i, url)
	}
	wg.Wait()

	var head uint64
	for _, r := range results {
		if r.err == nil && r.block > head {
			head = r.block
		}
	}
	if head == 0 {
		// Nothing responded — fall back to first candidate so the
		// caller's next RPC attempt at least gets a real upstream
		// error instead of an opaque selection failure.
		return ethrpc.New(candidates[0]), nil
	}
	for i, r := range results {
		if r.err == nil && head-r.block <= maxLag {
			log.Printf("pickFreshestRPC: chose %s (head=%d, behind=%d)", candidates[i], r.block, head-r.block)
			return r.rpc, nil
		}
	}
	// All responders are stale by more than maxLag. Pick the freshest
	// of them so we at least serve recent-ish data.
	bestIdx := -1
	for i, r := range results {
		if r.err != nil {
			continue
		}
		if bestIdx < 0 || results[bestIdx].block < r.block {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		log.Printf("pickFreshestRPC: ALL candidates >%d blocks behind (head=%d); using freshest %s at block %d",
			maxLag, head, candidates[bestIdx], results[bestIdx].block)
		return results[bestIdx].rpc, nil
	}
	return ethrpc.New(candidates[0]), nil
}

// defaultRPCTimeout bounds any call to DoRPC / DoRPCNamed that didn't
// provide its own context. A misbehaving upstream can't wedge a
// goroutine indefinitely — one failed RPC bubbles up an error after at
// most this long. Callers that genuinely need longer must go through
// DoRPCCtx / DoRPCNamedCtx with their own context.
const defaultRPCTimeout = 30 * time.Second

func (n *Network) DoRPC(method string, args ...any) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()
	return n.DoRPCCtx(ctx, method, args...)
}

// DoRPCCtx lets the caller pass a context for timeout / cancellation. Use
// this for RPC calls that could hang on a misbehaving upstream (simulate,
// debug_trace*, long-polling etc).
//
// Routes `modchain_*` proprietary methods (modchain_assets,
// modchain_lookupTxoBIP32, modchain_historyByAddress) to the dedicated
// modchain endpoint when one is configured for this chain, regardless
// of whatever freshness logic picked a different general-purpose RPC.
// Standard methods use the freshness-picked handle.
func (n *Network) DoRPCCtx(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	if _, err := n.getRPC(); err != nil {
		return nil, err
	}
	e := n.validRPC
	if n.modchainRPC != nil && strings.HasPrefix(method, "modchain_") {
		e = n.modchainRPC
	}
	start := time.Now()
	res, err := e.DoCtx(ctx, method, args...)
	if wltlog.Enabled(wltlog.LevelDebug) {
		if err != nil {
			wltlog.Debugf("rpc: chain=%s method=%s FAIL in %s: %s", n.ChainId, method, time.Since(start).Round(time.Millisecond), err)
		} else {
			wltlog.Debugf("rpc: chain=%s method=%s OK in %s (%d bytes)", n.ChainId, method, time.Since(start).Round(time.Millisecond), len(res))
		}
	}
	return res, err
}

// DoRPCNamed sends a JSON-RPC request with named (object) parameters.
// Required for APIs like Helius DAS (`getAssetsByOwner`) that expect the
// params field to be a JSON object rather than an array.
//
// Uses defaultRPCTimeout to bound the call. Use DoRPCNamedCtx when the
// caller needs a different deadline.
func (n *Network) DoRPCNamed(method string, args map[string]any) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()
	return n.DoRPCNamedCtx(ctx, method, args)
}

// DoRPCNamedCtx lets the caller pass a context for timeout / cancellation.
func (n *Network) DoRPCNamedCtx(ctx context.Context, method string, args map[string]any) (json.RawMessage, error) {
	e, err := n.getRPC()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	var res json.RawMessage
	if r, ok := e.(*ethrpc.RPC); ok {
		res, err = r.DoNamedCtx(ctx, method, args)
	} else {
		// Fallback (shouldn't happen with current ethrpc.New): use positional.
		res, err = e.DoCtx(ctx, method, args)
	}
	if wltlog.Enabled(wltlog.LevelDebug) {
		if err != nil {
			wltlog.Debugf("rpc-named: chain=%s method=%s FAIL in %s: %s", n.ChainId, method, time.Since(start).Round(time.Millisecond), err)
		} else {
			wltlog.Debugf("rpc-named: chain=%s method=%s OK in %s (%d bytes)", n.ChainId, method, time.Since(start).Round(time.Millisecond), len(res))
		}
	}
	return res, err
}

type AddressProvider interface {
	GetAddress() string
}

// XpubProvider is implemented by account types that can produce a BIP-32
// extended public key string (xpub). Used for xpub-aware RPC methods on
// Bitcoin-family chains.
type XpubProvider interface {
	Xpub() (string, error)
}

func (n *Network) nativeBalance(ctx context.Context, acct AddressProvider) (*wltobj.Amount, error) {
	switch n.Type {
	case "bitcoin":
		return n.bitcoinBalance(ctx, acct)
	case "evm":
		// fetch from RPC
		// https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getbalance
		amt, err := ethrpc.ReadString(n.DoRPCCtx(ctx, "eth_getBalance", acct.GetAddress(), "latest"))
		if err != nil {
			return nil, err
		}
		info, err := n.GetChainInfo()
		if err != nil {
			return nil, err
		}
		// amt is amount in hex
		// info.NativeCurrency.Decimals
		i, ok := new(big.Int).SetString(amt, 0)
		if !ok {
			return nil, errors.New("invalid amount obtained from rpc")
		}
		decimals := n.CurrencyDecimals
		if decimals == 0 {
			decimals = info.NativeCurrency.Decimals
		}
		return wltobj.NewAmountRaw(i, decimals), nil
	case "solana":
		result, err := n.DoRPCCtx(ctx, "getBalance", acct.GetAddress())
		if err != nil {
			return nil, err
		}
		var balResult struct {
			Value uint64 `json:"value"`
		}
		if err := json.Unmarshal(result, &balResult); err != nil {
			return nil, err
		}
		// Subtract the rent-exempt minimum so the balance the UI
		// shows matches what the user can actually spend. The
		// reserve is real SOL that paid for the account to exist
		// on-chain, but the user can never withdraw it without
		// closing the account — exposing it in the displayed
		// balance led to confusion (receive 0.01 SOL, see
		// 0.01089 balance, only able to send ~0.00910 once
		// fees and the reserve are subtracted at send time).
		// RPC failure here falls back to the canonical 0-byte
		// system-account value so we never over-report the
		// spendable amount.
		raw := balResult.Value
		rentRaw, rerr := n.DoRPCCtx(ctx, "getMinimumBalanceForRentExemption", 0)
		var rent uint64 = 890880
		if rerr == nil {
			_ = json.Unmarshal(rentRaw, &rent)
		}
		var spendable uint64
		if raw > rent {
			spendable = raw - rent
		}
		return wltobj.NewAmountRaw(new(big.Int).SetUint64(spendable), 9), nil
	default:
		return nil, fmt.Errorf("unsupported type %s", n.Type)
	}
}

// bitcoinBalance returns the spendable native balance for a Bitcoin-
// family account on n. When the account has an xpub it sums the
// receive-chain (m/0) and change-chain (m/1) balances reported by
// modchain_lookupTxoBIP32. When only a flat address is available it
// falls back to modchain_assets on that address.
//
// Why not modchain_assets on the xpub: that endpoint returns 0 for
// some xpubs even when modchain_lookupTxoBIP32 finds spendable UTXOs
// at the same paths (observed on litecoin with xpub661MyMw…cw —
// modchain_assets returns balance:0, modchain_lookupTxoBIP32/m-0
// returns balance:0.1). modchain_lookupTxoBIP32 is the source of
// truth used by every other libwallet bitcoin path (sign, max-
// sendable, next-address) — using it here too keeps the views
// consistent.
func (n *Network) bitcoinBalance(ctx context.Context, acct AddressProvider) (*wltobj.Amount, error) {
	if xp, ok := acct.(XpubProvider); ok {
		xpub, err := xp.Xpub()
		if err == nil && xpub != "" {
			return n.bitcoinXpubBalance(ctx, xpub)
		}
	}
	addr := acct.GetAddress()
	if addr == "" {
		return nil, errors.New("no address or xpub available")
	}
	return n.bitcoinAddressBalance(ctx, addr)
}

// bitcoinXpubBalance sums modchain_lookupTxoBIP32(m/0) + (m/1)
// balances for xpub. Each call returns a `balance` field already
// expressed in satoshis via outscript.BtcAmount.
func (n *Network) bitcoinXpubBalance(ctx context.Context, xpub string) (*wltobj.Amount, error) {
	type bitcoinTxoResp struct {
		Balance outscript.BtcAmount `json:"balance"`
	}
	var total uint64
	for _, path := range []string{"m/0", "m/1"} {
		raw, err := n.DoRPCCtx(ctx, "modchain_lookupTxoBIP32", xpub, path, true)
		if err != nil {
			return nil, fmt.Errorf("modchain_lookupTxoBIP32 %s: %w", path, err)
		}
		var resp bitcoinTxoResp
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("modchain_lookupTxoBIP32 %s decode: %w", path, err)
		}
		total += uint64(resp.Balance)
	}
	return wltobj.NewAmountRaw(new(big.Int).SetUint64(total), 8), nil
}

// bitcoinAddressBalance fetches modchain_assets for a single flat
// address (used by view-only accounts that have no xpub). Same
// parsing as the previous xpub path; this keeps view-only accounts
// working until they grow xpub support.
func (n *Network) bitcoinAddressBalance(ctx context.Context, address string) (*wltobj.Amount, error) {
	raw, err := n.DoRPCCtx(ctx, "modchain_assets", address)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Assets []struct {
			Asset    string              `json:"asset"`
			Decimals int                 `json:"decimals"`
			Balance  outscript.BtcAmount `json:"balance"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("modchain_assets decode: %w", err)
	}
	var total uint64
	decimals := 8
	for _, a := range resp.Assets {
		if a.Asset != "NATIVE" {
			continue
		}
		if a.Decimals > 0 {
			decimals = a.Decimals
		}
		total += uint64(a.Balance)
	}
	return wltobj.NewAmountRaw(new(big.Int).SetUint64(total), decimals), nil
}

func (n *Network) NativeAsset(ctx context.Context, e wltintf.Env, acct AddressProvider) (*wltasset.Asset, error) {
	switch n.Type {
	case "evm":
		amt, err := n.nativeBalance(ctx, acct)
		if err != nil {
			return nil, err
		}
		info, err := n.GetChainInfo()
		if err != nil {
			return nil, err
		}

		asset := &wltasset.Asset{
			Key:     n.String() + ".NATIVE",
			Name:    info.NativeCurrency.Name,
			Symbol:  info.NativeCurrency.Symbol,
			Amount:  amt,
			Network: n.Id,
			Type:    "fungible",
			TestNet: n.TestNet,
		}
		asset.Info, err = wltasset.CoinInfoBySymbol(e, info.NativeCurrency.Symbol)
		if err != nil {
			log.Printf("error fetching coin infos: %s", err)
		}

		return asset, nil
	case "bitcoin", "solana":
		amt, err := n.nativeBalance(ctx, acct)
		if err != nil {
			return nil, err
		}

		sym, _ := n.NativeSymbol()

		asset := &wltasset.Asset{
			Key:     n.String() + ".NATIVE",
			Name:    n.Name,
			Symbol:  sym,
			Amount:  amt,
			Network: n.Id,
			Type:    "fungible",
			TestNet: n.TestNet,
		}
		asset.Info, _ = wltasset.CoinInfoBySymbol(e, sym)

		return asset, nil
	default:
		return nil, fmt.Errorf("unsupported type %s", n.Type)
	}
}

func (n *Network) Nfts(e wltintf.Env, acct AddressProvider) (*[]wltnft.Nft, error) {
	switch n.Type {
	case "evm":
		// modchain_assets — the upstream NFT discovery service —
		// is mainnet-only. For any other EVM chain (Sepolia,
		// Polygon, Arbitrum, Base, …) return an empty list so
		// the wallet UI just renders "no NFTs" instead of
		// surfacing a 500 to the user. As we add coverage for
		// more chains, extend the supported set here.
		if n.ChainId != "1" {
			return &[]wltnft.Nft{}, nil
		}
		nfts, err := n.NftList(e, acct)
		if err != nil {
			return nil, err
		}
		return nfts, nil
	case "solana":
		return n.NftList(e, acct)
	default:
		return nil, fmt.Errorf("unsupported type %s", n.Type)
	}
}
