package wltbase

// Background backfill of the local Transaction table from on-chain
// indexers, so `client.transactions.list()` can return actual wallet
// activity (incoming txs, activity from other devices, historical txs
// from before a restore) — not just the txs this install built via
// signAndSend.
//
// Two paths, tried in order, fall through on any RPC-level error
// (method-not-found, unauthorized, rate-limited, …):
//
//   1. modchain_historyByAddress(addr, continueKey) — the preferred
//      path when the user's RPC is backed by a KarpelesLab modchain
//      data node. Paginated; returns {from, to, value, gas, gasPrice,
//      timestamp, blk, tx}.
//
//   2. Otterscan's ots_searchTransactionsAfter(addr, blockNumber,
//      pageSize) — erigon v3 includes Otterscan extensions. Returns a
//      similar shape. Used as a fallback for providers that don't run
//      modchain-datanode but do run erigon + Otterscan.
//
// Neither path is mandatory: if both fail, the user still sees their
// locally-built txs and no history — that's the pre-existing behavior,
// not a regression.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

func init() {
	pobj.RegisterStatic("Transaction:backfill", apiTransactionBackfill)
}

// apiTransactionBackfill exposes the otherwise-implicit tx-history
// backfill machinery to hosts that want to force a sweep without
// relying on the `account:current_changed` / `network:current_changed`
// side-effects. Idempotent — if a sweep is already in flight for
// (currentAccount, currentNetwork) the call is a no-op and returns
// `{started: false}`. Otherwise schedules a fresh sweep against the
// network's `TxHistoryProvider` and returns `{started: true,
// provider: <name>}` immediately; the sweep runs in the background
// and emits `tx:history_updated` on completion just like the
// implicit path does.
//
// Useful for "Pull to refresh" UIs and post-import flows where the
// host knows there's new history to pick up but hasn't toggled the
// current account / network.
func apiTransactionBackfill(ctx context.Context, in *struct{}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	envv, ok := e.(*env)
	if !ok {
		return nil, errors.New("env is not the wltbase env type")
	}
	acct, err := wltacct.CurrentAccount(e)
	if err != nil {
		return nil, fmt.Errorf("no current account: %w", err)
	}
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, fmt.Errorf("no current network: %w", err)
	}
	provider := n.TxHistoryProvider()
	if provider == "" {
		return map[string]any{
			"started":  false,
			"provider": "",
			"reason":   "no tx-history provider implemented for " + n.Type,
		}, nil
	}
	// scheduleTxHistoryBackfill is idempotent via the in-flight
	// LoadOrStore map; second concurrent call lands as a no-op.
	key := acct.Id.String() + "/" + n.Id.String()
	v, _ := txHistoryBackfillInFlight.LoadOrStore(key, new(atomic.Bool))
	flag := v.(*atomic.Bool)
	alreadyRunning := flag.Load()
	scheduleTxHistoryBackfill(envv, acct, n)
	return map[string]any{
		"started":  !alreadyRunning,
		"provider": provider,
	}, nil
}

const (
	// txHistoryTimeout caps one full backfill sweep. We don't want a
	// slow indexer holding a goroutine indefinitely; users care most
	// about their most recent txs which come first anyway.
	txHistoryTimeout = 45 * time.Second

	// txHistoryMaxPages bounds how many pages we pull per sweep.
	// modchain returns 25 per page, so 40 pages = 1000 txs, which is
	// enough to cover typical mainnet accounts.
	txHistoryMaxPages = 40
)

// txHistoryBackfillInFlight guards against concurrent sweeps for the
// same (account, network). A second trigger while one is still running
// is silently dropped.
var txHistoryBackfillInFlight sync.Map // key: "<acctId>/<netId>" → *atomic.Bool

// watchCurrentChanges listens for account:current_changed /
// network:current_changed events (emitted from wltacct + wltnet) and
// fires a tx-history backfill for the new (account, network) pair.
// Started once at env init — the channels stay open for the env's
// lifetime.
func watchCurrentChanges(e *env) {
	hub := e.em
	if hub == nil {
		return
	}
	trigger := func() {
		n, err := wltnet.CurrentNetwork(e)
		if err != nil {
			return
		}
		acct, err := wltacct.CurrentAccount(e)
		if err != nil {
			return
		}
		scheduleTxHistoryBackfill(e, acct, n)
	}
	go func() {
		ch := hub.On("account:current_changed")
		for range ch {
			trigger()
		}
	}()
	go func() {
		ch := hub.On("network:current_changed")
		for range ch {
			trigger()
		}
	}()
	// Initial sweep for whatever is current right now.
	trigger()
}

// scheduleTxHistoryBackfill starts an idempotent background sweep for
// the given account on the given network. Returns immediately; the
// sweep runs in a goroutine with its own timeout.
func scheduleTxHistoryBackfill(e *env, acct *wltacct.Account, n *wltnet.Network) {
	if e == nil || acct == nil || acct.Id == nil || n == nil || n.Id == nil {
		return
	}
	if n.TxHistoryProvider() == "" {
		// No on-chain indexer wired for this chain — skip silently.
		// Bitcoin family still falls in this bucket; its xpub-scan
		// story can come in a follow-up.
		return
	}
	if acct.GetAddress() == "" || acct.GetAddress() == "N/A" {
		return
	}

	key := acct.Id.String() + "/" + n.Id.String()
	v, _ := txHistoryBackfillInFlight.LoadOrStore(key, new(atomic.Bool))
	flag := v.(*atomic.Bool)
	if !flag.CompareAndSwap(false, true) {
		return // already running
	}

	go func() {
		defer flag.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), txHistoryTimeout)
		defer cancel()
		runTxHistoryBackfill(ctx, e, acct, n)
	}()
}

func runTxHistoryBackfill(ctx context.Context, e *env, acct *wltacct.Account, n *wltnet.Network) {
	log := slog.Default().With("component", "tx_history", "account", acct.Id.String(), "network", n.Id.String())

	switch n.Type {
	case "solana":
		count, err := backfillSolanaFromSignatures(ctx, e, acct, n)
		if err == nil {
			if count > 0 {
				log.Info("backfilled from getSignaturesForAddress", "count", count)
				broadcastTxHistoryUpdated(acct, n, count)
			}
			return
		}
		log.Debug("getSignaturesForAddress unavailable", "err", err)
		return

	case "evm":
		count, err := backfillEVMFromModchain(ctx, e, acct, n)
		if err == nil && count > 0 {
			log.Info("backfilled from modchain", "count", count)
			broadcastTxHistoryUpdated(acct, n, count)
			return
		}
		if err != nil {
			log.Debug("modchain_historyByAddress unavailable", "err", err)
		}

		count, err = backfillEVMFromOtterscan(ctx, e, acct, n)
		if err == nil && count > 0 {
			log.Info("backfilled from ots_searchTransactionsAfter", "count", count)
			broadcastTxHistoryUpdated(acct, n, count)
			return
		}
		if err != nil {
			log.Debug("ots_searchTransactionsAfter unavailable", "err", err)
		}
	default:
		// bitcoin family / future chains — no tx-history provider
		// implemented yet. Surfaced via Network.TxHistoryProvider so
		// hosts can tell "indexer empty" from "indexer not
		// implemented".
	}
}

func broadcastTxHistoryUpdated(acct *wltacct.Account, n *wltnet.Network, count int) {
	wltutil.BroadcastMsg("tx:history_updated", map[string]any{
		"account": acct.Id.String(),
		"network": n.Id.String(),
		"count":   count,
	})
}

// ── modchain_historyByAddress ─────────────────────────────────────────────

type modchainHistoryPage struct {
	Results []struct {
		Blk  uint64          `json:"blk"`
		Tx   string          `json:"tx"`
		Data json.RawMessage `json:"data"`
	} `json:"results"`
	ContinueKey string `json:"continueKey,omitempty"`
}

type modchainEvmSummary struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Value     string `json:"value"`
	Gas       string `json:"gas"`
	GasPrice  string `json:"gasPrice"`
	Timestamp string `json:"timestamp"`
}

func backfillEVMFromModchain(ctx context.Context, e *env, acct *wltacct.Account, n *wltnet.Network) (int, error) {
	addr := strings.ToLower(acct.GetAddress())
	continueKey := ""
	total := 0

	for page := 0; page < txHistoryMaxPages; page++ {
		raw, err := n.DoRPCCtx(ctx, "modchain_historyByAddress", addr, continueKey)
		if err != nil {
			return total, err
		}
		var p modchainHistoryPage
		if err := json.Unmarshal(raw, &p); err != nil {
			return total, fmt.Errorf("decode page %d: %w", page, err)
		}
		if len(p.Results) == 0 {
			break
		}

		// Newest → oldest on this page. We stop at the first row we
		// already have — the user's local DB is mostly caught up, so
		// after the initial sync subsequent sweeps do O(page-size)
		// work per account-activation.
		sawKnown := false
		for _, r := range p.Results {
			hash := strings.ToLower(r.Tx)
			if existingTxByHash(e, hash, n) {
				sawKnown = true
				continue
			}
			var s modchainEvmSummary
			if err := json.Unmarshal(r.Data, &s); err != nil {
				continue
			}
			tx := buildEvmHistoryTx(acct, n, hash, r.Blk, &s)
			if tx == nil {
				continue
			}
			if err := psql.Replace(e, tx); err != nil {
				continue
			}
			total++
		}

		if sawKnown || p.ContinueKey == "" {
			break
		}
		continueKey = p.ContinueKey
	}
	return total, nil
}

// ── ots_searchTransactionsAfter (Otterscan / erigon v3) ──────────────────

type otterscanSearchPage struct {
	Txs []struct {
		BlockNumber string `json:"blockNumber"`
		Hash        string `json:"hash"`
		From        string `json:"from"`
		To          string `json:"to"`
		Value       string `json:"value"`
		Gas         string `json:"gas"`
		GasPrice    string `json:"gasPrice"`
		Timestamp   any    `json:"timestamp"` // sometimes present under receipts instead
	} `json:"txs"`
	Receipts   []json.RawMessage `json:"receipts"`
	FirstPage  bool              `json:"firstPage"`
	LastPage   bool              `json:"lastPage"`
	FirstBlock string            `json:"firstBlock"`
	LastBlock  string            `json:"lastBlock"`
}

func backfillEVMFromOtterscan(ctx context.Context, e *env, acct *wltacct.Account, n *wltnet.Network) (int, error) {
	addr := strings.ToLower(acct.GetAddress())
	// blockNumber=0 + pageSize=25 walks from the earliest tx. For a
	// cache-fill this is fine; incremental updates could walk from
	// the last-known-height but we keep v1 simple.
	total := 0
	for page := 0; page < txHistoryMaxPages; page++ {
		raw, err := n.DoRPCCtx(ctx, "ots_searchTransactionsAfter", addr, page*25, 25)
		if err != nil {
			return total, err
		}
		var p otterscanSearchPage
		if err := json.Unmarshal(raw, &p); err != nil {
			return total, fmt.Errorf("decode page %d: %w", page, err)
		}
		if len(p.Txs) == 0 {
			break
		}
		sawKnown := false
		for _, t := range p.Txs {
			hash := strings.ToLower(t.Hash)
			if existingTxByHash(e, hash, n) {
				sawKnown = true
				continue
			}
			blk, _ := parseHex(t.BlockNumber)
			s := modchainEvmSummary{
				From: t.From, To: t.To, Value: t.Value,
				Gas: t.Gas, GasPrice: t.GasPrice,
			}
			tx := buildEvmHistoryTx(acct, n, hash, blk, &s)
			if tx == nil {
				continue
			}
			if err := psql.Replace(e, tx); err != nil {
				continue
			}
			total++
		}
		if sawKnown || p.LastPage {
			break
		}
	}
	return total, nil
}

// ── shared helpers ────────────────────────────────────────────────────────

func existingTxByHash(e *env, hash string, n *wltnet.Network) bool {
	_, err := psql.Get[wlttx.Transaction](e, map[string]any{
		"Hash":    hash,
		"Network": n.Id.String(),
	})
	return err == nil
}

func buildEvmHistoryTx(acct *wltacct.Account, n *wltnet.Network, hash string, blk uint64, s *modchainEvmSummary) *wlttx.Transaction {
	_ = blk // reserved for a future "confirmations" column
	id, err := xuid.NewRandom("tx")
	if err != nil {
		return nil
	}
	decimals := n.CurrencyDecimals
	if decimals == 0 {
		decimals = 18
	}
	val, _ := parseHexBig(s.Value)

	ts := time.Time{}
	if n, ok := parseHexBig(s.Timestamp); ok && n.IsInt64() {
		ts = time.Unix(n.Int64(), 0)
	}

	gas, _ := parseHex(s.Gas)
	return &wlttx.Transaction{
		Id:       id,
		Type:     "transfer",
		Asset:    n.String() + ".NATIVE",
		From:     strings.ToLower(s.From),
		To:       strings.ToLower(s.To),
		Gas:      gas,
		GasPrice: s.GasPrice,
		Hash:     hash,
		Network:  n.Id,
		Amount:   wltobj.NewAmountRaw(val, decimals),
		URL:      n.TransactionUrl(hash),
		Created:  &ts,
	}
}

func parseHex(s string) (uint64, bool) {
	n, ok := parseHexBig(s)
	if !ok || !n.IsUint64() {
		return 0, false
	}
	return n.Uint64(), true
}

func parseHexBig(s string) (*big.Int, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		return big.NewInt(0), true
	}
	if _, err := hex.DecodeString(s); err == nil {
		n := new(big.Int)
		if _, ok := n.SetString(s, 16); ok {
			return n, true
		}
	}
	// Fallback: decimal (modchain sometimes returns timestamps as decimal).
	n := new(big.Int)
	if _, ok := n.SetString(s, 10); ok {
		return n, true
	}
	return nil, false
}
