package wltswap

// Swap: — quote-and-execute endpoint powered by Jupiter Ultra +
// dFlow (Solana) and 1inch (EVM). See the package doc for the flow
// shape; this file holds the public API types, the in-memory quote
// cache, and the top-level Swap:quote / Swap:execute handlers.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
)

// QuoteRequest is the input to Swap:quote. Callers pass the tokens
// by address (mint / contract) plus the base-unit amount — decimals
// come from the caller's own Asset:list (the Dart client already has
// the data, no reason to duplicate a chain-metadata lookup).
type QuoteRequest struct {
	// From is the account address or ID (empty = current account).
	From string `json:"from,omitempty"`
	// TokenIn / TokenOut are the full token references including
	// decimals. Address "NATIVE" means the chain's native currency.
	TokenIn  TokenRef `json:"tokenIn"`
	TokenOut TokenRef `json:"tokenOut"`
	// AmountIn is the input amount in base units (decimal string).
	AmountIn string `json:"amountIn"`
	// SlippageBps bounds the worst execution price relative to the
	// quote. Zero defaults to DefaultSlippageBps (50 bps / 0.5%).
	SlippageBps uint16 `json:"slippageBps,omitempty"`
	// Network overrides the current network.
	Network string `json:"network,omitempty"`
	// Provider forces a specific aggregator. Empty = auto-select
	// per chain with fallback (Jupiter → dFlow on Solana).
	Provider string `json:"provider,omitempty"`
}

// TokenRef identifies a token by address. Address "NATIVE" means
// the chain's native currency (SOL / ETH); the adapter translates
// to the provider-specific sentinel (1inch uses 0xeeee…eeee).
type TokenRef struct {
	Address  string `json:"address"`
	Symbol   string `json:"symbol,omitempty"`
	Decimals int    `json:"decimals"`
}

// Quote is the output of Swap:quote. The providerBlob (lowercase,
// not JSON-serialized) holds whatever adapter-specific data is
// needed to drive Swap:execute later.
type Quote struct {
	QuoteId       string `json:"quoteId"`
	Provider      string `json:"provider"`      // "jupiter_ultra" | "dflow" | "1inch"
	ProviderLabel string `json:"providerLabel"` // human-friendly: "Jupiter Ultra" / "dFlow" / "1inch"
	Chain         string `json:"chain"`         // "solana" | "evm"

	TokenIn      TokenRef       `json:"tokenIn"`
	TokenOut     TokenRef       `json:"tokenOut"`
	AmountIn     *wltobj.Amount `json:"amountIn"`
	AmountOut    *wltobj.Amount `json:"amountOut"`
	MinAmountOut *wltobj.Amount `json:"minAmountOut"`

	// PriceImpact is the provider-reported execution drift as a
	// fraction (0.01 = 1%). Apps typically warn at > 1%.
	PriceImpact float64 `json:"priceImpact,omitempty"`

	// Fees — bps for app-side math, absolute amounts for display.
	FeeBps      uint16         `json:"feeBps"`
	SlippageBps uint16         `json:"slippageBps"`
	// ReferralFee is our 50 bps take, denominated in the INPUT
	// token's base units (amountIn * feeBps / 10_000). Use this
	// for "platform fee: 0.005 SOL" UI strings.
	ReferralFee *wltobj.Amount `json:"referralFee,omitempty"`
	// NetworkFee is the estimated chain-side fee paid by the user
	// (gas on EVM, signature + priority on Solana). Always in the
	// native currency with the chain's decimals. Call it "Network
	// fee" in UI to distinguish from the platform referral fee.
	NetworkFee *wltobj.Amount `json:"networkFee,omitempty"`

	Route     []RouteHop `json:"route,omitempty"`
	ExpiresAt time.Time  `json:"expiresAt"`

	// ── EVM approval fields (populated by 1inch adapter for non-
	// native tokenIn; all zero-valued on Solana and for native ETH
	// swaps) ───────────────────────────────────────────────────────
	//
	// RequiresApproval is true when the router contract needs a
	// higher allowance on the input token than what the user
	// currently has.
	RequiresApproval bool `json:"requiresApproval,omitempty"`
	// ApprovalSpender is the address that needs the allowance
	// (the aggregator's router contract). Empty on chains /
	// pairs where approval is never needed.
	ApprovalSpender string `json:"approvalSpender,omitempty"`
	// CurrentAllowance is what the spender already has. Zero for
	// first-time approvals.
	CurrentAllowance *wltobj.Amount `json:"currentAllowance,omitempty"`
	// NeededAllowance is the minimum the spender needs for the
	// swap — equal to AmountIn.
	NeededAllowance *wltobj.Amount `json:"neededAllowance,omitempty"`

	// provider-internal fields — not JSON-exposed.
	providerBlob any       `json:"-"`
	createdAt    time.Time `json:"-"`
	from         string    `json:"-"` // account address the quote was issued to
}

// RouteHop is one step in a multi-hop swap path. Purely informative
// — the aggregator decides the actual routing.
type RouteHop struct {
	Venue     string  `json:"venue"`
	InSymbol  string  `json:"inSymbol,omitempty"`
	OutSymbol string  `json:"outSymbol,omitempty"`
	Share     float64 `json:"share,omitempty"`
}

// ExecuteRequest is the input to Swap:execute — the QuoteId and the
// signing keys. From is optional (defaults to the account the quote
// was issued for).
type ExecuteRequest struct {
	QuoteId string                    `json:"quoteId"`
	From    string                    `json:"from,omitempty"`
	Keys    []*wltsign.KeyDescription `json:"Keys,omitempty"`
}

// SwapResult is the output of Swap:execute. Kept as a distinct type
// rather than shoehorning into wlttx.Transaction — the swap shape
// (two tokens, a route, a provider) doesn't match the single-asset
// transfer shape that drives the rest of the Transaction API.
type SwapResult struct {
	QuoteId  string `json:"quoteId"`
	Provider string `json:"provider"`
	Chain    string `json:"chain"`
	// Hash is the on-chain transaction signature (Solana) or
	// transaction hash (EVM).
	Hash string `json:"hash"`
	// URL is a block-explorer link for the hash. Matches
	// wltnet.Network.TransactionUrl's output.
	URL string `json:"url,omitempty"`
	// Quote is a copy of the quote that was executed, for audit
	// trail (the app already has it but this guarantees the user
	// sees what they actually signed).
	Quote *Quote `json:"quote"`
}

// Default quote lifetime. Most aggregators' quotes go stale inside
// a minute due to price moves; 90 s gives the user time to read the
// approval sheet without leaving a window for arbitrage.
const quoteTTL = 90 * time.Second

// Cache cap — beyond this we evict the oldest entries. Chosen so a
// pathological caller can't grow unbounded memory.
const quoteCacheCap = 1000

// quoteCache stores issued quotes keyed by QuoteId. Concurrent-safe
// via mu; entries auto-expire on Get.
type quoteCacheT struct {
	mu      sync.Mutex
	entries map[string]*Quote
}

var quoteCache = &quoteCacheT{entries: make(map[string]*Quote)}

func (c *quoteCacheT) put(q *Quote) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[q.QuoteId] = q
	if len(c.entries) > quoteCacheCap {
		c.evictOldestLocked()
	}
}

func (c *quoteCacheT) get(id string) (*Quote, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	q, ok := c.entries[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(q.ExpiresAt) {
		delete(c.entries, id)
		return nil, false
	}
	return q, true
}

// evictOldestLocked drops ~25% of entries by createdAt. Called with
// c.mu held. Not a true LRU but close enough given the workload.
func (c *quoteCacheT) evictOldestLocked() {
	target := len(c.entries) / 4
	if target < 1 {
		target = 1
	}
	times := make([]time.Time, 0, len(c.entries))
	for _, q := range c.entries {
		times = append(times, q.createdAt)
	}
	for i := 1; i < len(times); i++ {
		for j := i; j > 0 && times[j-1].After(times[j]); j-- {
			times[j-1], times[j] = times[j], times[j-1]
		}
	}
	cutoff := times[target-1]
	for k, q := range c.entries {
		if !q.createdAt.After(cutoff) {
			delete(c.entries, k)
		}
	}
}

// newQuoteID returns a cryptographically random 128-bit opaque
// identifier. Prefixed so logs are greppable.
func newQuoteID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "q_" + hex.EncodeToString(b[:])
}

// swapQuote is the Swap:quote entry point.
func swapQuote(ctx context.Context, req *QuoteRequest) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if req == nil {
		return nil, newErr(ErrCodeInvalidRequest, "nil request")
	}
	if req.TokenIn.Address == "" || req.TokenOut.Address == "" {
		return nil, newErr(ErrCodeInvalidRequest, "tokenIn.address and tokenOut.address are required")
	}
	if req.AmountIn == "" {
		return nil, newErr(ErrCodeInvalidRequest, "amountIn is required")
	}
	if req.SlippageBps == 0 {
		req.SlippageBps = DefaultSlippageBps
	}

	acct, n, err := resolveAccountAndNetwork(e, req.From, req.Network)
	if err != nil {
		return nil, err
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	provider, err := selectProvider(n, req.Provider)
	if err != nil {
		return nil, err
	}

	quote, err := provider.Quote(ctx, n, acct, req)
	if err != nil {
		// Auto-fallback: if the caller didn't pin a provider and
		// the primary is unavailable on Solana, try dFlow.
		if req.Provider == "" && n.Type == "solana" && provider.Name() == "jupiter_ultra" {
			if sw, ok := AsSwapError(err); ok && sw.Code == ErrCodeProviderUnavailable {
				if fallback, ferr := getProvider("dflow"); ferr == nil {
					if q2, e2 := fallback.Quote(ctx, n, acct, req); e2 == nil {
						quote = q2
						err = nil
					}
				}
			}
		}
		if err != nil {
			return nil, err
		}
	}

	quote.QuoteId = newQuoteID()
	quote.createdAt = time.Now()
	quote.ExpiresAt = quote.createdAt.Add(quoteTTL)
	quote.from = acct.GetAddress()
	quoteCache.put(quote)
	return quote, nil
}

// swapExecute is the Swap:execute entry point.
func swapExecute(ctx context.Context, req *ExecuteRequest) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if req == nil || req.QuoteId == "" {
		return nil, newErr(ErrCodeInvalidRequest, "quoteId is required")
	}
	if len(req.Keys) == 0 {
		return nil, newErr(ErrCodeInvalidRequest, "Keys are required for execute")
	}

	q, ok := quoteCache.get(req.QuoteId)
	if !ok {
		return nil, newErr(ErrCodeQuoteNotFound, "quote not found or expired")
	}

	from := req.From
	if from == "" {
		from = q.from
	}
	acct, err := wltacct.FindAccount(e, from)
	if err != nil {
		return nil, err
	}
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, err
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	provider, err := getProvider(q.Provider)
	if err != nil {
		return nil, err
	}
	result, err := provider.Execute(ctx, n, acct, q, req.Keys)
	if err != nil {
		return nil, err
	}
	// Leave the quote in cache until natural expiry so the caller
	// can retry cheaply if broadcast failed after we returned.
	return result, nil
}

// resolveAccountAndNetwork centralises the (From, Network) → (acct,
// network) resolution for Swap:quote. Swap:execute uses the quote's
// own from field plus the current network.
func resolveAccountAndNetwork(e wltintf.Env, from, _ string) (*wltacct.Account, *wltnet.Network, error) {
	var acct *wltacct.Account
	var err error
	if from == "" {
		acct, err = wltacct.CurrentAccount(e)
	} else {
		acct, err = wltacct.FindAccount(e, from)
	}
	if err != nil {
		return nil, nil, err
	}
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, nil, err
	}
	return acct, n, nil
}
