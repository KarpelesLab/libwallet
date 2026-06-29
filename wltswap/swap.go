package wltswap

// Swap: — quote-and-execute endpoint powered by OKX DEX on both
// Solana and EVM families. See the package doc for the flow shape;
// this file holds the public API types, the in-memory quote cache,
// and the top-level Swap:quote / Swap:execute handlers.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wlttoken"
	"github.com/KarpelesLab/libwallet/wlttx"
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
	// per chain; today there's only one routed provider per family
	// (OKX) so the auto-select is single-element, but the field
	// stays for forward compatibility.
	Provider string `json:"provider,omitempty"`
}

// TokenRef identifies a token by address. Address "NATIVE" means
// the chain's native currency (SOL / ETH); the adapter translates
// to the provider-specific representation as needed.
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
	Provider      string `json:"provider"`      // "okx_solana" | "okx_evm"
	ProviderLabel string `json:"providerLabel"` // human-friendly: "OKX"
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
	FeeBps      uint16 `json:"feeBps"`
	SlippageBps uint16 `json:"slippageBps"`
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

	// ── EVM approval fields (populated by the OKX EVM adapter for
	// non-native tokenIn; all zero-valued on Solana and for native
	// ETH swaps) ───────────────────────────────────────────────────────
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

	// Status indicates whether this Quote is executable. Empty value
	// means executable (the normal happy path). A non-empty value
	// describes why Swap:execute will refuse to run on this quote;
	// callers should treat such results as advisory and surface
	// [StatusMessage] in the UI. Only Swap:maxSpendable populates
	// this — Swap:quote / Swap:quotes still fail loudly when no
	// route exists, because the user is asking for a specific
	// amount and a silent "no route" would be misleading.
	//
	// Stable values: see the QuoteStatus* constants.
	Status QuoteStatus `json:"status,omitempty"`
	// StatusMessage is the provider's or libwallet's human-readable
	// explanation for a non-empty Status (e.g. the OKX
	// "no_route" payload on dust-sized trades, or "balance does
	// not cover network fee + rent"). Empty when Status is empty.
	StatusMessage string `json:"statusMessage,omitempty"`

	// provider-internal fields — not JSON-exposed.
	providerBlob any       `json:"-"`
	createdAt    time.Time `json:"-"`
	from         string    `json:"-"` // account address the quote was issued to
}

// QuoteStatus tags non-executable maxSpendable results so the host
// can keep an asset visible in source-list UIs without trying to
// execute. Empty means executable.
type QuoteStatus string

const (
	// QuoteStatusOK is the implicit "no problem" status — a normal,
	// executable Quote. Encoded as the empty string so it's omitted
	// from JSON output entirely.
	QuoteStatusOK QuoteStatus = ""
	// QuoteStatusBalanceTooSmall fires when the resolved max-spendable
	// amount is zero because the wallet's balance can't cover the
	// network fee plus any required rent reservations. The Quote
	// carries TokenIn, TokenOut, AmountIn=0, and a StatusMessage
	// explaining the shortfall. Hosts should show the asset with a
	// "needs more SOL to swap" hint rather than hiding it.
	QuoteStatusBalanceTooSmall QuoteStatus = "balance_too_small"
	// QuoteStatusNoRoute fires when the provider explicitly reported
	// no route (OKX's no-route signal on dust-sized trades is the
	// canonical case). The Quote carries the resolved AmountIn and a
	// StatusMessage but no AmountOut / Route /
	// providerBlob — Swap:execute would fail on it, so the host
	// should treat it as informational and re-quote if conditions
	// change (price moves, user adds funds, etc.).
	QuoteStatusNoRoute QuoteStatus = "no_route"
)

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
	// MevProtection lets the host opt in/out of OKX's MEV-protected
	// broadcast for EVM swaps. nil = use the default (on); Solana ignores
	// it. Pointer so an omitted field is "unset" rather than false.
	MevProtection *bool `json:"mevProtection,omitempty"`
}

// ExecuteOpts carries per-execution host preferences resolved from the
// ExecuteRequest and threaded to Provider.Execute.
type ExecuteOpts struct {
	// MevProtection toggles OKX's MEV-protected broadcast for EVM swaps.
	// nil = provider default (on); Solana ignores it.
	MevProtection *bool
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
	// OrderId is OKX's broadcast handle for swaps routed through their
	// broadcast endpoint (Solana). Empty for paths that broadcast
	// directly to a chain RPC. The host can poll Crypto/Okx:orderStatus
	// with it to track final settlement.
	OrderId string `json:"orderId,omitempty"`
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
	// Normalise Asset.Key-shaped inputs ("solana.mainnet.EPjFW…",
	// "evm.1.0xA0b8…") to the bare mint / contract OKX expects.
	// Hosts get the prefixed form from Asset:list and reasonably
	// pass it through; the adapters only understand the bare form.
	req.TokenIn.Address = stripChainPrefix(req.TokenIn.Address)
	req.TokenOut.Address = stripChainPrefix(req.TokenOut.Address)
	if req.AmountIn == "" {
		return nil, newErr(ErrCodeInvalidRequest, "amountIn is required (use \"MAX\" to swap the full balance)")
	}
	// Apply the default-on-zero and clamp to the safe ceiling so a
	// hostile or buggy caller can't drive MinAmountOut to zero.
	req.SlippageBps = normalizeSlippageBps(req.SlippageBps)

	acct, n, err := resolveAccountAndNetwork(e, req.From, req.Network)
	if err != nil {
		return nil, err
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	// "MAX" sentinel: resolve to the largest base-unit amount the
	// account can spend in tokenIn. The Quote returned to the caller
	// has Quote.AmountIn populated with the resolved value, so the
	// frontend always knows what the user is actually swapping.
	if strings.EqualFold(req.AmountIn, "MAX") {
		amt, err := resolveMaxAmountIn(ctx, n, acct, req)
		if err != nil {
			return nil, err
		}
		req.AmountIn = amt
	}

	return runQuote(ctx, n, acct, req)
}

// swapQuotes is the Swap:quotes entry point — same input shape as
// Swap:quote but fans the request out to every available provider
// for the chain and returns the collected per-provider attempts.
// The host renders the attempts side-by-side and lets the user
// pick; libwallet does NOT silently fall back from one provider to
// another. Each successful attempt is cached so the caller can
// Swap:execute by id without re-quoting.
//
// "MAX" sentinel is resolved once (against the chain's primary
// provider's max calc) before fan-out so every provider gets the
// same amountIn — without that, providers with different ATA-rent
// reservations would each see different amounts and the side-by-side
// comparison would be apples-to-oranges.
func swapQuotes(ctx context.Context, req *QuoteRequest) (any, error) {
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
	req.TokenIn.Address = stripChainPrefix(req.TokenIn.Address)
	req.TokenOut.Address = stripChainPrefix(req.TokenOut.Address)
	if req.AmountIn == "" {
		return nil, newErr(ErrCodeInvalidRequest, "amountIn is required (use \"MAX\" to quote the full balance)")
	}
	// Apply the default-on-zero and clamp to the safe ceiling so a
	// hostile or buggy caller can't drive MinAmountOut to zero.
	req.SlippageBps = normalizeSlippageBps(req.SlippageBps)

	acct, n, err := resolveAccountAndNetwork(e, req.From, req.Network)
	if err != nil {
		return nil, err
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	if strings.EqualFold(req.AmountIn, "MAX") {
		amt, err := resolveMaxAmountIn(ctx, n, acct, req)
		if err != nil {
			return nil, err
		}
		req.AmountIn = amt
	}

	return runQuotes(ctx, n, acct, req)
}

// swapMaxSpendable is Swap:maxSpendable: build a Quote for the
// maximum amount of req.TokenIn the account can spend. The Quote
// shape is identical to Swap:quote — Quote.AmountIn carries the
// resolved max so the frontend can display "Max: 1.234 SOL".
//
// Equivalent to calling Swap:quote with amountIn="MAX". Provided as
// a discrete endpoint so callers don't need to special-case the
// sentinel string in their typed clients.
//
// Unlike Swap:quote, soft failures land as Quote results carrying
// a non-empty [QuoteStatus] instead of an error: the wallet's
// balance can't cover fees + rent (QuoteStatusBalanceTooSmall), or
// the provider had no route at the resolved amount (typically
// dust-sized trades — QuoteStatusNoRoute). The intent is to let
// host source-list UIs keep the asset visible with a clear
// explanation instead of having to filter on error type. Hard
// failures (invalid request, transport error, provider unavailable)
// still surface as errors.
func swapMaxSpendable(ctx context.Context, req *QuoteRequest) (any, error) {
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
	req.TokenIn.Address = stripChainPrefix(req.TokenIn.Address)
	req.TokenOut.Address = stripChainPrefix(req.TokenOut.Address)
	// Apply the default-on-zero and clamp to the safe ceiling so a
	// hostile or buggy caller can't drive MinAmountOut to zero.
	req.SlippageBps = normalizeSlippageBps(req.SlippageBps)

	acct, n, err := resolveAccountAndNetwork(e, req.From, req.Network)
	if err != nil {
		return nil, err
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	amt, err := resolveMaxAmountIn(ctx, n, acct, req)
	if err != nil {
		return nil, err
	}
	if amt == "0" || amt == "" {
		// Balance can't cover fee + rent. Return an informational
		// Quote so the asset stays visible in source-list UIs; the
		// host can render the StatusMessage as a hint and prompt
		// the user to top up rather than silently hiding the row.
		return buildAdvisoryQuote(n, req, "0", QuoteStatusBalanceTooSmall,
			"balance does not cover network fee + rent"), nil
	}
	req.AmountIn = amt
	q, err := runQuote(ctx, n, acct, req)
	if err != nil {
		// Distinguish "no route at this amount" (a soft failure —
		// the asset is technically swappable) from hard errors that
		// the caller really does need to surface as failures.
		if isNoRouteError(err) {
			return buildAdvisoryQuote(n, req, amt, QuoteStatusNoRoute, err.Error()), nil
		}
		return nil, err
	}
	return q, nil
}

// buildAdvisoryQuote constructs a non-executable Quote that carries
// the resolved AmountIn and a [QuoteStatus] so the host can keep the
// asset visible without trying to execute. The result is NOT inserted
// into the quoteCache (no QuoteId — Swap:execute would refuse it
// anyway), and Route / providerBlob are deliberately nil.
//
// AmountOut and MinAmountOut are populated with zero-valued Amounts
// carrying tokenOut's decimals — the advisory has no estimated
// output, but a fully-typed Amount keeps the wire shape valid for
// typed clients that expect non-null fields. The status field is
// the load-bearing signal; clients should branch on it rather than
// inspecting the placeholder zero-out values.
func buildAdvisoryQuote(n *wltnet.Network, req *QuoteRequest, amountIn string, status QuoteStatus, message string) *Quote {
	var providerName, providerLabel string
	if provider, err := selectProvider(n, req.Provider); err == nil && provider != nil {
		providerName = provider.Name()
		providerLabel = providerDisplayLabel(provider.Name())
	}
	amount, _ := new(big.Int).SetString(amountIn, 10)
	if amount == nil {
		amount = new(big.Int)
	}
	zeroOut := wltobj.NewAmountRaw(new(big.Int), req.TokenOut.Decimals)
	return &Quote{
		Provider:      providerName,
		ProviderLabel: providerLabel,
		Chain:         n.Type,
		TokenIn:       req.TokenIn,
		TokenOut:      req.TokenOut,
		AmountIn:      wltobj.NewAmountRaw(amount, req.TokenIn.Decimals),
		AmountOut:     zeroOut,
		MinAmountOut:  zeroOut,
		SlippageBps:   req.SlippageBps,
		Status:        status,
		StatusMessage: message,
	}
}

// isNoRouteError returns true when err carries the canonical
// "no route" signal from the upstream — OKX's no-route response
// surfaces as HTTP 400 wrapped in ErrCodeProviderBadRequest with a
// message that contains one of the known phrases. Used by
// Swap:maxSpendable to downgrade these to an advisory Quote rather
// than a hard error.
func isNoRouteError(err error) bool {
	sw, ok := AsSwapError(err)
	if !ok {
		return false
	}
	if sw.Code != ErrCodeProviderBadRequest {
		return false
	}
	msg := strings.ToLower(sw.Message)
	// Substring match keeps the check stable against minor wording
	// tweaks upstream. "Failed to get quotes" survives because it's
	// the phrase the older Jupiter-era tests pinned and OKX
	// occasionally uses it too on dust trades.
	return strings.Contains(msg, "failed to get quotes") ||
		strings.Contains(msg, "no route") ||
		strings.Contains(msg, "no liquidity") ||
		strings.Contains(msg, "insufficient liquidity")
}

// runQuote drives the provider call + cache, after the caller has
// already done validation, account/network resolution, and AmountIn
// resolution. Shared by swapQuote and swapMaxSpendable.
//
// As of 0.4.31 there is no silent fallback — if the primary provider
// errors, the caller sees that error verbatim. Hosts that want
// multiple providers' quotes side-by-side should call Swap:quotes
// (plural), which returns one attempt per registered provider for
// the chain.
func runQuote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error) {
	provider, err := selectProvider(n, req.Provider)
	if err != nil {
		return nil, err
	}
	quote, err := provider.Quote(ctx, n, acct, req)
	if err != nil {
		return nil, err
	}
	finalizeQuote(quote, acct)
	return quote, nil
}

// finalizeQuote stamps the cache-relevant fields (id, expiry, from)
// onto a freshly-built provider quote and inserts it into the
// quoteCache so the caller can execute by id. Shared by runQuote and
// runQuotes (the multi-provider fan-out).
func finalizeQuote(q *Quote, acct *wltacct.Account) {
	q.QuoteId = newQuoteID()
	q.createdAt = time.Now()
	q.ExpiresAt = q.createdAt.Add(quoteTTL)
	q.from = acct.GetAddress()
	quoteCache.put(q)
}

// QuoteAttempt is one provider's result in a multi-provider quote
// query. Exactly one of [Quote] or [Error] is populated. The host
// renders [Quote] (with a "[providerLabel]" badge) when set, or the
// error message otherwise — both are useful in the side-by-side
// picker UI so the user understands why a route is missing on one
// provider but available on another.
type QuoteAttempt struct {
	// Provider is the stable name ("okx_solana" | "okx_evm").
	Provider string `json:"provider"`
	// ProviderLabel is the display string ("OKX"). Pre-populated
	// even on Error so the UI can render "OKX: Failed to get
	// quotes" without a Quote.
	ProviderLabel string `json:"providerLabel"`
	// Quote is the successful price, populated when the provider
	// returned a viable route. nil when the provider errored.
	Quote *Quote `json:"quote,omitempty"`
	// Error explains why this provider didn't return a quote — no
	// liquidity, slippage exceeded, provider unavailable, etc.
	// nil when the provider succeeded.
	Error *SwapError `json:"error,omitempty"`
}

// QuotesResult is the response from Swap:quotes. One [QuoteAttempt]
// per provider available for the current chain, in
// [providerOrderForChain] order.
type QuotesResult struct {
	Attempts []QuoteAttempt `json:"attempts"`
}

// runQuotes is the multi-provider variant of runQuote — fans out the
// same request to every provider available for the chain and returns
// the collected attempts. Shared between Swap:quotes and (planned)
// future maxSpendable variants. Each successful provider gets a
// freshly-cached Quote so the caller can execute by id without
// re-quoting.
func runQuotes(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*QuotesResult, error) {
	providers, err := providersForChain(n)
	if err != nil {
		return nil, err
	}
	res := &QuotesResult{Attempts: make([]QuoteAttempt, 0, len(providers))}
	for _, p := range providers {
		att := QuoteAttempt{
			Provider:      p.Name(),
			ProviderLabel: providerDisplayLabel(p.Name()),
		}
		q, qerr := p.Quote(ctx, n, acct, req)
		if qerr != nil {
			if se, ok := AsSwapError(qerr); ok {
				att.Error = se
			} else {
				att.Error = &SwapError{Code: ErrCodeProviderUnavailable, Message: qerr.Error()}
			}
			res.Attempts = append(res.Attempts, att)
			continue
		}
		finalizeQuote(q, acct)
		att.Quote = q
		res.Attempts = append(res.Attempts, att)
	}
	return res, nil
}

// providerDisplayLabel maps a stable provider name to the
// human-friendly label shown in the picker UI. Kept in sync with the
// labels each adapter populates on a successful Quote.ProviderLabel.
func providerDisplayLabel(name string) string {
	switch name {
	case "okx_solana", "okx_evm":
		return "OKX"
	default:
		return name
	}
}

// resolveMaxAmountIn returns the largest base-unit amount of
// req.TokenIn the account can spend on n, ready to drop into a
// QuoteRequest.AmountIn. Native assets reserve fees + rents; tokens
// return the full balance because gas is paid in the chain's native
// currency.
//
// req.TokenIn.Address accepts the canonical TokenRef.Address shape:
//   - "NATIVE" or empty → native currency
//   - any other string  → on-chain mint / contract address
//
// On Solana, when the input is native SOL and the user does not yet
// hold the output mint, an extra reservation is subtracted to cover
// the rent-exempt minimum for the new Associated Token Account that
// the swap transaction injects. Without this reservation the OKX
// quote reports "Failed to get quotes" when the wallet's
// post-swap balance lands at the system-account rent minimum but
// lacks the ~2.04M lamports for an SPL ATA.
func resolveMaxAmountIn(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (string, error) {
	tokenInAddress := req.TokenIn.Address
	asset := n.Type + "." + n.ChainId + ".NATIVE"
	if tokenInAddress != "" && !strings.EqualFold(tokenInAddress, "NATIVE") {
		asset = n.Type + "." + n.ChainId + "." + tokenInAddress
	}
	res, err := wlttx.MaxSendable(ctx, n, acct, &wlttx.MaxSendableRequest{Asset: asset})
	if err != nil {
		return "", err
	}
	if res.Max == nil {
		return "0", nil
	}
	maxV := new(big.Int).Set(res.Max.Value())

	if extra := solanaOutputAtaReservation(ctx, n, acct, req); extra > 0 {
		ataR := new(big.Int).SetUint64(extra)
		if maxV.Cmp(ataR) > 0 {
			maxV.Sub(maxV, ataR)
		} else {
			maxV.SetInt64(0)
		}
	}

	return maxV.String(), nil
}

// solanaOutputAtaReservation returns the extra lamports that need to
// be held back on a native-SOL → SPL swap when the user has no ATA
// for the output mint yet. Returns 0 when:
//
//   - the chain isn't Solana, or
//   - the input isn't native SOL (an SPL→SPL swap consumes SOL for
//     ATA creation but it doesn't come out of the input amount —
//     surfacing that needs a different mechanism), or
//   - the output is itself native SOL / wSOL, or
//   - the user already has an ATA for the output mint.
//
// Errors from the RPC probes degrade to "no reservation" so a slow
// upstream doesn't fail the MAX path; in the worst case the upstream
// will still reject the actual swap and the user retries with a
// smaller amount. The fallback rent value (2_039_280) matches the
// canonical SPL token-account rent and is used when the live
// getMinimumBalanceForRentExemption call fails.
func solanaOutputAtaReservation(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) uint64 {
	if n.Type != "solana" {
		return 0
	}
	if !isNativeTokenAddress(req.TokenIn.Address) {
		return 0
	}
	outMint := solanaNativeMintOrAddr(req.TokenOut.Address)
	if outMint == WrappedSOLMint {
		return 0
	}
	has, err := solanaHasTokenAccount(ctx, n, acct.GetAddress(), outMint)
	if err != nil {
		// Conservative on probe failure: assume no ATA so we keep
		// the user safe rather than hand them a too-aggressive max.
		has = false
	}
	if has {
		return 0
	}
	rent, err := wlttx.SolanaRentExemptMinimum(ctx, n, 165) // 165 = SPL token-account size
	if err != nil || rent == 0 {
		return 2_039_280
	}
	return rent
}

// solanaHasTokenAccount returns true when owner already has at least
// one token account for the given mint. Uses getTokenAccountsByOwner
// filtered by mint — a single-shot RPC call.
func solanaHasTokenAccount(ctx context.Context, n *wltnet.Network, owner, mint string) (bool, error) {
	raw, err := n.DoRPCCtx(ctx, "getTokenAccountsByOwner",
		owner,
		map[string]any{"mint": mint},
		map[string]any{"encoding": "base64"},
	)
	if err != nil {
		return false, err
	}
	var resp struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, err
	}
	return len(resp.Value) > 0, nil
}

// isNativeTokenAddress reports whether a TokenRef.Address means "the
// chain's native currency" — empty, "NATIVE", or (on Solana) the
// wSOL mint.
func isNativeTokenAddress(addr string) bool {
	if addr == "" || strings.EqualFold(addr, "NATIVE") {
		return true
	}
	return addr == WrappedSOLMint
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
	result, err := provider.Execute(ctx, n, acct, q, req.Keys, &ExecuteOpts{MevProtection: req.MevProtection})
	if err != nil {
		return nil, err
	}

	// Post-execute housekeeping. Best-effort: a failure here doesn't
	// invalidate the swap that already broadcast — log and continue.
	//
	// 1. Nudge the balance poller so the spent (TokenIn) and earned
	//    (TokenOut) balances refresh within ~a second instead of
	//    waiting for the next 60 s tick. The Solana broadcast paths
	//    in wlttx call NotifyTxBroadcast already; aggregator-driven
	//    swaps run through the provider's own HTTP/RPC route and
	//    never touched this hook before.
	wltintf.NotifyTxBroadcast(e)
	// 2. Surface TokenOut in the user's token list when it isn't
	//    already tracked. Without this, the user sees the new
	//    balance via the chain RPC but the token name/symbol stays
	//    "Unknown" because no Token row exists.
	if !isNativeTokenAddress(q.TokenOut.Address) {
		if _, terr := wlttoken.EnsureToken(
			e,
			n.Id,
			q.TokenOut.Address,
			q.TokenOut.Symbol,
			"", // Name — TokenRef doesn't carry it; UI falls back to symbol/address
			q.TokenOut.Decimals,
			"", // Type — defaults to "erc20" / "spl-token" via wlttoken validate
		); terr != nil {
			wltlog.Warnf("swap/execute: failed to ensure TokenOut %s on %s: %v",
				q.TokenOut.Address, n.Id, terr)
		}
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

// OrderStatusRequest is the input to Swap:orderStatus.
type OrderStatusRequest struct {
	// OrderId is the SwapResult.orderId returned by Swap:execute.
	OrderId string `json:"orderId"`
	// From selects the account that signed the swap (default: current).
	// The order is keyed by that wallet's on-chain address, so it must
	// match the swap that produced the orderId.
	From string `json:"from,omitempty"`
	// Network overrides the network the order belongs to (default: current).
	Network string `json:"network,omitempty"`
}

// SwapOrderStatus is the normalized settlement state of a broadcast swap,
// polled from the provider. Status is one of "pending" | "success" |
// "failed". FailReason carries the provider/RPC error on failure; TxHash is
// set once the tx is on chain.
type SwapOrderStatus struct {
	OrderId    string `json:"orderId"`
	Chain      string `json:"chain"`
	Status     string `json:"status"`
	TxHash     string `json:"txHash,omitempty"`
	FailReason string `json:"failReason,omitempty"`
}

// swapOrderStatus is the Swap:orderStatus endpoint — poll the settlement
// state of a previously executed swap by its orderId. Swap:execute reports
// success as soon as the provider ACCEPTS the broadcast (which, for OKX,
// happens before the tx has even been validated — it returns an orderId for
// a garbage payload too), so a host that needs certainty the swap actually
// landed polls here until Status is no longer "pending".
func swapOrderStatus(ctx context.Context, req *OrderStatusRequest) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if req == nil || strings.TrimSpace(req.OrderId) == "" {
		return nil, newErr(ErrCodeInvalidRequest, "orderId is required")
	}
	acct, n, err := resolveAccountAndNetwork(e, req.From, req.Network)
	if err != nil {
		return nil, err
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}
	chainIndex, err := okxChainIndexFor(n)
	if err != nil {
		return nil, newErr(ErrCodeUnsupportedChain, err.Error())
	}
	entry, err := okxFetchOrderStatus(ctx, chainIndex, acct.GetAddress(), req.OrderId)
	if err != nil {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: orderStatus: "+err.Error())
	}
	res := &SwapOrderStatus{
		OrderId: req.OrderId,
		Chain:   n.Type,
		Status:  okxTxStatusLabel(entry),
	}
	if entry != nil {
		res.TxHash = entry.TxHash
		if res.Status == "failed" {
			res.FailReason = strings.TrimSpace(entry.FailReason)
		}
	}
	return res, nil
}
