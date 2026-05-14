package wltswap

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
)

// acctForTest returns a *wltacct.Account just usable enough for the
// runQuotes path — GetAddress() is the only method runQuotes reaches
// for (it stamps the resulting Quote.from). No DB / TSS involved.
func acctForTest(t *testing.T) *wltacct.Account {
	t.Helper()
	return &wltacct.Account{Address: "7EEygcr1HaF2PY8pdHaeYSNByXPpMQU4GzrCezvps7KH"}
}

func TestQuoteCache_PutGet(t *testing.T) {
	c := &quoteCacheT{entries: make(map[string]*Quote)}
	q := &Quote{
		QuoteId:   "q_test",
		createdAt: time.Now(),
		ExpiresAt: time.Now().Add(quoteTTL),
	}
	c.put(q)
	got, ok := c.get("q_test")
	if !ok {
		t.Fatal("expected quote to be in cache")
	}
	if got.QuoteId != "q_test" {
		t.Errorf("QuoteId = %q, want q_test", got.QuoteId)
	}
}

func TestQuoteCache_Expiry(t *testing.T) {
	c := &quoteCacheT{entries: make(map[string]*Quote)}
	q := &Quote{
		QuoteId:   "q_expired",
		createdAt: time.Now().Add(-2 * quoteTTL),
		ExpiresAt: time.Now().Add(-time.Second),
	}
	c.put(q)
	if _, ok := c.get("q_expired"); ok {
		t.Fatal("expired quote should not be returned")
	}
	// Cache self-cleans on miss.
	c.mu.Lock()
	_, stillThere := c.entries["q_expired"]
	c.mu.Unlock()
	if stillThere {
		t.Error("expired entry should have been removed on get()")
	}
}

func TestQuoteCache_Eviction(t *testing.T) {
	c := &quoteCacheT{entries: make(map[string]*Quote)}
	now := time.Now()
	// Insert well past the cap.
	for i := 0; i < quoteCacheCap+20; i++ {
		q := &Quote{
			QuoteId:   newQuoteID(),
			createdAt: now.Add(time.Duration(i) * time.Millisecond),
			ExpiresAt: now.Add(quoteTTL + time.Duration(i)*time.Millisecond),
		}
		c.put(q)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > quoteCacheCap {
		t.Errorf("cache grew to %d entries, cap is %d", n, quoteCacheCap)
	}
	if n == 0 {
		t.Error("cache emptied itself — eviction is too aggressive")
	}
}

func TestNewQuoteID_Unique(t *testing.T) {
	seen := make(map[string]struct{})
	const n = 100
	for i := 0; i < n; i++ {
		id := newQuoteID()
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate quote id %s on iteration %d", id, i)
		}
		seen[id] = struct{}{}
	}
	// Prefix sanity.
	for id := range seen {
		if len(id) < 4 || id[:2] != "q_" {
			t.Errorf("quote id %q does not start with q_", id)
			break
		}
	}
}

func TestSolanaNativeMintOrAddr(t *testing.T) {
	cases := map[string]string{
		"":       WrappedSOLMint,
		"NATIVE": WrappedSOLMint,
		"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		// Asset.Key-shaped input — strip the prefix so Jupiter sees
		// the bare mint. Reproduces the field bug where Jupiter
		// returned HTTP 400 "Invalid outputMint" for
		// "solana.mainnet.EPjFW…".
		"solana.mainnet.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"solana.mainnet.NATIVE":                                      WrappedSOLMint,
		"solana.mainnet.":                                            WrappedSOLMint,
	}
	for in, want := range cases {
		if got := solanaNativeMintOrAddr(in); got != want {
			t.Errorf("solanaNativeMintOrAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOneInchTokenOrSentinel(t *testing.T) {
	cases := map[string]string{
		"":           OneInchNativeSentinel,
		"NATIVE":     OneInchNativeSentinel,
		"0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48": "0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48",
		// Same prefix-strip behaviour as the Solana adapter.
		"evm.1.0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48": "0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48",
		"evm.1.NATIVE": OneInchNativeSentinel,
	}
	for in, want := range cases {
		if got := oneInchTokenOrSentinel(in); got != want {
			t.Errorf("oneInchTokenOrSentinel(%q) = %q, want %q", in, got, want)
		}
	}
}

// stubProvider is a tiny Provider double for tests. Quote returns the
// canned response without making an HTTP call.
type stubProvider struct {
	name  string
	chain string
	q     *Quote
	err   error
}

func (s *stubProvider) Name() string  { return s.name }
func (s *stubProvider) Chain() string { return s.chain }
func (s *stubProvider) Quote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error) {
	return s.q, s.err
}
func (s *stubProvider) Execute(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	return nil, fmt.Errorf("stub Execute not implemented")
}

// withStubProviders swaps in stubs for the duration of fn, then
// restores the original registry. Tests can call this to drive
// runQuotes without touching the live Jupiter / dFlow / 1inch
// adapters.
func withStubProviders(t *testing.T, stubs []*stubProvider, fn func()) {
	t.Helper()
	saved := make(map[string]Provider, len(providers))
	for k, v := range providers {
		saved[k] = v
	}
	// Wipe and install the stubs in their natural order. The chain's
	// providerOrderForChain list pulls them back out.
	providers = map[string]Provider{}
	for _, s := range stubs {
		RegisterProvider(s)
	}
	defer func() {
		providers = saved
	}()
	fn()
}

func TestRunQuotes_CollectsPerProviderAttempts(t *testing.T) {
	goodQuote := &Quote{
		Provider:      "jupiter_ultra",
		ProviderLabel: "Jupiter Ultra",
		Chain:         "solana",
		TokenIn:       TokenRef{Address: "NATIVE", Symbol: "SOL", Decimals: 9},
		TokenOut:      TokenRef{Address: "EPjFW", Symbol: "USDC", Decimals: 6},
		AmountIn:      wltobj.NewAmountRaw(big.NewInt(1_000_000), 9),
		AmountOut:     wltobj.NewAmountRaw(big.NewInt(200_000), 6),
	}
	stubs := []*stubProvider{
		{name: "jupiter_ultra", chain: "solana", q: goodQuote},
		{name: "dflow", chain: "solana", err: newErr(ErrCodeNoLiquidity, "no route")},
	}
	withStubProviders(t, stubs, func() {
		n := &wltnet.Network{Type: "solana", ChainId: "mainnet"}
		acct := acctForTest(t)
		req := &QuoteRequest{TokenIn: TokenRef{Address: "NATIVE"}, TokenOut: TokenRef{Address: "EPjFW"}, AmountIn: "1000000"}
		res, err := runQuotes(context.Background(), n, acct, req)
		if err != nil {
			t.Fatalf("runQuotes: %v", err)
		}
		if len(res.Attempts) != 2 {
			t.Fatalf("got %d attempts, want 2", len(res.Attempts))
		}
		if res.Attempts[0].Provider != "jupiter_ultra" || res.Attempts[0].Quote == nil {
			t.Errorf("attempt 0 = %+v, want jupiter_ultra with quote", res.Attempts[0])
		}
		if res.Attempts[0].ProviderLabel != "Jupiter Ultra" {
			t.Errorf("attempt 0 label = %q, want Jupiter Ultra", res.Attempts[0].ProviderLabel)
		}
		if res.Attempts[1].Provider != "dflow" || res.Attempts[1].Error == nil {
			t.Errorf("attempt 1 = %+v, want dflow with error", res.Attempts[1])
		}
		if res.Attempts[1].Error.Code != ErrCodeNoLiquidity {
			t.Errorf("attempt 1 code = %q, want %q", res.Attempts[1].Error.Code, ErrCodeNoLiquidity)
		}
		// The successful attempt must have its QuoteId stamped so
		// the host can immediately call Swap:execute with it.
		if res.Attempts[0].Quote.QuoteId == "" {
			t.Error("successful attempt missing QuoteId — caller can't execute it")
		}
	})
}

func TestProviderDisplayLabel(t *testing.T) {
	cases := map[string]string{
		"jupiter_ultra": "Jupiter Ultra",
		"dflow":         "dFlow",
		"1inch":         "1inch",
		"unknown":       "unknown",
	}
	for in, want := range cases {
		if got := providerDisplayLabel(in); got != want {
			t.Errorf("providerDisplayLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripChainPrefix(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"NATIVE":      "NATIVE",
		"0xAbcd":      "0xAbcd",
		"EPjFWdd5":    "EPjFWdd5",
		"evm.1.0xAb":  "0xAb",
		"solana.mainnet.EPjFW": "EPjFW",
		"solana.devnet.AAA":    "AAA",
		"trailing.dot.":        "",
	}
	for in, want := range cases {
		if got := stripChainPrefix(in); got != want {
			t.Errorf("stripChainPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAsSwapError(t *testing.T) {
	err := newErr(ErrCodeQuoteExpired, "test")
	se, ok := AsSwapError(err)
	if !ok {
		t.Fatal("AsSwapError should unwrap SwapError")
	}
	if se.Code != ErrCodeQuoteExpired {
		t.Errorf("Code = %q, want %q", se.Code, ErrCodeQuoteExpired)
	}
	if _, ok := AsSwapError(nil); ok {
		t.Error("AsSwapError(nil) should return false")
	}
}

func TestCompactU16_RoundTrip(t *testing.T) {
	// Test values spanning 1-byte, 2-byte, 3-byte encodings.
	for _, v := range []uint16{0, 1, 127, 128, 16383, 16384, 65535} {
		encoded := encodeCompactU16(v)
		decoded, n, err := decodeCompactU16(encoded, 0)
		if err != nil {
			t.Errorf("decode %d bytes for v=%d failed: %v", len(encoded), v, err)
			continue
		}
		if decoded != v {
			t.Errorf("round trip v=%d → encoded %x → decoded %d", v, encoded, decoded)
		}
		if n != len(encoded) {
			t.Errorf("v=%d consumed %d bytes, encoded %d", v, n, len(encoded))
		}
	}
}
