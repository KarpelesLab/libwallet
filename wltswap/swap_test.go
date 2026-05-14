package wltswap

import (
	"testing"
	"time"
)

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
