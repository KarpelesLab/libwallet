package wlttx

import (
	"strings"
	"testing"
	"time"
)

func TestUtxoTracker_FiltersSpentInjectsPending(t *testing.T) {
	// Fresh tracker so other tests' state can't leak in.
	tr := &utxoTracker{byXpub: map[string]*trackedXpub{}}

	const xpub = "xpubFAKE_TEST_KEY"
	upstream := []bitcoinTxo{
		{Txo: "abc:0", Path: "m/0/0", Amt: 100_000, Script: "p2wpkh"},
		{Txo: "abc:1", Path: "m/1/0", Amt: 50_000, Script: "p2wpkh"},
	}

	// Baseline: no tracked state → upstream comes through unchanged.
	got := tr.Apply(xpub, upstream)
	if len(got) != 2 {
		t.Fatalf("baseline: got %d, want 2", len(got))
	}

	// Simulate broadcast #1: spent abc:0, created change at xyz:1.
	tr.RecordTx(xpub,
		[]string{"abc:0"},
		[]bitcoinTxo{{Txo: "xyz:1", Path: "m/1/1", Amt: 80_000, Script: "p2wpkh"}},
	)

	// Apply: abc:0 should be filtered out, abc:1 stays, xyz:1 added.
	got = tr.Apply(xpub, upstream)
	if len(got) != 2 {
		t.Fatalf("after record: got %d entries, want 2", len(got))
	}
	gotRefs := map[string]bool{}
	for _, u := range got {
		gotRefs[u.Txo] = true
	}
	if gotRefs["abc:0"] {
		t.Errorf("abc:0 should have been filtered (we spent it)")
	}
	if !gotRefs["abc:1"] {
		t.Errorf("abc:1 should still be present (untouched)")
	}
	if !gotRefs["xyz:1"] {
		t.Errorf("xyz:1 should have been injected (our pending change)")
	}

	// Simulate modchain reindex catching up: xyz:1 now appears in
	// upstream. Apply should drop it from the pending map (no
	// duplicate output) and continue filtering abc:0.
	upstreamCaught := []bitcoinTxo{
		{Txo: "abc:1", Path: "m/1/0", Amt: 50_000, Script: "p2wpkh"},
		{Txo: "xyz:1", Path: "m/1/1", Amt: 80_000, Script: "p2wpkh"},
	}
	got = tr.Apply(xpub, upstreamCaught)
	if len(got) != 2 {
		t.Fatalf("after catchup: got %d, want 2 (no duplicate xyz:1)", len(got))
	}
	// And now the tracker's pending map should be empty for that ref
	// (it shouldn't double-inject on the next call).
	tr.mu.Lock()
	x := tr.byXpub[xpub]
	if _, exists := x.pending["xyz:1"]; exists {
		t.Errorf("xyz:1 should have been pruned from pending after upstream caught up")
	}
	tr.mu.Unlock()
}

func TestUtxoTracker_TTLExpiry(t *testing.T) {
	tr := &utxoTracker{byXpub: map[string]*trackedXpub{}}
	const xpub = "xpubTTL"

	// Inject a spent + pending entry, then backdate them past TTL.
	tr.RecordTx(xpub,
		[]string{"old:0"},
		[]bitcoinTxo{{Txo: "newchange:1", Path: "m/1/3", Amt: 1000, Script: "p2wpkh"}},
	)
	tr.mu.Lock()
	x := tr.byXpub[xpub]
	stale := time.Now().Add(-2 * utxoTrackerTTL)
	x.spent["old:0"] = stale
	p := x.pending["newchange:1"]
	p.when = stale
	x.pending["newchange:1"] = p
	tr.mu.Unlock()

	upstream := []bitcoinTxo{
		{Txo: "old:0", Path: "m/0/0", Amt: 99, Script: "p2wpkh"},
	}
	got := tr.Apply(xpub, upstream)
	// old:0 must NOT be filtered (TTL expired, tracker forgot the spend).
	// newchange:1 must NOT be injected (TTL expired, tracker forgot it).
	if len(got) != 1 || got[0].Txo != "old:0" {
		t.Errorf("expected only upstream's old:0, got %+v", got)
	}
}

func TestUtxoTracker_UnknownXpubPassthrough(t *testing.T) {
	tr := &utxoTracker{byXpub: map[string]*trackedXpub{}}
	upstream := []bitcoinTxo{{Txo: "x:0", Path: "m/0/0"}}
	got := tr.Apply("never-touched-xpub", upstream)
	if len(got) != 1 || got[0].Txo != "x:0" {
		t.Errorf("unknown xpub should pass upstream through unchanged, got %+v", got)
	}
}

// bitcoinChangeScript pins the chainId → script-type mapping so a
// future change to bitcoinAddress (e.g. switching litecoin's default
// receive to p2sh:p2wpkh) doesn't silently leave the tracker
// inconsistent with the actual on-wire change shape.
func TestBitcoinChangeScript(t *testing.T) {
	cases := map[string]string{
		"bitcoin":      "p2wpkh",
		"litecoin":     "p2wpkh",
		"monacoin":     "p2wpkh",
		"bitcoin-cash": "p2pkh",
		"dogecoin":     "p2pkh",
		"unknown":      "p2wpkh", // fallback
	}
	for chainId, want := range cases {
		t.Run(chainId, func(t *testing.T) {
			if got := bitcoinChangeScript(chainId); got != want {
				t.Errorf("bitcoinChangeScript(%q) = %q, want %q", chainId, got, want)
			}
		})
	}
	// Sanity: every script we return must be one btcInputSigner /
	// outscript actually knows how to spend.
	for _, chainId := range []string{"bitcoin", "litecoin", "monacoin", "bitcoin-cash", "dogecoin"} {
		s := bitcoinChangeScript(chainId)
		if !strings.Contains(s, "p2") {
			t.Errorf("bitcoinChangeScript(%q) = %q which doesn't look like a script type", chainId, s)
		}
	}
}
