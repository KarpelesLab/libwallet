package curated

import (
	"strings"
	"testing"
)

func TestRegistryLoads(t *testing.T) {
	// ForChain triggers ensureLoaded — if the embedded JSON is
	// malformed, the panic inside ensureLoaded surfaces the failing
	// file, which is far more useful than a nil-slice result.
	chains := Chains()
	if len(chains) == 0 {
		t.Fatal("no chains loaded from embedded data")
	}
	for _, ck := range chains {
		netType, chainId, err := ParseChainKey(ck)
		if err != nil {
			t.Errorf("chain key %q does not parse: %v", ck, err)
			continue
		}
		toks := ForChain(netType, chainId)
		if len(toks) == 0 {
			t.Errorf("chain %q has zero tokens", ck)
		}
	}
}

// ChiefPussy is the whole reason the overlay machinery exists. If the
// overlay file stopped being merged (or got written with the wrong
// chainKey) this test would fire — the token is not in Jupiter's
// verified list so the base feed won't save us.
func TestOverlayChiefPussyMerged(t *testing.T) {
	got := Lookup("solana", "mainnet", "DRtvTCzfiKGhCVREmBbZdN9sB8PHeq9KdRZ3VmFhpump")
	if got == nil {
		t.Fatal("ChiefPussy overlay did not merge into solana.mainnet")
	}
	if got.Symbol != "ChiefPussy" {
		t.Errorf("symbol: got %q, want ChiefPussy", got.Symbol)
	}
	if got.Name != "Tibane Thecat" {
		t.Errorf("name: got %q, want Tibane Thecat", got.Name)
	}
	if !hasTag(got.Tags, "meme") {
		t.Errorf("tags: want \"meme\" in %v", got.Tags)
	}
}

// USDT is the canary for the EVM mainnet seed: if this resolves we
// know the base loader + address normalization + symbol index are all
// wired up end-to-end.
func TestLookupBySymbolUSDTOnMainnet(t *testing.T) {
	got := LookupBySymbol("evm", "1", "usdt") // lowercase on purpose
	if got == nil {
		t.Fatal("USDT not found on evm.1")
	}
	const wantAddr = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
	if !strings.EqualFold(got.Address, wantAddr) {
		t.Errorf("address: got %q, want %q", got.Address, wantAddr)
	}
}

// Lookup must be address-case-aware the same way Solana base58 is
// (case-significant) and EVM hex isn't. If someone refactors
// normalizeAddress, this catches the regression.
func TestLookupEVMCaseInsensitive(t *testing.T) {
	got := Lookup("evm", "1", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	if got == nil {
		t.Fatal("USDC did not resolve via lowercase EVM address")
	}
	if got.Symbol != "USDC" {
		t.Errorf("got %q, want USDC", got.Symbol)
	}
}

// Every token in the registry must pass validateToken — guards
// against a generator emitting a malformed feed without the tests
// noticing.
func TestRegistryIntegrity(t *testing.T) {
	for _, ck := range Chains() {
		netType, chainId, _ := ParseChainKey(ck)
		for _, tok := range ForChain(netType, chainId) {
			if tok.Symbol == "" {
				t.Errorf("%s: empty symbol at address %q", ck, tok.Address)
			}
			if tok.Decimals < 0 || tok.Decimals > 32 {
				t.Errorf("%s/%s: implausible decimals %d", ck, tok.Symbol, tok.Decimals)
			}
			switch netType {
			case "evm":
				if !isLikelyEVMAddress(tok.Address) {
					t.Errorf("%s/%s: address %q is not a valid EVM hex", ck, tok.Symbol, tok.Address)
				}
			case "solana":
				if !isLikelySolanaAddress(tok.Address) {
					t.Errorf("%s/%s: address %q is not a valid Solana base58 mint", ck, tok.Symbol, tok.Address)
				}
			}
		}
	}
}

// Verify the tag-priority sort actually runs: stablecoins must come
// before meme tokens on solana.mainnet (USDC before ChiefPussy).
func TestTokenOrderingStablecoinsFirst(t *testing.T) {
	toks := ForChain("solana", "mainnet")
	var usdcIdx, chiefIdx = -1, -1
	for i, tok := range toks {
		switch tok.Symbol {
		case "USDC":
			usdcIdx = i
		case "ChiefPussy":
			chiefIdx = i
		}
	}
	if usdcIdx < 0 {
		t.Fatal("USDC missing from solana.mainnet")
	}
	if chiefIdx < 0 {
		t.Fatal("ChiefPussy missing from solana.mainnet")
	}
	if usdcIdx >= chiefIdx {
		t.Errorf("expected stablecoin USDC before meme ChiefPussy, got USDC=%d ChiefPussy=%d", usdcIdx, chiefIdx)
	}
}

func TestParseChainKey(t *testing.T) {
	cases := []struct {
		in        string
		wantType  string
		wantChain string
		wantErr   bool
	}{
		{"evm.1", "evm", "1", false},
		{"solana.mainnet", "solana", "mainnet", false},
		{"evm.", "", "", true},
		{".1", "", "", true},
		{"bare", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		gotType, gotChain, err := ParseChainKey(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseChainKey(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if gotType != c.wantType || gotChain != c.wantChain {
			t.Errorf("ParseChainKey(%q) = (%q, %q); want (%q, %q)", c.in, gotType, gotChain, c.wantType, c.wantChain)
		}
	}
}
