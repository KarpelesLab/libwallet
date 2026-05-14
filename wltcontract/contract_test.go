package wltcontract

import (
	"strings"
	"testing"
)

func TestLookup_KnownAddresses(t *testing.T) {
	cases := []struct {
		name      string
		netType   string
		chainId   string
		address   string
		wantLabel string
	}{
		{
			name:      "Permit2 on mainnet",
			netType:   "evm",
			chainId:   "1",
			address:   "0x000000000022D473030F116dDEE9F6B43aC78BA3",
			wantLabel: "Uniswap: Permit2",
		},
		{
			name:      "Permit2 deterministic address — same on Base",
			netType:   "evm",
			chainId:   "8453",
			address:   "0x000000000022D473030F116dDEE9F6B43aC78BA3",
			wantLabel: "Uniswap: Permit2",
		},
		{
			name:      "Uniswap V3 SwapRouter02 on mainnet",
			netType:   "evm",
			chainId:   "1",
			address:   "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
			wantLabel: "Uniswap V3: SwapRouter02",
		},
		{
			name:      "Same address lowercased still matches",
			netType:   "evm",
			chainId:   "1",
			address:   "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
			wantLabel: "Uniswap V3: SwapRouter02",
		},
		{
			name:      "Aave V3 Pool on Arbitrum",
			netType:   "evm",
			chainId:   "42161",
			address:   "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
			wantLabel: "Aave V3: Pool",
		},
		{
			name:      "Seaport 1.6 on Polygon",
			netType:   "evm",
			chainId:   "137",
			address:   "0x0000000000000068F116a894984e2DB1123eB395",
			wantLabel: "OpenSea: Seaport 1.6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Lookup(tc.netType, tc.chainId, tc.address)
			if e == nil {
				t.Fatalf("Lookup(%s, %s, %s) = nil, want entry with label %q",
					tc.netType, tc.chainId, tc.address, tc.wantLabel)
			}
			if e.Label != tc.wantLabel {
				t.Errorf("label = %q, want %q", e.Label, tc.wantLabel)
			}
		})
	}
}

func TestLookup_Misses(t *testing.T) {
	cases := []struct {
		name    string
		netType string
		chainId string
		address string
	}{
		{
			name:    "unknown address on known chain",
			netType: "evm",
			chainId: "1",
			address: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
		{
			name:    "known address on unknown chain",
			netType: "evm",
			chainId: "999999",
			address: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
		},
		{
			name:    "non-EVM chain (no entries yet)",
			netType: "solana",
			chainId: "mainnet",
			address: "AAaaBBBB",
		},
		{name: "empty inputs", netType: "", chainId: "", address: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if e := Lookup(tc.netType, tc.chainId, tc.address); e != nil {
				t.Errorf("expected nil, got %+v", e)
			}
		})
	}
}

func TestLookup_AddressNormalisation(t *testing.T) {
	// Loader lowercases all addresses at parse time; Lookup
	// lowercases the input at query time. These two paths together
	// mean callers can pass any case form interchangeably — the
	// canonical wire form is EIP-55 mixed-case, but EIP-712
	// verifyingContract is sometimes lowercased.
	addr := "0x000000000022D473030F116dDEE9F6B43aC78BA3"
	e := Lookup("evm", "1", addr)
	if e == nil {
		t.Fatal("expected entry for Permit2")
	}
	if e.Address != strings.ToLower(addr) {
		t.Errorf("stored address = %q, want lowercased %q", e.Address, strings.ToLower(addr))
	}
}

func TestLookupByChainKey(t *testing.T) {
	e := LookupByChainKey("evm.1", "0x000000000022D473030F116dDEE9F6B43aC78BA3")
	if e == nil || e.Label != "Uniswap: Permit2" {
		t.Errorf("LookupByChainKey miss: %+v", e)
	}
	if e := LookupByChainKey("", "0x..."); e != nil {
		t.Errorf("empty chainKey should miss, got %+v", e)
	}
	if e := LookupByChainKey("evm.1", ""); e != nil {
		t.Errorf("empty address should miss, got %+v", e)
	}
}

func TestRegistry_NoLoadError(t *testing.T) {
	// Force load and check the package-level loadErr stayed nil —
	// catches malformed embedded JSON or duplicate-address regressions
	// added to the data files.
	ensureLoaded()
	if loadErr != nil {
		t.Fatalf("registry failed to load: %v", loadErr)
	}
	if len(byChainAndAddress) == 0 {
		t.Fatal("registry loaded but is empty")
	}
}
