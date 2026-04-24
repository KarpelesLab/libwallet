package wltswap

import "testing"

// fullReg mirrors what init.go populates — used as the default
// "this build has all three adapters" registry.
func fullReg() map[string]Provider {
	return map[string]Provider{
		"jupiter_ultra": &jupiterProvider{},
		"dflow":         &dflowProvider{},
		"1inch":         &oneInchProvider{},
	}
}

func TestComputeAvailability(t *testing.T) {
	tests := []struct {
		name          string
		netType       string
		chainId       string
		reg           map[string]Provider
		oneInchKey    string
		wantAvailable bool
		wantNetwork   string
		wantProviders []string
		wantReason    string
	}{
		// ── Solana ────────────────────────────────────────────
		{
			name:          "solana mainnet — available",
			netType:       "solana",
			chainId:       "mainnet",
			reg:           fullReg(),
			wantAvailable: true,
			wantNetwork:   "solana.mainnet",
			wantProviders: []string{"jupiter_ultra", "dflow"},
		},
		{
			name:        "solana devnet — not supported (Jupiter/dFlow mainnet-only)",
			netType:     "solana",
			chainId:     "devnet",
			reg:         fullReg(),
			wantNetwork: "solana.devnet",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "solana testnet — not supported",
			netType:     "solana",
			chainId:     "testnet",
			reg:         fullReg(),
			wantNetwork: "solana.testnet",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "solana mainnet — no providers registered",
			netType:     "solana",
			chainId:     "mainnet",
			reg:         map[string]Provider{},
			wantNetwork: "solana.mainnet",
			wantReason:  "unsupported_chain",
		},

		// ── EVM ────────────────────────────────────────────────
		{
			name:        "evm ethereum — missing API key",
			netType:     "evm",
			chainId:     "1",
			reg:         fullReg(),
			oneInchKey:  "",
			wantNetwork: "evm.1",
			wantProviders: []string{"1inch"},
			wantReason:  "missing_api_key",
		},
		{
			name:          "evm ethereum — key populated",
			netType:       "evm",
			chainId:       "1",
			reg:           fullReg(),
			oneInchKey:    "test-key-123",
			wantAvailable: true,
			wantNetwork:   "evm.1",
			wantProviders: []string{"1inch"},
		},
		{
			name:          "evm polygon — key populated",
			netType:       "evm",
			chainId:       "137",
			reg:           fullReg(),
			oneInchKey:    "test-key-123",
			wantAvailable: true,
			wantNetwork:   "evm.137",
			wantProviders: []string{"1inch"},
		},
		{
			name:          "evm arbitrum — key populated",
			netType:       "evm",
			chainId:       "42161",
			reg:           fullReg(),
			oneInchKey:    "test-key-123",
			wantAvailable: true,
			wantNetwork:   "evm.42161",
			wantProviders: []string{"1inch"},
		},
		{
			name:        "evm chain not in 1inch coverage — key populated but unsupported",
			netType:     "evm",
			chainId:     "99999",
			reg:         fullReg(),
			oneInchKey:  "test-key-123",
			wantNetwork: "evm.99999",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "evm chain not in 1inch coverage + no key — chain-level miss wins",
			netType:     "evm",
			chainId:     "99999",
			reg:         fullReg(),
			oneInchKey:  "",
			wantNetwork: "evm.99999",
			wantReason:  "unsupported_chain",
		},

		// ── Bitcoin family ─────────────────────────────────────
		{
			name:        "bitcoin mainnet — not supported",
			netType:     "bitcoin",
			chainId:     "bitcoin",
			reg:         fullReg(),
			wantNetwork: "bitcoin.bitcoin",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "dogecoin — not supported",
			netType:     "bitcoin",
			chainId:     "dogecoin",
			reg:         fullReg(),
			wantNetwork: "bitcoin.dogecoin",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "litecoin — not supported",
			netType:     "bitcoin",
			chainId:     "litecoin",
			reg:         fullReg(),
			wantNetwork: "bitcoin.litecoin",
			wantReason:  "unsupported_chain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeAvailability(tc.netType, tc.chainId, tc.reg, tc.oneInchKey)
			if got.Available != tc.wantAvailable {
				t.Errorf("Available = %v, want %v", got.Available, tc.wantAvailable)
			}
			if got.Network != tc.wantNetwork {
				t.Errorf("Network = %q, want %q", got.Network, tc.wantNetwork)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if len(got.Providers) != len(tc.wantProviders) {
				t.Fatalf("Providers len = %d (%v), want %d (%v)",
					len(got.Providers), got.Providers,
					len(tc.wantProviders), tc.wantProviders)
			}
			for i := range got.Providers {
				if got.Providers[i] != tc.wantProviders[i] {
					t.Errorf("Providers[%d] = %q, want %q", i, got.Providers[i], tc.wantProviders[i])
				}
			}
		})
	}
}
