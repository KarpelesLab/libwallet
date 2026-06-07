package wltswap

import "testing"

// okxReg mirrors what init.go populates — used as the default
// "this build has the OKX adapters" registry.
func okxReg() map[string]Provider {
	return map[string]Provider{
		"okx_solana": &okxSolanaProvider{},
		"okx_evm":    &okxEVMProvider{},
	}
}

func TestComputeAvailability(t *testing.T) {
	tests := []struct {
		name          string
		netType       string
		chainId       string
		reg           map[string]Provider
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
			reg:           okxReg(),
			wantAvailable: true,
			wantNetwork:   "solana.mainnet",
			wantProviders: []string{"okx_solana"},
		},
		{
			name:        "solana devnet — not supported (OKX mainnet-only)",
			netType:     "solana",
			chainId:     "devnet",
			reg:         okxReg(),
			wantNetwork: "solana.devnet",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "solana testnet — not supported",
			netType:     "solana",
			chainId:     "testnet",
			reg:         okxReg(),
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
			name:          "evm ethereum — available",
			netType:       "evm",
			chainId:       "1",
			reg:           okxReg(),
			wantAvailable: true,
			wantNetwork:   "evm.1",
			wantProviders: []string{"okx_evm"},
		},
		{
			name:          "evm polygon — available",
			netType:       "evm",
			chainId:       "137",
			reg:           okxReg(),
			wantAvailable: true,
			wantNetwork:   "evm.137",
			wantProviders: []string{"okx_evm"},
		},
		{
			name:          "evm arbitrum — available",
			netType:       "evm",
			chainId:       "42161",
			reg:           okxReg(),
			wantAvailable: true,
			wantNetwork:   "evm.42161",
			wantProviders: []string{"okx_evm"},
		},
		{
			name:        "evm chain not in OKX coverage",
			netType:     "evm",
			chainId:     "99999",
			reg:         okxReg(),
			wantNetwork: "evm.99999",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "evm chain supported but no provider registered",
			netType:     "evm",
			chainId:     "1",
			reg:         map[string]Provider{},
			wantNetwork: "evm.1",
			wantReason:  "unsupported_chain",
		},

		// ── Bitcoin family ─────────────────────────────────────
		{
			name:        "bitcoin mainnet — not supported",
			netType:     "bitcoin",
			chainId:     "bitcoin",
			reg:         okxReg(),
			wantNetwork: "bitcoin.bitcoin",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "dogecoin — not supported",
			netType:     "bitcoin",
			chainId:     "dogecoin",
			reg:         okxReg(),
			wantNetwork: "bitcoin.dogecoin",
			wantReason:  "unsupported_chain",
		},
		{
			name:        "litecoin — not supported",
			netType:     "bitcoin",
			chainId:     "litecoin",
			reg:         okxReg(),
			wantNetwork: "bitcoin.litecoin",
			wantReason:  "unsupported_chain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeAvailability(tc.netType, tc.chainId, tc.reg)
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
