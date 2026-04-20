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
		chain         string
		reg           map[string]Provider
		oneInchKey    string
		wantAvailable bool
		wantChain     string
		wantProviders []string
		wantReason    string
	}{
		{
			name:          "solana — both providers registered",
			chain:         "solana",
			reg:           fullReg(),
			wantAvailable: true,
			wantChain:     "solana",
			wantProviders: []string{"jupiter_ultra", "dflow"},
		},
		{
			name:          "solana — only jupiter registered",
			chain:         "solana",
			reg:           map[string]Provider{"jupiter_ultra": &jupiterProvider{}},
			wantAvailable: true,
			wantChain:     "solana",
			wantProviders: []string{"jupiter_ultra"},
		},
		{
			name:          "solana — no providers at all",
			chain:         "solana",
			reg:           map[string]Provider{},
			wantAvailable: false,
			wantChain:     "solana",
			wantReason:    "unsupported_chain",
		},
		{
			name:          "evm — missing API key (current default build)",
			chain:         "evm",
			reg:           fullReg(),
			oneInchKey:    "",
			wantAvailable: false,
			wantChain:     "evm",
			wantProviders: []string{"1inch"},
			wantReason:    "missing_api_key",
		},
		{
			name:          "evm — API key populated",
			chain:         "evm",
			reg:           fullReg(),
			oneInchKey:    "test-key-123",
			wantAvailable: true,
			wantChain:     "evm",
			wantProviders: []string{"1inch"},
		},
		{
			name:          "evm — key populated but no provider registered",
			chain:         "evm",
			reg:           map[string]Provider{},
			oneInchKey:    "test-key-123",
			wantAvailable: false,
			wantChain:     "evm",
			wantReason:    "unsupported_chain",
		},
		{
			name:          "bitcoin — not supported",
			chain:         "bitcoin",
			reg:           fullReg(),
			wantAvailable: false,
			wantChain:     "bitcoin",
			wantReason:    "unsupported_chain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeAvailability(tc.chain, tc.reg, tc.oneInchKey)
			if got.Available != tc.wantAvailable {
				t.Errorf("Available = %v, want %v", got.Available, tc.wantAvailable)
			}
			if got.Chain != tc.wantChain {
				t.Errorf("Chain = %q, want %q", got.Chain, tc.wantChain)
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
