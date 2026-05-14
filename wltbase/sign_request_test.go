package wltbase

import (
	"encoding/json"
	"testing"
)

// EIP-712 domains in the wild carry `chainId` in inconsistent shapes —
// JSON numbers (most dApps), hex strings (some legacy ones), bare
// decimal strings (a few). The label lookup needs to normalise all of
// them to the registry's "evm.<decimal>" key.
func TestLookupVerifyingContractLabel_ChainIdShapes(t *testing.T) {
	const permit2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
	const want = "Uniswap: Permit2"

	cases := []struct {
		name    string
		chainId any
	}{
		{"json number 1", json.Number("1")},
		{"float64 1 (json.Unmarshal default)", float64(1)},
		{"int 1", 1},
		{"int64 1", int64(1)},
		{"decimal string \"1\"", "1"},
		{"hex string 0x1", "0x1"},
		{"uppercase hex 0X1", "0X1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			domain := map[string]any{
				"verifyingContract": permit2,
				"chainId":           tc.chainId,
			}
			got := lookupVerifyingContractLabel("evm", domain)
			if got != want {
				t.Errorf("got %q, want %q (chainId %T = %v)", got, want, tc.chainId, tc.chainId)
			}
		})
	}
}

func TestLookupVerifyingContractLabel_Misses(t *testing.T) {
	cases := []struct {
		name   string
		chain  string
		domain map[string]any
	}{
		{
			name:  "non-EVM chain — verifyingContract pattern doesn't apply",
			chain: "solana",
			domain: map[string]any{
				"chainId":           float64(1),
				"verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
			},
		},
		{
			name:   "nil domain",
			chain:  "evm",
			domain: nil,
		},
		{
			name:  "missing verifyingContract",
			chain: "evm",
			domain: map[string]any{
				"chainId": float64(1),
			},
		},
		{
			name:  "missing chainId",
			chain: "evm",
			domain: map[string]any{
				"verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
			},
		},
		{
			name:  "unknown contract",
			chain: "evm",
			domain: map[string]any{
				"chainId":           float64(1),
				"verifyingContract": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
		},
		{
			name:  "known contract on unsupported chain",
			chain: "evm",
			domain: map[string]any{
				"chainId":           float64(999999),
				"verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lookupVerifyingContractLabel(tc.chain, tc.domain); got != "" {
				t.Errorf("got %q, want empty", got)
			}
		})
	}
}
