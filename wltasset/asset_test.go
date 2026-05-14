package wltasset

import "testing"

func TestAsset_IsNative(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"evm.1.NATIVE", true},
		{"solana.mainnet.NATIVE", true},
		{"bitcoin.bitcoin.NATIVE", true},
		// Asset.Type is "fungible" for both native and tokens, so the
		// caller can't distinguish by Type. Confirm IsNative keys on
		// the .NATIVE suffix instead.
		{"evm.1.0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48", false},
		{"solana.mainnet.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", false},
		{"", false},
		// A key that contains "NATIVE" as part of the address (not as
		// the trailing segment) is still a token. Use HasSuffix not
		// Contains.
		{"evm.1.NATIVE-something-extra", false},
	}
	for _, tc := range cases {
		a := &Asset{Key: tc.key}
		if got := a.IsNative(); got != tc.want {
			t.Errorf("Asset{Key: %q}.IsNative() = %v, want %v", tc.key, got, tc.want)
		}
	}

	// nil receiver doesn't panic.
	var nilA *Asset
	if nilA.IsNative() {
		t.Error("nil receiver should not report IsNative=true")
	}
}

func TestAsset_TokenAddress(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"evm.1.NATIVE", ""},
		{"evm.1.0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48", "0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48"},
		{"solana.mainnet.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
		{"", ""},
		{"no-dots", ""},
		{"trailing.dot.", ""},
	}
	for _, tc := range cases {
		a := &Asset{Key: tc.key}
		if got := a.TokenAddress(); got != tc.want {
			t.Errorf("Asset{Key: %q}.TokenAddress() = %q, want %q", tc.key, got, tc.want)
		}
	}

	// nil receiver returns empty.
	var nilA *Asset
	if got := nilA.TokenAddress(); got != "" {
		t.Errorf("nil receiver TokenAddress = %q, want empty", got)
	}
}
