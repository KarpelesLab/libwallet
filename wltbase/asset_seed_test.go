package wltbase

import (
	"testing"

	"github.com/KarpelesLab/libwallet/wltnet"
)

// isPlausibleFungible's spam filter is conservative on purpose. These
// table tests pin the policy so a future tweak (e.g. relaxing the
// 12-char symbol cap) is an intentional change, not a silent drift.
func TestIsPlausibleFungible(t *testing.T) {
	cases := []struct {
		name string
		in   wltnet.DiscoveredFungible
		want bool
	}{
		{"ok minimal", wltnet.DiscoveredFungible{Mint: "M", Symbol: "USDC", Decimals: 6}, true},
		{"ok long name within limit", wltnet.DiscoveredFungible{Mint: "M", Symbol: "X", Decimals: 9, Name: "Reasonable Brand-y Token Name"}, true},
		{"empty mint rejected", wltnet.DiscoveredFungible{Mint: "", Symbol: "X", Decimals: 6}, false},
		{"empty symbol rejected", wltnet.DiscoveredFungible{Mint: "M", Symbol: "", Decimals: 6}, false},
		{"zero decimals rejected", wltnet.DiscoveredFungible{Mint: "M", Symbol: "X", Decimals: 0}, false},
		{"negative decimals rejected", wltnet.DiscoveredFungible{Mint: "M", Symbol: "X", Decimals: -1}, false},
		{"symbol over 12 chars rejected", wltnet.DiscoveredFungible{Mint: "M", Symbol: "TOOLONGSYMBOL_", Decimals: 6}, false},
		{
			"name over 64 chars rejected (typical scam-link pattern)",
			wltnet.DiscoveredFungible{
				Mint:     "M",
				Symbol:   "FREE",
				Decimals: 6,
				Name:     "Claim your free tokens at https://totally-not-a-scam.example/airdrop-2026-q2",
			},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPlausibleFungible(tc.in); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMintFromAssetKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"net-AAAA.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
		{"no-dot", ""},
		{"trailing.dot.", ""},
		{".leading", "leading"},
	}
	for _, tc := range cases {
		if got := mintFromAssetKey(tc.in); got != tc.want {
			t.Errorf("mintFromAssetKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
