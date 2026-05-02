package wlttx

import (
	"encoding/json"
	"testing"
)

// TestBitcoinTxo_ChildIndex pins both response shapes — modchain
// emitting the modern path-only form and the legacy i+branch form
// (which we still parse for older backends or when a partial deploy
// hits us mid-rollout).
func TestBitcoinTxo_ChildIndex(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{
			name: "modern path-only",
			raw:  `{"txo":"abc:0","amt":0.1,"path":"m/0/3","script":"p2wpkh"}`,
			want: 3,
		},
		{
			name: "modern path on change chain",
			raw:  `{"txo":"abc:1","amt":0.05,"path":"m/1/12","script":"p2wpkh"}`,
			want: 12,
		},
		{
			name: "legacy i+branch (no path)",
			raw:  `{"txo":"abc:0","amt":0.2,"i":7,"script":"p2pkh"}`,
			want: 7,
		},
		{
			name: "both present — path wins",
			raw:  `{"txo":"abc:0","amt":0.3,"path":"m/0/9","i":2,"script":"p2wpkh"}`,
			want: 9,
		},
		{
			name: "malformed path falls back to i",
			raw:  `{"txo":"abc:0","amt":0.4,"path":"m/0/notanumber","i":4,"script":"p2wpkh"}`,
			want: 4,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var x bitcoinTxo
			if err := json.Unmarshal([]byte(c.raw), &x); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := x.childIndex(); got != c.want {
				t.Errorf("childIndex() = %d, want %d", got, c.want)
			}
		})
	}
}

func TestBitcoinTxo_ChainFromPath(t *testing.T) {
	cases := []struct {
		path string
		want int
	}{
		{"m/0/0", 0},
		{"m/0/12", 0},
		{"m/1/0", 1},
		{"m/1/9", 1},
		{"", 0},          // missing → default receive
		{"garbage", 0},   // malformed → default receive
		{"m/0", 0},       // truncated → default receive (no chain segment)
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			x := bitcoinTxo{Path: c.path}
			if got := x.chainFromPath(); got != c.want {
				t.Errorf("chainFromPath() = %d, want %d", got, c.want)
			}
		})
	}
}

func TestBitcoinTxo_Vsize(t *testing.T) {
	// Per-input vsize must reflect the actual script type — a single
	// p2pkh input mixed in with p2wpkh would otherwise blow our fee
	// estimate by ~80 vbytes per input.
	cases := []struct {
		script string
		want   int
	}{
		{"p2wpkh", 68},
		{"p2wsh", 68},
		{"p2sh:p2wpkh", 91},
		{"p2sh-p2wpkh", 91},
		{"p2pkh", 148},
		{"p2pukh", 148},
		{"unknown-script-shape", 148}, // pessimistic fallback
		{"", 148},
	}
	for _, c := range cases {
		t.Run(c.script, func(t *testing.T) {
			x := bitcoinTxo{Script: c.script}
			if got := x.vsize(); got != c.want {
				t.Errorf("vsize(%q) = %d, want %d", c.script, got, c.want)
			}
		})
	}
}

func TestEstimateMixedTxVSize(t *testing.T) {
	// 11 overhead + 2 outputs × 31 = 73 base
	// + p2wpkh 68 + p2pkh 148 = 216 inputs = 289 total
	ins := []bitcoinTxo{{Script: "p2wpkh"}, {Script: "p2pkh"}}
	if got := estimateMixedTxVSize(ins, 2); got != 289 {
		t.Errorf("estimateMixedTxVSize(mixed, 2 out) = %d, want 289", got)
	}
	// Empty inputs (degenerate) — base only.
	if got := estimateMixedTxVSize(nil, 2); got != 73 {
		t.Errorf("estimateMixedTxVSize(no inputs, 2 out) = %d, want 73", got)
	}
}
