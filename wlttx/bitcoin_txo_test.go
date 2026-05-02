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
