package wltnames

import (
	"encoding/hex"
	"testing"
)

func TestNamehash(t *testing.T) {
	// Reference test vectors from EIP-137
	cases := []struct {
		name string
		want string
	}{
		{"", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"eth", "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"},
		{"foo.eth", "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hex.EncodeToString(namehash(c.name))
			if got != c.want {
				t.Errorf("namehash(%q):\ngot  %s\nwant %s", c.name, got, c.want)
			}
		})
	}
}

func TestIsZeroAddress(t *testing.T) {
	if !isZeroAddress("0x0000000000000000000000000000000000000000") {
		t.Error("expected zero address")
	}
	if isZeroAddress("0x0000000000000000000000000000000000000001") {
		t.Error("expected non-zero address")
	}
}
