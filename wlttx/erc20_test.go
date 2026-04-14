package wlttx

import (
	"math/big"
	"strings"
	"testing"
)

func TestEncodeERC20Transfer(t *testing.T) {
	// Known test vector: transfer(0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed, 1000000)
	// = 0xa9059cbb
	//   0000000000000000000000005aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
	//   00000000000000000000000000000000000000000000000000000000000f4240
	data, err := encodeERC20Transfer(
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		big.NewInt(1_000_000),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "0xa9059cbb" +
		"0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed" +
		"00000000000000000000000000000000000000000000000000000000000f4240"
	if !strings.EqualFold(data, want) {
		t.Errorf("unexpected data\ngot:  %s\nwant: %s", data, want)
	}
}

func TestEncodeERC20Transfer_errors(t *testing.T) {
	cases := []struct {
		name string
		addr string
		amt  *big.Int
	}{
		{"missing 0x prefix", "abc123", big.NewInt(1)},
		{"short address", "0x1234", big.NewInt(1)},
		{"nil amount", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", nil},
		{"negative amount", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", big.NewInt(-1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := encodeERC20Transfer(c.addr, c.amt); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
