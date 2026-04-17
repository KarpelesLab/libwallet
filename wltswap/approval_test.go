package wltswap

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/KarpelesLab/libwallet/wltobj"
)

func TestEncodeERC20Approve(t *testing.T) {
	// Known vector: approve(0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed, 1_000_000)
	got, err := encodeERC20Approve(
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		big.NewInt(1_000_000),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "0x" + erc20ApproveSelector +
		"0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed" +
		"00000000000000000000000000000000000000000000000000000000000f4240"
	if !strings.EqualFold(got, want) {
		t.Errorf("unexpected calldata\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodeERC20Approve_Errors(t *testing.T) {
	tests := []struct {
		name    string
		spender string
		amount  *big.Int
	}{
		{"missing 0x prefix", "abc", big.NewInt(1)},
		{"short address", "0x1234", big.NewInt(1)},
		{"nil amount", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", nil},
		{"negative amount", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", big.NewInt(-1)},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			if _, err := encodeERC20Approve(c.spender, c.amount); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestEncodeERC20Approve_UnlimitedRoundTrip(t *testing.T) {
	// Unlimited approve with 2^256-1.
	got, err := encodeERC20Approve("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", approvalMax)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(got, "0x"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Last 32 bytes should be all 0xff.
	for i, b := range raw[len(raw)-32:] {
		if b != 0xff {
			t.Errorf("byte %d of amount = 0x%02x, want 0xff", i, b)
		}
	}
}

func TestResolveApprovalAmount(t *testing.T) {
	q := &Quote{
		AmountIn: wltobj.NewAmountRaw(big.NewInt(1_000_000), 6),
	}
	tests := []struct {
		name string
		in   string
		want *big.Int
		err  bool
	}{
		{"empty defaults to amountIn", "", big.NewInt(1_000_000), false},
		{"max sentinel → 2^256-1", "max", approvalMax, false},
		{"unlimited sentinel → 2^256-1", "unlimited", approvalMax, false},
		{"uppercase sentinel works too", "MAX", approvalMax, false},
		{"explicit decimal", "2500000", big.NewInt(2_500_000), false},
		{"bogus string", "two million", nil, true},
		{"negative", "-1", nil, true},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			req := &BuildApprovalRequest{ApprovalAmount: c.in}
			got, err := resolveApprovalAmount(req, q)
			if c.err {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Cmp(c.want) != 0 {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestResolveApprovalAmount_DefaultIsExact(t *testing.T) {
	// Important: the default must be exactly the swap's input
	// amount. Widening the default would silently expose users to
	// drainer risk.
	q := &Quote{
		AmountIn: wltobj.NewAmountRaw(big.NewInt(42_000_000), 6),
	}
	req := &BuildApprovalRequest{} // no ApprovalAmount — defaults
	got, err := resolveApprovalAmount(req, q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(q.AmountIn.Value()) != 0 {
		t.Errorf("default approval = %s, want AmountIn %s — this would widen user risk", got, q.AmountIn.Value())
	}
}

func TestIsNativeEVMInput(t *testing.T) {
	cases := map[string]bool{
		"":            true,
		"NATIVE":      true,
		OneInchNativeSentinel:                         true,
		strings.ToUpper(OneInchNativeSentinel):        true,
		"0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48":  false,
	}
	for in, want := range cases {
		if got := isNativeEVMInput(in); got != want {
			t.Errorf("isNativeEVMInput(%q) = %v, want %v", in, got, want)
		}
	}
}
