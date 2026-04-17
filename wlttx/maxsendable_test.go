package wlttx

import (
	"testing"
)

func TestComputeSolanaMaxSendable(t *testing.T) {
	const (
		fee        = uint64(5000)
		senderRent = uint64(890880)
	)

	tests := []struct {
		name            string
		balance         uint64
		recipientRent   uint64
		recipientExists bool
		wantMax         uint64
		wantReserved    uint64
		wantReason      bool // true if we expect a non-empty reason
	}{
		{
			// The user's original scenario: 0.01 SOL = 10_000_000 lamports.
			// 10_000_000 - 5000 - 890880 = 9_104_120 lamports max.
			name:            "0.01 SOL, recipient exists",
			balance:         10_000_000,
			recipientExists: true,
			wantMax:         9_104_120,
			wantReserved:    895_880,
			wantReason:      false,
		},
		{
			// Same balance but funding a brand new recipient: the
			// recipient's rent also comes out of the max.
			name:            "0.01 SOL, new recipient",
			balance:         10_000_000,
			recipientRent:   senderRent,
			recipientExists: false,
			wantMax:         8_213_240,
			wantReserved:    1_786_760,
			wantReason:      false,
		},
		{
			// Exact edge: balance == fee + senderRent → no room to send.
			name:            "exactly fee+rent",
			balance:         fee + senderRent,
			recipientExists: true,
			wantMax:         0,
			wantReserved:    fee + senderRent,
			wantReason:      true,
		},
		{
			// Classic insufficient-funds: below fee+rent.
			name:            "below fee+rent",
			balance:         100_000,
			recipientExists: true,
			wantMax:         0,
			wantReserved:    fee + senderRent,
			wantReason:      true,
		},
		{
			// Large balance: fully covers everything.
			name:            "1 SOL, recipient exists",
			balance:         1_000_000_000,
			recipientExists: true,
			wantMax:         1_000_000_000 - fee - senderRent,
			wantReserved:    fee + senderRent,
			wantReason:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			max, reserved, reason := computeSolanaMaxSendable(tc.balance, fee, senderRent, tc.recipientRent, tc.recipientExists)
			if max != tc.wantMax {
				t.Errorf("max = %d, want %d", max, tc.wantMax)
			}
			if reserved != tc.wantReserved {
				t.Errorf("reserved = %d, want %d", reserved, tc.wantReserved)
			}
			if (reason != "") != tc.wantReason {
				t.Errorf("reason = %q, wantNonEmpty=%v", reason, tc.wantReason)
			}
			// Balance conservation: balance = max + reserved (when max > 0)
			if max > 0 && max+reserved != tc.balance {
				t.Errorf("max+reserved=%d != balance=%d", max+reserved, tc.balance)
			}
		})
	}
}

func TestComputeBitcoinMaxSendable(t *testing.T) {
	tests := []struct {
		name       string
		totalSats  int64
		nInputs    int
		feeRate    int64
		wantMax    int64
		wantReason bool
	}{
		{
			// 1 BTC = 100_000_000 sats, 1 input at 10 sat/vB
			// vsize = 11 + 1*68 + 1*31 = 110; fee = 1100
			name:      "1 BTC, 1 input @10 sat/vB",
			totalSats: 100_000_000,
			nInputs:   1,
			feeRate:   10,
			wantMax:   100_000_000 - 1100,
		},
		{
			// 3 inputs → vsize = 11 + 3*68 + 31 = 246; fee = 246
			// at 1 sat/vB.
			name:      "3 inputs @1 sat/vB",
			totalSats: 10_000_000,
			nInputs:   3,
			feeRate:   1,
			wantMax:   10_000_000 - 246,
		},
		{
			// Dust input below the fee.
			name:       "dust input",
			totalSats:  500,
			nInputs:    1,
			feeRate:    10,
			wantMax:    0,
			wantReason: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			max, fee, reason := computeBitcoinMaxSendable(tc.totalSats, tc.nInputs, tc.feeRate)
			if max != tc.wantMax {
				t.Errorf("max = %d, want %d", max, tc.wantMax)
			}
			if (reason != "") != tc.wantReason {
				t.Errorf("reason = %q, wantNonEmpty=%v", reason, tc.wantReason)
			}
			if max > 0 && max+fee != tc.totalSats {
				t.Errorf("max+fee=%d != total=%d", max+fee, tc.totalSats)
			}
		})
	}
}

func TestIsNativeAsset(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"NATIVE", true},
		{"evm.1.NATIVE", true},
		{"solana.mainnet-beta.NATIVE", true},
		{"evm.1.0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48", false},
		{"solana.mainnet-beta.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := isNativeAsset(c.in, nil); got != c.want {
				t.Errorf("isNativeAsset(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
