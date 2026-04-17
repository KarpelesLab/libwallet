package wlttx

import (
	"math/big"
	"testing"
)

func TestIsUnlimitedApproval(t *testing.T) {
	cases := []struct {
		name   string
		amount *big.Int
		want   bool
	}{
		{"nil", nil, false},
		{"zero", big.NewInt(0), false},
		{"small", big.NewInt(1_000_000), false},
		{
			// 2^128 — "large" but still bounded. Genuine treasury
			// allocations routinely approve this much.
			"2^128",
			new(big.Int).Lsh(big.NewInt(1), 128),
			false,
		},
		{
			// 2^255 — the cutoff. At this point it's effectively
			// infinite on any real token.
			"2^255",
			new(big.Int).Lsh(big.NewInt(1), 255),
			true,
		},
		{
			// 2^256-1 — the classic "max approve" drainer pattern.
			"uint256 max",
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUnlimitedApproval(c.amount); got != c.want {
				t.Errorf("isUnlimitedApproval(%v) = %v, want %v", c.amount, got, c.want)
			}
		})
	}
}

func TestWarningCodesAreStable(t *testing.T) {
	// Apps in the wild pattern-match on these strings. Changing a
	// value is a breaking change to the Dart + host-app API.
	cases := map[string]string{
		"WarnRecipientIsContract":    WarnRecipientIsContract,
		"WarnRecipientNewAccount":    WarnRecipientNewAccount,
		"WarnErc20ApproveUnlimited":  WarnErc20ApproveUnlimited,
		"WarnNetLossExceedsAmount":   WarnNetLossExceedsAmount,
		"WarnPriorityFeeRecommended": WarnPriorityFeeRecommended,
	}
	expected := map[string]string{
		"WarnRecipientIsContract":    "recipient_is_contract",
		"WarnRecipientNewAccount":    "recipient_new_account",
		"WarnErc20ApproveUnlimited":  "erc20_approve_unlimited",
		"WarnNetLossExceedsAmount":   "net_loss_exceeds_amount",
		"WarnPriorityFeeRecommended": "priority_fee_recommended",
	}
	for k, got := range cases {
		if got != expected[k] {
			t.Errorf("%s = %q, want %q", k, got, expected[k])
		}
	}
}
