package wltswap

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/KarpelesLab/libwallet/wltnet"
)

// TestIsNoRouteError pins the substrings the advisory-quote path
// recognises as "no route at this amount" — the canonical OKX
// "no route" / "insufficient liquidity" surfaces, plus the older
// "Failed to get quotes" phrasing that some upstreams still use.
// False positives here would downgrade real errors into silent
// no-routes; false negatives would let dust-trade rejections bubble
// up as hard errors and hide the asset from source-list UIs.
func TestIsNoRouteError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"plain error", errors.New("transport refused"), false},
		{"invalid request — caller bug, not no-route",
			&SwapError{Code: ErrCodeInvalidRequest, Message: "amountIn missing"}, false},
		{"provider unavailable — hard failure",
			&SwapError{Code: ErrCodeProviderUnavailable, Message: "503"}, false},
		{"provider 4xx — generic",
			&SwapError{Code: ErrCodeProviderBadRequest, Message: "validation failed"}, false},
		{"failed to get quotes — dust trade phrasing",
			&SwapError{Code: ErrCodeProviderBadRequest, Message: "Failed to get quotes"}, true},
		{"failed to get quotes — case-insensitive",
			&SwapError{Code: ErrCodeProviderBadRequest, Message: "FAILED to GET quotes"}, true},
		{"no route wording",
			&SwapError{Code: ErrCodeProviderBadRequest, Message: "no route"}, true},
		{"no liquidity wording",
			&SwapError{Code: ErrCodeProviderBadRequest, Message: "no liquidity in pool"}, true},
		{"insufficient liquidity wording",
			&SwapError{Code: ErrCodeProviderBadRequest, Message: "insufficient liquidity"}, true},
		// errors.As chain: a wrapped SwapError still classifies.
		{"wrapped no-route error",
			fmt.Errorf("upstream: %w", &SwapError{Code: ErrCodeProviderBadRequest, Message: "Failed to get quotes"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNoRouteError(tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBuildAdvisoryQuote verifies the shape of the non-executable
// Quote returned on soft failures: AmountIn populated, Status +
// StatusMessage set, no AmountOut / Route / providerBlob, no
// QuoteId (so Swap:execute will refuse it via the cache miss).
func TestBuildAdvisoryQuote(t *testing.T) {
	n := &wltnet.Network{Type: "solana", ChainId: "mainnet"}
	req := &QuoteRequest{
		TokenIn:     TokenRef{Address: "NATIVE", Symbol: "SOL", Decimals: 9},
		TokenOut:    TokenRef{Address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", Symbol: "USDC", Decimals: 6},
		SlippageBps: DefaultSlippageBps,
	}

	t.Run("balance too small carries amount 0", func(t *testing.T) {
		q := buildAdvisoryQuote(n, req, "0", QuoteStatusBalanceTooSmall, "balance does not cover network fee + rent")
		if q.Status != QuoteStatusBalanceTooSmall {
			t.Errorf("Status = %q, want %q", q.Status, QuoteStatusBalanceTooSmall)
		}
		if q.StatusMessage == "" {
			t.Error("StatusMessage must be populated for non-OK statuses")
		}
		if q.AmountIn == nil || q.AmountIn.Value().Sign() != 0 {
			t.Errorf("AmountIn must be zero for balance_too_small, got %v", q.AmountIn)
		}
		if q.AmountOut == nil || q.AmountOut.Value().Sign() != 0 {
			t.Errorf("AmountOut must be a zero-valued Amount (not nil) on advisory quote, got %v", q.AmountOut)
		}
		if q.MinAmountOut == nil || q.MinAmountOut.Value().Sign() != 0 {
			t.Errorf("MinAmountOut must be a zero-valued Amount on advisory quote, got %v", q.MinAmountOut)
		}
		if q.QuoteId != "" {
			t.Errorf("QuoteId must be empty so Swap:execute refuses the advisory quote, got %q", q.QuoteId)
		}
		if q.providerBlob != nil {
			t.Error("providerBlob must be nil on advisory quote")
		}
		if q.TokenIn.Symbol != "SOL" || q.TokenOut.Symbol != "USDC" {
			t.Error("tokens must be preserved verbatim for source-list UIs")
		}
	})

	t.Run("no route carries the resolved AmountIn", func(t *testing.T) {
		// 0.0061 SOL ≈ 6,100,000 lamports — the dust amount from the
		// tester's report. Confirms the helper preserves the
		// resolveMaxAmountIn output verbatim so the host can render
		// "Max: 0.0061 SOL — no route at this amount".
		q := buildAdvisoryQuote(n, req, "6100000", QuoteStatusNoRoute, "Jupiter: Failed to get quotes")
		if q.Status != QuoteStatusNoRoute {
			t.Errorf("Status = %q, want %q", q.Status, QuoteStatusNoRoute)
		}
		if q.AmountIn == nil || q.AmountIn.Value().Int64() != 6_100_000 {
			t.Errorf("AmountIn = %v, want 6100000 base units", q.AmountIn)
		}
		if !strings.Contains(q.StatusMessage, "Failed to get quotes") {
			t.Errorf("StatusMessage = %q must propagate provider's reason", q.StatusMessage)
		}
		if q.Chain != "solana" {
			t.Errorf("Chain = %q, want \"solana\"", q.Chain)
		}
	})

	t.Run("invalid amount string degrades to zero, not panic", func(t *testing.T) {
		// big.Int.SetString returns (nil, false) on garbage; the
		// helper must produce a Quote (not panic) so the caller
		// always has something to surface.
		q := buildAdvisoryQuote(n, req, "garbage", QuoteStatusNoRoute, "test")
		if q == nil {
			t.Fatal("buildAdvisoryQuote returned nil on bad amount")
		}
		if q.AmountIn == nil || q.AmountIn.Value().Sign() != 0 {
			t.Errorf("invalid amount must degrade to zero, got %v", q.AmountIn)
		}
	})
}
