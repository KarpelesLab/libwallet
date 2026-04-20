package wltswap

// Swap:availability — UI-facing feature check. Apps call this to
// decide whether to render a "Swap" button at all on the current
// network. Cheap: no RPC calls, purely local policy + registry
// inspection.

import (
	"context"
	"errors"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// AvailabilityResult is the response from Swap:availability.
type AvailabilityResult struct {
	// Available reports whether Swap:quote / Swap:execute can be
	// called on the current network in this build. True only when
	// at least one provider is registered AND the build carries
	// whatever credentials that provider needs.
	Available bool `json:"available"`
	// Chain is the current network's chain family: "solana" /
	// "evm" / "bitcoin". Always populated so apps can branch UI
	// without a second lookup.
	Chain string `json:"chain"`
	// Providers lists the provider names that would be eligible
	// for Quote on this chain — in fallback order. Empty when
	// Available is false and the chain simply isn't supported.
	Providers []string `json:"providers,omitempty"`
	// Reason carries a short machine-readable explanation when
	// Available is false. Stable values: "unsupported_chain",
	// "missing_api_key".
	Reason string `json:"reason,omitempty"`
}

// swapAvailability is the Swap:availability entry point.
func swapAvailability(ctx context.Context, _ *struct{}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, err
	}
	return computeAvailability(n.Type, providers, OneInchAPIKey), nil
}

// computeAvailability is the pure-function core of the check — no
// env, no RPC, just policy. Separated so the per-chain rules can be
// unit-tested without setting up a temp env per case.
func computeAvailability(chainType string, reg map[string]Provider, oneInchKey string) *AvailabilityResult {
	res := &AvailabilityResult{Chain: chainType}

	switch chainType {
	case "solana":
		// Jupiter Ultra + dFlow are wired in this build; neither
		// needs an API key the user has to configure. Available.
		for _, name := range []string{"jupiter_ultra", "dflow"} {
			if _, ok := reg[name]; ok {
				res.Providers = append(res.Providers, name)
			}
		}
		res.Available = len(res.Providers) > 0
		if !res.Available {
			res.Reason = "unsupported_chain"
		}
	case "evm":
		// 1inch is wired but ships without an API key by default.
		// Keep the provider listed so apps can explain why swap
		// is temporarily unavailable, but Available stays false
		// until OneInchAPIKey is populated at build time.
		if _, ok := reg["1inch"]; ok {
			res.Providers = append(res.Providers, "1inch")
		}
		if oneInchKey == "" {
			res.Available = false
			res.Reason = "missing_api_key"
		} else {
			res.Available = len(res.Providers) > 0
			if !res.Available {
				res.Reason = "unsupported_chain"
			}
		}
	default:
		res.Available = false
		res.Reason = "unsupported_chain"
	}
	return res
}
