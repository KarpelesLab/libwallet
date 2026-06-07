package wltswap

import (
	"context"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
)

// Provider is the adapter surface each aggregator implements.
//
// Quote talks to the provider's price/routing endpoint and returns
// a partially-filled Quote (QuoteId, createdAt, ExpiresAt, from are
// filled by the central swap.go caller — adapters don't touch those).
//
// Execute consumes the Quote's providerBlob to sign and broadcast
// via whatever the provider requires (the OKX Solana adapter
// broadcasts the signed Solana tx; the OKX EVM adapter broadcasts
// to the chain's EVM RPC directly).
type Provider interface {
	Name() string
	Chain() string // "solana" | "evm"
	Quote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error)
	Execute(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error)
}

// providers is the registry. Keys are the stable names exposed in
// QuoteRequest.Provider / Quote.Provider. Populated by each adapter's
// init via RegisterProvider so that injecting test doubles is just
// one registry overwrite.
var providers = map[string]Provider{}

// RegisterProvider adds (or replaces) an entry in the provider
// registry. Safe to call during init; tests call it after setup to
// swap in an httptest-backed double.
func RegisterProvider(p Provider) {
	providers[p.Name()] = p
}

func getProvider(name string) (Provider, error) {
	p, ok := providers[name]
	if !ok {
		return nil, newErr(ErrCodeInvalidRequest, fmt.Sprintf("unknown provider %q", name))
	}
	return p, nil
}

// computeReferralFee returns amountIn * bps / 10_000 with matching
// decimals, suitable for dropping straight into Quote.ReferralFee.
// Handy in adapters so the math lives in one place.
func computeReferralFee(amountIn *big.Int, bps uint16, decimals int) *wltobj.Amount {
	if amountIn == nil || bps == 0 {
		return wltobj.NewAmountRaw(big.NewInt(0), decimals)
	}
	v := new(big.Int).Mul(amountIn, big.NewInt(int64(bps)))
	v.Quo(v, big.NewInt(10_000))
	return wltobj.NewAmountRaw(v, decimals)
}

// providerOrderForChain returns the priority-ordered provider names
// libwallet attempts for n's chain family. With OKX as the only
// routed provider the list is always single-element; the slice
// shape is kept so the surrounding multi-provider plumbing
// (Swap:quotes fan-out, fallback retry) doesn't need to know.
func providerOrderForChain(n *wltnet.Network) ([]string, error) {
	switch n.Type {
	case "solana":
		return []string{"okx_solana"}, nil
	case "evm":
		return []string{"okx_evm"}, nil
	default:
		return nil, newErr(ErrCodeUnsupportedChain, fmt.Sprintf("swap not supported on %s networks", n.Type))
	}
}

// providersForChain resolves [providerOrderForChain] to the actual
// registered Provider implementations. Used by Swap:quotes to fan
// out a quote request across every available provider for the chain.
func providersForChain(n *wltnet.Network) ([]Provider, error) {
	order, err := providerOrderForChain(n)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(order))
	for _, name := range order {
		if p, ok := providers[name]; ok {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("no provider registered for %s", n.Type))
	}
	return out, nil
}

// selectProvider decides which provider to use for a single-quote
// request. Caller-pinned Provider wins; otherwise pick the first
// registered provider from [providerOrderForChain].
//
// As of 0.4.31 there is no silent fallback at the runQuote layer —
// Swap:quote returns the primary's result verbatim. Hosts that want
// dFlow's number too should call Swap:quotes (plural).
func selectProvider(n *wltnet.Network, pinned string) (Provider, error) {
	if pinned != "" {
		p, err := getProvider(pinned)
		if err != nil {
			return nil, err
		}
		if p.Chain() != n.Type {
			return nil, newErr(ErrCodeInvalidRequest,
				fmt.Sprintf("provider %q is for %s but the current network is %s", pinned, p.Chain(), n.Type))
		}
		return p, nil
	}
	ps, err := providersForChain(n)
	if err != nil {
		return nil, err
	}
	return ps[0], nil
}
