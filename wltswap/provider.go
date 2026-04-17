package wltswap

import (
	"context"
	"fmt"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
)

// Provider is the adapter surface each aggregator implements.
//
// Quote talks to the provider's price/routing endpoint and returns
// a partially-filled Quote (QuoteId, createdAt, ExpiresAt, from are
// filled by the central swap.go caller — adapters don't touch those).
//
// Execute consumes the Quote's providerBlob to sign and broadcast
// via whatever the provider requires (Jupiter posts a signed tx
// back to /execute; dFlow broadcasts to the Solana RPC directly;
// 1inch broadcasts to the EVM RPC directly).
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

// selectProvider decides which provider to use for a given request.
// Caller-pinned Provider wins; otherwise pick the primary for the
// chain. For Solana the primary is Jupiter Ultra; if unregistered
// for some reason we fall to dFlow. For EVM there's one: 1inch.
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

	var order []string
	switch n.Type {
	case "solana":
		order = []string{"jupiter_ultra", "dflow"}
	case "evm":
		order = []string{"1inch"}
	default:
		return nil, newErr(ErrCodeUnsupportedChain, fmt.Sprintf("swap not supported on %s networks", n.Type))
	}

	for _, name := range order {
		if p, ok := providers[name]; ok {
			return p, nil
		}
	}
	return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("no provider registered for %s", n.Type))
}
