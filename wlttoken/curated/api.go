package curated

import (
	"fmt"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
)

// Token:listCurated returns the embedded, vetted token list for a
// given chain. Purely local — no RPC, no external network.
//
// Input:
//
//	Network string  // canonical "<type>.<chainId>" form,
//	                // e.g. "evm.1", "solana.mainnet".
//
// Output: []*CuratedToken (empty when the chain has no curated
// entries; never nil).
//
// Rationale for taking the string form (vs. the Network xuid the
// existing Token:discoverToken takes): the frontend already holds
// the Network.network string field from Asset:list and can call
// this endpoint without an extra Network:fetch round-trip.
func init() {
	pobj.RegisterStatic("Token:listCurated", apiListCurated)
}

func apiListCurated(ctx *apirouter.Context, in struct {
	Network string
}) (any, error) {
	if in.Network == "" {
		return nil, fmt.Errorf("Network is required (canonical \"<type>.<chainId>\" form)")
	}
	netType, chainId, err := ParseChainKey(in.Network)
	if err != nil {
		return nil, err
	}
	list := ForChain(netType, chainId)
	if netType == "solana" && chainId == "mainnet" {
		list = appendChiefStaker(list)
	}
	if list == nil {
		// Never return nil — the Dart client expects a JSON
		// array so it can always `.map(...)` over the response
		// without a null guard.
		return []*CuratedToken{}, nil
	}
	return list, nil
}

// appendChiefStaker folds the latest ChiefStaker snapshot into the
// embedded curated list. Embedded entries win on address collision so
// generator-curated metadata (Jupiter / overlays) is never silently
// overridden by the dynamic feed. Allocates a fresh slice — the
// embedded list returned by [ForChain] is shared and must not be
// mutated.
func appendChiefStaker(base []*CuratedToken) []*CuratedToken {
	extra := chiefStakerSolanaTokens()
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]bool, len(base))
	for _, t := range base {
		seen[t.Address] = true
	}
	out := make([]*CuratedToken, 0, len(base)+len(extra))
	out = append(out, base...)
	for _, t := range extra {
		if seen[t.Address] {
			continue
		}
		seen[t.Address] = true
		out = append(out, t)
	}
	return out
}
