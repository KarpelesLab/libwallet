package wltnet

// Helius DAS getAssetsByOwner with showFungible:true — returns the
// fungible SPL tokens an address holds, enriched with name / symbol /
// decimals metadata. The standard getTokenAccountsByOwner SPL RPC call
// (see solana.go's SolanaTokenBalances) only returns mints + balances;
// the host then needs a separate metadata lookup per mint. DAS bundles
// metadata in a single call, which is what we want at first-launch
// token-list seeding.
//
// Used by wltbase to populate the user's Token table the first time
// they open the wallet on a Solana mainnet account.

import (
	"context"
	"encoding/json"
	"fmt"
)

// DiscoveredFungible is one entry returned by SolanaDiscoverFungibles.
// All fields are optional except Mint (the SPL token's mint address).
// Symbol / Name come from the on-chain metadata account; for tokens
// that don't expose Metaplex metadata these will be empty.
type DiscoveredFungible struct {
	Mint     string
	Name     string
	Symbol   string
	Decimals int
}

// SolanaDiscoverFungibles asks the Helius DAS endpoint (already the
// RPC for our Solana networks — see network.go's getRPC) for every
// fungible SPL token the given owner currently holds with a non-zero
// balance, and returns the parsed metadata for each.
//
// This is the wire-level helper — the caller is responsible for any
// filtering (spam, name length, …) and for persisting via the
// wlttoken package. Pure read; no state changes.
//
// Returns an empty slice (not an error) when the owner has no SPL
// holdings, so callers can treat both shapes the same way.
func (n *Network) SolanaDiscoverFungibles(ctx context.Context, owner string) ([]DiscoveredFungible, error) {
	if n.Type != "solana" {
		return nil, fmt.Errorf("SolanaDiscoverFungibles requires Type=solana, got %q", n.Type)
	}
	if owner == "" {
		return nil, fmt.Errorf("owner is required")
	}

	// limit=1000 is the DAS hard cap; addresses with more fungibles than
	// that are vanishingly rare in practice. Paging support can be added
	// later if it turns out to matter.
	result, err := n.DoRPCNamedCtx(ctx, "getAssetsByOwner", map[string]any{
		"ownerAddress": owner,
		"page":         1,
		"limit":        1000,
		"displayOptions": map[string]any{
			"showFungible":     true,
			"showZeroBalance":  false,
			"showNativeBalance": false,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("DAS getAssetsByOwner: %w", err)
	}

	var resp struct {
		Items []struct {
			ID      string `json:"id"`
			Content struct {
				Metadata struct {
					Name   string `json:"name"`
					Symbol string `json:"symbol"`
				} `json:"metadata"`
			} `json:"content"`
			TokenInfo struct {
				Symbol   string `json:"symbol"`
				Decimals int    `json:"decimals"`
			} `json:"token_info"`
			Interface string `json:"interface"`
		} `json:"items"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("decode getAssetsByOwner response: %w", err)
	}

	out := make([]DiscoveredFungible, 0, len(resp.Items))
	for _, it := range resp.Items {
		// DAS returns an `interface` discriminator. With
		// showFungible:true Helius mixes "FungibleToken",
		// "FungibleAsset", and bare SPL token entries into Items;
		// reject anything else (NFTs, compressed, programmable) so
		// we don't accidentally write an NFT into the Token table.
		switch it.Interface {
		case "FungibleToken", "FungibleAsset", "":
			// keep
		default:
			continue
		}
		// Prefer the token_info symbol (comes from the SPL token's
		// own metadata extension) over the off-chain JSON metadata
		// name field — the latter is sometimes a longer marketing
		// string. Fall back when token_info is empty.
		sym := it.TokenInfo.Symbol
		if sym == "" {
			sym = it.Content.Metadata.Symbol
		}
		out = append(out, DiscoveredFungible{
			Mint:     it.ID,
			Name:     it.Content.Metadata.Name,
			Symbol:   sym,
			Decimals: it.TokenInfo.Decimals,
		})
	}
	return out, nil
}
