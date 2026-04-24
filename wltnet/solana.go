package wltnet

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/libwallet/wltasset"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnft"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wlttoken/curated"
)

// Solana RPC response types

type solanaRPCContext struct {
	Slot uint64 `json:"slot"`
}

type solanaBalanceResult struct {
	Context solanaRPCContext `json:"context"`
	Value   uint64           `json:"value"`
}

type solanaBlockhashResult struct {
	Context solanaRPCContext `json:"context"`
	Value   struct {
		Blockhash            string `json:"blockhash"`
		LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
	} `json:"value"`
}

type solanaTokenAccount struct {
	Pubkey  string `json:"pubkey"`
	Account struct {
		Data struct {
			Parsed struct {
				Info struct {
					Mint        string `json:"mint"`
					Owner       string `json:"owner"`
					TokenAmount struct {
						Amount         string  `json:"amount"`
						Decimals       int     `json:"decimals"`
						UIAmountString string  `json:"uiAmountString"`
						UIAmount       float64 `json:"uiAmount"`
					} `json:"tokenAmount"`
				} `json:"info"`
				Type string `json:"type"`
			} `json:"parsed"`
			Program string `json:"program"`
			Space   int    `json:"space"`
		} `json:"data"`
	} `json:"account"`
}

type solanaTokenAccountsResult struct {
	Context solanaRPCContext     `json:"context"`
	Value   []solanaTokenAccount `json:"value"`
}

// SolanaTokenBalances returns SPL token balances for the given account.
func (n *Network) SolanaTokenBalances(ctx context.Context, e wltintf.Env, acct AddressProvider) ([]*wltasset.Asset, error) {
	result, err := n.DoRPCCtx(ctx, "getTokenAccountsByOwner",
		acct.GetAddress(),
		map[string]any{"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
		map[string]any{"encoding": "jsonParsed"},
	)
	if err != nil {
		return nil, err
	}

	var parsed solanaTokenAccountsResult
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, err
	}

	var assets []*wltasset.Asset
	for _, ta := range parsed.Value {
		info := ta.Account.Data.Parsed.Info
		amt, ok := new(big.Int).SetString(info.TokenAmount.Amount, 10)
		if !ok {
			continue
		}
		if amt.Sign() == 0 {
			continue
		}

		// Enrich Name / Symbol from the embedded curated registry
		// when the mint is well-known. Falls back to a truncated
		// mint so unlisted tokens still have something non-empty
		// to display. ChainId here matches wltnet/api.go's Solana
		// registration (ChainId="mainnet").
		name, symbol := info.Mint[:8]+"...", info.Mint[:6]
		if ct := curated.Lookup(n.Type, n.ChainId, info.Mint); ct != nil {
			name, symbol = ct.Name, ct.Symbol
		}
		asset := &wltasset.Asset{
			Key:     n.String() + "." + info.Mint,
			Name:    name,
			Symbol:  symbol,
			Amount:  wltobj.NewAmountRaw(amt, info.TokenAmount.Decimals),
			Network: n.Id,
			Type:    "fungible",
			TestNet: n.TestNet,
		}
		assets = append(assets, asset)
	}

	return assets, nil
}

// solanaNftList fetches NFTs using the Helius DAS API (getAssetsByOwner).
func (n *Network) solanaNftList(e wltintf.Env, acct AddressProvider) (*[]wltnft.Nft, error) {
	result, err := n.DoRPCNamed("getAssetsByOwner", map[string]any{
		"ownerAddress":   acct.GetAddress(),
		"page":           1,
		"limit":          100,
		"displayOptions": map[string]any{"showFungible": false},
	})
	if err != nil {
		return nil, fmt.Errorf("DAS API not available: %w", err)
	}

	var dasResult struct {
		Items []struct {
			Id      string `json:"id"`
			Content struct {
				Metadata struct {
					Name        string `json:"name"`
					Symbol      string `json:"symbol"`
					Description string `json:"description"`
				} `json:"metadata"`
				Links struct {
					Image string `json:"image"`
				} `json:"links"`
				JsonURI string `json:"json_uri"`
			} `json:"content"`
			Grouping []struct {
				GroupKey   string `json:"group_key"`
				GroupValue string `json:"group_value"`
			} `json:"grouping"`
		} `json:"items"`
	}
	if err := json.Unmarshal(result, &dasResult); err != nil {
		return nil, err
	}

	var nfts []wltnft.Nft
	for _, item := range dasResult.Items {
		contractAddr := ""
		for _, g := range item.Grouping {
			if g.GroupKey == "collection" {
				contractAddr = g.GroupValue
				break
			}
		}

		nft := wltnft.Nft{
			ContractAddress: contractAddr,
			Network:         n.Id,
			TokenId:         item.Id,
			Name:            item.Content.Metadata.Name,
			Description:     item.Content.Metadata.Description,
			Image:           item.Content.Links.Image,
		}
		nfts = append(nfts, nft)
	}

	return &nfts, nil
}
