package wltbase

import (
	"context"
	"errors"
	"io/fs"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltasset"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/pobj"
)

func init() {
	//pobj.RegisterStatic("Asset", transactionValidate)
	pobj.RegisterActions[wltasset.Asset]("Asset",
		&pobj.ObjectActions{
			Fetch: pobj.Static(apiFetchAsset),
			List:  pobj.Static(apiListAsset),
		},
	)
}

func apiFetchAsset(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	return nil, fs.ErrNotExist
}

// assetSnapshot is the `{network, account, assets}` shape returned by
// Asset list and consumed by the balance poller.
type assetSnapshot struct {
	Network *wltnet.Network   `json:"network"`
	Account *wltacct.Account  `json:"account"`
	Assets  []*wltasset.Asset `json:"assets"`
}

// currentAssets builds an assetSnapshot for the current account + network
// (or the specific ones passed in). Extracted so both the list endpoint
// and the balance poller can use the same logic.
//
// ctx is threaded through every RPC call so callers can bound the work
// (the background poller wraps this in a 15 s timeout; the API endpoint
// inherits the apirouter request context). Without a deadline, a slow
// or unreachable upstream RPC would hang this call indefinitely.
func currentAssets(ctx context.Context, e wltintf.Env, n *wltnet.Network, acct *wltacct.Account) (*assetSnapshot, error) {
	if n == nil {
		var err error
		n, err = wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, err
		}
	}
	if acct == nil {
		var err error
		acct, err = wltacct.CurrentAccount(e)
		if err != nil {
			return nil, err
		}
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	var assets []*wltasset.Asset
	if acct.GetAddress() != "N/A" {
		if nat, err := n.NativeAsset(ctx, e, acct); err == nil {
			assets = append(assets, nat)
		} else {
			return nil, err
		}
	}
	if n.Type == "solana" && acct.GetAddress() != "N/A" {
		if tokens, err := n.SolanaTokenBalances(ctx, e, acct); err == nil {
			assets = append(assets, tokens...)
		}
	}
	return &assetSnapshot{Network: n, Account: acct, Assets: assets}, nil
}

func apiListAsset(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	snap, err := currentAssets(ctx, e,
		apirouter.GetObject[wltnet.Network](ctx, "Network"),
		apirouter.GetObject[wltacct.Account](ctx, "Account"),
	)
	if err != nil {
		return nil, err
	}
	if convert, okconv := apirouter.GetParam[string](ctx, "_convert"); okconv {
		for _, a := range snap.Assets {
			a.ConvertTo(e, convert)
		}
	}
	return map[string]any{
		"network": snap.Network,
		"account": snap.Account,
		"assets":  snap.Assets,
	}, nil
}
