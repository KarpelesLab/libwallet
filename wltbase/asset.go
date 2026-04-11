package wltbase

import (
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

func apiListAsset(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	n := apirouter.GetObject[wltnet.Network](ctx, "Network")
	if n == nil {
		// if no network passed, take current net
		var err error
		n, err = wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, err
		}
	}
	acct := apirouter.GetObject[wltacct.Account](ctx, "Account")
	if acct == nil {
		var err error
		acct, err = wltacct.CurrentAccount(e)
		if err != nil {
			return nil, err
		}
	}

	// Account fetch formats the address for whatever was CurrentNetwork at
	// load time; re-format it for the network the caller actually asked for.
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	var assets []*wltasset.Asset

	// Skip the native asset entirely when the account has no valid address on
	// this network (e.g. an ed25519 wallet on EVM): there is nothing to query.
	if acct.GetAddress() != "N/A" {
		nat, err := n.NativeAsset(e, acct)
		if err != nil {
			return nil, err
		}
		assets = append(assets, nat)
	}

	// Fetch SPL tokens for Solana networks
	if n.Type == "solana" && acct.GetAddress() != "N/A" {
		tokens, err := n.SolanaTokenBalances(e, acct)
		if err == nil {
			assets = append(assets, tokens...)
		}
	}

	if convert, okconv := apirouter.GetParam[string](ctx, "_convert"); okconv {
		for _, a := range assets {
			a.ConvertTo(e, convert)
		}
	}

	res := map[string]any{
		"network": n,
		"account": acct,
		"assets":  assets,
	}

	return res, nil
}
