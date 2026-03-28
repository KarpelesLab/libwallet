package wltbase

import (
	"errors"
	"io/fs"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltnft"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/typutil"
)

func init() {
	pobj.RegisterActions[wltnft.Nft]("Nft",
		&pobj.ObjectActions{
			Fetch: typutil.Func(apiFetchNft),
			List:  typutil.Func(apiListNft),
		},
	)
}

func apiFetchNft(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	return nil, fs.ErrNotExist
}

func apiListNft(ctx *apirouter.Context) (any, error) {
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

	nfts, err := n.Nfts(e, acct)
	if err != nil {
		return nil, err
	}

	res := map[string]any{
		"network": n,
		"account": acct,
		"nfts":    nfts,
	}

	return res, nil
}
