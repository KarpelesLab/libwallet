package wltwallet

import (
	"errors"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterActions[WalletKey]("Wallet/Key",
		&pobj.ObjectActions{
			Fetch: pobj.Static(apiFetchWalletKey),
			List:  pobj.Static(apiListWalletKey),
		},
	)
	pobj.RegisterStatic("Wallet/Key:recrypt", walletKeyRecrypt)
}

func apiFetchWalletKey(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.ParsePrefix(in.Id, "wkey")
	if err != nil {
		return nil, err
	}

	return wltintf.ByPrimaryKey[WalletKey](e, id)
}

func apiListWalletKey(ctx *apirouter.Context) (any, error) {
	return wltintf.ListHelper[WalletKey](ctx, "")
}

func walletKeyRecrypt(ctx *apirouter.Context, in struct {
	Old *wltsign.KeyDescription
	New *wltsign.KeyDescription
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	wk := apirouter.GetObject[WalletKey](ctx, "Wallet/Key")
	if wk == nil {
		return nil, errors.New("Wallet/Key required")
	}

	var err error

	wk.sdata, err = wk.decrypt(in.Old, keyRecryptPurpose)
	if err != nil {
		return nil, err
	}

	err = wk.encrypt(in.New)
	if err != nil {
		return nil, err
	}
	err = wk.save(e)
	if err != nil {
		return nil, err
	}

	return wk, nil
}
