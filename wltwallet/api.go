package wltwallet

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterActions[Wallet]("Wallet",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchWallet),
			List:   pobj.Static(apiListWallet),
			Create: pobj.Static(apiCreateWallet),
		},
	)
	pobj.RegisterStatic("Wallet:reshare", apiWalletReshare)
}

func WalletById(e wltintf.Env, id *xuid.XUID) (*Wallet, error) {
	if id.Prefix != "wlt" {
		return nil, fmt.Errorf("invalid key for wallet: %s", id.Prefix)
	}

	res, err := wltintf.ByPrimaryKey[Wallet](e, id)
	if err != nil {
		return nil, err
	}

	// load res.Keys
	err = e.Find(&res.Keys, map[string]any{"Wallet": res.Id.String(), "Gen": res.Gen})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func apiFetchWallet(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.Parse(in.Id)
	if err != nil {
		return nil, err
	}

	return WalletById(e, id)
}

func apiListWallet(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	return GetAllWallets(e, ctx)
}

func GetAllWallets(e wltintf.Env, ctx *apirouter.Context) ([]*Wallet, error) {
	var res []*Wallet
	err := e.ListHelper(ctx, &res, "Name ASC")
	if err != nil {
		return nil, err
	}

	for _, v := range res {
		// load keys
		err = e.Find(&v.Keys, map[string]any{"Wallet": v.Id, "Gen": v.Gen})
		if err != nil {
			return nil, err
		}
		if len(v.Keys) == 0 {
			return nil, fmt.Errorf("failed to load keys for wallet %s (gen %d)", v.Id, v.Gen)
		}
	}
	return res, nil
}

func HasWallet(e wltintf.Env) bool {
	// Use CountWithError to properly handle database errors
	count, err := e.CountWithError(&Wallet{})
	if err != nil {
		// Log the error but return false as if no wallets exist
		log.Printf("Error counting wallets: %v", err)
		return false
	}
	return count > 0
}

func FirstWallet(e wltintf.Env) (w *Wallet, err error) {
	err = e.First(&w)
	return
}

func apiCreateWallet(ctx *apirouter.Context, in struct {
	Name  string
	Curve string
	Keys  []*wltsign.KeyDescription
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	keyCnt := len(in.Keys)
	if keyCnt < 3 {
		return nil, fmt.Errorf("need at least 3 keys, got %d", keyCnt)
	}

	wallet := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     in.Name,
		Created:  time.Now(),
		Modified: time.Now(),
	}

	var err error
	if in.Curve == "ed25519" {
		err = wallet.initializeEdDSAWallet(ctx, in.Keys)
	} else {
		err = wallet.initializeWallet(ctx, in.Keys)
	}
	if err != nil {
		return nil, err
	}

	if err := wallet.save(e); err != nil {
		return nil, err
	}

	return wallet, nil
}

func apiWalletReshare(ctx *apirouter.Context, in struct {
	Old []*wltsign.KeyDescription
	New []*wltsign.KeyDescription
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	w := apirouter.GetObject[Wallet](ctx, "Wallet")
	if w == nil {
		return nil, errors.New("Wallet required")
	}

	var err error

	err = w.Reshare(ctx, in.Old, in.New)
	if err != nil {
		return nil, err
	}
	err = w.save(e)
	if err != nil {
		return nil, err
	}

	return w, nil
}

func newWallet(name string) *Wallet {
	res := &Wallet{
		Id:        xuid.New("wlt"),
		Name:      name,
		Threshold: 1,
		Created:   time.Now(),
		Modified:  time.Now(),
	}

	return res
}
