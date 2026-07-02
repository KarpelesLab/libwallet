package wltwallet

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

func init() {
	pobj.RegisterActions[Wallet]("Wallet",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchWallet),
			List:   pobj.Static(apiListWallet),
			Create: pobj.Static(apiCreateWallet),
		},
	)
	pobj.RegisterStatic("Wallet:multiCreate", apiMultiCreateWallet)
	pobj.RegisterStatic("Wallet:reshare", apiWalletReshare)
	pobj.RegisterStatic("Wallet:repairRemoteKey", apiWalletRepairRemoteKey)
	pobj.RegisterStatic("Wallet:importPrivateKey", apiImportPrivateKey)
	pobj.RegisterStatic("Wallet:importMnemonic", apiImportMnemonic)
	pobj.RegisterStatic("Wallet:promote", apiWalletPromote)
	pobj.RegisterStatic("Wallet:probeActivity", apiWalletProbeActivity)
	pobj.RegisterStatic("Wallet:promoteMnemonic", apiWalletPromoteMnemonic)
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
	keys, err := psql.Fetch[WalletKey](e, map[string]any{"Wallet": res.Id.String(), "Gen": res.Gen})
	if err != nil {
		return nil, err
	}
	res.Keys = keys
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
	res, err := psql.Fetch[Wallet](e, nil, psql.Sort(psql.S("Name", "ASC")))
	if err != nil {
		return nil, err
	}

	for _, v := range res {
		// load keys
		keys, err := psql.Fetch[WalletKey](e, map[string]any{"Wallet": v.Id, "Gen": v.Gen})
		if err != nil {
			return nil, err
		}
		v.Keys = keys
		if len(v.Keys) == 0 {
			return nil, fmt.Errorf("failed to load keys for wallet %s (gen %d)", v.Id, v.Gen)
		}
	}
	return res, nil
}

func HasWallet(e wltintf.Env) bool {
	count, err := psql.Count[Wallet](e, nil)
	if err != nil {
		log.Printf("Error counting wallets: %v", err)
		return false
	}
	return count > 0
}

func FirstWallet(e wltintf.Env) (*Wallet, error) {
	wallets, err := psql.Fetch[Wallet](e, nil, psql.Limit(1))
	if err != nil {
		return nil, err
	}
	if len(wallets) == 0 {
		return nil, fmt.Errorf("no wallets found")
	}
	return wallets[0], nil
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

	switch in.Curve {
	case "", "secp256k1", "ed25519":
	default:
		return nil, fmt.Errorf("unsupported curve %q (expected \"secp256k1\" or \"ed25519\")", in.Curve)
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

// apiWalletRepairRemoteKey re-uploads the wallet's locally-stored RemoteKey
// share blob to the WalletSign backend under a fresh, validated crws session.
//
// Why this exists: the RemoteKey share is stored server-side per crws record
// and overwritten in place by Crypto/WalletSign:setGeneratedKey. A reshare
// abandoned mid-upload (field case: a 90s http2 header timeout) can leave the
// server holding a share from the abandoned ceremony's polynomial while the
// local wallet keeps the old committee — after which any reshare requiring
// the RemoteKey's participation stalls, and if the StoreKey is also gone the
// wallet drops below T+1 recoverable shares. Because encrypt() keeps the
// exact uploaded bytes in WalletKey.Data (and Wallet:backup serializes them),
// a restored backup carries the consistent, fleet-encrypted share — this
// endpoint pushes those bytes back, restoring the record without any
// server-side rollback. The blob is encrypted to the WalletSign HSM keyring,
// so the client never sees the share plaintext.
//
// Key must be a freshly validated session ("crws-…:crwsv-…" from
// RemoteKey:reshare + RemoteKey:validate). After repair, run the recovery
// reshare with ANOTHER fresh session as usual.
func apiWalletRepairRemoteKey(ctx *apirouter.Context, in struct {
	Key string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	w := apirouter.GetObject[Wallet](ctx, "Wallet")
	if w == nil {
		return nil, errors.New("Wallet required")
	}
	if in.Key == "" {
		return nil, errors.New("Key (validated RemoteKey session) is required")
	}
	var wk *WalletKey
	for _, k := range w.Keys {
		if k.Type == "RemoteKey" {
			wk = k
			break
		}
	}
	if wk == nil {
		return nil, errors.New("wallet has no RemoteKey share")
	}
	if len(wk.Data) == 0 {
		return nil, errors.New("wallet's RemoteKey share has no local data blob — was this wallet restored from a backup that includes key data?")
	}
	if err := wk.pushRemoteShare(w, in.Key); err != nil {
		return nil, err
	}
	if err := w.save(e); err != nil {
		return nil, err
	}
	return w, nil
}

func apiMultiCreateWallet(ctx *apirouter.Context, in struct {
	Name string
	Keys []*wltsign.KeyDescription
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	keyCnt := len(in.Keys)
	if keyCnt < 3 {
		return nil, fmt.Errorf("need at least 3 keys, got %d", keyCnt)
	}

	now := time.Now()
	wSecp := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     in.Name,
		Created:  now,
		Modified: now,
	}
	wEd := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     in.Name,
		Created:  now,
		Modified: now,
	}

	var errSecp, errEd error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		errSecp = wSecp.initializeWallet(ctx, in.Keys)
	}()
	go func() {
		defer wg.Done()
		errEd = wEd.initializeEdDSAWallet(ctx, in.Keys)
	}()
	wg.Wait()

	if errSecp != nil {
		return nil, fmt.Errorf("secp256k1 wallet creation failed: %w", errSecp)
	}
	if errEd != nil {
		return nil, fmt.Errorf("ed25519 wallet creation failed: %w", errEd)
	}

	if err := wSecp.save(e); err != nil {
		return nil, fmt.Errorf("failed to save secp256k1 wallet: %w", err)
	}
	if err := wEd.save(e); err != nil {
		return nil, fmt.Errorf("failed to save ed25519 wallet: %w", err)
	}

	return map[string]*Wallet{
		"secp256k1": wSecp,
		"ed25519":   wEd,
	}, nil
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
