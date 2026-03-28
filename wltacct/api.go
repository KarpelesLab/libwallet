package wltacct

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"gorm.io/gorm"
)

func init() {
	pobj.RegisterActions[Account]("Account",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchAccount),
			List:   pobj.Static(apiListAccount),
			Create: pobj.Static(apiCreateAccount),
		},
	)
	pobj.RegisterStatic("Account:setCurrent", accountSetCurrent)
}

func CreateAccount(e wltintf.Env, wallet *wltwallet.Wallet, name, typ string, index int) (*Account, error) {
	if typ != "ethereum" && typ != "bitcoin" {
		return nil, fmt.Errorf("unsupported account type %s", typ)
	}

	if name == "" {
		name = fmt.Sprintf("Account %d", index+1)
	}

	account := &Account{
		Id:        xuid.New("acct"),
		Name:      name,
		Chaincode: wallet.Chaincode,
		Index:     index,
		Wallet:    wallet.Id,
		Type:      typ, // "ethereum"
		Created:   time.Now(),
	}

	err := account.init(wallet)
	if err != nil {
		return nil, err
	}

	err = account.save(e)
	if err == nil {
		account.setCurrent(e)
	}
	return account, err
}

func HasAccount(e wltintf.Env) bool {
	// Use CountWithError to properly handle database errors
	count, err := e.CountWithError(&Account{})
	if err != nil {
		// Log the error but return false as if no accounts exist
		log.Printf("Error counting accounts: %v", err)
		return false
	}
	return count > 0
}

func FirstAccount(e wltintf.Env) (a *Account, err error) {
	err = e.First(&a)

	if err == nil {
		err = a.check(e)
	}
	return
}

func CurrentAccount(e wltintf.Env) (*Account, error) {
	id, err := CurrentAccountId(e)
	if err == nil {
		if res, err := AccountById(e, id); err == nil {
			return res, nil
		}
	}

	// get first
	if acct, err := FirstAccount(e); err == nil {
		return acct, nil
	} else if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, gorm.ErrRecordNotFound) {
		// if not a not found error, return it
		return nil, err
	}
	// make one for each wallet
	ws, err2 := wltwallet.GetAllWallets(e, nil)
	if err2 != nil {
		return nil, err2
	}
	var firstAcct *Account
	for n, w := range ws {
		acct, err := CreateAccount(e, w, fmt.Sprintf("Account %d", n+1), "ethereum", 0)
		if err != nil {
			continue
		}
		if firstAcct == nil {
			firstAcct = acct
		}
	}
	if firstAcct != nil {
		return firstAcct, nil
	}
	return nil, err
}

func CurrentAccountId(e wltintf.Env) (*xuid.XUID, error) {
	id, err := e.GetCurrent("account")
	if err != nil {
		return nil, err
	}

	return xuid.ParsePrefix(id, "acct")
}

func FindAccount(e wltintf.Env, id string) (*Account, error) {
	if id, err := xuid.Parse(id); err == nil {
		acct, err := AccountById(e, id)
		if err == nil {
			return acct, nil
		}
	}

	var acct *Account
	e.FirstWhere(&acct, map[string]any{"Address": id})
	if acct != nil {
		return acct, nil
	}
	return nil, fs.ErrNotExist // res.Error
}

func AccountById(e wltintf.Env, id *xuid.XUID) (*Account, error) {
	if id.Prefix != "acct" {
		return nil, fmt.Errorf("invalid key for account: %s", id.Prefix)
	}

	res, err := wltintf.ByPrimaryKey[Account](e, id)
	if err != nil {
		return nil, err
	}

	err = res.check(e)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func apiFetchAccount(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	if in.Id == "@" {
		return CurrentAccount(e)
	}

	id, err := xuid.Parse(in.Id)
	if err != nil {
		return nil, err
	}

	return AccountById(e, id)
}

func apiListAccount(ctx *apirouter.Context) (any, error) {
	return wltintf.ListHelper[Account](ctx, "Created ASC", "Wallet")
}

func apiCreateAccount(ctx *apirouter.Context, in struct {
	Name   string
	Wallet string
	Type   string
	Index  int
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	wltid, err := xuid.Parse(in.Wallet)
	if err != nil {
		return nil, err
	}
	wallet, err := wltwallet.WalletById(e, wltid)
	if err != nil {
		return nil, err
	}

	return CreateAccount(e, wallet, in.Name, in.Type, in.Index)
}

func accountSetCurrent(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	acct := apirouter.GetObject[Account](ctx, "Account")
	if acct == nil {
		return nil, errors.New("account required")
	}

	err := acct.setCurrent(e)
	return acct, err
}
