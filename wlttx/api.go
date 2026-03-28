package wlttx

import (
	"context"
	"errors"
	"fmt"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterActions[Transaction]("Transaction",
		&pobj.ObjectActions{
			Fetch: pobj.Static(apiFetchTransaction),
			List:  pobj.Static(apiListTransaction),
			Clear: pobj.Static(apiClearTransaction),
		},
	)
	pobj.RegisterStatic("Transaction:validate", transactionValidate)
	pobj.RegisterStatic("Transaction:signAndSend", transactionSignAndSend)
}

func TransactionById(e wltintf.Env, id *xuid.XUID) (*Transaction, error) {
	if id.Prefix != "tx" {
		return nil, fmt.Errorf("invalid key for transaction: %s", id.Prefix)
	}

	return wltintf.ByPrimaryKey[Transaction](e, id)
}

func transactionValidate(ctx context.Context, tx *Transaction) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	tx.Keys = nil

	return tx, tx.Validate(e)
}

func transactionSignAndSend(ctx context.Context, tx *Transaction) (any, error) {
	return tx, tx.SignAndSend(ctx, nil)
}

func apiFetchTransaction(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.Parse(in.Id)
	if err != nil {
		return nil, err
	}

	return TransactionById(e, id)
}

func apiListTransaction(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	var res []*Transaction

	err := e.ListHelper(ctx, &res, "Created DESC", "From", "Network")
	if err != nil {
		return nil, err
	}

	if convert, okconv := apirouter.GetParam[string](ctx, "_convert"); okconv {
		for _, a := range res {
			a.convertTo(e, convert)
		}
	}

	return res, nil
}

func apiClearTransaction(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	where := make(map[string]any)

	if from, ok := apirouter.GetParam[string](ctx, "From"); ok {
		where["From"] = from
	}
	if net, ok := apirouter.GetParam[string](ctx, "Network"); ok {
		where["Network"] = net
	}

	if len(where) == 0 {
		return nil, e.DeleteAll(&Transaction{})
	}

	return nil, e.DeleteWhere(&Transaction{}, where)
}
