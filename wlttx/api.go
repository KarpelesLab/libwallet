package wlttx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
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

// Transaction list paging defaults.
const (
	txListDefaultLimit = 50
	txListMaxLimit     = 200
)

func apiListTransaction(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	// Build the where clause from the documented filter params plus
	// the new `before` cursor. Up to 0.3.16 the From/Network filters
	// were documented in api.md but never read on this path — only
	// Clear honoured them. Bring List into parity here.
	where := make(map[string]any)
	if from, ok := apirouter.GetParam[string](ctx, "From"); ok && from != "" {
		where["From"] = from
	}
	if net, ok := apirouter.GetParam[string](ctx, "Network"); ok && net != "" {
		where["Network"] = net
	}
	if before, ok := apirouter.GetParam[string](ctx, "before"); ok && before != "" {
		t, err := time.Parse(time.RFC3339Nano, before)
		if err != nil {
			return nil, fmt.Errorf("invalid 'before' timestamp (want RFC3339): %w", err)
		}
		where["Created"] = map[string]any{"$lt": t}
	}

	limit := txListDefaultLimit
	if l, ok := apirouter.GetParam[int](ctx, "limit"); ok && l > 0 {
		limit = l
		if limit > txListMaxLimit {
			limit = txListMaxLimit
		}
	}

	var whereArg any
	if len(where) > 0 {
		whereArg = where
	}

	res, err := psql.Fetch[Transaction](e, whereArg, psql.Sort(psql.S("Created", "DESC")), psql.Limit(limit))
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

	var whereArg any
	if len(where) > 0 {
		whereArg = where
	}

	_, err := psql.ForceDelete[Transaction](e, whereArg)
	return nil, err
}
