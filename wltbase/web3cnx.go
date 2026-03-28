package wltbase

import (
	"errors"
	"log"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

func init() {
	pobj.RegisterActions[connectedSite]("Web3/Connection",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchWeb3Connection),
			List:   pobj.Static(apiListWeb3Connection),
			Create: pobj.Static(apiCreateWeb3Connection),
		},
	)
}

type connectedSite struct {
	psql.Name   `sql:"ConnectedSite"`
	Id          *xuid.XUID       `sql:",key=PRIMARY"`
	Host        string           `sql:",type=VARCHAR,size=255,key=UNIQUE:Host_Account"`
	Account     *xuid.XUID       `sql:",type=VARCHAR,size=255,key=UNIQUE:Host_Account"`
	Created     time.Time        `sql:",type=DATETIME"`
	Updated     time.Time        `sql:",type=DATETIME"`
	AccountInfo *wltacct.Account `sql:"-"`
}

func (e *env) connectedAccounts(key string) ([]*connectedSite, error) {
	conn, err := psql.Fetch[connectedSite](e.sqlCtx, map[string]any{"Host": key})
	if err != nil {
		return nil, err
	}
	if len(conn) <= 1 {
		// no point changing the order if only 1 account
		return conn, nil
	}

	// if "current account" is part of connected accounts, move it to first position
	id, err := e.GetCurrent("account")
	if err != nil {
		return conn, nil
	}
	for n, c := range conn {
		if c.Account.String() == id {
			// this is the current main account
			if n != 0 {
				// need to move c to 1st position
				return append(append([]*connectedSite{c}, conn[:n]...), conn[n+1:]...), nil
			}
		}
	}
	return conn, nil
}

func (c *connectedSite) save(e *env) error {
	if c.Id == nil {
		c.Id = xuid.Must(xuid.NewRandom("cnx"))
	}
	now := time.Now()
	if c.Created.IsZero() {
		c.Created = now
	}
	c.Updated = now
	return psql.Replace(e.sqlCtx, c)
}

func apiFetchWeb3Connection(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.ParsePrefix(in.Id, "cnx")
	if err != nil {
		return nil, err
	}

	c, err := byPrimaryKey[connectedSite](e, id)
	if err != nil {
		return nil, err
	}

	var accErr error
	c.AccountInfo, accErr = wltacct.AccountById(e, c.Account)
	if accErr != nil {
		log.Printf("failed to get account %s: %v", c.Account, accErr)
	}

	return c, nil
}

func apiListWeb3Connection(ctx *apirouter.Context) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	where := make(map[string]any)
	if host, ok := apirouter.GetParam[string](ctx, "Host"); ok {
		where["Host"] = host
	}

	var whereArg any
	if len(where) > 0 {
		whereArg = where
	}

	res, err := psql.Fetch[connectedSite](e.sqlCtx, whereArg, psql.Sort(psql.S("Created", "ASC")), psql.Limit(50))
	if err != nil {
		return nil, err
	}

	for _, c := range res {
		var err error
		c.AccountInfo, err = wltacct.AccountById(e, c.Account)
		if err != nil {
			log.Printf("failed to get account %s: %v", c.Account, err)
		}
	}
	return res, nil
}

func (c *connectedSite) ApiDelete(ctx *apirouter.Context) error {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return errors.New("failed to get env")
	}

	_, err := psql.ForceDelete[connectedSite](e.sqlCtx, map[string]any{"Id": c.Id})
	return err
}

func apiCreateWeb3Connection(ctx *apirouter.Context, ct *connectedSite) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	if ct.Host == "" {
		return nil, errors.New("host cannot be empty")
	}

	acct, err := wltacct.AccountById(e, ct.Account)
	if err != nil {
		return nil, err
	}
	ct.AccountInfo = acct

	return ct, ct.save(e)
}
