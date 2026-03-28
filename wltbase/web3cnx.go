package wltbase

import (
	"errors"
	"log"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
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
	Id          *xuid.XUID       `gorm:"primaryKey"`
	Host        string           `gorm:"index:Host_Account,unique"`
	Account     *xuid.XUID       `gorm:"index:Host_Account,unique"`
	Created     time.Time        `gorm:"autoCreateTime"`
	Updated     time.Time        `gorm:"autoUpdateTime"`
	AccountInfo *wltacct.Account `gorm:"-:all"`
}

func (e *env) connectedAccounts(key string) ([]*connectedSite, error) {
	var conn []*connectedSite
	res := e.sql.Where(map[string]any{"Host": key}).Find(&conn)
	if res.Error != nil {
		return nil, res.Error
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
	return e.Save(c)
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

	var res []*connectedSite

	tx := e.sql
	tx = tx.Scopes(ctx.Paginate(50))
	tx = tx.Order("Created ASC")
	if host, ok := apirouter.GetParam[string](ctx, "Host"); ok {
		tx = tx.Where(map[string]any{"Host": host})
	}

	tx = tx.Find(&res)
	if tx.Error != nil {
		return nil, tx.Error
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

	tx := e.sql.Delete(c)
	return tx.Error
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
