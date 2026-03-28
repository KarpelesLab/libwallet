package wltcontact

import (
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/ModChain/outscript"
)

type contact struct {
	Id      *xuid.XUID `gorm:"primaryKey"`
	Name    string
	Address string
	Type    string   // ethereum | bitcoin
	Flags   []string `gorm:"serializer:json"` // bitcoin | bitcoin-cash | litecoin | etc...
	Memo    string
	Created time.Time `gorm:"autoCreateTime"`
	Updated time.Time `gorm:"autoUpdateTime"`
}

func init() {
	pobj.RegisterActions[contact]("Contact",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchContact),
			List:   pobj.Static(apiListContact),
			Create: pobj.Static(apiCreateContact),
		},
	)
}

func InitEnv(e wltintf.Env) {
	e.AutoMigrate(&contact{})
}

func (c *contact) validate() error {
	switch c.Type {
	case "ethereum":
		// check if address is valid
		addr, err := outscript.ParseEvmAddress(c.Address)
		if err != nil {
			return fmt.Errorf("failed to parse address: %s", err)
		}
		c.Address, err = addr.Address() // re-output address to guarantee proper formatting
		if err != nil {
			return fmt.Errorf("failed to reformat address: %s", err)
		}
		c.Flags = addr.Flags

		return nil
	case "bitcoin":
		addr, err := outscript.ParseBitcoinAddress(c.Address)
		if err != nil {
			return fmt.Errorf("failed to parse address: %s", err)
		}
		c.Address, err = addr.Address() // will use the initial parsing address, so we should get back the same stuff
		if err != nil {
			return fmt.Errorf("failed to reformat address: %s", err)
		}
		c.Flags = addr.Flags
		return nil
	default:
		return fmt.Errorf("unsupported contact type %s", c.Type)
	}
}

func (c *contact) save(e wltintf.Env) error {
	return e.Save(c)
}

func ContactById(e wltintf.Env, id *xuid.XUID) (*contact, error) {
	if id.Prefix != "ct" {
		return nil, fmt.Errorf("invalid key for contact: %s", id.Prefix)
	}
	return wltintf.ByPrimaryKey[contact](e, id)
}

func (c *contact) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	return e.Delete(c)
}

func (c *contact) ApiUpdate(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	updated := false

	if v, ok := apirouter.GetParam[string](ctx, "Name"); ok {
		c.Name = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Memo"); ok {
		c.Memo = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Address"); ok {
		if v2, ok := apirouter.GetParam[string](ctx, "Type"); ok {
			c.Type = v2
		}
		c.Address = v
		if err := c.validate(); err != nil {
			return err
		}
		updated = true
	}

	if !updated {
		return nil
	}
	return c.save(e)
}

func apiListContact(ctx *apirouter.Context) (any, error) {
	return wltintf.ListHelper[contact](ctx, "Name ASC", "Name", "Address", "Type")
}

func apiFetchContact(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.Parse(in.Id)
	if err != nil {
		return nil, err
	}

	return ContactById(e, id)
}

func apiCreateContact(ctx *apirouter.Context, ct *contact) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	err := ct.validate()
	if err != nil {
		return nil, err
	}

	ct.Id, err = xuid.NewRandom("ct")
	if err != nil {
		return nil, err
	}

	err = e.Save(ct)
	if err != nil {
		return nil, err
	}

	return ct, nil
}
