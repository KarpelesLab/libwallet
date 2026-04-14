package wlttoken

import (
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

type token struct {
	TableName psql.Name  `sql:"Token"`
	Id        *xuid.XUID `sql:",key=PRIMARY"`
	Name      string     `sql:",type=VARCHAR,size=255"`
	Symbol    string     `sql:",type=VARCHAR,size=255"`
	Address   string     `sql:",type=VARCHAR,size=255"`
	Decimals  int        `sql:",type=INT"`
	Type      string     `sql:",type=VARCHAR,size=255"` // erc20, nft, spl-token, spl-token-2022
	Network   *xuid.XUID `sql:",type=VARCHAR,size=255"`
	Logo      string     `sql:",type=TEXT"`
	Memo      string     `sql:",type=TEXT"`
	Created   time.Time  `sql:",type=DATETIME"`
	Updated   time.Time  `sql:",type=DATETIME"`
}

func init() {
	pobj.RegisterActions[token]("Token",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchToken),
			List:   pobj.Static(apiListToken),
			Create: pobj.Static(apiCreateToken),
		},
	)
}

func (t *token) validate(e wltintf.Env) error {
	if t.Network == nil {
		return errors.New("Network is required")
	}
	if t.Address == "" {
		return errors.New("Address is required")
	}

	net, err := wltnet.NetworkById(e, t.Network)
	if err != nil {
		return fmt.Errorf("invalid network: %w", err)
	}

	switch net.Type {
	case "evm":
		addr, err := outscript.ParseEvmAddress(t.Address)
		if err != nil {
			return fmt.Errorf("invalid EVM address: %w", err)
		}
		t.Address, err = addr.Address()
		if err != nil {
			return fmt.Errorf("failed to normalize EVM address: %w", err)
		}
		if t.Type == "" {
			t.Type = "erc20"
		}
	case "solana":
		decoded, err := base58.Bitcoin.Decode(t.Address)
		if err != nil {
			return fmt.Errorf("invalid Solana address: %w", err)
		}
		if len(decoded) != 32 {
			return errors.New("invalid Solana address: must be 32 bytes")
		}
		t.Address = base58.Bitcoin.Encode(decoded)
		if t.Type == "" {
			t.Type = "spl-token"
		}
	default:
		return fmt.Errorf("tokens are not supported on %s networks", net.Type)
	}

	if t.Decimals < 0 {
		return errors.New("Decimals must be >= 0")
	}

	return nil
}

func (t *token) save(e wltintf.Env) error {
	now := time.Now()
	if t.Created.IsZero() {
		t.Created = now
	}
	t.Updated = now
	return psql.Replace(e, t)
}

func TokenById(e wltintf.Env, id *xuid.XUID) (*token, error) {
	if id.Prefix != "tok" {
		return nil, fmt.Errorf("invalid key for token: %s", id.Prefix)
	}
	return wltintf.ByPrimaryKey[token](e, id)
}

// Exported accessors for external callers (e.g. wlttx for ERC-20 transfer encoding).

func (t *token) GetAddress() string   { return t.Address }
func (t *token) GetDecimals() int     { return t.Decimals }
func (t *token) GetType() string      { return t.Type }
func (t *token) GetNetwork() *xuid.XUID { return t.Network }

func (t *token) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	_, err := psql.ForceDelete[token](e, map[string]any{"Id": t.Id})
	return err
}

func (t *token) ApiUpdate(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	updated := false

	if v, ok := apirouter.GetParam[string](ctx, "Name"); ok {
		t.Name = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Symbol"); ok {
		t.Symbol = v
		updated = true
	}
	if v, ok := apirouter.GetParam[int](ctx, "Decimals"); ok {
		if v < 0 {
			return errors.New("Decimals must be >= 0")
		}
		t.Decimals = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Logo"); ok {
		t.Logo = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Memo"); ok {
		t.Memo = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Type"); ok {
		t.Type = v
		updated = true
	}

	if !updated {
		return nil
	}
	return t.save(e)
}

func apiListToken(ctx *apirouter.Context) (any, error) {
	return wltintf.ListHelper[token](ctx, "Name ASC", "Name", "Symbol", "Address", "Type")
}

func apiFetchToken(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.Parse(in.Id)
	if err != nil {
		return nil, err
	}

	return TokenById(e, id)
}

func apiCreateToken(ctx *apirouter.Context, t *token) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	err := t.validate(e)
	if err != nil {
		return nil, err
	}

	t.Id, err = xuid.NewRandom("tok")
	if err != nil {
		return nil, err
	}

	err = t.save(e)
	if err != nil {
		return nil, err
	}

	return t, nil
}
