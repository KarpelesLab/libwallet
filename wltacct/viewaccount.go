package wltacct

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/secp256k1/ecckd"
	"github.com/KarpelesLab/xuid"
)

// IsViewOnly reports whether this account has no backing wallet and cannot
// produce signatures. View accounts are created via CreateViewAccount from
// a bare address or an xpub and are suitable for balance and NFT queries
// but not for sending transactions.
func (a *Account) IsViewOnly() bool {
	return a.Wallet == nil
}

// CreateViewAccount creates a read-only account from a bare address or an
// xpub. View accounts have no wallet behind them and cannot sign.
//
//   - If xpub is provided (secp256k1-family only), its pubkey + chaincode
//     are decoded so modchain-style HD scans work (gap-limit UTXO lookup
//     for BTC, next-address derivation, etc.).
//   - If only address is provided, the account can report balance for that
//     single address on compatible networks.
//
// Exactly one of address or xpub must be non-empty.
func CreateViewAccount(e wltintf.Env, name, typ, address, xpub string) (*Account, error) {
	if typ != "ethereum" && typ != "bitcoin" && typ != "solana" {
		return nil, fmt.Errorf("unsupported account type %s", typ)
	}
	if (address == "") == (xpub == "") {
		return nil, errors.New("exactly one of address or xpub is required")
	}
	if xpub != "" && typ != "bitcoin" {
		return nil, errors.New("xpub view accounts are only supported for bitcoin-family networks")
	}

	if name == "" {
		name = "View Account"
	}

	acct := &Account{
		Id:      xuid.New("acct"),
		Name:    name,
		Type:    typ,
		Created: time.Now(),
	}

	switch typ {
	case "solana":
		acct.Curve = "ed25519"
	default:
		acct.Curve = "secp256k1"
	}

	if xpub != "" {
		ext, err := ecckd.FromString(xpub)
		if err != nil {
			return nil, fmt.Errorf("parse xpub: %w", err)
		}
		if ext.IsPrivate() {
			return nil, errors.New("xpriv keys are not allowed here; provide an xpub")
		}
		acct.Pubkey = base64.RawURLEncoding.EncodeToString(ext.KeyData)
		acct.Chaincode = base64.RawURLEncoding.EncodeToString(ext.ChainCode)
		// Address derivation happens in UpdateAddressForNetwork; see check().
	} else {
		acct.Address = address
	}

	if err := acct.save(e); err != nil {
		return nil, err
	}

	// Populate Address / URI for the current network.
	if net, err := wltnet.CurrentNetwork(e); err == nil {
		if err := acct.UpdateAddressForNetwork(net); err == nil {
			acct.save(e)
		}
	}

	acct.setCurrent(e)
	return acct, nil
}

func init() {
	pobj.RegisterStatic("Account:createView", accountCreateView)
}

func accountCreateView(ctx *apirouter.Context, in struct {
	Name    string
	Type    string
	Address string
	Xpub    string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	return CreateViewAccount(e, in.Name, in.Type, in.Address, in.Xpub)
}

