package wlttx

// Account:listUTXOs — read-only enumeration of every spendable UTXO
// the active Bitcoin-family account holds. Powers an "advanced coin
// selection" UI: the frontend shows the user every output (across
// receive AND change chains, with their script type and source
// address) and the user picks which ones to spend by passing the
// chosen "<txid>:<vout>" entries back via Transaction.UTXOs.

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterStatic("Account:listUTXOs", accountListUTXOs)
}

// BitcoinUTXOEntry is one row of the Account:listUTXOs response.
type BitcoinUTXOEntry struct {
	// Txo is the on-chain reference, "<txid>:<vout>". Pass this
	// back via Transaction.UTXOs to spend it.
	Txo string `json:"txo"`
	// Path is the BIP32 derivation under the account xpub, e.g.
	// "m/0/3" (receive #3) or "m/1/0" (change #0).
	Path string `json:"path"`
	// Amount is the output value in the chain's smallest unit
	// (satoshis), as a decimal string for big-int safety.
	Amount string `json:"amount"`
	// Script is the locking script type ("p2wpkh", "p2pkh",
	// "p2sh:p2wpkh") — drives both the address shape and the
	// per-input vsize when this output is later spent.
	Script string `json:"script"`
	// Address is the formatted address the script locks to,
	// rendered for the chain's family ("ltc1...", "L...", …).
	// Useful for displaying "received at L…" in the picker.
	Address string `json:"address"`
	// Height is the block the output landed in, or 0 when still
	// unconfirmed.
	Height int64 `json:"height"`
}

// BitcoinUTXOListResponse is the full Account:listUTXOs payload.
type BitcoinUTXOListResponse struct {
	// ChainId echoes the resolved network's ChainId so callers
	// don't need to re-look-up.
	ChainId string `json:"chainId"`
	// UTXOs is the full set, sorted largest amount first to match
	// the default coin-selection order.
	UTXOs []BitcoinUTXOEntry `json:"utxos"`
}

func accountListUTXOs(ctx *apirouter.Context, in struct {
	Network string `json:"Network"`
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	acct := apirouter.GetObject[wltacct.Account](ctx, "Account")
	if acct == nil {
		return nil, errors.New("account required")
	}
	net, err := resolveBtcNetwork(e, in.Network)
	if err != nil {
		return nil, err
	}
	xpub, err := acct.Xpub()
	if err != nil {
		return nil, fmt.Errorf("xpub: %w", err)
	}
	utxos, err := fetchBitcoinUTXOs(net, xpub)
	if err != nil {
		return nil, err
	}

	// Sort largest first — matches the default selectUTXOs ordering
	// so the frontend's "auto" view and "manual picker" view show
	// the same priority order.
	sortUTXOsLargestFirst(utxos)

	tag := outscriptAddressTag(net.ChainId)
	out := make([]BitcoinUTXOEntry, 0, len(utxos))
	for _, u := range utxos {
		entry := BitcoinUTXOEntry{
			Txo:    u.Txo,
			Path:   u.Path,
			Amount: strconv.FormatUint(uint64(u.Amt), 10),
			Script: u.Script,
			Height: u.Height,
		}
		// Best-effort address derivation — failure leaves Address
		// empty rather than dropping the whole UTXO. The frontend
		// can still display + spend it via the txo ref.
		if addr, derr := deriveAddressForTxo(acct, u, tag); derr == nil {
			entry.Address = addr
		}
		out = append(out, entry)
	}

	return &BitcoinUTXOListResponse{
		ChainId: net.ChainId,
		UTXOs:   out,
	}, nil
}

// deriveAddressForTxo renders the on-chain address for a given UTXO
// — needs the path (so we know which child key to derive) and the
// script (so we know what shape to render). chainTag is the outscript
// flag for the target network (e.g. "litecoin", "bitcoincash").
func deriveAddressForTxo(acct *wltacct.Account, u bitcoinTxo, chainTag string) (string, error) {
	if u.Path == "" || u.Script == "" {
		return "", errors.New("missing path or script")
	}
	pub, err := acct.DerivePublic(u.Path)
	if err != nil {
		return "", fmt.Errorf("derive %s: %w", u.Path, err)
	}
	scr, err := outscript.New(pub).Out(u.Script)
	if err != nil {
		return "", fmt.Errorf("script %s: %w", u.Script, err)
	}
	return scr.Address(chainTag)
}

// outscriptAddressTag maps our hyphenated chainId to the upstream
// outscript flag — only differs for bitcoin-cash. Three lines, copied
// here rather than re-exported from wltacct to keep this file
// standalone.
func outscriptAddressTag(chainId string) string {
	if chainId == "bitcoin-cash" {
		return "bitcoincash"
	}
	return chainId
}

// resolveBtcNetwork mirrors wltacct/btc_api.go's helper. Same
// motivation as outscriptAddressTag — keep this file standalone so
// the endpoint registers cleanly without a back-import chain.
func resolveBtcNetwork(e wltintf.Env, networkId string) (*wltnet.Network, error) {
	var net *wltnet.Network
	var err error
	if networkId == "" {
		net, err = wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, err
		}
	} else {
		id, perr := xuid.Parse(networkId)
		if perr != nil {
			return nil, perr
		}
		net, err = wltnet.NetworkById(e, id)
		if err != nil {
			return nil, err
		}
	}
	if net.Type != "bitcoin" {
		return nil, fmt.Errorf("network %s is not a bitcoin-family chain (type=%s)", net.Id, net.Type)
	}
	return net, nil
}

// sortUTXOsLargestFirst is the same insertion sort selectUTXOs
// uses — small N, simple, and matches the default selection order.
func sortUTXOsLargestFirst(utxos []bitcoinTxo) {
	for i := 1; i < len(utxos); i++ {
		for j := i; j > 0 && utxos[j-1].Amt < utxos[j].Amt; j-- {
			utxos[j-1], utxos[j] = utxos[j], utxos[j-1]
		}
	}
}
