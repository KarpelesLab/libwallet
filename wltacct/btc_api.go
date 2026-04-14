package wltacct

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/xuid"
)

// accountXpub returns the BIP-32 extended public key (xpub) for this account.
func accountXpub(ctx *apirouter.Context) (any, error) {
	acct := apirouter.GetObject[Account](ctx, "Account")
	if acct == nil {
		return nil, errors.New("account required")
	}
	xp, err := acct.Xpub()
	if err != nil {
		return nil, err
	}
	return map[string]string{"xpub": xp}, nil
}

// accountNextAddress returns the next clean (unused) receive address for a
// Bitcoin-family account. Queries modchain_lookupTxoBIP32 to find lastI (the
// highest child index with observed activity) and returns the address at
// lastI+1.
//
// Parameters (optional):
//   - Network: network XUID to query on. Defaults to the current network.
//   - Change: if true, returns a change-chain address (m/1/i) instead of
//     receive-chain (m/0/i). Default false.
func accountNextAddress(ctx *apirouter.Context, in struct {
	Network string `json:"Network"`
	Change  bool   `json:"Change"`
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	acct := apirouter.GetObject[Account](ctx, "Account")
	if acct == nil {
		return nil, errors.New("account required")
	}
	net, err := resolveBtcNetwork(e, in.Network)
	if err != nil {
		return nil, err
	}

	xpub, err := acct.Xpub()
	if err != nil {
		return nil, err
	}

	path := "m/0"
	if in.Change {
		path = "m/1"
	}
	raw, err := net.DoRPC("modchain_lookupTxoBIP32", xpub, path, true)
	if err != nil {
		return nil, fmt.Errorf("modchain_lookupTxoBIP32: %w", err)
	}
	var resp struct {
		LastI int `json:"lastI"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse lookupTxoBIP32: %w", err)
	}

	nextIndex := resp.LastI + 1
	addr, err := acct.bitcoinAddress(net.ChainId, nextIndex, in.Change)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"address": addr,
		"path":    fmt.Sprintf("%s/%d", path, nextIndex),
		"index":   nextIndex,
		"chain":   ternary(in.Change, "change", "receive"),
	}, nil
}

// accountAllAddresses returns all HD addresses (receive + change) that have
// seen any activity, plus the next clean address on each chain.
func accountAllAddresses(ctx *apirouter.Context, in struct {
	Network string `json:"Network"`
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	acct := apirouter.GetObject[Account](ctx, "Account")
	if acct == nil {
		return nil, errors.New("account required")
	}
	net, err := resolveBtcNetwork(e, in.Network)
	if err != nil {
		return nil, err
	}

	receive, err := scanChain(net, acct, 0)
	if err != nil {
		return nil, err
	}
	change, err := scanChain(net, acct, 1)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"receive": receive,
		"change":  change,
	}, nil
}

// scanChain derives addresses from 0..lastI+1 for a given chain (0=receive,
// 1=change) and reports their derivation paths. Balance info is left to the
// caller if needed (use modchain_assets directly with the xpub for that).
func scanChain(net *wltnet.Network, acct *Account, chain int) ([]map[string]any, error) {
	xpub, err := acct.Xpub()
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("m/%d", chain)
	raw, err := net.DoRPC("modchain_lookupTxoBIP32", xpub, path, false)
	if err != nil {
		return nil, fmt.Errorf("modchain_lookupTxoBIP32 chain=%d: %w", chain, err)
	}
	var resp struct {
		LastI int `json:"lastI"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}

	out := make([]map[string]any, 0, resp.LastI+2)
	for i := 0; i <= resp.LastI+1; i++ {
		addr, err := acct.bitcoinAddress(net.ChainId, i, chain == 1)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"index":   i,
			"address": addr,
			"path":    fmt.Sprintf("%s/%d", path, i),
			"clean":   i > resp.LastI,
		})
	}
	return out, nil
}

// resolveBtcNetwork returns the Bitcoin-family network specified by the XUID
// (or the current network if empty). Errors if the network isn't a bitcoin type.
func resolveBtcNetwork(e wltintf.Env, networkId string) (*wltnet.Network, error) {
	var net *wltnet.Network
	if networkId == "" {
		var err error
		net, err = wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, err
		}
	} else {
		id, err := xuid.Parse(networkId)
		if err != nil {
			return nil, err
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

func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
