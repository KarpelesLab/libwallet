package wltbase

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/pobj"
)

//go:embed injection/provider.js
var providerJs string

const providerConfigPlaceholder = "__LIBWALLET_CONFIG__"

func init() {
	pobj.RegisterStatic("Web3:injectionScript", web3InjectionScript)
}

// web3InjectionScript builds a JS blob the host app can run inside a webview
// to expose libwallet as an EIP-6963 Ethereum provider, a window.solana
// provider (with a minimal Wallet Standard announce), and window.mpurse for
// Monacoin (https://github.com/tadajam/mpurse).
//
// The host is expected to wire up two directions:
//
//   - outbound: install a message channel named by `Bridge` whose
//     postMessage(json) gets routed to Web3:request (typical pattern: a
//     WebView JavaScript channel that calls Web3:request and then
//     webview.runJavaScript('__libwalletResolve(id, jsonResponse)')).
//   - inbound: when libwallet fires a js:* event (accountsChanged,
//     chainChanged, …) the host should execute
//     webview.runJavaScript('__libwalletEvent(name, data)') — the provider
//     re-dispatches it per standard (EIP-1193 emit, mpurse updateEmitter,
//     Solana connect/disconnect).
//
// The Host field is optional — if given, the returned script pre-populates
// the connected accounts so the provider doesn't report null on first paint.
func web3InjectionScript(ctx *apirouter.Context, in struct {
	Name   string `json:"Name"`
	Rdns   string `json:"Rdns"`
	Uuid   string `json:"Uuid"`
	Icon   string `json:"Icon"`   // data: URL or https:// URL
	Bridge string `json:"Bridge"` // window property name of the host message channel
	Host   string `json:"Host"`   // e.g. "https://app.uniswap.org" — optional
}) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if in.Name == "" {
		return nil, errors.New("Name is required")
	}
	if in.Rdns == "" {
		return nil, errors.New("Rdns is required (reverse DNS, e.g. com.example.wallet)")
	}
	if in.Uuid == "" {
		return nil, errors.New("Uuid is required (stable per-install random UUID)")
	}
	if in.Bridge == "" {
		return nil, errors.New("Bridge is required (name of the host JS message channel)")
	}

	cfg := map[string]any{
		"name":   in.Name,
		"rdns":   in.Rdns,
		"uuid":   in.Uuid,
		"icon":   in.Icon,
		"bridge": in.Bridge,
	}

	// Initial state — lets the provider answer eth_chainId / eth_accounts
	// synchronously on first paint without a host round-trip. Optional; if
	// anything fails we just omit it and the dApp will fetch on first call.
	if n, err := wltnet.CurrentNetwork(e); err == nil {
		if n.Type == "evm" {
			bigV := new(big.Int)
			if _, ok := bigV.SetString(n.ChainId, 10); ok {
				cfg["initialChainId"] = "0x" + bigV.Text(16)
				cfg["initialNetworkVersion"] = n.ChainId
			}
		}
	}
	if in.Host != "" {
		if u, err := url.Parse(in.Host); err == nil && u.Host != "" {
			key := (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
			if conn, err := e.connectedAccounts(key); err == nil {
				accs := make([]string, 0, len(conn))
				for _, c := range conn {
					if a, err := wltacct.FindAccount(e, c.Account.String()); err == nil {
						accs = append(accs, a.Address)
					}
				}
				cfg["initialAccounts"] = accs
			}
		}
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}

	script := strings.ReplaceAll(providerJs, providerConfigPlaceholder, string(cfgJSON))
	return map[string]any{"script": script}, nil
}
