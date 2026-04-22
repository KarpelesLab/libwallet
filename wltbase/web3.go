package wltbase

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/ethrpc/chains"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/typutil"
	"github.com/portablesql/psql"
	"golang.org/x/crypto/sha3"
)

func init() {
	pobj.RegisterStatic("Web3:request", web3Req)

}

// Implement JSON-RPC methods from ethereum

type eip2255caveat struct {
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

type eip2255perm struct {
	Id               string           `json:"id"`
	ParentCapability string           `json:"parentCapability"` // EIP-2255: required ("eth_accounts")
	Invoker          string           `json:"invoker"`
	Caveats          []*eip2255caveat `json:"caveats"`
}

func web3Req(ctx context.Context, in struct {
	URL   string `json:"url"`
	Query struct {
		Method string `json:"method"`
		Params []any  `json:"params"`
	} `json:"query"`
}) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	// parse host from url
	u, err := url.Parse(in.URL)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("url: host is missing")
	}
	// key is only scheme and host (Host includes the port in url if any was specified)
	key := (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()

	conn, _ := e.connectedAccounts(key)

	// fetch current network
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, err
	}

	// Cross-chain detection: if the dApp called an action method
	// (sign / send / connect) on a chain family different from the
	// active one, ask the user to switch + pick an account in one
	// approval. After approval the rest of the handler proceeds
	// against the chosen network.
	if family := methodChainFamily(in.Query.Method); family != "" && isActionMethod(in.Query.Method) && family != n.Type {
		sel, err := requestChainSwitch(e, key, family, in.Query.Method, n)
		if err != nil {
			return nil, err
		}
		if err := sel.Network.SetCurrent(e); err != nil {
			return nil, err
		}
		n = sel.Network
		// requestChainSwitch already added a ConnectedSite for
		// (host, sel.Account) if missing — refresh the local
		// view so the existing handlers see it.
		conn, _ = e.connectedAccounts(key)
	}

	// See: https://docs.metamask.io/wallet/reference/wallet_addethereumchain/

	switch in.Query.Method {
	case "eth_chainId":
		bigV := new(big.Int)
		bigV.SetString(n.ChainId, 10)
		return "0x" + bigV.Text(16), nil
	case "net_version":
		return n.ChainId, nil
	case "web3_clientVersion":
		return "libwallet/" + dateTag + "-" + gitTag, nil
	case "web3_sha3":
		if len(in.Query.Params) != 1 {
			return nil, errors.New("web3_sha3 expects exactly 1 param")
		}
		v := web3HexValue(in.Query.Params[0])
		if v == nil {
			return nil, errors.New("invalid parameter")
		}
		h := sha3.NewLegacyKeccak256()
		h.Write(v)
		res := h.Sum(nil)
		return "0x" + hex.EncodeToString(res), nil
	case "eth_requestAccounts":
		req := &request{
			Type: "connect",
			Host: key,
		}
		err := req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		conn, _ = e.connectedAccounts(key)

		if len(conn) == 0 {
			return nil, nil
		}
		fallthrough
	case "eth_accounts":
		// Only return EVM-compatible (secp256k1) account
		// addresses. A wallet that holds a Solana account also
		// connected to this dApp shouldn't surface its base58
		// pubkey here, and an account that's been re-derived
		// onto an EVM network where it has no address would
		// show as "N/A" — both filtered out so the dApp sees
		// only valid 0x addresses.
		return collectEVMAccountAddresses(e, conn), nil
	case "wallet_requestPermissions":
		// params: [{ eth_accounts: {} }],
		if len(in.Query.Params) != 1 {
			return nil, errors.New("wallet_requestPermissions requires one param")
		}
		// this is crappy, but we need to check if params[0] is indeed a map[string]any{"eth_accounts":map[string]any{}}
		pmap, ok := in.Query.Params[0].(map[string]any)
		if !ok {
			return nil, errors.New("wallet_requestPermissions requires param[0] to be an object")
		}
		var perms []string
		for k, _ := range pmap {
			switch k {
			case "eth_accounts":
				perms = append(perms, k)
			default:
				return nil, fmt.Errorf("unsupported permission %s", k)
			}
		}
		if len(perms) > 0 {
			// can only be eth_accounts
			req := &request{
				Type: "connect",
				Host: key,
			}
			err := req.run(e)
			if err != nil {
				return nil, err
			}
			// approved
			conn, _ = e.connectedAccounts(key)

			if len(conn) == 0 {
				return nil, nil
			}
		}
		fallthrough
	case "wallet_getPermissions":
		return buildEthAccountsPermission(e, key, conn), nil
	case "wallet_revokePermissions":
		// EIP-2255: params = [{ <permName>: {} }]. The only
		// permission libwallet currently grants is eth_accounts;
		// revoking it disconnects the dApp by removing every
		// ConnectedSite row for this host (same semantics as
		// solana_disconnect on the Solana side). Unknown
		// permissions are silently ignored for forward-compat,
		// matching MetaMask. Return `null`, which is what the
		// EIP says wallets should return on success.
		//
		// Up through 0.3.20 this method was unhandled — it fell
		// through to the chain-RPC relay which returned a non-
		// JSON error and surfaced as "invalid character 'm'
		// looking for beginning of value" on etherscan.io.
		if len(in.Query.Params) != 1 {
			return nil, errors.New("wallet_revokePermissions requires one param")
		}
		pmap, ok := in.Query.Params[0].(map[string]any)
		if !ok {
			return nil, errors.New("wallet_revokePermissions: param[0] must be an object")
		}
		for k := range pmap {
			if k == "eth_accounts" {
				for _, c := range conn {
					psql.ForceDelete[connectedSite](e.sqlCtx, map[string]any{"Id": c.Id})
				}
				// Refresh the slice so any later case in this
				// switch sees the new state. (Currently no
				// fall-through, but keeps the invariant.)
				conn = nil
				break
			}
		}
		return nil, nil
	case "personal_sign":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("personal_sign requires at least one parameter")
		}
		// params: [0xhex_msg, 0xoptional_sign_addr]
		if len(conn) == 0 {
			return nil, errors.New("no addr available")
		}
		addr := conn[0]
		if len(in.Query.Params) >= 2 {
			signAddr, ok := in.Query.Params[1].(string)
			if !ok {
				return nil, errors.New("invalid address parameter")
			}
			signAddr = strings.ToLower(signAddr)
			// addr in params[1], format is 0x...
			addr = nil
			for _, c := range conn {
				a, err := wltacct.FindAccount(e, c.Account.String())
				if err == nil {
					if strings.ToLower(a.Address) == signAddr {
						addr = c
						break
					}
				}
			}
			if addr == nil {
				return nil, errors.New("requested address not connected")
			}
		}
		val, ok := in.Query.Params[0].(string)
		if !ok {
			return nil, errors.New("invalid string for signature")
		}
		if !strings.HasPrefix(val, "0x") {
			return nil, errors.New("personal_sign: value must start with 0x")
		}
		valBin, err := hex.DecodeString(val[2:])
		if err != nil {
			return nil, fmt.Errorf("personal_sign: invalid value: %w", err)
		}
		a, err := wltacct.FindAccount(e, addr.Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}

		req := &request{
			Type:    "personal_sign",
			Host:    key,
			Account: &a.Address,
			Value:   "0x" + hex.EncodeToString(valBin),
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		return req.Result, nil
	case "eth_signTypedData_v4", "eth_signTypedData_v3", "eth_signTypedData":
		if len(in.Query.Params) < 2 {
			return nil, errors.New("eth_signTypedData_v4 requires [address, typedData]")
		}
		if len(conn) == 0 {
			return nil, errors.New("no addr available")
		}
		signAddr, ok := in.Query.Params[0].(string)
		if !ok {
			return nil, errors.New("invalid address parameter")
		}
		signAddr = strings.ToLower(signAddr)
		var addr *connectedSite
		for _, c := range conn {
			a, err := wltacct.FindAccount(e, c.Account.String())
			if err == nil {
				if strings.ToLower(a.Address) == signAddr {
					addr = c
					break
				}
			}
		}
		if addr == nil {
			return nil, errors.New("requested address not connected")
		}
		typedDataStr, ok := in.Query.Params[1].(string)
		if !ok {
			// might be passed as object, marshal it back
			raw, err := json.Marshal(in.Query.Params[1])
			if err != nil {
				return nil, errors.New("invalid typedData parameter")
			}
			typedDataStr = string(raw)
		}
		a, err := wltacct.FindAccount(e, addr.Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}
		req := &request{
			Type:    "sign_typed_data",
			Host:    key,
			Account: &a.Address,
			Value:   typedDataStr,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		return req.Result, nil
	case "wallet_watchAsset":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("wallet_watchAsset requires 1 parameter")
		}
		req := &request{
			Type:  "watch_asset",
			Host:  key,
			Value: in.Query.Params[0],
		}
		err := req.run(e)
		if err != nil {
			return nil, err
		}
		return true, nil
	case "eth_sendTransaction":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("eth_sendTransaction requires a transaction to sign")
		}
		tx, err := typutil.As[*wlttx.Transaction](in.Query.Params[0])
		if err != nil {
			return nil, err
		}
		tx.Type = "evm"
		err = tx.Validate(e)
		if err != nil {
			return nil, err
		}
		req := &request{
			Type:        "sign",
			Host:        key,
			Transaction: tx,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		return req.Transaction.Hash, nil
	case "wallet_addEthereumChain":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("wallet_addEthereumChain requires 1 parameter")
		}
		obj, err := typutil.As[*wltnet.AddEthereumChainParameter](in.Query.Params[0])
		if err != nil {
			return nil, err
		}
		err = obj.Validate()
		if err != nil {
			return nil, err
		}
		net := obj.AsNetwork()
		_, err = wltnet.NetworkById(e, net.Id)
		if err == nil {
			// already have this chain
			return nil, nil
		}

		req := &request{
			Type:  "add_network",
			Host:  key,
			Value: net,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		err = net.Save(e)
		if err != nil {
			return nil, err
		}
		return nil, nil
	case "wallet_switchEthereumChain":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("wallet_switchEthereumChain requires 1 parameter")
		}
		// EIP-3326 compliant form: [{ chainId: "0x…" }]. Some
		// non-compliant dApps pass the bare hex string instead —
		// accept both. Pre-0.3.20 only handled the bare-string
		// form, which produced a "failed to convert
		// map[string]interface {} to string" 500 on etherscan.io
		// and any other spec-compliant caller.
		var s string
		switch p := in.Query.Params[0].(type) {
		case string:
			s = p
		case map[string]any:
			if v, ok := p["chainId"].(string); ok {
				s = v
			}
		}
		if s == "" {
			return nil, errors.New("wallet_switchEthereumChain: expected { chainId: \"0x…\" } or a bare hex chainId string")
		}
		// The chain ID as a 0x-prefixed hexadecimal string, per the eth_chainId method.
		bigV, ok := new(big.Int).SetString(s, 0)
		if !ok {
			return nil, fmt.Errorf("failed to parse network param %s", s)
		}
		id := wltnet.NetworkIdForTypeAndChainId("evm", bigV.Text(10))
		net, err := wltnet.NetworkById(e, id)
		if err != nil {
			// Chain isn't in the wallet yet. If we know it from
			// the static chain list (chainid.network data via
			// ethrpc/chains), offer to add+switch in one
			// approval. Unknown-to-us chains keep returning 4902
			// so dApps fall back to wallet_addEthereumChain with
			// explicit parameters.
			net = buildNetworkFromChainInfo(bigV)
			if net == nil {
				return nil, &apirouter.Error{Code: 4902, Message: "Unrecognized chain ID. Try adding the chain using wallet_addEthereumChain first."}
			}
			req := &request{
				// New subtype: UI can render "dApp wants to add
				// <Chain> and switch to it" in a single prompt
				// instead of the back-to-back add+switch the
				// spec nominally implies. Hosts that haven't
				// updated their UI get the familiar add_network
				// copy via the existing handler (request.go
				// already groups them).
				Type:  "add_and_switch_network",
				Host:  key,
				Value: net,
			}
			if err := req.run(e); err != nil {
				return nil, err
			}
			if err := net.Save(e); err != nil {
				return nil, err
			}
			if err := net.SetCurrent(e); err != nil {
				return nil, err
			}
			return nil, nil
		}

		req := &request{
			Type:  "change_network",
			Host:  key,
			Value: net,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		err = net.SetCurrent(e)
		if err != nil {
			return nil, err
		}
		return nil, nil
	// Solana Wallet Standard methods
	case "solana_connect", "solana_requestAccounts":
		req := &request{
			Type: "connect",
			Host: key,
		}
		err := req.run(e)
		if err != nil {
			return nil, err
		}
		conn, _ = e.connectedAccounts(key)
		res := make([]string, 0, len(conn))
		for _, c := range conn {
			a, err := wltacct.FindAccount(e, c.Account.String())
			if err == nil {
				res = append(res, a.Address)
			}
		}
		return map[string]any{"publicKey": res}, nil
	case "solana_accounts":
		res := make([]string, 0, len(conn))
		for _, c := range conn {
			a, err := wltacct.FindAccount(e, c.Account.String())
			if err == nil {
				res = append(res, a.Address)
			}
		}
		return res, nil
	case "solana_disconnect":
		// remove all connections for this host
		for _, c := range conn {
			psql.ForceDelete[connectedSite](e.sqlCtx, map[string]any{"Id": c.Id})
		}
		return nil, nil
	case "solana_signMessage":
		// params: { message: base64-encoded message, pubkey: base58 public key }
		if len(in.Query.Params) < 1 {
			return nil, errors.New("solana_signMessage requires 1 parameter")
		}
		pmap, ok := in.Query.Params[0].(map[string]any)
		if !ok {
			return nil, errors.New("solana_signMessage param must be an object")
		}
		msgB64, _ := pmap["message"].(string)
		if msgB64 == "" {
			return nil, errors.New("solana_signMessage: message is required")
		}
		pubkey, _ := pmap["pubkey"].(string)
		if len(conn) == 0 {
			return nil, errors.New("no account connected")
		}
		var addr *connectedSite
		if pubkey != "" {
			for _, c := range conn {
				a, err := wltacct.FindAccount(e, c.Account.String())
				if err == nil && a.Address == pubkey {
					addr = c
					break
				}
			}
			if addr == nil {
				return nil, errors.New("requested pubkey not connected")
			}
		} else {
			addr = conn[0]
		}
		a, err := wltacct.FindAccount(e, addr.Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}
		req := &request{
			Type:    "solana_sign_message",
			Host:    key,
			Account: &a.Address,
			Value:   msgB64,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		return req.Result, nil
	case "solana_signTransaction":
		// params: { transaction: base64-encoded serialized transaction }
		if len(in.Query.Params) < 1 {
			return nil, errors.New("solana_signTransaction requires 1 parameter")
		}
		pmap, ok := in.Query.Params[0].(map[string]any)
		if !ok {
			return nil, errors.New("solana_signTransaction param must be an object")
		}
		txB64, _ := pmap["transaction"].(string)
		if txB64 == "" {
			return nil, errors.New("solana_signTransaction: transaction is required")
		}
		if len(conn) == 0 {
			return nil, errors.New("no account connected")
		}
		a, err := wltacct.FindAccount(e, conn[0].Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}
		req := &request{
			Type:    "solana_sign_transaction",
			Host:    key,
			Account: &a.Address,
			Value:   txB64,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		return req.Result, nil
	case "solana_signAndSendTransaction":
		// params: { transaction: base64-encoded serialized transaction }
		if len(in.Query.Params) < 1 {
			return nil, errors.New("solana_signAndSendTransaction requires 1 parameter")
		}
		pmap, ok := in.Query.Params[0].(map[string]any)
		if !ok {
			return nil, errors.New("solana_signAndSendTransaction param must be an object")
		}
		txB64, _ := pmap["transaction"].(string)
		if txB64 == "" {
			return nil, errors.New("solana_signAndSendTransaction: transaction is required")
		}
		if len(conn) == 0 {
			return nil, errors.New("no account connected")
		}
		a, err := wltacct.FindAccount(e, conn[0].Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}
		req := &request{
			Type:    "solana_sign_send_transaction",
			Host:    key,
			Account: &a.Address,
			Value:   txB64,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		return req.Result, nil
	case "wallet_registerOnboarding":
		return false, nil

	// ── Mpurse (Monacoin) — github.com/tadajam/mpurse ────────────────────
	case "mpurse_getAddress":
		// First call triggers a connect prompt, subsequent calls return
		// the connected address without prompting.
		if len(conn) == 0 {
			req := &request{Type: "connect", Host: key}
			if err := req.run(e); err != nil {
				return nil, err
			}
			conn, _ = e.connectedAccounts(key)
		}
		if len(conn) == 0 {
			return nil, errors.New("no account connected")
		}
		a, err := wltacct.FindAccount(e, conn[0].Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}
		return a.Address, nil
	case "mpurse_signMessage":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("mpurse_signMessage requires 1 parameter")
		}
		msg, ok := in.Query.Params[0].(string)
		if !ok {
			return nil, errors.New("mpurse_signMessage param must be a string")
		}
		if len(conn) == 0 {
			return nil, errors.New("no account connected; call mpurse_getAddress first")
		}
		a, err := wltacct.FindAccount(e, conn[0].Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}
		// Use the account ID (not address) as the back-reference: bitcoin-
		// family accounts re-format their Address per current network, so
		// matching on address across a network switch would miss.
		acctId := a.Id.String()
		req := &request{
			Type:    "mpurse_sign_message",
			Host:    key,
			Account: &acctId,
			Value:   msg,
		}
		if err := req.run(e); err != nil {
			return nil, err
		}
		return req.Result, nil
	case "mpurse_signRawTransaction":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("mpurse_signRawTransaction requires 1 parameter")
		}
		txHex, ok := in.Query.Params[0].(string)
		if !ok {
			return nil, errors.New("mpurse_signRawTransaction param must be a hex string")
		}
		if len(conn) == 0 {
			return nil, errors.New("no account connected; call mpurse_getAddress first")
		}
		a, err := wltacct.FindAccount(e, conn[0].Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}
		acctId := a.Id.String()
		req := &request{
			Type:    "mpurse_sign_transaction",
			Host:    key,
			Account: &acctId,
			Value:   txHex,
		}
		if err := req.run(e); err != nil {
			return nil, err
		}
		return req.Result, nil
	case "mpurse_sendRawTransaction":
		// Pass-through — this is just a broadcast of a pre-signed tx, no
		// wallet authority involved. The signed hex came from
		// mpurse_signRawTransaction (or another wallet) already.
		if len(in.Query.Params) < 1 {
			return nil, errors.New("mpurse_sendRawTransaction requires 1 parameter")
		}
		txHex, ok := in.Query.Params[0].(string)
		if !ok {
			return nil, errors.New("mpurse_sendRawTransaction param must be a hex string")
		}
		raw, err := n.DoRPC("sendrawtransaction", txHex)
		if err != nil {
			return nil, fmt.Errorf("sendrawtransaction: %w", err)
		}
		var txid string
		if err := json.Unmarshal(raw, &txid); err != nil {
			return nil, fmt.Errorf("parse sendrawtransaction response: %w", err)
		}
		wltintf.NotifyTxBroadcast(e)
		return txid, nil
	case "mpurse_sendAsset":
		// mpurse_sendAsset builds + signs + broadcasts a Counterparty
		// asset transfer. Counterparty tx construction depends on the
		// external Counterparty server API, which is out of scope for
		// this wallet. dApps should build the tx via counterparty and
		// then call mpurse_signRawTransaction + mpurse_sendRawTransaction.
		return nil, errors.New("mpurse_sendAsset is not implemented; build via counterparty + signRawTransaction")

	default:
		// relay to current network
		return n.DoRPC(in.Query.Method, in.Query.Params...)
	}
}

func web3HexValue(in any) []byte {
	switch v := in.(type) {
	case string:
		// should start with 0x
		v = strings.TrimSpace(v)
		var ok bool
		v, ok = strings.CutPrefix(v, "0x")
		if !ok {
			return nil
		}
		r, err := hex.DecodeString(v)
		if err != nil {
			return nil
		}
		return r
	default:
		return nil
	}
}

// buildNetworkFromChainInfo returns a *Network populated from the
// static chainid.network metadata when the given chain id is known
// there, or nil when it isn't. Used by wallet_switchEthereumChain
// to offer a single "add + switch" approval for well-known chains
// the wallet hasn't seen yet, instead of bouncing back with the
// EIP-3326 4902 error.
func buildNetworkFromChainInfo(chainId *big.Int) *wltnet.Network {
	if !chainId.IsUint64() {
		return nil
	}
	info := chains.Get(chainId.Uint64())
	if info == nil || info.NativeCurrency == nil {
		return nil
	}
	return &wltnet.Network{
		Id:               wltnet.NetworkIdForTypeAndChainId("evm", chainId.Text(10)),
		Type:             "evm",
		ChainId:          chainId.Text(10),
		Name:             info.Name,
		RPC:              "auto",
		CurrencySymbol:   info.NativeCurrency.Symbol,
		CurrencyDecimals: info.NativeCurrency.Decimals,
	}
}

// collectEVMAccountAddresses returns the 0x-prefixed addresses of
// every connected account whose key curve is secp256k1 (i.e. usable
// on EVM). Filters out:
//   - non-EVM accounts (ed25519 — Solana — leaks here when a Solana
//     wallet is connected to an EVM dApp via chain_switch)
//   - accounts whose Address field is "N/A" (set by
//     UpdateAddressForNetwork when the account has no derivation
//     for the active network type)
//   - accounts whose Address doesn't look like 0x… (defensive last
//     filter — anything that survived the curve check should already
//     be 0x-prefixed but checking costs nothing)
//
// Always returns a non-nil slice so the JSON wire shape is `[]` and
// not `null` when nothing matches; matches what dApps expect from
// eth_accounts on a fresh connection.
func collectEVMAccountAddresses(e *env, conn []*connectedSite) []string {
	out := make([]string, 0, len(conn))
	for _, c := range conn {
		a, err := wltacct.FindAccount(e, c.Account.String())
		if err != nil {
			continue
		}
		if a.Curve != "" && a.Curve != "secp256k1" {
			continue
		}
		if a.Address == "" || a.Address == "N/A" {
			continue
		}
		if !strings.HasPrefix(a.Address, "0x") && !strings.HasPrefix(a.Address, "0X") {
			continue
		}
		out = append(out, a.Address)
	}
	return out
}

// buildEthAccountsPermission assembles the EIP-2255 wire shape
// for wallet_getPermissions / wallet_requestPermissions: a single
// permission entry whose caveat carries every authorised EVM
// address — NOT one entry per account, which is what 0.3.21 and
// earlier emitted and which broke dApps that read
// `perm.parentCapability` and the array-shaped caveat value.
//
// Returns an empty slice (not nil) when no EVM accounts are
// connected so the JSON wire shape stays `[]`.
func buildEthAccountsPermission(e *env, key string, conn []*connectedSite) []*eip2255perm {
	addrs := collectEVMAccountAddresses(e, conn)
	if len(addrs) == 0 {
		return []*eip2255perm{}
	}
	// Stable id derived from the host so the dApp can recognise
	// the same permission across calls.
	return []*eip2255perm{{
		Id:               "perm:" + key,
		ParentCapability: "eth_accounts",
		Invoker:          key,
		Caveats: []*eip2255caveat{{
			Type:  "restrictReturnedAccounts",
			Value: addrs,
		}},
	}}
}
