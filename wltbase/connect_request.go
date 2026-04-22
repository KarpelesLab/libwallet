package wltbase

// Rich Value payload for connect, add_network, and watch_asset
// approval requests. Same pattern as TransactionSignValue /
// MessageSignValue: hosts should never have to round-trip a
// second API call to render the approval sheet with good copy.

import (
	"encoding/hex"
	"strings"

	"github.com/KarpelesLab/ethrpc/chains"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/portablesql/psql"
)

// ConnectRequestValue — rich context for a connect / account-permission
// approval. Lets the UI render:
//
//	"<host> wants to connect to your <chainFamily> wallet"
//	[ ] Account A       (already connected)
//	[ ] Account B
//	[ ] Account C
//	[ Approve ]  [ Reject ]
//
// — without a separate accounts.list call.
type ConnectRequestValue struct {
	// The RPC method that asked for the connection. Lets the UI
	// distinguish "eth_requestAccounts" (connect any EVM account)
	// from "solana_connect" (connect an ed25519 account) from
	// "mpurse_getAddress" (connect a Bitcoin-family account) from
	// "wallet_requestPermissions" (EIP-2255 permission grant).
	Method string `json:"method"`

	// Chain family the method implies: "evm" / "solana" / "bitcoin".
	// Empty when the connect isn't chain-scoped (generic flows).
	Family string `json:"family,omitempty"`

	// AvailableAccounts: every account whose key curve is
	// compatible with Family. UI pre-populates the picker with
	// these. Empty when Family is empty or no accounts match.
	AvailableAccounts []*wltacct.Account `json:"availableAccounts,omitempty"`

	// AlreadyConnected: account IDs already connected to this
	// host. Lets the UI pre-check them in the picker or render
	// "Reconnect" instead of "Connect".
	AlreadyConnected []string `json:"alreadyConnected,omitempty"`

	// RequestedPermissions: the EIP-2255 permission names the
	// dApp asked for (e.g. ["eth_accounts"]). Empty for non-EIP-2255
	// connects.
	RequestedPermissions []string `json:"requestedPermissions,omitempty"`
}

// buildConnectValue assembles the rich payload for a connect-style
// approval. family may be empty when the caller doesn't know (the
// generic solana_signIn flow etc.); in that case AvailableAccounts
// is left nil and the UI falls back to accounts.list on demand.
func buildConnectValue(e *env, host, method, family string, requestedPerms []string) *ConnectRequestValue {
	val := &ConnectRequestValue{
		Method:               method,
		Family:               family,
		RequestedPermissions: requestedPerms,
	}
	if family != "" {
		var curve string
		switch family {
		case "evm", "bitcoin":
			curve = "secp256k1"
		case "solana":
			curve = "ed25519"
		}
		if curve != "" {
			accts, _ := psql.Fetch[wltacct.Account](e.sqlCtx,
				map[string]any{"Curve": curve},
				psql.Sort(psql.S("Created", "ASC")))
			val.AvailableAccounts = accts
		}
	}
	if conn, err := e.connectedAccounts(host); err == nil {
		for _, c := range conn {
			if c.Account != nil {
				val.AlreadyConnected = append(val.AlreadyConnected, c.Account.String())
			}
		}
	}
	return val
}

// AddNetworkRequestValue — add_network approval context.
type AddNetworkRequestValue struct {
	// Network: the proposed Network record (same shape as any
	// other Network — chainId, name, rpc, currency, testnet).
	Network *wltnet.Network `json:"network"`

	// IsKnown: true when the chain appears in libwallet's static
	// chain metadata (chainid.network). False = totally novel chain,
	// UI should surface a warning copy.
	IsKnown bool `json:"isKnown,omitempty"`

	// AlreadyExists: true when the wallet already has this chain
	// registered. Approval would be a no-op; UI should say so.
	AlreadyExists bool `json:"alreadyExists,omitempty"`

	// KnownName: the name the static registry has for this chain
	// ID — lets the UI flag "dApp proposed 'My Mainnet' but this
	// chain ID is known as 'Ethereum'" which is a classic phishing
	// vector. Empty when IsKnown is false.
	KnownName string `json:"knownName,omitempty"`
}

// buildAddNetworkValue wraps a proposed Network with flags the UI
// needs to label it safely.
func buildAddNetworkValue(e *env, net *wltnet.Network) *AddNetworkRequestValue {
	val := &AddNetworkRequestValue{Network: net}
	if net == nil {
		return val
	}
	// AlreadyExists — look up by deterministic ID.
	if net.Id != nil {
		if _, err := wltnet.NetworkById(e, net.Id); err == nil {
			val.AlreadyExists = true
		}
	}
	// IsKnown + KnownName — consult the static registry. The
	// registry keys by uint64 chain id; try to parse ours.
	var chainIdU uint64
	for _, c := range net.ChainId {
		if c < '0' || c > '9' {
			chainIdU = 0
			break
		}
		chainIdU = chainIdU*10 + uint64(c-'0')
	}
	if chainIdU > 0 {
		if info := chains.Get(chainIdU); info != nil {
			val.IsKnown = true
			val.KnownName = info.Name
		}
	}
	return val
}

// WatchAssetRequestValue — typed EIP-747 payload. dApps send this
// as the bare params[0] object but we parse it into a known shape
// so the UI doesn't have to navigate a raw map.
type WatchAssetRequestValue struct {
	// Type as the dApp sent it: "ERC20", "ERC721", "ERC1155".
	// Default "ERC20" per EIP-747.
	Type string `json:"type"`

	// Address: token contract address. 0x-prefixed for EVM.
	Address string `json:"address,omitempty"`

	// Symbol / Decimals / Image: display metadata.
	Symbol   string `json:"symbol,omitempty"`
	Decimals int    `json:"decimals,omitempty"`
	Image    string `json:"image,omitempty"`

	// TokenId: only for ERC-721 / ERC-1155. Empty for fungibles.
	TokenId string `json:"tokenId,omitempty"`

	// Raw: the original params object — kept for forward-compat
	// with fields EIP-747 adds later. UIs rarely read this.
	Raw map[string]any `json:"raw,omitempty"`

	// IsAlreadyTracked: true when libwallet's Token table already
	// has this (network, address). UI can short-circuit the
	// approval flow.
	IsAlreadyTracked bool `json:"isAlreadyTracked,omitempty"`

	// AddressLooksInvalid: true when Address doesn't parse as a
	// valid EVM address (length + hex) — phishing heuristic.
	AddressLooksInvalid bool `json:"addressLooksInvalid,omitempty"`
}

// buildWatchAssetValue parses the EIP-747 params object into the
// typed struct and adds wallet-side flags.
func buildWatchAssetValue(raw any) *WatchAssetRequestValue {
	val := &WatchAssetRequestValue{Type: "ERC20"}
	m, ok := raw.(map[string]any)
	if !ok {
		return val
	}
	val.Raw = m
	if t, ok := m["type"].(string); ok && t != "" {
		val.Type = t
	}
	opts, _ := m["options"].(map[string]any)
	if opts == nil {
		opts = m // some dApps flatten — be tolerant
	}
	if s, ok := opts["address"].(string); ok {
		val.Address = s
	}
	if s, ok := opts["symbol"].(string); ok {
		val.Symbol = s
	}
	if n, ok := opts["decimals"].(float64); ok {
		val.Decimals = int(n)
	}
	if s, ok := opts["image"].(string); ok {
		val.Image = s
	}
	if s, ok := opts["tokenId"].(string); ok {
		val.TokenId = s
	}
	val.AddressLooksInvalid = !looksLikeEVMAddress(val.Address)
	return val
}

func looksLikeEVMAddress(addr string) bool {
	if !strings.HasPrefix(addr, "0x") && !strings.HasPrefix(addr, "0X") {
		return false
	}
	body := addr[2:]
	if len(body) != 40 {
		return false
	}
	if _, err := hex.DecodeString(body); err != nil {
		return false
	}
	return true
}
