package wltbase

// Cross-chain detection for Web3:request.
//
// dApps in a WebView (or via WalletConnect) can call methods on
// any of the three providers libwallet injects (window.ethereum,
// window.solana, window.mpurse) regardless of which network the
// wallet is currently set to. When a sign / send / connect call
// hits a chain family different from the active network, prompt
// the user to switch — and let them pick which specific network
// + which account in the same approval.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// methodChainFamily maps a Web3 RPC method name to the chain family
// it requires. Returns "" for methods that don't pin to a family
// (eth_chainId is technically EVM but it's a query — we treat it as
// "always answerable from the current network", classified via
// isActionMethod below).
func methodChainFamily(method string) string {
	switch {
	case strings.HasPrefix(method, "eth_"),
		strings.HasPrefix(method, "wallet_"),
		strings.HasPrefix(method, "personal_"),
		strings.HasPrefix(method, "net_"),
		strings.HasPrefix(method, "web3_"):
		return "evm"
	case strings.HasPrefix(method, "solana_"):
		return "solana"
	case strings.HasPrefix(method, "mpurse_"):
		return "bitcoin"
	}
	return ""
}

// actionMethods are methods that require the wallet to be on the
// matching chain family (signing, sending, connecting). Read-only
// methods like eth_chainId / eth_getBalance / net_version are
// answered from whatever the current state is and don't trigger
// a cross-chain switch prompt.
var actionMethods = map[string]bool{
	// EVM
	"eth_requestAccounts":           true,
	"personal_sign":                 true,
	"eth_sign":                      true,
	"eth_signTypedData":             true,
	"eth_signTypedData_v3":          true,
	"eth_signTypedData_v4":          true,
	"eth_sendTransaction":           true,
	"wallet_watchAsset":             true,
	"wallet_requestPermissions":     true,
	// wallet_switchEthereumChain / wallet_addEthereumChain are
	// intentionally chain-changing themselves; don't double-prompt.
	// wallet_revokePermissions / wallet_getPermissions are
	// connection-management, not chain-bound.

	// Solana
	"solana_connect":                true,
	"solana_requestAccounts":        true,
	"solana_signMessage":            true,
	"solana_signTransaction":        true,
	"solana_signAndSendTransaction": true,

	// Bitcoin family (mpurse)
	"mpurse_getAddress":         true,
	"mpurse_signMessage":        true,
	"mpurse_signRawTransaction": true,
	"mpurse_sendRawTransaction": true,
	"mpurse_sendAsset":          true,
}

func isActionMethod(method string) bool {
	return actionMethods[method]
}

// candidateNetworksForFamily lists every Network the user has of the
// requested family. Surface in the chain_switch approval so the user
// picks the specific chain they want (e.g. Ethereum vs. Polygon vs.
// Arbitrum for the EVM family).
func candidateNetworksForFamily(e *env, family string) ([]*wltnet.Network, error) {
	return psql.Fetch[wltnet.Network](e.sqlCtx,
		map[string]any{"Type": family},
		psql.Sort(psql.S("Priority", "DESC"), psql.S("Name", "ASC")))
}

// candidateAccountsForFamily lists every Account whose key curve is
// usable on the requested family. EVM and Bitcoin both use
// secp256k1; Solana uses ed25519.
func candidateAccountsForFamily(e *env, family string) ([]*wltacct.Account, error) {
	var curve string
	switch family {
	case "evm", "bitcoin":
		curve = "secp256k1"
	case "solana":
		curve = "ed25519"
	default:
		return nil, fmt.Errorf("unknown chain family %q", family)
	}
	return psql.Fetch[wltacct.Account](e.sqlCtx,
		map[string]any{"Curve": curve},
		psql.Sort(psql.S("Created", "ASC")))
}

// chainSwitchSelection is what comes back from the user's approval
// of a chain_switch request — which specific network + account they
// chose to use for this dApp interaction.
type chainSwitchSelection struct {
	Network *wltnet.Network
	Account *wltacct.Account
}

// requestChainSwitch emits a chain_switch approval request and
// blocks until the user picks (network, account) or rejects. On
// approval, also adds a ConnectedSite row so the dApp is treated
// as connected to the chosen account afterwards (matches the
// implicit consent the user just granted).
//
// Returns an EIP-1193-style 4001 user-rejected error if the user
// declines, or 4901 (chain unavailable) when no candidate network
// or account exists for this family in the user's wallet.
func requestChainSwitch(e *env, host, family, method string, current *wltnet.Network) (*chainSwitchSelection, error) {
	nets, err := candidateNetworksForFamily(e, family)
	if err != nil {
		return nil, err
	}
	if len(nets) == 0 {
		return nil, &apirouter.Error{Code: 4901, Message: "no " + family + " network configured in this wallet"}
	}
	accts, err := candidateAccountsForFamily(e, family)
	if err != nil {
		return nil, err
	}
	if len(accts) == 0 {
		return nil, &apirouter.Error{Code: 4901, Message: "no " + family + " account available in this wallet"}
	}

	req := &request{
		Type: "chain_switch",
		Host: host,
		Value: map[string]any{
			"requestedFamily":   family,
			"requestedMethod":   method,
			"currentNetwork":    current,
			"candidateNetworks": nets,
			"candidateAccounts": accts,
		},
	}
	if err := req.run(e); err != nil {
		return nil, err
	}

	// req.Result is the {network, account} the user selected
	// (set by requestDoApprove for chain_switch type).
	resMap, ok := req.Result.(map[string]any)
	if !ok {
		return nil, errors.New("chain_switch approval did not include selection")
	}
	netIdStr, _ := resMap["network"].(string)
	acctIdStr, _ := resMap["account"].(string)
	if netIdStr == "" || acctIdStr == "" {
		return nil, errors.New("chain_switch selection missing network or account")
	}
	netXuid, err := xuid.Parse(netIdStr)
	if err != nil {
		return nil, fmt.Errorf("invalid network id %q: %w", netIdStr, err)
	}
	n, err := wltnet.NetworkById(e, netXuid)
	if err != nil {
		return nil, fmt.Errorf("network not found: %w", err)
	}
	acct, err := wltacct.FindAccount(e, acctIdStr)
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}

	// Implicit connect — the user just consented to use this
	// account for this dApp. Save a ConnectedSite if one doesn't
	// already exist for (host, account) so subsequent calls to
	// eth_accounts / solana_accounts return it.
	existing, _ := e.connectedAccounts(host)
	already := false
	for _, c := range existing {
		if c.Account.String() == acct.Id.String() {
			already = true
			break
		}
	}
	if !already {
		conn := &connectedSite{
			Host:        host,
			Account:     acct.Id,
			AccountInfo: acct,
		}
		if err := conn.save(e); err != nil {
			return nil, fmt.Errorf("save connection: %w", err)
		}
	}

	return &chainSwitchSelection{Network: n, Account: acct}, nil
}
