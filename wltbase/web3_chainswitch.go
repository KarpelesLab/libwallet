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
	"encoding/json"
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

// hasChainSwitchCandidates reports whether we have at least one
// candidate network AND at least one candidate account for the
// requested family. Cheap (two psql lookups) — used to gate the
// chain_switch prompt at the top of Web3:request so we don't show
// a "switch network" sheet that the user can't actually fulfil.
// When this returns false the original method handler runs and
// surfaces its own error (e.g. "no account connected"), which is
// more informative than a generic 4901.
func hasChainSwitchCandidates(e *env, family string) bool {
	nets, _ := candidateNetworksForFamily(e, family)
	if len(nets) == 0 {
		return false
	}
	accts, _ := candidateAccountsForFamily(e, family)
	return len(accts) > 0
}

// ChainSwitchValue is the request payload for a chain_switch
// approval. Two shapes, picked by which field is populated:
//
//  1. Pre-specified target (wallet_switchEthereumChain case):
//     TargetNetwork is set. UI renders a single-option confirm
//     prompt. IsNewNetwork=true means the chain isn't in the
//     wallet's DB yet and approval implies Add+Switch.
//
//  2. Cross-family picker (action method on different family):
//     TargetNetwork nil, CandidateNetworks populated. UI renders a
//     picker so the user chooses from the compatible networks.
//
// CandidateAccounts is always populated (compatible with
// RequestedFamily) — the user always picks an account to bind to
// this dApp on the chosen chain.
type ChainSwitchValue struct {
	RequestedFamily   string              `json:"requestedFamily"`
	RequestedMethod   string              `json:"requestedMethod"`
	CurrentNetwork    *wltnet.Network     `json:"currentNetwork,omitempty"`
	TargetNetwork     *wltnet.Network     `json:"targetNetwork,omitempty"`
	IsNewNetwork      bool                `json:"isNewNetwork,omitempty"`
	CandidateNetworks []*wltnet.Network   `json:"candidateNetworks,omitempty"`
	CandidateAccounts []*wltacct.Account  `json:"candidateAccounts"`
}

// decodeChainSwitchValue unmarshals a request's Value (persisted as
// JSON via psql) into a typed ChainSwitchValue. Used by the
// approve handler to read what shape the original request had
// (target vs. picker) so it can validate + stash the selection.
func decodeChainSwitchValue(v any) (*ChainSwitchValue, error) {
	if v == nil {
		return nil, errors.New("nil value")
	}
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := &ChainSwitchValue{}
	if err := json.Unmarshal(buf, out); err != nil {
		return nil, err
	}
	return out, nil
}

// chainSwitchSelection is what comes back from the user's approval
// of a chain_switch request — which specific network + account they
// chose, plus whether the network needs to be saved before use.
type chainSwitchSelection struct {
	Network *wltnet.Network
	Account *wltacct.Account
	IsNew   bool
}

// requestChainSwitchForTarget emits a chain_switch approval for a
// specific target network the dApp asked for (the
// wallet_switchEthereumChain flow). Used for both EVM-to-EVM
// (target already in DB) and the add+switch case (target freshly
// built from static chain metadata).
//
// On approval the caller should apply the returned selection via
// applyChainSwitchSelection, which handles Save (if isNew) +
// SetCurrent + implicit connect.
func requestChainSwitchForTarget(e *env, host, method string, current, target *wltnet.Network, isNew bool) (*chainSwitchSelection, error) {
	accts, err := candidateAccountsForFamily(e, target.Type)
	if err != nil {
		return nil, err
	}
	if len(accts) == 0 {
		return nil, &apirouter.Error{Code: 4901, Message: "no " + target.Type + " account available in this wallet"}
	}
	req := &request{
		Type: "chain_switch",
		Host: host,
		Value: &ChainSwitchValue{
			RequestedFamily:   target.Type,
			RequestedMethod:   method,
			CurrentNetwork:    current,
			TargetNetwork:     target,
			IsNewNetwork:      isNew,
			CandidateAccounts: accts,
		},
	}
	if err := req.run(e); err != nil {
		return nil, err
	}
	return applySelectionFromResult(e, req.Result)
}

// requestChainSwitchPicker emits a chain_switch approval with a full
// network+account picker (cross-family mismatch case). Returns the
// user's selection; caller applies it via applyChainSwitchSelection.
//
// 4001 on user reject. 4901 when no candidate network or account
// exists for this family in the wallet.
func requestChainSwitchPicker(e *env, host, family, method string, current *wltnet.Network) (*chainSwitchSelection, error) {
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
		Value: &ChainSwitchValue{
			RequestedFamily:   family,
			RequestedMethod:   method,
			CurrentNetwork:    current,
			CandidateNetworks: nets,
			CandidateAccounts: accts,
		},
	}
	if err := req.run(e); err != nil {
		return nil, err
	}
	return applySelectionFromResult(e, req.Result)
}

// applySelectionFromResult parses the req.Result payload the
// approve handler wrote and resolves it to real Network / Account
// objects. Single helper so both target + picker paths share the
// same result-unpacking logic.
func applySelectionFromResult(e *env, result any) (*chainSwitchSelection, error) {
	resMap, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("chain_switch approval did not include selection")
	}
	netIdStr, _ := resMap["network"].(string)
	acctIdStr, _ := resMap["account"].(string)
	isNew, _ := resMap["isNew"].(bool)
	if netIdStr == "" || acctIdStr == "" {
		return nil, errors.New("chain_switch selection missing network or account")
	}
	netXuid, err := xuid.Parse(netIdStr)
	if err != nil {
		return nil, fmt.Errorf("invalid network id %q: %w", netIdStr, err)
	}

	var n *wltnet.Network
	if isNew {
		// For the add+switch flow the approve handler stashed the
		// full Network object (not yet in DB). Pull it from the
		// result map rather than round-tripping through NetworkById.
		rawNet, _ := resMap["networkObj"]
		if rawNet != nil {
			buf, mErr := json.Marshal(rawNet)
			if mErr == nil {
				n = &wltnet.Network{}
				if uErr := json.Unmarshal(buf, n); uErr != nil {
					n = nil
				}
			}
		}
		if n == nil {
			return nil, errors.New("chain_switch add+switch: target network payload missing")
		}
	} else {
		n, err = wltnet.NetworkById(e, netXuid)
		if err != nil {
			return nil, fmt.Errorf("network not found: %w", err)
		}
	}

	acct, err := wltacct.FindAccount(e, acctIdStr)
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}
	return &chainSwitchSelection{Network: n, Account: acct, IsNew: isNew}, nil
}

// applyChainSwitchSelection runs the post-approval side effects:
// Save (if the network is freshly proposed), SetCurrent, and
// implicit connect of (host, account). Callers (web3Req for
// cross-family, wallet_switchEthereumChain for the target path)
// share this so the behaviour stays consistent.
func applyChainSwitchSelection(e *env, host string, sel *chainSwitchSelection) error {
	if sel.IsNew {
		if err := sel.Network.Save(e); err != nil {
			return fmt.Errorf("save new network: %w", err)
		}
	}
	if err := sel.Network.SetCurrent(e); err != nil {
		return err
	}
	existing, _ := e.connectedAccounts(host)
	for _, c := range existing {
		if c.Account.String() == sel.Account.Id.String() {
			return nil
		}
	}
	conn := &connectedSite{
		Host:        host,
		Account:     sel.Account.Id,
		AccountInfo: sel.Account,
	}
	return conn.save(e)
}
