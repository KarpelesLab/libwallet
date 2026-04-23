// Wallet:probeActivity — takes a mnemonic-backed wallet, derives
// the canonical addresses for every supported chain (+ standard
// BIP variants where applicable), probes each RPC for on-chain
// activity, and returns the candidate list to the caller.
//
// Read-only. No Account rows created, no state changed. Callers
// use the returned candidates to decide:
//   - which Accounts to create on the mnemonic wallet itself
//     (for keep-as-mnemonic usage), or
//   - which chains to migrate to MPC via Wallet:promote.

package wltwallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
	"github.com/tyler-smith/go-bip39"
)

// probeCandidate describes one (chain, BIP variant) combination the
// probe will try. The address is computed from the curve-appropriate
// pubkey of derivePrivkeyFromSeed(seed, curve, Path); the probeFn
// then hits the chain's RPC to detect activity.
type probeCandidate struct {
	Network        string // human-readable chain tag: "bitcoin" | "litecoin" | "monacoin" | "bitcoin-cash" | "dogecoin" | "ethereum" | "solana"
	Variant        string // short label for UI: "P2PKH" | "P2WPKH (BIP84)" | "standard" | "phantom" | "sollet"
	Curve          string // "secp256k1" | "ed25519"
	DerivationPath string // BIP32 path, e.g. "m/84'/0'/0'/0/0" (empty string means curve-specific default)
	outputScript   string // outscript.New(pub).Out(...) — "p2wpkh" / "p2pkh" / "eth" (ignored for solana)
	addressChain   string // outscript .Address(...) chain tag
	networkType    string // wltnet.Network.Type for the probe call
	networkChainId string // wltnet.Network.ChainId for the probe call
}

// ProbeResult is one row in the Wallet:probeActivity response.
type ProbeResult struct {
	Network        string `json:"network"`                  // "bitcoin" | "ethereum" | ...
	Variant        string `json:"variant"`                  // "P2WPKH (BIP84)" etc.
	Curve          string `json:"curve"`                    // "secp256k1" | "ed25519"
	DerivationPath string `json:"derivationPath"`           // path that produced the address
	Address        string `json:"address"`                  // derived address
	Pubkey         string `json:"pubkey"`                   // base64url-encoded (compressed for secp, raw for ed25519)
	HasActivity    bool   `json:"hasActivity"`              // true if balance > 0 or any tx history
	Balance        string `json:"balance,omitempty"`        // raw balance units (wei, satoshi, lamports). Empty on probe error.
	Error          string `json:"error,omitempty"`          // per-candidate probe error (stringified)
}

// defaultProbeCandidates returns the baseline chain list the probe
// endpoint enumerates when the caller doesn't pass an explicit
// Networks filter. Order matters only for display; each is probed
// concurrently.
func defaultProbeCandidates() []probeCandidate {
	return []probeCandidate{
		// Bitcoin family. BIP84 native segwit is the modern default
		// where the chain supports it; BCH + DOGE are P2PKH-only.
		// BIP44 legacy address is also surfaced for BTC since many
		// older wallets still use it.
		{
			Network: "bitcoin", Variant: "P2WPKH (BIP84)",
			Curve: "secp256k1", DerivationPath: "m/84'/0'/0'/0/0",
			outputScript: "p2wpkh", addressChain: "bitcoin",
			networkType: "bitcoin", networkChainId: "bitcoin",
		},
		{
			Network: "bitcoin", Variant: "P2PKH (BIP44)",
			Curve: "secp256k1", DerivationPath: "m/44'/0'/0'/0/0",
			outputScript: "p2pkh", addressChain: "bitcoin",
			networkType: "bitcoin", networkChainId: "bitcoin",
		},
		{
			Network: "litecoin", Variant: "P2WPKH (BIP84)",
			Curve: "secp256k1", DerivationPath: "m/84'/2'/0'/0/0",
			outputScript: "p2wpkh", addressChain: "litecoin",
			networkType: "bitcoin", networkChainId: "litecoin",
		},
		{
			Network: "monacoin", Variant: "P2WPKH (BIP84)",
			Curve: "secp256k1", DerivationPath: "m/84'/22'/0'/0/0",
			outputScript: "p2wpkh", addressChain: "monacoin",
			networkType: "bitcoin", networkChainId: "monacoin",
		},
		{
			Network: "monacoin", Variant: "P2PKH (BIP44)",
			Curve: "secp256k1", DerivationPath: "m/44'/22'/0'/0/0",
			outputScript: "p2pkh", addressChain: "monacoin",
			networkType: "bitcoin", networkChainId: "monacoin",
		},
		{
			Network: "bitcoin-cash", Variant: "P2PKH (BIP44)",
			Curve: "secp256k1", DerivationPath: "m/44'/145'/0'/0/0",
			outputScript: "p2pkh", addressChain: "bitcoincash",
			networkType: "bitcoin", networkChainId: "bitcoin-cash",
		},
		{
			Network: "dogecoin", Variant: "P2PKH (BIP44)",
			Curve: "secp256k1", DerivationPath: "m/44'/3'/0'/0/0",
			outputScript: "p2pkh", addressChain: "dogecoin",
			networkType: "bitcoin", networkChainId: "dogecoin",
		},

		// EVM — BIP44 coin_type 60. Same derivation covers every
		// EVM chain (Ethereum, Polygon, Arbitrum, Base, Optimism,
		// BSC, etc.); we probe mainnet Ethereum as the canonical
		// reference. If the user has activity only on an L2,
		// nothing in this probe surfaces it — a follow-up would
		// probe a configured list of EVM chains.
		{
			Network: "ethereum", Variant: "standard",
			Curve: "secp256k1", DerivationPath: "m/44'/60'/0'/0/0",
			outputScript: "eth", addressChain: "",
			networkType: "evm", networkChainId: "1",
		},

		// Solana — both "correct" conventions. Auto-detect picks
		// whichever one has activity; if neither, UI shows both
		// and the user picks.
		{
			Network: "solana", Variant: "sollet (seed[:32])",
			Curve: "ed25519", DerivationPath: "",
			networkType: "solana", networkChainId: "mainnet",
		},
		{
			Network: "solana", Variant: "phantom (m/44'/501'/0'/0')",
			Curve: "ed25519", DerivationPath: "m/44'/501'/0'/0'",
			networkType: "solana", networkChainId: "mainnet",
		},
	}
}

// apiWalletProbeActivity implements Wallet/{id}:probeActivity.
//
//	Keys []*wltsign.KeyDescription  // length 1, decrypts the mnemonic
//	Networks []string               // optional filter — only probe these network tags
//	                                //   ("bitcoin", "ethereum", "solana", …). Empty = all.
//	Timeout  int                    // optional, seconds; default 10
func apiWalletProbeActivity(ctx *apirouter.Context, in struct {
	Keys     []*wltsign.KeyDescription
	Networks []string
	Timeout  int
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	w := apirouter.GetObject[Wallet](ctx, "Wallet")
	if w == nil {
		return nil, errors.New("Wallet required")
	}
	if len(w.Keys) != 1 || w.Keys[0].Schema != "mnemonic" {
		return nil, errors.New("probeActivity requires a mnemonic-backed wallet")
	}
	if len(in.Keys) != 1 {
		return nil, fmt.Errorf("probeActivity requires exactly 1 KeyDescription, got %d", len(in.Keys))
	}

	share, err := w.Keys[0].decryptMnemonic(in.Keys[0])
	if err != nil {
		return nil, fmt.Errorf("decrypt mnemonic: %w", err)
	}

	mnemonicStr, err := reconstructMnemonic(share)
	if err != nil {
		return nil, err
	}
	seed := bip39.NewSeed(mnemonicStr, share.Passphrase)
	defer zero(seed)

	// Filter candidates by the requested network list (empty = all).
	candidates := defaultProbeCandidates()
	if len(in.Networks) > 0 {
		wanted := map[string]struct{}{}
		for _, n := range in.Networks {
			wanted[strings.ToLower(n)] = struct{}{}
		}
		filtered := candidates[:0]
		for _, c := range candidates {
			if _, ok := wanted[strings.ToLower(c.Network)]; ok {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}

	timeout := time.Duration(in.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := make([]ProbeResult, len(candidates))
	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		go func(i int, c probeCandidate) {
			defer wg.Done()
			results[i] = probeOne(probeCtx, seed, c)
		}(i, c)
	}
	wg.Wait()
	return results, nil
}

// probeOne derives a candidate address from the seed and hits its
// chain's RPC for activity. Returns a ProbeResult; any error is
// recorded on Result.Error so the caller gets partial data instead
// of a whole-request failure.
func probeOne(ctx context.Context, seed []byte, c probeCandidate) ProbeResult {
	out := ProbeResult{
		Network:        c.Network,
		Variant:        c.Variant,
		Curve:          c.Curve,
		DerivationPath: c.DerivationPath,
	}

	priv, err := derivePrivkeyFromSeed(seed, c.Curve, c.DerivationPath)
	if err != nil {
		out.Error = fmt.Sprintf("derive: %s", err)
		return out
	}
	defer zero(priv)

	pub, err := derivePub(c.Curve, priv)
	if err != nil {
		out.Error = fmt.Sprintf("derive pub: %s", err)
		return out
	}
	out.Pubkey = base64.RawURLEncoding.EncodeToString(pub)

	addr, err := encodeAddress(c, pub)
	if err != nil {
		out.Error = fmt.Sprintf("encode address: %s", err)
		return out
	}
	out.Address = addr

	bal, hasActivity, err := probeBalance(ctx, c, addr)
	if err != nil {
		out.Error = fmt.Sprintf("probe: %s", err)
		return out
	}
	out.Balance = bal
	out.HasActivity = hasActivity
	return out
}

// encodeAddress formats a derived pubkey as the chain-native address
// string. Uses outscript for Bitcoin-family and EVM; base58 for
// Solana (ed25519 raw pubkey).
func encodeAddress(c probeCandidate, pub []byte) (string, error) {
	switch c.Curve {
	case "ed25519":
		return base58.Bitcoin.Encode(pub), nil
	case "secp256k1":
		pk, err := secp256k1.ParsePubKey(pub)
		if err != nil {
			return "", err
		}
		o, err := outscript.New(pk).Out(c.outputScript)
		if err != nil {
			return "", fmt.Errorf("outscript.Out(%q): %w", c.outputScript, err)
		}
		if c.addressChain == "" {
			// EVM: Address() doesn't take a chain tag
			return o.Address()
		}
		return o.Address(c.addressChain)
	default:
		return "", fmt.Errorf("unsupported curve %q", c.Curve)
	}
}

// probeBalance hits the appropriate RPC method for the candidate's
// chain. Returns the raw balance (in the chain's smallest units as
// a decimal string) and a bool indicating non-zero activity.
func probeBalance(ctx context.Context, c probeCandidate, address string) (balance string, hasActivity bool, err error) {
	// Ephemeral Network — populated with just enough fields that
	// getRPC() wires up the right endpoint (freshness-picked for
	// EVM mainnet, modchain for Bitcoin family, helius for Solana).
	n := &wltnet.Network{
		Type:    c.networkType,
		ChainId: c.networkChainId,
	}

	switch c.networkType {
	case "evm":
		var hexBal string
		raw, err := n.DoRPCCtx(ctx, "eth_getBalance", address, "latest")
		if err != nil {
			return "", false, err
		}
		if err := json.Unmarshal(raw, &hexBal); err != nil {
			return "", false, err
		}
		v, ok := new(big.Int).SetString(hexBal, 0)
		if !ok {
			return "", false, fmt.Errorf("invalid eth_getBalance response %q", hexBal)
		}
		return v.String(), v.Sign() > 0, nil

	case "bitcoin":
		// Bitcoin-family modchain "modchain_assets" returns the
		// asset list for an address. Presence of any item (native
		// coin UTXOs or tokens) indicates activity.
		raw, err := n.DoRPCCtx(ctx, "modchain_assets", address)
		if err != nil {
			return "", false, err
		}
		// The response shape varies; detect activity by "not empty
		// / not null". We surface the raw JSON as balance so the
		// client can render it without another round-trip.
		trimmed := strings.TrimSpace(string(raw))
		empty := trimmed == "" || trimmed == "null" || trimmed == "[]" || trimmed == "{}"
		return trimmed, !empty, nil

	case "solana":
		var resp struct {
			Value uint64 `json:"value"`
		}
		raw, err := n.DoRPCCtx(ctx, "getBalance", address)
		if err != nil {
			return "", false, err
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return "", false, err
		}
		return fmt.Sprintf("%d", resp.Value), resp.Value > 0, nil

	default:
		return "", false, fmt.Errorf("unsupported network type %q", c.networkType)
	}
}

// reconstructMnemonic re-encodes stored entropy into the original
// BIP39 mnemonic string. Same logic mnemonicToSeed uses, exposed
// separately so the probe path can keep the raw mnemonic string
// around (bip39.NewSeed wants a string).
func reconstructMnemonic(share *MnemonicKeyShare) (string, error) {
	prevList := bip39.GetWordList()
	if list := wordlistByName(share.Language); list != nil {
		bip39.SetWordList(list)
		defer bip39.SetWordList(prevList)
	}
	m, err := bip39.NewMnemonic(share.Entropy)
	if err != nil {
		return "", fmt.Errorf("bip39: re-encode entropy: %w", err)
	}
	return m, nil
}
