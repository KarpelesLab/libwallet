package wltswap

// Swap:availability — UI-facing feature check. Apps call this to
// decide whether to render a "Swap" button at all on the current
// network. Cheap: no RPC calls, purely local policy + registry
// inspection.

import (
	"context"
	"errors"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// AvailabilityResult is the response from Swap:availability.
type AvailabilityResult struct {
	// Available reports whether Swap:quote / Swap:execute can be
	// called on the current network in this build. True only when
	// (a) the OKX adapter is registered for this chain family, and
	// (b) the chain id is in the OKX-supported allow-list.
	Available bool `json:"available"`
	// Network is the canonical network identifier matching the
	// format Asset:list uses — "<type>.<chainId>", e.g.
	// "evm.1" / "evm.137" / "solana.mainnet" /
	// "bitcoin.dogecoin". Apps that need just the chain family
	// can split on ".".
	Network string `json:"network"`
	// Providers lists the provider names eligible on this
	// specific chain. With OKX as the only routed provider this is
	// always either ["okx_solana"] / ["okx_evm"] or empty.
	Providers []string `json:"providers,omitempty"`
	// Reason carries a short machine-readable explanation when
	// Available is false. Stable values: "unsupported_chain" —
	// chain family or specific chainId not covered by OKX.
	Reason string `json:"reason,omitempty"`
}

// swapAvailability is the Swap:availability entry point. No input
// params — signature matches the idiom used by other zero-param
// handlers (infoOnboarding, infoFirstRun). An anonymous
// `*struct{}` second arg was tried and produced a route-miss from
// apirouter's dispatcher.
func swapAvailability(ctx context.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, err
	}
	return computeAvailability(n.Type, n.ChainId, providers), nil
}

// computeAvailability is the pure-function core of the check — no
// env, no RPC, just policy. Separated so the per-chain rules can be
// unit-tested without setting up a temp env per case.
//
// Decisions per family:
//   - solana: only mainnet routes through OKX. Devnet / testnet
//     clusters return unsupported_chain. The stored Network.ChainId
//     for Solana is "mainnet" (see wltnet/api.go).
//   - evm: per-chainId gate via okxSupportedEVMChains.
//   - anything else (bitcoin-family, etc.): unsupported_chain.
func computeAvailability(netType, chainId string, reg map[string]Provider) *AvailabilityResult {
	res := &AvailabilityResult{Network: netType + "." + chainId}

	switch netType {
	case "solana":
		if chainId != "mainnet" {
			res.Reason = "unsupported_chain"
			return res
		}
		if _, ok := reg["okx_solana"]; ok {
			res.Providers = append(res.Providers, "okx_solana")
		}
		res.Available = len(res.Providers) > 0
		if !res.Available {
			res.Reason = "unsupported_chain"
		}
	case "evm":
		if _, ok := reg["okx_evm"]; ok && okxSupportedEVMChains[chainId] {
			res.Providers = append(res.Providers, "okx_evm")
		}
		res.Available = len(res.Providers) > 0
		if !res.Available {
			res.Reason = "unsupported_chain"
		}
	default:
		res.Reason = "unsupported_chain"
	}
	return res
}

// okxSupportedEVMChains is the static allowlist used by
// `Swap:availability` to gate the EVM swap UI. Kept hard-coded so
// the availability check is a cheap predicate the host can run
// without a network round trip; refresh it against
// `Crypto/Okx:supportedChains` when OKX expands coverage.
//
// Source: OKX DEX docs (https://web3.okx.com/onchainos/dev-docs/),
// "supported chains" table — covers the chains libwallet has ever
// routed plus the major new ones a future Network row might pick
// up. Anything missing from here surfaces `unsupported_chain` to
// the host even though OKX may actually support it; flip the
// matching key on when libwallet adds the chain.
var okxSupportedEVMChains = map[string]bool{
	"1":      true, // Ethereum
	"10":     true, // Optimism
	"25":     true, // Cronos
	"56":     true, // BNB Smart Chain
	"100":    true, // Gnosis
	"137":    true, // Polygon
	"169":    true, // Manta Pacific
	"196":    true, // X Layer
	"250":    true, // Fantom
	"324":    true, // zkSync Era
	"480":    true, // World Chain
	"1101":   true, // Polygon zkEVM
	"5000":   true, // Mantle
	"8217":   true, // Klaytn / Kaia
	"8453":   true, // Base
	"34443":  true, // Mode
	"42161":  true, // Arbitrum One
	"42220":  true, // Celo
	"43114":  true, // Avalanche C-Chain
	"59144":  true, // Linea
	"81457":  true, // Blast
	"534352": true, // Scroll
}
