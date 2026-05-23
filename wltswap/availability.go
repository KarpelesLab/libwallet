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
	// (a) at least one provider is registered, (b) the provider
	// supports this specific chain id, and (c) the build carries
	// whatever credentials that provider needs.
	Available bool `json:"available"`
	// Network is the canonical network identifier matching the
	// format Asset:list uses — "<type>.<chainId>", e.g.
	// "evm.1" / "evm.137" / "solana.mainnet" /
	// "bitcoin.dogecoin". Apps that need just the chain family
	// can split on ".".
	Network string `json:"network"`
	// Providers lists the provider names eligible on this
	// specific chain, in fallback order. Empty when Available is
	// false and no provider covers this chain.
	Providers []string `json:"providers,omitempty"`
	// Reason carries a short machine-readable explanation when
	// Available is false. Stable values: "unsupported_chain"
	// (chain family or specific chainId has no provider) /
	// "missing_api_key" (EVM build ships without the 1inch key).
	Reason string `json:"reason,omitempty"`
}

// oneInchSupportedChains is the set of EVM chain IDs 1inch's
// Classic Swap API currently exposes an endpoint for. Sourced from
// their public API portal. Add an entry here when 1inch expands
// coverage; a user on an EVM chain not in this set gets
// Available=false, reason=unsupported_chain — no point hitting the
// upstream only to get a 404.
var oneInchSupportedChains = map[string]bool{
	"1":     true, // Ethereum
	"10":    true, // Optimism
	"56":    true, // BNB Chain
	"100":   true, // Gnosis
	"137":   true, // Polygon
	"250":   true, // Fantom
	"324":   true, // zkSync Era
	"8453":  true, // Base
	"42161": true, // Arbitrum One
	"43114": true, // Avalanche
	"59144": true, // Linea
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
	return computeAvailability(n.Type, n.ChainId, providers, OneInchAPIKey), nil
}

// computeAvailability is the pure-function core of the check — no
// env, no RPC, just policy. Separated so the per-chain rules can be
// unit-tested without setting up a temp env per case.
//
// Decisions per family:
//   - solana: only mainnet routes through Jupiter/dFlow. Devnet /
//     testnet clusters return unsupported_chain. The stored
//     Network.ChainId for Solana is "mainnet" (see wltnet/api.go).
//   - evm: per-chainId gate via oneInchSupportedChains. API key
//     missing → reason=missing_api_key. Chain not in 1inch's
//     coverage → unsupported_chain even with a valid key.
//   - anything else (bitcoin-family, etc.): unsupported_chain.
func computeAvailability(netType, chainId string, reg map[string]Provider, oneInchKey string) *AvailabilityResult {
	res := &AvailabilityResult{Network: netType + "." + chainId}

	switch netType {
	case "solana":
		if chainId != "mainnet" {
			res.Reason = "unsupported_chain"
			return res
		}
		// OKX DEX is the routed provider as of the licensing
		// migration. Legacy Solana adapters (jupiter_ultra / dflow)
		// stay in the lookup for the soft-disable flip-back path —
		// if they get re-registered, advertise them too.
		for _, name := range []string{"okx_solana", "jupiter_ultra", "dflow"} {
			if _, ok := reg[name]; ok {
				res.Providers = append(res.Providers, name)
			}
		}
		res.Available = len(res.Providers) > 0
		if !res.Available {
			res.Reason = "unsupported_chain"
		}
	case "evm":
		// EVM coverage now comes from the OKX-supported chain list
		// rather than the (smaller, license-bound) 1inch one. The
		// 1inch oneInchKey gate is preserved only for the flip-back
		// case — when okx_evm is the routed provider it's
		// irrelevant.
		_, hasOkx := reg["okx_evm"]
		_, has1inch := reg["1inch"]
		if hasOkx && okxSupportedEVMChains[chainId] {
			res.Providers = append(res.Providers, "okx_evm")
		}
		if has1inch && oneInchSupportedChains[chainId] {
			res.Providers = append(res.Providers, "1inch")
			if oneInchKey == "" {
				// only relevant when 1inch is the only provider
				if !hasOkx {
					res.Reason = "missing_api_key"
					return res
				}
			}
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
	"1":     true, // Ethereum
	"10":    true, // Optimism
	"25":    true, // Cronos
	"56":    true, // BNB Smart Chain
	"100":   true, // Gnosis
	"137":   true, // Polygon
	"169":   true, // Manta Pacific
	"196":   true, // X Layer
	"250":   true, // Fantom
	"324":   true, // zkSync Era
	"480":   true, // World Chain
	"1101":  true, // Polygon zkEVM
	"5000":  true, // Mantle
	"8217":  true, // Klaytn / Kaia
	"8453":  true, // Base
	"34443": true, // Mode
	"42161": true, // Arbitrum One
	"42220": true, // Celo
	"43114": true, // Avalanche C-Chain
	"59144": true, // Linea
	"81457": true, // Blast
	"534352": true, // Scroll
}
