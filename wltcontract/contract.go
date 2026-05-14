// Package wltcontract ships a curated per-chain registry of well-known
// smart contracts — swap routers (Uniswap V2/V3, Universal Router,
// Permit2), marketplaces (Seaport), lending pools (Aave V3, Compound
// V3), AMM vaults (Balancer V2), etc. — baked into the binary via
// go:embed.
//
// The data backs two surfaces:
//
//  1. EIP-712 typed-data signing approval — MessageSignValue.
//     VerifyingContractLabel is populated from this registry at
//     request-build time so the sign sheet can show
//     "Uniswap V3: SwapRouter02" above the raw `0xE592...7e64`
//     instead of just hex.
//
//  2. Generic `Contracts:lookup` endpoint for hosts that want to
//     label addresses at any render site (effect rows, watch_asset,
//     etc.) without forking the registry data into their own code.
//
// Conventions matching wlttoken/curated:
//
//   - Per-chain JSON files in data/evm-<chainId>.json.
//   - Address index is case-insensitive (EVM addresses lowercased at
//     load time and at lookup time).
//   - Errors of commission (mislabelling a known contract) are worse
//     than errors of omission (no label, host renders raw hex). When
//     in doubt, leave the entry out.
//
// Out of scope: per-method labels ("Swap exact tokens"), risk badges,
// Solana program labels (separate kind; same shape applies but the
// initial registry is EVM-only).
package wltcontract

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
)

// Entry is one row in the curated registry.
type Entry struct {
	// ChainKey is the canonical "<type>.<chainId>" form, matching
	// wltnet.Network.String() and the Asset.network field. Examples:
	// "evm.1", "evm.8453".
	ChainKey string `json:"chainKey"`

	// Address is the contract address, lowercased and 0x-prefixed.
	// Loaders normalise to this form so lookups are case-insensitive.
	Address string `json:"address"`

	// Label is the display string the sign sheet renders.
	// Convention: "<Project>: <Component>" — e.g.
	// "Uniswap V3: SwapRouter02", "OpenSea: Seaport 1.6",
	// "Aave V3: Pool". Keep under ~40 chars so it fits the
	// approval-sheet header.
	Label string `json:"label"`

	// Kind is a stable, informational category. Hosts may filter
	// or icon on it; libwallet doesn't branch on the value.
	// Values: "router" | "permit2" | "lending_pool" |
	// "marketplace" | "amm_vault" | "permit_target".
	Kind string `json:"kind,omitempty"`

	// Project groups entries by upstream brand (e.g. "uniswap",
	// "aave", "opensea"). Useful for hosts that want to render a
	// per-project icon next to the label.
	Project string `json:"project,omitempty"`
}

//go:embed data/*.json
var registryFS embed.FS

var (
	loadOnce sync.Once
	loadErr  error

	// byChainAndAddress[chainKey][lowercased-address] → entry.
	byChainAndAddress map[string]map[string]*Entry
)

func ensureLoaded() {
	loadOnce.Do(func() {
		byChainAndAddress = make(map[string]map[string]*Entry)
		entries, err := fs.ReadDir(registryFS, "data")
		if err != nil {
			loadErr = fmt.Errorf("read embedded contract registry: %w", err)
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			raw, err := registryFS.ReadFile("data/" + entry.Name())
			if err != nil {
				loadErr = fmt.Errorf("read %s: %w", entry.Name(), err)
				return
			}
			var fileEntries []*Entry
			if err := json.Unmarshal(raw, &fileEntries); err != nil {
				loadErr = fmt.Errorf("parse %s: %w", entry.Name(), err)
				return
			}
			for _, e := range fileEntries {
				if e.ChainKey == "" || e.Address == "" || e.Label == "" {
					loadErr = fmt.Errorf("%s: incomplete entry %+v", entry.Name(), e)
					return
				}
				addr := strings.ToLower(e.Address)
				e.Address = addr
				if byChainAndAddress[e.ChainKey] == nil {
					byChainAndAddress[e.ChainKey] = make(map[string]*Entry)
				}
				if existing, dup := byChainAndAddress[e.ChainKey][addr]; dup {
					loadErr = fmt.Errorf("%s: duplicate %s on %s (existing %q, new %q)",
						entry.Name(), addr, e.ChainKey, existing.Label, e.Label)
					return
				}
				byChainAndAddress[e.ChainKey][addr] = e
			}
		}
	})
}

// Lookup returns the curated entry for (netType, chainId, address), or
// nil when the address is not on the registry for that chain. Address
// comparison is case-insensitive — callers can pass EIP-55-cased or
// fully lowercased forms interchangeably.
//
// Returns nil with no error on miss — callers are expected to handle
// "no label" by falling back to the raw address, not by surfacing an
// error to the user.
func Lookup(netType, chainId, address string) *Entry {
	ensureLoaded()
	if loadErr != nil {
		return nil
	}
	if netType == "" || chainId == "" || address == "" {
		return nil
	}
	chainKey := netType + "." + chainId
	addrs, ok := byChainAndAddress[chainKey]
	if !ok {
		return nil
	}
	return addrs[strings.ToLower(address)]
}

// LookupByChainKey is the same as Lookup but accepts the chain key
// directly (matches the Asset.network shape returned by Asset:list).
// Convenience for callers that already have the "<type>.<chainId>"
// string.
func LookupByChainKey(chainKey, address string) *Entry {
	ensureLoaded()
	if loadErr != nil {
		return nil
	}
	if chainKey == "" || address == "" {
		return nil
	}
	addrs, ok := byChainAndAddress[chainKey]
	if !ok {
		return nil
	}
	return addrs[strings.ToLower(address)]
}

func init() {
	pobj.RegisterStatic("Contracts:lookup", apiContractsLookup)
}

// apiContractsLookup is the Dart-facing endpoint. Returns the registry
// entry for (chainKey, address) or `null` (Go nil) when no match.
// Hosts call this at any address-render site to decide whether to
// prepend a label.
func apiContractsLookup(ctx *apirouter.Context, in struct {
	ChainKey string `json:"chainKey"`
	Address  string `json:"address"`
}) (any, error) {
	if in.ChainKey == "" {
		return nil, errors.New("chainKey is required")
	}
	if in.Address == "" {
		return nil, errors.New("address is required")
	}
	if e := LookupByChainKey(in.ChainKey, in.Address); e != nil {
		return e, nil
	}
	return nil, nil
}

// InitEnv mirrors the InitEnv shape every wlt* package exposes so the
// env-wiring loop in wltbase/env.go can include this package. No
// per-env state today — the registry is global + read-only.
func InitEnv(_ wltintf.Env) {}
