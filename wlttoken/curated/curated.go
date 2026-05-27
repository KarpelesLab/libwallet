// Package curated ships a vetted per-chain list of well-known tokens
// baked into the binary via go:embed. Used by:
//
//   - Swap UI — dropdown of "swap to X" destinations without the user
//     pasting a contract address.
//   - Asset enrichment — look up Name / Symbol / Logo by mint or
//     contract address so a user's USDC balance shows as "USDC" rather
//     than "EPjFWdd5..." on Solana / "0xA0b8699..." on Ethereum.
//
// Data origin: Jupiter's verified list (Solana) + Uniswap's default
// list (EVM), regenerated at release time by `go generate
// ./wlttoken/curated/...` which pulls the upstream feeds into
// data/*.json. Hand-curated entries that upstream lists do not carry
// (meme tokens, pre-market mints) live in data/overlay-*.json and are
// merged over the generated data — overlay wins on address collision.
//
// Everything here is pure-local: init() parses the embedded JSON into
// an in-memory registry; there is no runtime network dependency and
// no disk I/O beyond what the embed reader does once.
package curated

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

// CuratedToken is the normalized shape every upstream token list is
// folded into. Uniswap / Jupiter / hand-written overlays all serialize
// to this struct so the Dart client sees one schema regardless of
// chain family.
type CuratedToken struct {
	// ChainKey is the canonical "<type>.<chainId>" form — identical
	// to wltnet.Network.String() and the Asset.network field returned
	// by Asset:list. Examples: "evm.1", "solana.mainnet".
	ChainKey string `json:"chainKey"`

	// Address is the on-chain identifier: EIP-55-cased contract for
	// EVM (0x-prefixed, 40 hex chars), base58 mint for Solana. Guard
	// rails: the loader rejects entries whose address does not match
	// the expected chain-family layout so a malformed upstream feed
	// cannot poison the registry.
	Address string `json:"address"`

	Symbol   string `json:"symbol"`
	Name     string `json:"name"`
	Decimals int    `json:"decimals"`

	// Type is the contract / mint flavour. Stable values:
	// "erc20", "spl-token", "spl-token-2022".
	Type string `json:"type"`

	LogoURI     string   `json:"logoURI,omitempty"`
	CoingeckoID string   `json:"coingeckoId,omitempty"`
	CMCID       int      `json:"cmcId,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

//go:embed data/*.json
var curatedFS embed.FS

var (
	initOnce sync.Once
	initErr  error

	// byChain maps ChainKey → slice of tokens, sorted by
	// (tag-preference, symbol). Callers get a shared reference;
	// treat it as read-only (documented on ForChain).
	byChain map[string][]*CuratedToken

	// byAddress is ChainKey → lowercased-address → token. Used by
	// Lookup to enrich on-chain balances.
	byAddress map[string]map[string]*CuratedToken

	// bySymbol is ChainKey → UPPERCASE-symbol → token. Used by
	// LookupBySymbol to resolve user-facing strings back to the
	// canonical entry (price feeds, swap selection).
	bySymbol map[string]map[string]*CuratedToken
)

// ForChain returns the curated token list for (netType, chainId),
// e.g. ForChain("evm", "1") or ForChain("solana", "mainnet"). Returns
// nil when the chain has no embedded data.
//
// The returned slice is a shared reference; callers must not mutate
// it (sort, append, or rewrite entries in place).
func ForChain(netType, chainId string) []*CuratedToken {
	ensureLoaded()
	return byChain[netType+"."+chainId]
}

// Lookup resolves a mint / contract address to a CuratedToken, or nil
// when the address is not on the curated list for that chain. Case is
// normalized: EVM addresses are matched on their lowercased form,
// Solana mints are compared as-is (base58 is case-sensitive).
//
// For solana.mainnet, falls back to the dynamic ChiefStaker snapshot
// when the embedded registry has no entry — this lets balance-list
// enrichment surface pump-pool tokens that aren't on the Jupiter
// verified list (most don't clear the embedded mcap floor).
func Lookup(netType, chainId, address string) *CuratedToken {
	ensureLoaded()
	if m, ok := byAddress[netType+"."+chainId]; ok {
		if t := m[normalizeAddress(netType, address)]; t != nil {
			return t
		}
	}
	if netType == "solana" && chainId == "mainnet" {
		return chiefStakerLookup(address)
	}
	return nil
}

// LookupBySymbol resolves a symbol ("USDT", "usdc", "WETH") to the
// canonical CuratedToken for that chain. Case-insensitive. Returns
// nil when the symbol is not present.
//
// Symbols are not globally unique — many chains have a "USDT" — so
// the chain must be specified. Don't use this for cross-chain
// asset-ID resolution; use (ChainKey, Address) for that.
func LookupBySymbol(netType, chainId, symbol string) *CuratedToken {
	ensureLoaded()
	m, ok := bySymbol[netType+"."+chainId]
	if !ok {
		return nil
	}
	return m[strings.ToUpper(symbol)]
}

// ParseChainKey splits a canonical "<type>.<chainId>" key into its
// two parts. Returns an error on malformed input. Exported so API
// handlers that receive the string from client code can validate it
// once and reuse the normalized halves.
func ParseChainKey(key string) (netType, chainId string, err error) {
	i := strings.IndexByte(key, '.')
	if i <= 0 || i == len(key)-1 {
		return "", "", fmt.Errorf("invalid chain key %q: want \"<type>.<chainId>\"", key)
	}
	return key[:i], key[i+1:], nil
}

// Chains returns the set of ChainKeys that have embedded curated
// data. Useful for diagnostics / admin UIs; not used on the hot path.
func Chains() []string {
	ensureLoaded()
	out := make([]string, 0, len(byChain))
	for k := range byChain {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ensureLoaded() {
	initOnce.Do(func() { initErr = loadFromEmbed() })
	if initErr != nil {
		// Loader failures are bugs in the embedded data (stale
		// generator output, malformed overlay). Surface loudly
		// rather than silently serving an empty list — a panic
		// in init-adjacent code only fires on the first lookup,
		// which is fine for CI and dev, and tests assert loader
		// success explicitly so prod binaries never hit this.
		panic("curated: load failed: " + initErr.Error())
	}
}

func loadFromEmbed() error {
	byChain = make(map[string][]*CuratedToken)
	byAddress = make(map[string]map[string]*CuratedToken)
	bySymbol = make(map[string]map[string]*CuratedToken)

	entries, err := fs.ReadDir(curatedFS, "data")
	if err != nil {
		return fmt.Errorf("read data dir: %w", err)
	}

	// Two-pass load: base files first, overlays second. Overlay
	// entries overwrite base entries with the same address on the
	// same chain, which is how hand-curated additions (ChiefPussy)
	// and corrections are expressed.
	type fileEntry struct {
		name    string
		overlay bool
	}
	var files []fileEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, fileEntry{
			name:    e.Name(),
			overlay: strings.HasPrefix(e.Name(), "overlay-"),
		})
	}
	// Stable order: non-overlay names first (asc), then overlay
	// names (asc). Keeps loader output reproducible.
	sort.Slice(files, func(i, j int) bool {
		if files[i].overlay != files[j].overlay {
			return !files[i].overlay
		}
		return files[i].name < files[j].name
	})

	for _, f := range files {
		buf, err := fs.ReadFile(curatedFS, "data/"+f.name)
		if err != nil {
			return fmt.Errorf("read %s: %w", f.name, err)
		}
		// An empty list file is legal (e.g. a chain that the
		// generator hasn't populated yet) — JSON parser will
		// produce a nil slice; no work to do, move on.
		if strings.TrimSpace(string(buf)) == "" {
			continue
		}
		var toks []*CuratedToken
		if err := json.Unmarshal(buf, &toks); err != nil {
			return fmt.Errorf("parse %s: %w", f.name, err)
		}
		for _, t := range toks {
			if err := validateToken(t, f.name); err != nil {
				return err
			}
			addToRegistry(t, f.overlay)
		}
	}

	// Sort each chain's list so the client gets a deterministic
	// order. Stablecoins / wrapped first, then alphabetical by
	// symbol — matches how most wallet UIs group these.
	for k, list := range byChain {
		sort.SliceStable(list, func(i, j int) bool {
			pi, pj := tagPriority(list[i].Tags), tagPriority(list[j].Tags)
			if pi != pj {
				return pi < pj
			}
			return strings.ToUpper(list[i].Symbol) < strings.ToUpper(list[j].Symbol)
		})
		byChain[k] = list
	}
	return nil
}

func validateToken(t *CuratedToken, srcFile string) error {
	if t.ChainKey == "" {
		return fmt.Errorf("%s: token missing chainKey (symbol=%q)", srcFile, t.Symbol)
	}
	if t.Address == "" {
		return fmt.Errorf("%s: token missing address (symbol=%q)", srcFile, t.Symbol)
	}
	if t.Symbol == "" {
		return fmt.Errorf("%s: token missing symbol (address=%q)", srcFile, t.Address)
	}
	if t.Decimals < 0 || t.Decimals > 32 {
		return fmt.Errorf("%s: implausible decimals %d (symbol=%q)", srcFile, t.Decimals, t.Symbol)
	}
	netType, _, err := ParseChainKey(t.ChainKey)
	if err != nil {
		return fmt.Errorf("%s: %w", srcFile, err)
	}
	// Sanity-check address layout against chain family. Keeps a
	// typo-prone overlay from poisoning the registry with a
	// string that will fail downstream at RPC time.
	switch netType {
	case "evm":
		if !isLikelyEVMAddress(t.Address) {
			return fmt.Errorf("%s: %q is not a valid EVM address (symbol=%q)", srcFile, t.Address, t.Symbol)
		}
	case "solana":
		if !isLikelySolanaAddress(t.Address) {
			return fmt.Errorf("%s: %q is not a valid Solana base58 mint (symbol=%q)", srcFile, t.Address, t.Symbol)
		}
	}
	return nil
}

func addToRegistry(t *CuratedToken, overlay bool) {
	key := t.ChainKey
	addr := normalizeAddress(chainKeyFamily(key), t.Address)
	sym := strings.ToUpper(t.Symbol)

	if _, ok := byAddress[key]; !ok {
		byAddress[key] = make(map[string]*CuratedToken)
		bySymbol[key] = make(map[string]*CuratedToken)
	}
	// Overlay overrides base entries; replace in byChain + the
	// secondary maps. Non-overlay duplicates keep the first seen
	// entry — the generator dedupes before emitting, so hitting
	// this branch outside overlay means the upstream feed had a
	// dupe, not much we can do other than ignore the second one.
	if existing, ok := byAddress[key][addr]; ok {
		if !overlay {
			return
		}
		// Find and replace in byChain slice.
		for i, v := range byChain[key] {
			if v == existing {
				byChain[key][i] = t
				break
			}
		}
		byAddress[key][addr] = t
		// Old symbol keying may still point at the replaced
		// entry; rewrite so LookupBySymbol returns the overlay.
		delete(bySymbol[key], strings.ToUpper(existing.Symbol))
		bySymbol[key][sym] = t
		return
	}
	byChain[key] = append(byChain[key], t)
	byAddress[key][addr] = t
	// Symbol is not globally unique even within a chain (old vs.
	// new USDT deployments exist). First-seen wins; overlays can
	// force a rebind via the overlay branch above.
	if _, dup := bySymbol[key][sym]; !dup {
		bySymbol[key][sym] = t
	}
}

// tagPriority orders the visible list so stable / wrapped / governance
// tokens surface first. Anything unrecognized sinks to the bottom
// (priority max int) so meme entries are findable but don't crowd the
// default view.
func tagPriority(tags []string) int {
	if hasTag(tags, "stablecoin") {
		return 0
	}
	if hasTag(tags, "wrapped") {
		return 1
	}
	if hasTag(tags, "lst") {
		return 2
	}
	if hasTag(tags, "governance") {
		return 3
	}
	return 100
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func chainKeyFamily(key string) string {
	if i := strings.IndexByte(key, '.'); i > 0 {
		return key[:i]
	}
	return key
}

// normalizeAddress lowercases EVM addresses (case-insensitive hex)
// and passes Solana base58 through unchanged (case-significant).
func normalizeAddress(netType, addr string) string {
	if netType == "evm" {
		return strings.ToLower(addr)
	}
	return addr
}

func isLikelyEVMAddress(s string) bool {
	if !strings.HasPrefix(s, "0x") || len(s) != 42 {
		return false
	}
	for _, c := range s[2:] {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// isLikelySolanaAddress accepts 32-44 character base58 strings — the
// full decoded-length check lives in wlttoken/token.go's validate; we
// keep the loader cheap and only reject obvious non-addresses.
func isLikelySolanaAddress(s string) bool {
	if len(s) < 32 || len(s) > 44 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '1' && c <= '9':
		case c >= 'A' && c <= 'H':
		case c >= 'J' && c <= 'N':
		case c >= 'P' && c <= 'Z':
		case c >= 'a' && c <= 'k':
		case c >= 'm' && c <= 'z':
		default:
			return false
		}
	}
	return true
}
