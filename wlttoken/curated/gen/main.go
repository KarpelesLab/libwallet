// Generator: refreshes the embedded curated-token JSON under
// wlttoken/curated/data/ from upstream feeds.
//
// Run at release time:
//
//	go generate ./wlttoken/curated/...
//
// NOT compiled into the library — this is a separate `package main`
// so `go build ./...` doesn't drag net/http into the runtime.
//
// What it writes:
//   - data/evm-<chainId>.json — Uniswap default list, filtered to
//     our chain allowlist.
//   - data/solana-mainnet.json — Jupiter verified list.
//
// What it does NOT touch:
//   - data/overlay-*.json — hand-curated additions the upstream feeds
//     don't carry (ChiefPussy, pre-market mints). Overlay entries
//     merge over base entries at load time; the generator must never
//     overwrite them.
//
// Output is deterministic: tokens within a chain are sorted by
// address, two consecutive runs produce byte-identical output. Makes
// diffs in data/ reviewable.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	uniswapListURL = "https://tokens.uniswap.org/"
	// lite-api is Jupiter's no-auth edge; tokens.jup.ag (the
	// documented endpoint) 404s from some egress points. Same
	// dataset.
	jupiterVerifiedURL = "https://lite-api.jup.ag/tokens/v2/tag?query=verified"
)

// chainAllowlist maps canonical "<type>.<chainId>" → output file name
// (without the data/ prefix). Limited to the chain set the rest of
// libwallet actually supports — notably the 1inch-covered EVM chains
// plus Solana mainnet. Adding a chain means adding a row here and
// nothing else.
var chainAllowlist = map[string]struct {
	netType  string
	chainId  string
	fileName string
}{
	"evm.1":         {"evm", "1", "evm-1.json"},
	"evm.10":        {"evm", "10", "evm-10.json"},
	"evm.56":        {"evm", "56", "evm-56.json"},
	"evm.100":       {"evm", "100", "evm-100.json"},
	"evm.137":       {"evm", "137", "evm-137.json"},
	"evm.250":       {"evm", "250", "evm-250.json"},
	"evm.324":       {"evm", "324", "evm-324.json"},
	"evm.8453":      {"evm", "8453", "evm-8453.json"},
	"evm.42161":     {"evm", "42161", "evm-42161.json"},
	"evm.43114":     {"evm", "43114", "evm-43114.json"},
	"evm.59144":     {"evm", "59144", "evm-59144.json"},
	"solana.mainnet": {"solana", "mainnet", "solana-mainnet.json"},
}

// token is the output schema. Must match
// wlttoken/curated/curated.go:CuratedToken exactly (json keys).
type token struct {
	ChainKey    string   `json:"chainKey"`
	Address     string   `json:"address"`
	Symbol      string   `json:"symbol"`
	Name        string   `json:"name"`
	Decimals    int      `json:"decimals"`
	Type        string   `json:"type"`
	LogoURI     string   `json:"logoURI,omitempty"`
	CoingeckoID string   `json:"coingeckoId,omitempty"`
	CMCID       int      `json:"cmcId,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func main() {
	// CWD when invoked via `go generate` is the dir containing the
	// directive (wlttoken/curated/). data/ lives alongside.
	outDir := "data"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if _, err := os.Stat(outDir); err != nil {
		fatalf("output dir %q not found — run from wlttoken/curated/ or pass a path: %v", outDir, err)
	}

	evm, err := fetchUniswap()
	if err != nil {
		fatalf("uniswap fetch: %v", err)
	}
	sol, err := fetchJupiter()
	if err != nil {
		fatalf("jupiter fetch: %v", err)
	}

	// Group and write per-chain.
	for key, cfg := range chainAllowlist {
		var list []*token
		switch cfg.netType {
		case "evm":
			list = evm[cfg.chainId]
		case "solana":
			list = sol
		}
		if list == nil {
			fmt.Fprintf(os.Stderr, "[warn] no tokens from upstream for %s — writing empty list\n", key)
			list = []*token{}
		}
		// Annotate chainKey on every entry so the loader can
		// group them without relying on the filename.
		for _, t := range list {
			t.ChainKey = key
		}
		// Dedup by lowercased address. Upstream feeds occasionally
		// duplicate when a token is listed under multiple tags.
		seen := make(map[string]bool, len(list))
		dedup := make([]*token, 0, len(list))
		for _, t := range list {
			k := strings.ToLower(t.Address)
			if seen[k] {
				continue
			}
			seen[k] = true
			dedup = append(dedup, t)
		}
		// Stable sort by lowercased address for byte-identical
		// reruns.
		sort.Slice(dedup, func(i, j int) bool {
			return strings.ToLower(dedup[i].Address) < strings.ToLower(dedup[j].Address)
		})
		path := filepath.Join(outDir, cfg.fileName)
		if err := writeJSON(path, dedup); err != nil {
			fatalf("write %s: %v", path, err)
		}
		fmt.Printf("wrote %s (%d tokens)\n", path, len(dedup))
	}
}

// fetchUniswap pulls the Uniswap default list and buckets its
// entries by chainId (filtered to the chains we care about). Returns
// a map keyed by the stringified chain id (so "1", "137", ...).
func fetchUniswap() (map[string][]*token, error) {
	var wrapper struct {
		Tokens []struct {
			ChainID  int               `json:"chainId"`
			Address  string            `json:"address"`
			Symbol   string            `json:"symbol"`
			Name     string            `json:"name"`
			Decimals int               `json:"decimals"`
			LogoURI  string            `json:"logoURI"`
			Tags     []string          `json:"tags"`
			Extensions map[string]any `json:"extensions"`
		} `json:"tokens"`
	}
	if err := getJSON(uniswapListURL, &wrapper); err != nil {
		return nil, err
	}
	// Build a set of ids we care about for quick filtering.
	want := make(map[string]bool)
	for _, cfg := range chainAllowlist {
		if cfg.netType == "evm" {
			want[cfg.chainId] = true
		}
	}
	out := make(map[string][]*token)
	for _, t := range wrapper.Tokens {
		cid := strconv.Itoa(t.ChainID)
		if !want[cid] {
			continue
		}
		if t.Symbol == "" || t.Address == "" {
			continue
		}
		tags := filterTags(t.Tags)
		if len(tags) == 0 {
			// Uniswap's default list does not tag most entries;
			// fall back to a symbol-based heuristic so the
			// stablecoins-first sort at load time still kicks in
			// for USDT / USDC / WBTC / WETH / etc.
			tags = heuristicTags(t.Symbol, t.Name)
		}
		tt := &token{
			Address:  t.Address, // Uniswap already emits EIP-55 casing
			Symbol:   t.Symbol,
			Name:     t.Name,
			Decimals: t.Decimals,
			Type:     "erc20",
			LogoURI:  t.LogoURI,
			Tags:     tags,
		}
		if cgid, ok := t.Extensions["coingeckoId"].(string); ok {
			tt.CoingeckoID = cgid
		}
		out[cid] = append(out[cid], tt)
	}
	return out, nil
}

// fetchJupiter pulls Jupiter's verified token list for Solana mainnet.
// Jupiter does not ship coingecko/cmc ids; those fields stay empty
// and can be hand-filled via an overlay when the frontend needs them.
//
// Jupiter returns ~5000 verified mints (~1.4 MB JSON). Embedding the
// whole list would balloon the library binary for mostly long-tail
// tokens with no UX value — we filter to mcap ≥ solanaMcapFloor so
// the embedded file stays under ~100 KB while still covering every
// token a normal user holds. Hand-curated overlays (ChiefPussy) are
// merged at load time and bypass this floor.
func fetchJupiter() ([]*token, error) {
	var list []struct {
		ID           string  `json:"id"` // mint address
		Name         string  `json:"name"`
		Symbol       string  `json:"symbol"`
		Icon         string  `json:"icon"`
		Decimals     int     `json:"decimals"`
		TokenProgram string  `json:"tokenProgram"`
		MCap         float64 `json:"mcap"`
	}
	if err := getJSON(jupiterVerifiedURL, &list); err != nil {
		return nil, err
	}
	out := make([]*token, 0, len(list))
	for _, t := range list {
		if t.Symbol == "" || t.ID == "" {
			continue
		}
		if t.MCap < solanaMcapFloor {
			continue
		}
		tt := &token{
			Address:  t.ID,
			Symbol:   t.Symbol,
			Name:     t.Name,
			Decimals: t.Decimals,
			Type:     solanaProgramToType(t.TokenProgram),
			LogoURI:  t.Icon,
			Tags:     heuristicTags(t.Symbol, t.Name),
		}
		out = append(out, tt)
	}
	return out, nil
}

// solanaMcapFloor is the $USD market-cap threshold below which a
// Jupiter-verified token is dropped from the embedded list. Tuned
// around 1M$ — keeps the well-known mints (USDC, USDT, SOL, JUP,
// mSOL, …) and drops long-tail verified noise that would otherwise
// push the .json past a megabyte. Overlays aren't filtered.
const solanaMcapFloor = 1_000_000

// solanaProgramToType maps a Solana mint's token program ID to our
// normalized Type field. Token-2022 mints require different transfer
// instructions, so the split matters downstream.
func solanaProgramToType(program string) string {
	switch program {
	case "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb":
		return "spl-token-2022"
	default:
		return "spl-token"
	}
}

// Tag allowlist: keep only tags that have a semantic meaning across
// Uniswap / Jupiter. Upstream-specific noise ("verified", "community",
// "1inch-test") gets filtered out before we embed.
var allowedTags = map[string]bool{
	"stablecoin": true,
	"wrapped":    true,
	"meme":       true,
	"lst":        true,
	"governance": true,
}

func filterTags(in []string) []string {
	var out []string
	for _, t := range in {
		lc := strings.ToLower(t)
		if allowedTags[lc] {
			out = append(out, lc)
		}
	}
	return out
}

// Symbols / name substrings that mark a token as a stablecoin or
// wrapped asset. Uniswap's default list doesn't tag these, and we
// rely on tag-priority for the frontend sort order — so we fill
// them in from the symbol. Only runs when upstream tags are empty.
var stablecoinSymbols = map[string]bool{
	"USDT":   true, "USDC": true, "DAI": true, "BUSD": true, "TUSD": true,
	"FRAX":   true, "USDP": true, "GUSD": true, "LUSD": true, "MIM": true,
	"sUSD":   true, "USDD": true, "USD1": true, "RLUSD": true, "PYUSD": true,
	"crvUSD": true, "FDUSD": true, "USDE": true, "USDS": true, "USDV": true,
	"USD0":   true, "USDtb": true, "USDY": true, "EURC": true, "EURS": true,
	"USDC.e": true, "USDT.e": true, "DAI.e": true, "USDbC": true,
}

var wrappedSymbols = map[string]bool{
	"WETH": true, "WBTC": true, "WSOL": true, "WMATIC": true,
	"WAVAX": true, "WBNB": true, "WFTM": true, "WPOL": true,
	"WcBTC": true, "WEETH": true, "WSTETH": true, "WXRP": true,
}

// heuristicTags augments a token's tags from its symbol / name when
// the upstream feed didn't set them. Only fires for entries with no
// existing tags.
func heuristicTags(symbol, name string) []string {
	sym := strings.ToUpper(symbol)
	if stablecoinSymbols[symbol] || stablecoinSymbols[sym] {
		return []string{"stablecoin"}
	}
	if wrappedSymbols[symbol] || wrappedSymbols[sym] {
		return []string{"wrapped"}
	}
	// Liquid-staking tokens typically start with st* / m* SOL or
	// end in "-LST". Conservative: only match the common Solana
	// LSTs explicitly since broad substring rules pick up noise.
	switch sym {
	case "MSOL", "JITOSOL", "BSOL", "JUPSOL", "INF":
		return []string{"lst"}
	}
	return nil
}

// getJSON performs a bounded GET and decodes into dst. Bounded so the
// generator fails fast instead of hanging a release build on a slow
// upstream.
func getJSON(url string, dst any) error {
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "libwallet-curated-gen/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// writeJSON emits pretty-printed JSON with a trailing newline so the
// file is patch-friendly (git diff doesn't complain, editors don't
// re-add one). Uses indent=2 to match the hand-written seed files.
func writeJSON(path string, v any) error {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	return os.WriteFile(path, buf, 0644)
}

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "curated-gen: "+f+"\n", args...)
	os.Exit(1)
}
