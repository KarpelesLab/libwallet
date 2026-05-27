package curated

// ChiefStaker dynamic source.
//
// The base curated registry (embedded JSON under data/) is pure-local;
// this file relaxes that contract for one specific feed. ChiefStaker
// ships an actively-changing list of Solana mints that have at least
// one staker on the AtOnline pool, and we want those to surface in
// the wallet's token list without waiting for the next release-time
// generator run.
//
// Lifecycle:
//   - Goroutine starts lazily on the first call to
//     [chiefStakerSolanaTokens] (i.e., the first Token:listCurated
//     request for solana.mainnet). Tests and short-lived CLI binaries
//     that import this package but never hit that path pay nothing.
//   - The fetcher loops forever once started: pull every page, store
//     an immutable snapshot, sleep, repeat. On error it keeps the
//     previous snapshot and logs.
//   - State lives in an [atomic.Value] holding a []*CuratedToken slice.
//     Readers get the current pointer with no lock; the writer swaps
//     in a freshly built slice. Treat the returned slice as read-only.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	chiefStakerURL             = "https://ws.atonline.com/_special/rest/Crypto/Solana/ChiefStaker"
	chiefStakerChainKey        = "solana.mainnet"
	chiefStakerRefreshInterval = 10 * time.Minute
	chiefStakerPageSize        = 100
	chiefStakerHTTPTimeout     = 30 * time.Second
	// chiefStakerMaxPages bounds the pagination loop. Page_max in the
	// upstream paging block is the authoritative stop, but the cap
	// prevents an infinite loop if a future upstream change reports a
	// missing/zero page_max.
	chiefStakerMaxPages = 200
)

// chiefStakerSnapshot is the immutable per-refresh state stored in
// [chiefStakerCache]. Slice + map are built together and swapped
// atomically so readers see a consistent pair.
type chiefStakerSnapshot struct {
	tokens []*CuratedToken
	byAddr map[string]*CuratedToken // Solana base58 — case-significant, raw key.
}

var (
	chiefStakerOnce  sync.Once
	chiefStakerCache atomic.Value // *chiefStakerSnapshot
)

// chiefStakerLoad returns the latest snapshot, starting the background
// refresher on first call. Returns nil until the first successful
// fetch completes — callers must tolerate that case.
func chiefStakerLoad() *chiefStakerSnapshot {
	chiefStakerOnce.Do(startChiefStakerFetcher)
	if v := chiefStakerCache.Load(); v != nil {
		return v.(*chiefStakerSnapshot)
	}
	return nil
}

// chiefStakerSolanaTokens returns the latest token slice (read-only).
func chiefStakerSolanaTokens() []*CuratedToken {
	if s := chiefStakerLoad(); s != nil {
		return s.tokens
	}
	return nil
}

// chiefStakerLookup resolves a Solana mint to a ChiefStaker-sourced
// CuratedToken, or nil if absent. Used as a fallback by [Lookup] when
// the static curated registry has no entry for an address.
func chiefStakerLookup(address string) *CuratedToken {
	if address == "" {
		return nil
	}
	if s := chiefStakerLoad(); s != nil {
		return s.byAddr[address]
	}
	return nil
}

func startChiefStakerFetcher() {
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), chiefStakerHTTPTimeout)
			tokens, err := fetchChiefStakerAll(ctx)
			cancel()
			if err != nil {
				log.Printf("curated/chiefstaker: refresh failed: %v", err)
			} else {
				snap := &chiefStakerSnapshot{
					tokens: tokens,
					byAddr: make(map[string]*CuratedToken, len(tokens)),
				}
				for _, t := range tokens {
					snap.byAddr[t.Address] = t
				}
				chiefStakerCache.Store(snap)
			}
			time.Sleep(chiefStakerRefreshInterval)
		}
	}()
}

// chiefStakerEntry mirrors the upstream JSON shape. Only the fields
// the curated token shape needs are decoded; the rest (Pool_Data,
// timestamps, supply, price) are ignored.
//
// Most numeric-looking fields are quoted strings in the response (see
// the API doc); we coerce on read.
type chiefStakerEntry struct {
	Mint     string `json:"Mint"`
	Name     string `json:"Name"`
	Symbol   string `json:"Symbol"`
	Decimals string `json:"Decimals"`
	Members  string `json:"Members"`
	LogoURL  string `json:"Logo_Url"`
}

type chiefStakerResp struct {
	Result string              `json:"result"`
	Data   []*chiefStakerEntry `json:"data"`
	Paging struct {
		PageNo         int `json:"page_no"`
		PageMax        int `json:"page_max"`
		Count          int `json:"count"`
		ResultsPerPage int `json:"results_per_page"`
	} `json:"paging"`
}

// fetchChiefStakerAll walks every page of the ChiefStaker list and
// returns the filtered/normalized CuratedToken slice. Filter:
// Members >= 1 (per the requirement that surfacing a token implies it
// has at least one staker on the pool).
func fetchChiefStakerAll(ctx context.Context) ([]*CuratedToken, error) {
	client := &http.Client{Timeout: chiefStakerHTTPTimeout}
	var out []*CuratedToken
	for page := 1; page <= chiefStakerMaxPages; page++ {
		q := url.Values{}
		q.Set("page_no", strconv.Itoa(page))
		q.Set("results_per_page", strconv.Itoa(chiefStakerPageSize))
		u := chiefStakerURL + "?" + q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("chiefstaker page %d: build request: %w", page, err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "libwallet-curated/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("chiefstaker page %d: %w", page, err)
		}
		body := io.LimitReader(resp.Body, 4<<20)
		if resp.StatusCode != http.StatusOK {
			buf, _ := io.ReadAll(io.LimitReader(body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("chiefstaker page %d: HTTP %d: %s", page, resp.StatusCode, strings.TrimSpace(string(buf)))
		}
		var r chiefStakerResp
		err = json.NewDecoder(body).Decode(&r)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("chiefstaker page %d: decode: %w", page, err)
		}

		for _, e := range r.Data {
			tok, ok := convertChiefStakerEntry(e)
			if !ok {
				continue
			}
			out = append(out, tok)
		}

		// Stop when the server tells us we've consumed the last page.
		// Defensive: also stop on an empty data page so we don't loop
		// forever if page_max is missing or zero.
		if r.Paging.PageMax > 0 && page >= r.Paging.PageMax {
			break
		}
		if len(r.Data) == 0 {
			break
		}
	}
	return out, nil
}

// convertChiefStakerEntry filters and projects a single ChiefStaker
// entry to a CuratedToken. Returns ok=false when the entry should be
// skipped (Members < 1, missing mint/symbol, or malformed address).
func convertChiefStakerEntry(e *chiefStakerEntry) (*CuratedToken, bool) {
	if e == nil || e.Mint == "" || e.Symbol == "" {
		return nil, false
	}
	members, _ := strconv.Atoi(strings.TrimSpace(e.Members))
	if members < 1 {
		return nil, false
	}
	if !isLikelySolanaAddress(e.Mint) {
		return nil, false
	}
	decimals, _ := strconv.Atoi(strings.TrimSpace(e.Decimals))
	if decimals < 0 || decimals > 32 {
		return nil, false
	}
	return &CuratedToken{
		ChainKey: chiefStakerChainKey,
		Address:  e.Mint,
		Symbol:   e.Symbol,
		Name:     e.Name,
		Decimals: decimals,
		Type:     "spl-token",
		LogoURI:  e.LogoURL,
		Tags:     []string{"meme"},
	}, true
}
