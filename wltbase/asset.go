package wltbase

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltasset"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wlttoken"
	"github.com/KarpelesLab/pobj"
)

func init() {
	//pobj.RegisterStatic("Asset", transactionValidate)
	pobj.RegisterActions[wltasset.Asset]("Asset",
		&pobj.ObjectActions{
			Fetch: pobj.Static(apiFetchAsset),
			List:  pobj.Static(apiListAsset),
		},
	)
}

func apiFetchAsset(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	return nil, fs.ErrNotExist
}

// assetSnapshot is the `{network, account, assets}` shape returned by
// Asset list and consumed by the balance poller.
type assetSnapshot struct {
	Network *wltnet.Network   `json:"network"`
	Account *wltacct.Account  `json:"account"`
	Assets  []*wltasset.Asset `json:"assets"`
}

// currentAssets builds an assetSnapshot for the current account + network
// (or the specific ones passed in). Extracted so both the list endpoint
// and the balance poller can use the same logic.
//
// ctx is threaded through every RPC call so callers can bound the work
// (the background poller wraps this in a 15 s timeout; the API endpoint
// inherits the apirouter request context). Without a deadline, a slow
// or unreachable upstream RPC would hang this call indefinitely.
func currentAssets(ctx context.Context, e wltintf.Env, n *wltnet.Network, acct *wltacct.Account) (*assetSnapshot, error) {
	if n == nil {
		var err error
		n, err = wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, err
		}
	}
	if acct == nil {
		var err error
		acct, err = wltacct.CurrentAccount(e)
		if err != nil {
			return nil, err
		}
	}
	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	var assets []*wltasset.Asset
	if acct.GetAddress() != "N/A" {
		if nat, err := n.NativeAsset(ctx, e, acct); err == nil {
			assets = append(assets, nat)
		} else {
			return nil, err
		}
	}
	if n.Type == "solana" && acct.GetAddress() != "N/A" {
		// First-launch token discovery: on the very first Asset:list
		// for a (mainnet solana, owner) pair, ask Helius DAS for the
		// full token-list with rich metadata and persist non-spam
		// entries via wlttoken.EnsureToken. Subsequent calls find the
		// flag set and skip. Best-effort: failure here doesn't block
		// the balance fetch — we'll just retry on the next call (the
		// flag stays unset until success).
		seedSolanaTokensOnce(ctx, e, n, acct.GetAddress())

		if tokens, err := n.SolanaTokenBalances(ctx, e, acct); err == nil {
			// Enrich each token with the user's Token-table metadata
			// when present. The on-chain RPC path's fallback name is
			// the truncated mint ("EPjFW..."); a Token row populated
			// by either the curated registry, a prior swap, or the
			// initial Helius discovery has the proper name/symbol.
			for _, a := range tokens {
				mint := mintFromAssetKey(a.Key)
				if mint == "" {
					continue
				}
				t, err := wlttoken.LookupTokenByMint(e, n.Id, mint)
				if err != nil || t == nil {
					continue
				}
				if name := t.GetName(); name != "" {
					a.Name = name
				}
				if sym := t.GetSymbol(); sym != "" {
					a.Symbol = sym
				}
			}
			assets = append(assets, tokens...)
		}
	}
	return &assetSnapshot{Network: n, Account: acct, Assets: assets}, nil
}

// mintFromAssetKey extracts the SPL mint address from an Asset.Key of
// the form "<network-id>.<mint>" (the format SolanaTokenBalances
// emits). Returns "" when the key isn't in that shape — defensive
// against future format changes.
func mintFromAssetKey(key string) string {
	idx := strings.LastIndex(key, ".")
	if idx < 0 || idx == len(key)-1 {
		return ""
	}
	return key[idx+1:]
}

// seedSolanaTokensOnce runs token discovery for the given (network,
// owner) the first time it's asked, and stores a config flag so
// subsequent calls skip. Mainnet-only — Helius DAS coverage on
// devnet/testnet is patchy and the discovered metadata is unreliable
// there. Best-effort: any error is logged and swallowed; the flag is
// only set on success so the next call retries.
//
// Spam filter is intentionally conservative: skip entries with an
// empty symbol, ludicrously long names, or non-positive decimals.
// More aggressive heuristics (e.g. checking against a known-scam
// list) can be added later once concrete spam patterns surface.
func seedSolanaTokensOnce(ctx context.Context, e wltintf.Env, n *wltnet.Network, owner string) {
	if n.Type != "solana" || n.ChainId != "mainnet" {
		return
	}
	flagKey := "solana_discovery:" + n.Id.String() + ":" + owner
	if _, err := e.ConfigGet(flagKey); err == nil {
		return
	}
	items, err := n.SolanaDiscoverFungibles(ctx, owner)
	if err != nil {
		wltlog.Debugf("solana-discover: %s on %s skipped: %v", owner, n.Id, err)
		return
	}
	for _, it := range items {
		if !isPlausibleFungible(it) {
			continue
		}
		if _, terr := wlttoken.EnsureToken(e, n.Id, it.Mint, it.Symbol, it.Name, it.Decimals, ""); terr != nil {
			wltlog.Debugf("solana-discover: EnsureToken %s failed: %v", it.Mint, terr)
		}
	}
	_ = e.ConfigSet(flagKey, []byte{1})
	wltlog.Debugf("solana-discover: seeded %d candidates for %s on %s", len(items), owner, n.Id)
}

// isPlausibleFungible filters obvious scam / malformed DAS entries
// before we persist them. Tuned to be conservative — better to skip
// a legitimate token (the user can add it manually) than to fill the
// Token table with link-shortener scams.
func isPlausibleFungible(d wltnet.DiscoveredFungible) bool {
	if d.Mint == "" || d.Symbol == "" {
		return false
	}
	if d.Decimals <= 0 {
		// Most legitimate SPL tokens use 6 or 9 decimals; zero-
		// decimal mints are usually NFT-likes that slipped past
		// the Interface filter.
		return false
	}
	if len(d.Symbol) > 12 {
		return false
	}
	if len(d.Name) > 64 {
		// Scam tokens routinely stuff a URL into the name field.
		return false
	}
	return true
}

func apiListAsset(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	snap, err := currentAssets(ctx, e,
		apirouter.GetObject[wltnet.Network](ctx, "Network"),
		apirouter.GetObject[wltacct.Account](ctx, "Account"),
	)
	if err != nil {
		return nil, err
	}
	if convert, okconv := apirouter.GetParam[string](ctx, "_convert"); okconv {
		for _, a := range snap.Assets {
			a.ConvertTo(e, convert)
		}
	}
	return map[string]any{
		"network": snap.Network,
		"account": snap.Account,
		"assets":  snap.Assets,
	}, nil
}
