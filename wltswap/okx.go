package wltswap

// OKX DEX adapter — multi-chain (Solana + every EVM chain OKX
// supports). One Provider implementation under the hood, registered
// twice (Name="okx_solana" / Chain="solana" and Name="okx_evm" /
// Chain="evm") so `providerOrderForChain`'s per-chain routing keeps
// working unchanged.
//
// Auth is server-side: every call goes through
// `Crypto/Okx:<endpoint>` on the platform backend, which adds the
// OK-ACCESS-* HMAC headers and forwards to OKX. libwallet itself
// never holds the OKX API key. The same trust boundary that
// already protects `Crypto/WalletSign:*`.
//
// Fee model: also server-side. `Crypto/Okx:quote` / `:swap` accept
// `feePercent` + a referrer address as platform-config and echo the
// applied values back in a `platformFee` block at the response
// root. libwallet reads that echo into `Quote.FeeBps` /
// `Quote.ReferralFee` for the UI's "Platform fee: X" line. Empty
// echo (no referrer configured for the chain) → FeeBps stays 0.
//
// Flow:
//
//   Quote:    GET Crypto/Okx:quote  →   build *Quote (+ approval
//                                       check on EVM via the chain's
//                                       dexTokenApproveAddress).
//   Execute:  GET Crypto/Okx:swap   →   { routerResult, tx, platformFee },
//                                       then sign locally and broadcast
//                                       through OKX (Crypto/Okx:
//                                       broadcastTransaction → orderId,
//                                       tracked via :orderStatus). Going
//                                       through OKX's node — rather than our
//                                       own RPC — avoids node-lag "Blockhash
//                                       not found" on Solana and gets MEV-
//                                       protected submission on EVM.
//                                       Solana: tx.data is the serialized tx
//                                         blob; splice-sign it via
//                                         solanaSplicingSignLocal, broadcast
//                                         base64 (retry with a fresh
//                                         blockhash on expiry).
//                                       EVM: build wlttx.Transaction from
//                                         tx.to/data/value/gas/…, SignEVMRaw
//                                         it, broadcast the raw hex with MEV
//                                         protection enabled.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/rest"
)

// okxEVMNativeSentinel is the address OKX uses on every EVM chain
// to mean "the chain's native currency" (ETH on mainnet, BNB on
// BSC, MATIC on Polygon, …). The 0xeeee…eeee form is the
// industry-standard sentinel every major EVM aggregator uses.
const okxEVMNativeSentinel = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

// okxSolanaNativeSentinel is the address OKX uses on Solana for
// native SOL — the canonical wSOL mint. Confusing on its face, but
// it's what `Crypto/Okx:allTokens?chainId=501` returns for the
// native token entry, so it's what the quote / swap endpoints
// expect for native SOL inputs and outputs.
const okxSolanaNativeSentinel = WrappedSOLMint

// okxSolanaProvider is the registry entry for Solana swaps.
// Implementation lives on the shared `okx` helpers below; the two
// per-chain wrapper structs only exist so providerOrderForChain
// can dispatch by Chain() without collision.
type okxSolanaProvider struct{}

func (okxSolanaProvider) Name() string  { return "okx_solana" }
func (okxSolanaProvider) Chain() string { return "solana" }

func (okxSolanaProvider) Quote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error) {
	return okxQuote(ctx, n, acct, req, "okx_solana", "OKX")
}

func (okxSolanaProvider) Execute(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	return okxExecuteSolana(ctx, n, acct, q, keys)
}

// okxEVMProvider mirrors okxSolanaProvider for the EVM chains.
// Same OKX backend, different transaction shape on the execute
// side.
type okxEVMProvider struct{}

func (okxEVMProvider) Name() string  { return "okx_evm" }
func (okxEVMProvider) Chain() string { return "evm" }

func (okxEVMProvider) Quote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error) {
	return okxQuote(ctx, n, acct, req, "okx_evm", "OKX")
}

func (okxEVMProvider) Execute(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	return okxExecuteEVM(ctx, n, acct, q, keys)
}

// ── wire shapes ─────────────────────────────────────────────────

// okxToken is the per-side token block embedded in /quote responses.
type okxToken struct {
	TokenContractAddress string `json:"tokenContractAddress"`
	TokenSymbol          string `json:"tokenSymbol"`
	TokenUnitPrice       string `json:"tokenUnitPrice"`
	Decimal              string `json:"decimal"`
	IsHoneyPot           bool   `json:"isHoneyPot"`
	TaxRate              string `json:"taxRate"`
}

type okxDexProtocol struct {
	DexName string `json:"dexName"`
	Percent string `json:"percent"`
}

// okxRouter is one hop of OKX's flat V6 dexRouterList. V5 had a
// nested router/subRouter tree with arrays of dexProtocols; V6
// collapsed it: each entry carries a single dexProtocol object and
// the from/to token decoration for that hop. Build the libwallet
// RouteHop list by walking the entries in order.
type okxRouter struct {
	DexProtocol    okxDexProtocol `json:"dexProtocol"`
	FromToken      okxToken       `json:"fromToken"`
	ToToken        okxToken       `json:"toToken"`
	FromTokenIndex string         `json:"fromTokenIndex"`
	ToTokenIndex   string         `json:"toTokenIndex"`
}

// okxPlatformFee is the platform's echo of the feePercent + referrer
// it forwarded to OKX. Injected by Crypto/Okx at the response root.
// Empty when the chain has no referrer configured server-side.
type okxPlatformFee struct {
	Side         string `json:"side"`         // "from" or "to"
	Percent      string `json:"percent"`      // e.g. "0.5" for 0.5%
	Amount       string `json:"amount"`       // smallest unit of the side
	TokenAddress string `json:"tokenAddress"` // contract address of the side
	Referrer     string `json:"referrer"`     // where the fee lands
}

type okxQuoteEntry struct {
	ChainIndex         string          `json:"chainIndex"`
	SwapMode           string          `json:"swapMode"`
	ContextSlot        int64           `json:"contextSlot"`
	Router             string          `json:"router"`
	FromTokenAmount    string          `json:"fromTokenAmount"`
	ToTokenAmount      string          `json:"toTokenAmount"`
	TradeFee           string          `json:"tradeFee"`
	EstimateGasFee     string          `json:"estimateGasFee"`
	PriceImpactPercent string          `json:"priceImpactPercent"`
	FromToken          okxToken        `json:"fromToken"`
	ToToken            okxToken        `json:"toToken"`
	DexRouterList      []okxRouter     `json:"dexRouterList"`
	PlatformFee        *okxPlatformFee `json:"platformFee,omitempty"`
}

type okxSwapTx struct {
	From                 string   `json:"from"`
	To                   string   `json:"to"`
	Value                string   `json:"value"`
	Data                 string   `json:"data"`
	Gas                  string   `json:"gas"`
	GasPrice             string   `json:"gasPrice"`
	MaxPriorityFeePerGas string   `json:"maxPriorityFeePerGas"`
	MaxSpendAmount       string   `json:"maxSpendAmount"`
	MinReceiveAmount     string   `json:"minReceiveAmount"`
	SlippagePercent      string   `json:"slippagePercent"`
	SignatureData        []string `json:"signatureData"`
}

type okxSwapEntry struct {
	RouterResult okxQuoteEntry   `json:"routerResult"`
	Tx           okxSwapTx       `json:"tx"`
	PlatformFee  *okxPlatformFee `json:"platformFee,omitempty"`
}

type okxApproveEntry struct {
	Data               string `json:"data"`
	DexContractAddress string `json:"dexContractAddress"`
	GasLimit           string `json:"gasLimit"`
	GasPrice           string `json:"gasPrice"`
}

type okxSupportedChain struct {
	ChainIndex             string `json:"chainIndex"`
	ChainName              string `json:"chainName"`
	DexTokenApproveAddress string `json:"dexTokenApproveAddress"`
}

// okxBlob caches what Execute needs from Quote: the raw tx pieces
// returned by /swap so Execute doesn't have to re-quote.
type okxBlob struct {
	Tx            okxSwapTx
	IsEVM         bool
	NativeDec     int    // chain's native decimals — for parsing tx.value
	ChainIndexNum string // OKX numeric chain index (501, 1, 56, …)
}

// ── shared helpers ──────────────────────────────────────────────

// okxChainIndexFor maps libwallet's Network.Type+ChainId pair onto
// OKX's numeric chain index (V6 vocabulary; same value space as V5's
// `chainId`). Solana mainnet → "501", devnet → "103"; for EVM we
// forward n.ChainId verbatim because chainlist already stores it
// numerically.
func okxChainIndexFor(n *wltnet.Network) (string, error) {
	switch n.Type {
	case "evm":
		if n.ChainId == "" {
			return "", fmt.Errorf("okx: evm network missing ChainId")
		}
		return n.ChainId, nil
	case "solana":
		switch n.ChainId {
		case "", "mainnet", "mainnet-beta":
			return "501", nil
		case "devnet":
			return "103", nil
		case "testnet":
			// OKX doesn't support Solana testnet; surface as an
			// unsupported-chain error rather than route to a chain
			// id OKX would reject.
			return "", fmt.Errorf("okx: solana testnet is not supported")
		default:
			return n.ChainId, nil
		}
	default:
		return "", fmt.Errorf("okx: unsupported network type %q", n.Type)
	}
}

// okxTokenAddrFor maps a libwallet TokenRef.Address to the form OKX
// expects on the given chain — "NATIVE" sentinels translate to the
// chain's wrapped-SOL mint (Solana) or the all-eee sentinel (EVM).
// Bare addresses pass through, with chain-prefix stripping for
// Asset.Key inputs.
func okxTokenAddrFor(n *wltnet.Network, addr string) string {
	addr = stripChainPrefix(addr)
	if addr == "" || strings.EqualFold(addr, "NATIVE") {
		if n.Type == "solana" {
			return okxSolanaNativeSentinel
		}
		return okxEVMNativeSentinel
	}
	return addr
}

// okxSlippagePercent converts libwallet's bps slippage into the
// percent string OKX's V6 /swap expects (50bps → "0.5"). V5 used a
// fraction (0.005); V6 renamed the param to `slippagePercent` and
// switched the units.
func okxSlippagePercent(bps uint16) string {
	if bps == 0 {
		bps = DefaultSlippageBps
	}
	pct := float64(bps) / 100.0
	return strconv.FormatFloat(pct, 'f', -1, 64)
}

// okxCallEntry runs one Crypto/Okx:* endpoint and decodes the
// returned array into a single typed entry. Every /quote / /swap /
// /approveTransaction response is shaped as `[ { … } ]` even when
// only one entry can be present; this helper strips that wrapper.
func okxCallEntry[T any](ctx context.Context, endpoint string, params rest.Param, out *T) error {
	var raw []json.RawMessage
	if err := rest.Apply(ctx, endpoint, "GET", params, &raw); err != nil {
		return fmt.Errorf("%s: %w", endpoint, err)
	}
	if len(raw) == 0 {
		return newErr(ErrCodeNoLiquidity, endpoint+": empty response")
	}
	if err := json.Unmarshal(raw[0], out); err != nil {
		return fmt.Errorf("%s: decode entry: %w", endpoint, err)
	}
	return nil
}

// okxQuote is the shared Quote implementation behind both
// per-chain registrations. providerName / providerLabel land in
// Quote.Provider / Quote.ProviderLabel so the UI keeps consistent
// branding regardless of which chain the user is on.
func okxQuote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest, providerName, providerLabel string) (*Quote, error) {
	chainIndex, err := okxChainIndexFor(n)
	if err != nil {
		return nil, newErr(ErrCodeUnsupportedChain, err.Error())
	}
	fromAddr := okxTokenAddrFor(n, req.TokenIn.Address)
	toAddr := okxTokenAddrFor(n, req.TokenOut.Address)

	if req.AmountIn == "" || req.AmountIn == "0" {
		return nil, newErr(ErrCodeInvalidRequest, "okx: amountIn is required and non-zero")
	}

	var entry okxQuoteEntry
	if err := okxCallEntry(ctx, "Crypto/Okx:quote", rest.Param{
		"chainIndex":       chainIndex,
		"fromTokenAddress": fromAddr,
		"toTokenAddress":   toAddr,
		"amount":           req.AmountIn,
		// V6 /quote takes no slippage parameter — slippage applies
		// only at /swap. Pass req.SlippageBps through to the swap
		// call instead.
	}, &entry); err != nil {
		return nil, err
	}

	amountIn, ok := new(big.Int).SetString(entry.FromTokenAmount, 10)
	if !ok {
		amountIn, _ = new(big.Int).SetString(req.AmountIn, 10)
	}
	// When OKX has no route for the pair, the proxy still returns a
	// `[{}]` envelope and the entry decodes into the zero value —
	// every numeric field is the empty string. Distinguish that from
	// a "parse error" so the host sees `no_liquidity` (which the UI
	// downgrades to an advisory) rather than `provider_unavailable`
	// (which surfaces as a hard error). The address / amount echo is
	// useful when forwarding to OKX support.
	if entry.ToTokenAmount == "" || entry.ToTokenAmount == "0" {
		return nil, newErr(ErrCodeNoLiquidity, fmt.Sprintf(
			"okx: no route for %s %s → %s on chain %s",
			req.AmountIn, fromAddr, toAddr, chainIndex))
	}
	amountOut, ok := new(big.Int).SetString(entry.ToTokenAmount, 10)
	if !ok {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf(
			"okx: parse toTokenAmount %q for %s→%s on chain %s",
			entry.ToTokenAmount, fromAddr, toAddr, chainIndex))
	}

	// minReceive: amountOut * (1 - slippage). OKX echoes the
	// minReceiveAmount on /swap, but /quote doesn't carry it, so
	// compute deterministically from SlippageBps for the UI's
	// "minimum received" line.
	slippage := req.SlippageBps
	if slippage == 0 {
		slippage = DefaultSlippageBps
	}
	bpsFactor := big.NewInt(int64(10_000 - slippage))
	minOut := new(big.Int).Mul(amountOut, bpsFactor)
	minOut.Quo(minOut, big.NewInt(10_000))

	// PriceImpact: percent string → fraction. V6 renamed the field
	// from V5's `priceImpactPercentage`; the unit (percent) is the
	// same.
	var priceImpact float64
	if entry.PriceImpactPercent != "" {
		if pf, err := strconv.ParseFloat(entry.PriceImpactPercent, 64); err == nil {
			priceImpact = pf / 100
		}
	}

	// NetworkFee: estimateGasFee is in smallest unit of the chain's
	// native token. For Solana that's lamports (9 decimals); for
	// EVM that's wei (chain's native decimals).
	var networkFee *wltobj.Amount
	if entry.EstimateGasFee != "" {
		if gas, ok := new(big.Int).SetString(entry.EstimateGasFee, 10); ok {
			nativeDec := okxNativeDecimals(n)
			networkFee = wltobj.NewAmountRaw(gas, nativeDec)
		}
	}

	// Route: flatten dexRouterList → []RouteHop. Take the dominant
	// router's first sub-router's dexProtocol list as the venues;
	// share comes from each dexProtocol.percent.
	route := okxBuildRoute(entry.DexRouterList, req.TokenIn.Symbol, req.TokenOut.Symbol)

	q := &Quote{
		Provider:      providerName,
		ProviderLabel: providerLabel,
		Chain:         n.Type,
		TokenIn:       req.TokenIn,
		TokenOut:      req.TokenOut,
		AmountIn:      wltobj.NewAmountRaw(amountIn, req.TokenIn.Decimals),
		AmountOut:     wltobj.NewAmountRaw(amountOut, req.TokenOut.Decimals),
		MinAmountOut:  wltobj.NewAmountRaw(minOut, req.TokenOut.Decimals),
		PriceImpact:   priceImpact,
		SlippageBps:   slippage,
		NetworkFee:    networkFee,
		Route:         route,
	}
	okxApplyPlatformFee(q, entry.PlatformFee, req)

	// EVM allowance check — OKX returns the spender per-chain via
	// /supportedChains. Cache the lookup; same spender for every
	// quote on a given chain.
	if n.Type == "evm" && !okxIsNativeEVMInput(req.TokenIn.Address) {
		spender, serr := okxApproveAddress(ctx, chainIndex)
		if serr == nil && spender != "" {
			q.ApprovalSpender = spender
			q.NeededAllowance = wltobj.NewAmountRaw(new(big.Int).Set(amountIn), req.TokenIn.Decimals)
			current, aerr := readERC20Allowance(ctx, n, fromAddr, acct.GetAddress(), spender)
			if aerr == nil {
				q.CurrentAllowance = wltobj.NewAmountRaw(current, req.TokenIn.Decimals)
				q.RequiresApproval = current.Cmp(amountIn) < 0
			} else {
				q.CurrentAllowance = wltobj.NewAmountRaw(big.NewInt(0), req.TokenIn.Decimals)
				q.RequiresApproval = true
			}
		}
	}

	return q, nil
}

// okxApplyPlatformFee maps the server-echoed feePercent + amount
// onto Quote.FeeBps / ReferralFee for the UI's "Platform fee" line.
// No-op when the chain has no referrer configured (PlatformFee
// omitted from the response).
func okxApplyPlatformFee(q *Quote, fee *okxPlatformFee, req *QuoteRequest) {
	if fee == nil {
		return
	}
	if pct, err := strconv.ParseFloat(fee.Percent, 64); err == nil && pct > 0 {
		q.FeeBps = uint16(pct * 100)
	}
	if amount, ok := new(big.Int).SetString(fee.Amount, 10); ok {
		// `side` is "from" or "to" — the platformFee.amount is in
		// the smallest unit of whichever side the fee is denominated
		// in. Use the appropriate decimals so the UI renders a
		// human-friendly amount.
		dec := req.TokenIn.Decimals
		if fee.Side == "to" {
			dec = req.TokenOut.Decimals
		}
		q.ReferralFee = wltobj.NewAmountRaw(amount, dec)
	}
}

// okxBuildRoute flattens OKX's V6 dexRouterList → libwallet's
// []RouteHop. V6 collapsed the previous router/subRouter tree: each
// entry now carries a single dexProtocol object plus its hop's
// from/to token decoration, so we just walk the list in order. Each
// hop's symbols come from the entry's tokens (falling back to the
// caller-supplied request symbols when the hop omits them); share
// comes from each dexProtocol.percent. Display-only; the underlying
// route is locked in by /swap.
func okxBuildRoute(routers []okxRouter, inSym, outSym string) []RouteHop {
	if len(routers) == 0 {
		return nil
	}
	hops := make([]RouteHop, 0, len(routers))
	for i, r := range routers {
		share := 0.0
		if r.DexProtocol.Percent != "" {
			if pf, err := strconv.ParseFloat(r.DexProtocol.Percent, 64); err == nil {
				share = pf / 100
			}
		}
		// Prefer the hop's own token symbols; only fall back to the
		// caller's overall request symbols when the entry hasn't been
		// populated by OKX (multi-hop intermediates almost always
		// carry their own symbols on V6).
		hopIn := r.FromToken.TokenSymbol
		hopOut := r.ToToken.TokenSymbol
		if hopIn == "" && i == 0 {
			hopIn = inSym
		}
		if hopOut == "" && i == len(routers)-1 {
			hopOut = outSym
		}
		hops = append(hops, RouteHop{
			Venue:     r.DexProtocol.DexName,
			InSymbol:  hopIn,
			OutSymbol: hopOut,
			Share:     share,
		})
	}
	return hops
}

// okxNativeDecimals returns the smallest-unit decimals for n's
// native currency. Solana: 9 (lamports → SOL). EVM: defaults to
// 18, or n.CurrencyDecimals when populated.
func okxNativeDecimals(n *wltnet.Network) int {
	if n.Type == "solana" {
		return 9
	}
	if n.CurrencyDecimals > 0 {
		return n.CurrencyDecimals
	}
	if info, err := n.GetChainInfo(); err == nil {
		return info.NativeCurrency.Decimals
	}
	return 18
}

func okxIsNativeEVMInput(addr string) bool {
	addr = stripChainPrefix(addr)
	return addr == "" || strings.EqualFold(addr, "NATIVE") ||
		strings.EqualFold(addr, okxEVMNativeSentinel)
}

// okxApproveCache caches the EVM ApproveAddress lookup per OKX
// chain id. The address is a router-deployment property — same
// every swap until OKX redeploys; a few-minute TTL is more than
// safe.
var okxApproveCache sync.Map // string (chainId) → okxApproveCacheEntry

type okxApproveCacheEntry struct {
	addr      string
	fetchedAt time.Time
}

const okxApproveCacheTTL = 30 * time.Minute

// okxApproveAddress returns OKX's ERC-20 approve spender contract
// for the given chain index. Uses Crypto/Okx:supportedChains (TTL
// cached). Returns ("", err) on lookup failure — caller treats as
// "spender unknown" and the approval flow degrades gracefully.
func okxApproveAddress(ctx context.Context, chainIndex string) (string, error) {
	if v, ok := okxApproveCache.Load(chainIndex); ok {
		entry := v.(okxApproveCacheEntry)
		if time.Since(entry.fetchedAt) < okxApproveCacheTTL && entry.addr != "" {
			return entry.addr, nil
		}
	}
	var chains []okxSupportedChain
	if err := rest.Apply(ctx, "Crypto/Okx:supportedChains", "GET", nil, &chains); err != nil {
		return "", fmt.Errorf("Crypto/Okx:supportedChains: %w", err)
	}
	for _, c := range chains {
		if c.ChainIndex == chainIndex {
			okxApproveCache.Store(chainIndex, okxApproveCacheEntry{
				addr:      c.DexTokenApproveAddress,
				fetchedAt: time.Now(),
			})
			return c.DexTokenApproveAddress, nil
		}
	}
	return "", fmt.Errorf("okx: chain %s not in supportedChains", chainIndex)
}

// ── Execute (Solana) ────────────────────────────────────────────

// okxDecodeSolanaTxData decodes OKX's Solana tx.data payload, which
// comes back in one of two encodings depending on the route:
//
//   - base58 — the encoding the DEX aggregator /swap endpoint
//     documents for Solana, returned for most routes.
//   - base64 (standard or URL-safe `-_`) — seen on some routes,
//     notably the larger v0/address-lookup-table transactions
//     (>~1 KB), historically surfacing as `illegal base64 at input
//     <n>` before we normalized the alphabet.
//
// The two alphabets overlap: every base58 string is also a
// syntactically valid base64 string, so a base64 decode of a base58
// payload SUCCEEDS but yields garbage — downstream this manifested as
// `signatures truncated: declared 79, tx only 708 bytes`, the garbage
// leading byte read as a 79-signature count. We therefore decode under
// each candidate scheme and return the first whose bytes parse as a
// structurally valid Solana transaction (looksLikeSolanaTx).
func okxDecodeSolanaTxData(s string) ([]byte, error) {
	candidates := make([][]byte, 0, 2)
	// base58 first — the documented /swap encoding. Decode only
	// succeeds when every char is in the base58 alphabet, so genuine
	// base64 payloads (with +/=/-/_) never produce a base58 candidate.
	if raw, err := base58.Bitcoin.Decode(s); err == nil && len(raw) > 0 {
		candidates = append(candidates, raw)
	}
	// base64 / base64url — normalize the alphabet and re-pad.
	b := strings.ReplaceAll(s, "-", "+")
	b = strings.ReplaceAll(b, "_", "/")
	if pad := len(b) % 4; pad != 0 {
		b += strings.Repeat("=", 4-pad)
	}
	if raw, err := base64.StdEncoding.DecodeString(b); err == nil {
		candidates = append(candidates, raw)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("tx.data is neither valid base58 nor base64")
	}
	// Prefer a candidate that parses as a Solana transaction; this is
	// what disambiguates a base58 payload from its garbage base64 twin.
	for _, raw := range candidates {
		if looksLikeSolanaTx(raw) {
			return raw, nil
		}
	}
	// None validated — hand back the first decode so the caller emits a
	// descriptive structural error rather than a vague decode failure.
	return candidates[0], nil
}

// okxSolanaBroadcastAttempts bounds the fetch→sign→broadcast retries. Each
// attempt re-fetches the swap tx so it carries a FRESH blockhash: the
// blockhash is frozen into the message at sign time, so the only cure for a
// stale/expired one is to rebuild and re-sign. The keys are already in hand
// (the user approved before Execute was called), so retries need no further
// user interaction.
const okxSolanaBroadcastAttempts = 3

func okxExecuteSolana(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	chainIndex, err := okxChainIndexFor(n)
	if err != nil {
		return nil, newErr(ErrCodeUnsupportedChain, err.Error())
	}

	var lastErr error
	for attempt := 1; attempt <= okxSolanaBroadcastAttempts; attempt++ {
		tx, err := okxFetchSwapTx(ctx, n, acct, q)
		if err != nil {
			return nil, err
		}
		if tx.Data == "" {
			return nil, newErr(ErrCodeProviderUnavailable, "okx: solana swap returned empty tx.data")
		}
		rawTx, err := okxDecodeSolanaTxData(tx.Data)
		if err != nil {
			return nil, newErr(ErrCodeProviderUnavailable, "okx: decode solana tx.data: "+err.Error())
		}
		signed, sig, err := solanaSplicingSignLocal(ctx, acct, keys, rawTx)
		if err != nil {
			return nil, fmt.Errorf("sign okx solana transaction: %w", err)
		}

		// Broadcast through OKX rather than our own RPC sendTransaction:
		// OKX's node knows the blockhash it just embedded (so there's no
		// node-lag "Blockhash not found" at preflight) and lands the tx via
		// its staked submission path. Solana's wire format for the broadcast
		// endpoint is base64.
		bres, err := okxBroadcastSwapTx(ctx, chainIndex, acct.GetAddress(), q.QuoteId,
			base64.StdEncoding.EncodeToString(signed), false)
		if err != nil {
			lastErr = fmt.Errorf("okx solana broadcastTransaction: %w", err)
			if attempt < okxSolanaBroadcastAttempts && isRetryableSolanaBroadcast(err) {
				wltlog.Errorf("swap: okx broadcast attempt %d/%d failed, retrying with fresh blockhash: %s",
					attempt, okxSolanaBroadcastAttempts, err)
				continue
			}
			return nil, lastErr
		}

		// The Solana txid is the slot-0 signature we just spliced; prefer
		// OKX's reported hash when present but fall back to the local one so
		// the UI always has a working explorer link without polling.
		hash := solanaBase58(sig)
		if bres.TxHash != "" {
			hash = bres.TxHash
		}

		// Cheap, single best-effort confirm: if OKX already considers the
		// order terminally failed (e.g. it couldn't land before expiry),
		// retry with a fresh blockhash rather than report a phantom success.
		// Pending/success/not-yet-seen all proceed — the host tracks final
		// settlement via Crypto/Okx:orderStatus(orderId).
		if bres.OrderId != "" {
			if st := okxOrderFailed(ctx, chainIndex, acct.GetAddress(), bres.OrderId); st != "" {
				lastErr = newErr(ErrCodeProviderUnavailable,
					fmt.Sprintf("okx reported swap %s (orderId %s)", st, bres.OrderId))
				if attempt < okxSolanaBroadcastAttempts {
					wltlog.Errorf("swap: okx order %s %s, retrying with fresh blockhash", bres.OrderId, st)
					continue
				}
				return nil, lastErr
			}
		}

		return &SwapResult{
			QuoteId:  q.QuoteId,
			Provider: q.Provider,
			Chain:    "solana",
			Hash:     hash,
			OrderId:  bres.OrderId,
			URL:      n.TransactionUrl(hash),
			Quote:    q,
		}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("okx solana broadcast: exhausted %d attempts", okxSolanaBroadcastAttempts)
	}
	return nil, lastErr
}

// okxBroadcastResult is the entry shape returned by
// Crypto/Okx:broadcastTransaction. TxHash may be empty briefly right after
// broadcast; OrderId is the durable handle for orderStatus polling.
type okxBroadcastResult struct {
	OrderId    string `json:"orderId"`
	ChainIndex string `json:"chainIndex"`
	Address    string `json:"address"`
	TxHash     string `json:"txHash"`
}

// okxOrderStatusResult is the entry shape returned by Crypto/Okx:orderStatus.
type okxOrderStatusResult struct {
	OrderId string `json:"orderId"`
	TxHash  string `json:"txHash"`
	Status  string `json:"status"` // pending|success|failed (OKX terminology)
}

// okxBroadcastSwapTx broadcasts a signed swap tx through OKX and returns the
// resulting order handle. signedTx is base64 (Solana) or hex (EVM); mev is
// honored EVM-side only (Solana ignores it).
func okxBroadcastSwapTx(ctx context.Context, chainIndex, address, quoteId, signedTx string, mev bool) (*okxBroadcastResult, error) {
	body := rest.Param{
		"quoteId":    quoteId,
		"chainIndex": chainIndex,
		"address":    address,
		"signedTx":   signedTx,
	}
	if mev {
		body["enableMevProtection"] = true
	}
	var raw []json.RawMessage
	if err := rest.Apply(ctx, "Crypto/Okx:broadcastTransaction", "POST", body, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: broadcastTransaction returned empty response")
	}
	var res okxBroadcastResult
	if err := json.Unmarshal(raw[0], &res); err != nil {
		return nil, fmt.Errorf("okx: decode broadcast entry: %w", err)
	}
	return &res, nil
}

// okxOrderFailed does a single best-effort orderStatus check right after
// broadcast. It returns the status string only when OKX already reports the
// order terminally failed — so the caller can retry/surface it instead of
// claiming success; "" means pending/success/unknown/not-yet-seen. Errors are
// swallowed (it's advisory): final settlement is tracked host-side.
func okxOrderFailed(ctx context.Context, chainIndex, address, orderId string) string {
	var raw []json.RawMessage
	if err := rest.Apply(ctx, "Crypto/Okx:orderStatus", "GET", rest.Param{
		"chainIndex": chainIndex,
		"address":    address,
		"orderId":    orderId,
	}, &raw); err != nil || len(raw) == 0 {
		return ""
	}
	var res okxOrderStatusResult
	if err := json.Unmarshal(raw[0], &res); err != nil {
		return ""
	}
	if strings.EqualFold(res.Status, "failed") || strings.EqualFold(res.Status, "fail") {
		return res.Status
	}
	return ""
}

// isRetryableSolanaBroadcast reports whether an OKX broadcast error is the
// kind a fresh blockhash + re-sign can cure (stale/expired blockhash, preflight
// simulation miss, transient timeout) versus a terminal one (e.g. insufficient
// balance) that retrying would only waste a signing round-trip on.
func isRetryableSolanaBroadcast(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, m := range []string{
		"blockhash", "block height", "expired", "simulation failed",
		"-32002", "not found", "timeout", "timed out", "deadline",
	} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// ── Execute (EVM) ───────────────────────────────────────────────

func okxExecuteEVM(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	tx, err := okxFetchSwapTx(ctx, n, acct, q)
	if err != nil {
		return nil, err
	}
	if tx.To == "" || tx.Data == "" {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: evm swap returned empty tx")
	}

	nonce, err := fetchEVMNonce(ctx, n, acct.GetAddress())
	if err != nil {
		return nil, err
	}

	nativeDec := okxNativeDecimals(n)
	valueI, ok := new(big.Int).SetString(tx.Value, 10)
	if !ok {
		valueI = big.NewInt(0)
	}
	data := tx.Data
	if !strings.HasPrefix(data, "0x") {
		data = "0x" + data
	}
	gasU, err := strconv.ParseUint(tx.Gas, 10, 64)
	if err != nil {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: parse tx.gas "+tx.Gas)
	}
	// OKX guidance: raise gas by ~50% before broadcasting to leave
	// headroom for state changes between quote and confirmation.
	gasU = gasU * 3 / 2

	gasPriceI, ok := new(big.Int).SetString(tx.GasPrice, 10)
	if !ok {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: parse tx.gasPrice "+tx.GasPrice)
	}

	wTx := &wlttx.Transaction{
		Type:     "evm",
		From:     acct.GetAddress(),
		To:       tx.To,
		Value:    wltobj.NewAmountRaw(valueI, nativeDec),
		Data:     data,
		Gas:      gasU,
		GasPrice: gasPriceI.String(),
		Nonce:    nonce,
		Format:   "legacy",
		Network:  n.Id,
	}

	// Broadcast every EVM swap through OKX with MEV protection on. We sign
	// locally, then hand the raw signed tx to OKX rather than
	// eth_sendRawTransaction'ing it ourselves: OKX routes it through a
	// MEV-protected (private) mempool where supported and silently ignores
	// the flag on chains that don't, so it's safe to enable unconditionally.
	chainIndex, err := okxChainIndexFor(n)
	if err != nil {
		return nil, newErr(ErrCodeUnsupportedChain, err.Error())
	}
	rawHex, hash, err := wTx.SignEVMRaw(ctx, keys)
	if err != nil {
		return nil, err
	}
	bres, err := okxBroadcastSwapTx(ctx, chainIndex, acct.GetAddress(), q.QuoteId, rawHex, true)
	if err != nil {
		return nil, fmt.Errorf("okx evm broadcastTransaction: %w", err)
	}
	if bres.TxHash != "" {
		hash = bres.TxHash
	}
	return &SwapResult{
		QuoteId:  q.QuoteId,
		Provider: q.Provider,
		Chain:    "evm",
		Hash:     hash,
		OrderId:  bres.OrderId,
		URL:      n.TransactionUrl(hash),
		Quote:    q,
	}, nil
}

// okxFetchSwapTx hits Crypto/Okx:swap once and returns the inner tx
// block. Shared between the Solana and EVM execute paths.
func okxFetchSwapTx(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote) (*okxSwapTx, error) {
	chainIndex, err := okxChainIndexFor(n)
	if err != nil {
		return nil, newErr(ErrCodeUnsupportedChain, err.Error())
	}
	fromAddr := okxTokenAddrFor(n, q.TokenIn.Address)
	toAddr := okxTokenAddrFor(n, q.TokenOut.Address)

	amountInRaw := "0"
	if q.AmountIn != nil && q.AmountIn.Value() != nil {
		amountInRaw = q.AmountIn.Value().String()
	}

	var entry okxSwapEntry
	if err := okxCallEntry(ctx, "Crypto/Okx:swap", rest.Param{
		"chainIndex":        chainIndex,
		"fromTokenAddress":  fromAddr,
		"toTokenAddress":    toAddr,
		"amount":            amountInRaw,
		"userWalletAddress": acct.GetAddress(),
		// V6 renamed the param from `slippage` (fraction) to
		// `slippagePercent` (percent units, 0.5 = 0.5%).
		"slippagePercent": okxSlippagePercent(q.SlippageBps),
	}, &entry); err != nil {
		return nil, err
	}
	return &entry.Tx, nil
}

// solanaBase58 — thin alias so the OKX Solana path can re-use the
// existing base58 helper without poking at the import directly in
// the Execute method body.
func solanaBase58(data []byte) string {
	return base58.Bitcoin.Encode(data)
}
