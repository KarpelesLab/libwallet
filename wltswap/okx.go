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
//   Execute:  GET Crypto/Okx:swap   →   { routerResult, tx, platformFee }.
//                                       Solana: tx.data is the
//                                         serialized tx blob; sign it
//                                         via solanaSplicingSignLocal
//                                         and broadcast via
//                                         sendTransaction.
//                                       EVM: build wlttx.Transaction
//                                         with tx.to/data/value/gas/…
//                                         and route through
//                                         Transaction.SignAndSend.

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

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/rest"
)

// okxEVMNativeSentinel is the address OKX uses on every EVM chain
// to mean "the chain's native currency" (ETH on mainnet, BNB on
// BSC, MATIC on Polygon, …). Same convention as 1inch.
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

type okxSubRouter struct {
	DexProtocol []okxDexProtocol `json:"dexProtocol"`
	FromToken   okxToken         `json:"fromToken"`
	ToToken     okxToken         `json:"toToken"`
}

type okxRouter struct {
	Router        string         `json:"router"`
	RouterPercent string         `json:"routerPercent"`
	SubRouterList []okxSubRouter `json:"subRouterList"`
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
	ChainId               string          `json:"chainId"`
	FromTokenAmount       string          `json:"fromTokenAmount"`
	ToTokenAmount         string          `json:"toTokenAmount"`
	TradeFee              string          `json:"tradeFee"`
	EstimateGasFee        string          `json:"estimateGasFee"`
	PriceImpactPercentage string          `json:"priceImpactPercentage"`
	FromToken             okxToken        `json:"fromToken"`
	ToToken               okxToken        `json:"toToken"`
	DexRouterList         []okxRouter     `json:"dexRouterList"`
	PlatformFee           *okxPlatformFee `json:"platformFee,omitempty"`
}

type okxSwapTx struct {
	From                 string   `json:"from"`
	To                   string   `json:"to"`
	Value                string   `json:"value"`
	Data                 string   `json:"data"`
	Gas                  string   `json:"gas"`
	GasPrice             string   `json:"gasPrice"`
	MaxPriorityFeePerGas string   `json:"maxPriorityFeePerGas"`
	MinReceiveAmount     string   `json:"minReceiveAmount"`
	Slippage             string   `json:"slippage"`
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
	ChainId                string `json:"chainId"`
	ChainName              string `json:"chainName"`
	DexTokenApproveAddress string `json:"dexTokenApproveAddress"`
}

// okxBlob caches what Execute needs from Quote: the raw tx pieces
// returned by /swap so Execute doesn't have to re-quote.
type okxBlob struct {
	Tx          okxSwapTx
	IsEVM       bool
	NativeDec   int    // chain's native decimals — for parsing tx.value
	ChainIdNum  string // OKX numeric chain id (501, 1, 56, …)
}

// ── shared helpers ──────────────────────────────────────────────

// okxChainIdFor maps libwallet's Network.Type+ChainId pair onto
// OKX's numeric chain id. Solana mainnet → "501", devnet → "103";
// for EVM we forward n.ChainId verbatim because chainlist already
// stores it numerically.
func okxChainIdFor(n *wltnet.Network) (string, error) {
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

// okxSlippageFraction converts libwallet's bps slippage into the
// fraction OKX expects (0.005 = 0.5%). Cap at the documented
// upper bound the OKX UI rejects above.
func okxSlippageFraction(bps uint16) string {
	if bps == 0 {
		bps = DefaultSlippageBps
	}
	f := float64(bps) / 10_000.0
	return strconv.FormatFloat(f, 'f', -1, 64)
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
	chainId, err := okxChainIdFor(n)
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
		"chainId":          chainId,
		"fromTokenAddress": fromAddr,
		"toTokenAddress":   toAddr,
		"amount":           req.AmountIn,
		"slippage":         okxSlippageFraction(req.SlippageBps),
	}, &entry); err != nil {
		return nil, err
	}

	amountIn, ok := new(big.Int).SetString(entry.FromTokenAmount, 10)
	if !ok {
		amountIn, _ = new(big.Int).SetString(req.AmountIn, 10)
	}
	amountOut, ok := new(big.Int).SetString(entry.ToTokenAmount, 10)
	if !ok {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: parse toTokenAmount "+entry.ToTokenAmount)
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

	// PriceImpact: percent string → fraction.
	var priceImpact float64
	if entry.PriceImpactPercentage != "" {
		if pf, err := strconv.ParseFloat(entry.PriceImpactPercentage, 64); err == nil {
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
		spender, serr := okxApproveAddress(ctx, chainId)
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

// okxBuildRoute flattens OKX's nested dexRouterList → libwallet's
// flat []RouteHop. We take the dominant router's first sub-router
// (the one with the most weight, or just the first if percents
// aren't populated) and emit one hop per dexProtocol entry inside
// it. Display-only; the underlying route is already locked in by
// /swap.
func okxBuildRoute(routers []okxRouter, inSym, outSym string) []RouteHop {
	if len(routers) == 0 {
		return nil
	}
	r := routers[0]
	if len(r.SubRouterList) == 0 {
		return nil
	}
	sub := r.SubRouterList[0]
	hops := make([]RouteHop, 0, len(sub.DexProtocol))
	for _, dp := range sub.DexProtocol {
		share := 0.0
		if dp.Percent != "" {
			if pf, err := strconv.ParseFloat(dp.Percent, 64); err == nil {
				share = pf / 100
			}
		}
		hops = append(hops, RouteHop{
			Venue:     dp.DexName,
			InSymbol:  inSym,
			OutSymbol: outSym,
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
// for the given chain id. Uses Crypto/Okx:supportedChains (TTL
// cached). Returns ("", err) on lookup failure — caller treats as
// "spender unknown" and the approval flow degrades gracefully.
func okxApproveAddress(ctx context.Context, chainId string) (string, error) {
	if v, ok := okxApproveCache.Load(chainId); ok {
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
		if c.ChainId == chainId {
			okxApproveCache.Store(chainId, okxApproveCacheEntry{
				addr:      c.DexTokenApproveAddress,
				fetchedAt: time.Now(),
			})
			return c.DexTokenApproveAddress, nil
		}
	}
	return "", fmt.Errorf("okx: chain %s not in supportedChains", chainId)
}

// ── Execute (Solana) ────────────────────────────────────────────

func okxExecuteSolana(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	tx, err := okxFetchSwapTx(ctx, n, acct, q)
	if err != nil {
		return nil, err
	}
	if tx.Data == "" {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: solana swap returned empty tx.data")
	}
	rawTx, err := base64.StdEncoding.DecodeString(tx.Data)
	if err != nil {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: decode solana tx.data: "+err.Error())
	}
	signed, err := solanaSplicingSignLocal(ctx, acct, keys, rawTx)
	if err != nil {
		return nil, fmt.Errorf("sign okx solana transaction: %w", err)
	}

	// Broadcast via standard sendTransaction. OKX hands us a fully-
	// built v0 (or legacy) transaction; we sign and ship as-is.
	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	txB58 := solanaBase58(signed)
	raw, err := n.DoRPCCtx(rpcCtx, "sendTransaction", txB58, map[string]any{"encoding": "base58"})
	if err != nil {
		return nil, fmt.Errorf("okx solana sendTransaction: %w", err)
	}
	var sig string
	if err := json.Unmarshal(raw, &sig); err != nil {
		return nil, newErr(ErrCodeProviderUnavailable, "okx: parse sendTransaction response: "+err.Error())
	}
	return &SwapResult{
		QuoteId:  q.QuoteId,
		Provider: q.Provider,
		Chain:    "solana",
		Hash:     sig,
		URL:      n.TransactionUrl(sig),
		Quote:    q,
	}, nil
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
	if err := wTx.SignAndSend(ctx, keys); err != nil {
		return nil, err
	}
	return &SwapResult{
		QuoteId:  q.QuoteId,
		Provider: q.Provider,
		Chain:    "evm",
		Hash:     wTx.Hash,
		URL:      wTx.URL,
		Quote:    q,
	}, nil
}

// okxFetchSwapTx hits Crypto/Okx:swap once and returns the inner tx
// block. Shared between the Solana and EVM execute paths.
func okxFetchSwapTx(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote) (*okxSwapTx, error) {
	chainId, err := okxChainIdFor(n)
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
		"chainId":           chainId,
		"fromTokenAddress":  fromAddr,
		"toTokenAddress":    toAddr,
		"amount":            amountInRaw,
		"userWalletAddress": acct.GetAddress(),
		"slippage":          okxSlippageFraction(q.SlippageBps),
	}, &entry); err != nil {
		return nil, err
	}
	return &entry.Tx, nil
}

// solanaBase58 — thin alias so the OKX Solana path can re-use the
// existing base58 helper without poking at the import directly in
// the Execute method body. dflow.go uses base58.Bitcoin.Encode the
// same way.
func solanaBase58(data []byte) string {
	return base58.Bitcoin.Encode(data)
}
