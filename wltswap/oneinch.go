package wltswap

// 1inch Classic Swap adapter (EVM).
//
// Flow:
//   GET /swap/v6.0/{chainId}/swap → { tx: {to, data, value, gas, gasPrice}, ... }
//   Build a wlttx.Transaction with the returned fields, sign and
//   broadcast via the existing EVM path (Transaction.SignAndSend).
//
// Limitation in v1: ERC-20 input tokens require a prior `approve`
// of 1inch's allowance target. 1inch will surface an error in /swap
// if allowance is missing; apps must drive the approval tx
// separately via Transaction:signAndSend before calling Swap:execute.

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wlttx"
)

type oneInchProvider struct{}

func (oneInchProvider) Name() string  { return "1inch" }
func (oneInchProvider) Chain() string { return "evm" }

// OneInchNativeSentinel is the address 1inch uses in their API to
// mean "the chain's native currency" (ETH on mainnet, BNB on BSC,
// MATIC on Polygon, …).
const OneInchNativeSentinel = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

type oneInchSwapResponse struct {
	ToAmount string          `json:"dstAmount"`
	Tx       oneInchTxObject `json:"tx"`
}

type oneInchTxObject struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`    // decimal (wei)
	Gas      uint64 `json:"gas"`
	GasPrice string `json:"gasPrice"` // decimal
}

// oneInchBlob caches the raw /swap response for Execute to consume.
type oneInchBlob struct {
	Tx oneInchTxObject
}

func (oneInchProvider) Quote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error) {
	if n.Type != "evm" {
		return nil, newErr(ErrCodeUnsupportedChain, "1inch only supports EVM")
	}
	if OneInchAPIKey == "" {
		return nil, newErr(ErrCodeMissingAPIKey,
			"1inch API key is not configured in this build — populate wltswap.OneInchAPIKey to enable EVM swaps")
	}

	src := oneInchTokenOrSentinel(req.TokenIn.Address)
	dst := oneInchTokenOrSentinel(req.TokenOut.Address)

	// 1inch expresses slippage as a percentage (0-50) not bps.
	slippagePct := float64(req.SlippageBps) / 100.0
	// Fee is 0-3 in percent; referrer is 0x-prefixed address.
	feePct := float64(DefaultFeeBps) / 100.0

	endpoint := fmt.Sprintf("%s/%s/swap", OneInchBaseURL, n.ChainId)
	query := url.Values{}
	query.Set("src", src)
	query.Set("dst", dst)
	query.Set("amount", req.AmountIn)
	query.Set("from", acct.GetAddress())
	query.Set("slippage", strconvFmtFloat(slippagePct))
	query.Set("referrer", OneInchReferrer)
	query.Set("fee", strconvFmtFloat(feePct))
	query.Set("disableEstimate", "false")
	query.Set("allowPartialFill", "false")

	var resp oneInchSwapResponse
	hdr := func(h http.Header) {
		h.Set("Authorization", "Bearer "+OneInchAPIKey)
	}
	if err := httpGetJSON(ctx, endpoint, query, hdr, &resp); err != nil {
		return nil, err
	}
	if resp.Tx.To == "" || resp.Tx.Data == "" {
		return nil, newErr(ErrCodeNoLiquidity, "1inch returned no swap transaction")
	}

	amountIn, _ := new(big.Int).SetString(req.AmountIn, 10)
	amountOut, ok := new(big.Int).SetString(resp.ToAmount, 10)
	if !ok {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("parse 1inch dstAmount %q", resp.ToAmount))
	}
	// Worst-case amount out, after slippage.
	bpsFactor := big.NewInt(int64(10_000 - req.SlippageBps))
	minOut := new(big.Int).Mul(amountOut, bpsFactor)
	minOut.Quo(minOut, big.NewInt(10_000))

	q := &Quote{
		Provider:     "1inch",
		Chain:        "evm",
		TokenIn:      req.TokenIn,
		TokenOut:     req.TokenOut,
		AmountIn:     wltobj.NewAmountRaw(amountIn, req.TokenIn.Decimals),
		AmountOut:    wltobj.NewAmountRaw(amountOut, req.TokenOut.Decimals),
		MinAmountOut: wltobj.NewAmountRaw(minOut, req.TokenOut.Decimals),
		FeeBps:       DefaultFeeBps,
		SlippageBps:  req.SlippageBps,
		providerBlob: &oneInchBlob{Tx: resp.Tx},
	}

	// Allowance check — skip for native input (ETH swaps attach
	// value directly, no approve needed). The spender is the
	// router address 1inch returned in tx.to.
	if !isNativeEVMInput(req.TokenIn.Address) {
		spender := resp.Tx.To
		current, err := readERC20Allowance(ctx, n, req.TokenIn.Address, acct.GetAddress(), spender)
		q.ApprovalSpender = spender
		q.NeededAllowance = wltobj.NewAmountRaw(new(big.Int).Set(amountIn), req.TokenIn.Decimals)
		if err == nil {
			q.CurrentAllowance = wltobj.NewAmountRaw(current, req.TokenIn.Decimals)
			q.RequiresApproval = current.Cmp(amountIn) < 0
		} else {
			// Unknown allowance — err on the side of "needs
			// approval" so the app surfaces a confirm step.
			q.CurrentAllowance = wltobj.NewAmountRaw(big.NewInt(0), req.TokenIn.Decimals)
			q.RequiresApproval = true
		}
	}

	return q, nil
}

// isNativeEVMInput reports whether the token input is the chain's
// native currency (no allowance ever needed).
func isNativeEVMInput(addr string) bool {
	if addr == "" || addr == "NATIVE" {
		return true
	}
	return strings.EqualFold(addr, OneInchNativeSentinel)
}

func (oneInchProvider) Execute(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	blob, ok := q.providerBlob.(*oneInchBlob)
	if !ok || blob == nil {
		return nil, newErr(ErrCodeQuoteNotFound, "quote is missing its 1inch payload")
	}
	txo := blob.Tx

	// Build a wlttx.Transaction that the existing EVM sign+send
	// pipeline can consume. We skip Transaction.Validate because
	// it would re-fetch gas / gasPrice and overwrite 1inch's
	// carefully-computed values. We still need a nonce, which
	// Validate would normally fill — fetch it explicitly.
	nonce, err := fetchEVMNonce(ctx, n, acct.GetAddress())
	if err != nil {
		return nil, err
	}

	// Value: 1inch returns a decimal-wei string; wltobj.Amount
	// expects raw big.Int with the chain's native decimals.
	info, err := n.GetChainInfo()
	if err != nil {
		return nil, err
	}
	decimals := n.CurrencyDecimals
	if decimals == 0 {
		decimals = info.NativeCurrency.Decimals
	}
	valueI, ok := new(big.Int).SetString(txo.Value, 10)
	if !ok {
		valueI = big.NewInt(0)
	}

	// Data: 1inch already returns 0x-prefixed hex. wlttx expects
	// the same shape, so pass through.
	data := txo.Data
	if !strings.HasPrefix(data, "0x") {
		data = "0x" + data
	}

	gasPriceI, ok := new(big.Int).SetString(txo.GasPrice, 10)
	if !ok {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("parse 1inch gasPrice %q", txo.GasPrice))
	}

	tx := &wlttx.Transaction{
		Type:     "evm",
		From:     acct.GetAddress(),
		To:       txo.To,
		Value:    wltobj.NewAmountRaw(valueI, decimals),
		Data:     data,
		Gas:      txo.Gas,
		GasPrice: gasPriceI.String(),
		Nonce:    nonce,
		Format:   "legacy", // 1inch returns a single gasPrice
		Network:  n.Id,
	}

	if err := tx.SignAndSend(ctx, keys); err != nil {
		return nil, err
	}

	return &SwapResult{
		QuoteId:  q.QuoteId,
		Provider: "1inch",
		Chain:    "evm",
		Hash:     tx.Hash,
		URL:      tx.URL,
		Quote:    q,
	}, nil
}

// oneInchTokenOrSentinel translates the package's "NATIVE" marker to
// 1inch's native-sentinel address.
func oneInchTokenOrSentinel(addr string) string {
	if addr == "NATIVE" || addr == "" {
		return OneInchNativeSentinel
	}
	return addr
}

// fetchEVMNonce pulls the sender's pending nonce. Uses the same
// ethrpc.ReadUint64 helper as wlttx/transaction.go:324.
func fetchEVMNonce(ctx context.Context, n *wltnet.Network, address string) (uint64, error) {
	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	v, err := ethrpc.ReadUint64(n.DoRPCCtx(rpcCtx, "eth_getTransactionCount", address, "pending"))
	if err != nil {
		return 0, fmt.Errorf("eth_getTransactionCount: %w", err)
	}
	return v, nil
}

// strconvFmtFloat formats a float as a short decimal string without
// trailing zeroes (e.g. 0.5 → "0.5", 1 → "1"). Avoids the
// scientific notation strconv.FormatFloat picks for small values.
func strconvFmtFloat(f float64) string {
	// Cheap enough — bounded range (0–50 for slippage, 0–3 for fee).
	return fmt.Sprintf("%g", f)
}
