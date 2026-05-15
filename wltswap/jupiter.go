package wltswap

// Jupiter Ultra adapter.
//
// Flow:
//  GET  /ultra/v1/order   → { transaction (b64), requestId, ... }
//  (we sign the transaction's message locally)
//  POST /ultra/v1/execute → { signature, status, ... }
//
// Jupiter returns a transaction with the account/instructions
// pre-built and signature slots allocated (zeroed for the user's
// fee-payer slot). We parse the wire format to locate where the
// message begins, sign those bytes with the user's Ed25519 key via
// the existing TSS pipeline, splice the signature back into slot 0,
// and post the result to /execute.
//
// /order is a GET with all parameters in the query string —
// Jupiter responds with HTTP 404 to a POST. /execute is a POST
// because the signed-transaction blob doesn't fit a query string.

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
)

type jupiterProvider struct{}

func (jupiterProvider) Name() string  { return "jupiter_ultra" }
func (jupiterProvider) Chain() string { return "solana" }

// Response shape — only the fields we read. Jupiter Ultra /order is
// a GET so the request shape is just url.Values built inline below.
//
// Error fields can be populated even on HTTP 200: an "Insufficient
// funds" route surfaces as a 200 with `transaction:""`,
// `errorCode:1`, `errorMessage:"Insufficient funds"`. Surface those
// to the caller instead of the generic ErrCodeNoLiquidity we used
// to return for any empty-transaction response.
type jupiterOrderResponse struct {
	Transaction    string             `json:"transaction"`
	RequestId      string             `json:"requestId"`
	InAmount       string             `json:"inAmount"`
	OutAmount      string             `json:"outAmount"`
	OtherAmount    string             `json:"otherAmountThreshold"` // min out w/ slippage
	SlippageBps    uint16             `json:"slippageBps"`
	PriceImpactPct string             `json:"priceImpactPct"`
	RoutePlan      []jupiterRoutePlan `json:"routePlan"`
	SwapType       string             `json:"swapType"`

	// Per-order errors that ride along with HTTP 200.
	ErrorCode    int    `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	Error        string `json:"error,omitempty"`
}

type jupiterRoutePlan struct {
	SwapInfo jupiterSwapInfo `json:"swapInfo"`
	Percent  float64         `json:"percent"`
}

type jupiterSwapInfo struct {
	AmmKey      string `json:"ammKey"`
	Label       string `json:"label"`
	InputMint   string `json:"inputMint"`
	OutputMint  string `json:"outputMint"`
	InAmount    string `json:"inAmount"`
	OutAmount   string `json:"outAmount"`
	FeeAmount   string `json:"feeAmount"`
	FeeMint     string `json:"feeMint"`
}

type jupiterExecuteRequest struct {
	SignedTransaction string `json:"signedTransaction"`
	RequestId         string `json:"requestId"`
}

type jupiterExecuteResponse struct {
	Signature string `json:"signature"`
	Status    string `json:"status"`
	// Error fields — presence means something went wrong even on 200.
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// jupiterBlob is cached in the Quote.providerBlob for later use by
// Execute. Holds exactly what we need to send back to /execute.
type jupiterBlob struct {
	RawTx     []byte // decoded base64 — ready for sig-splicing
	RequestId string
}

func jupiterHeader() func(http.Header) {
	return func(h http.Header) {
		h.Set("x-api-key", JupiterAPIKey)
	}
}

func (jupiterProvider) Quote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error) {
	if n.Type != "solana" {
		return nil, newErr(ErrCodeUnsupportedChain, "Jupiter Ultra only supports Solana")
	}

	inMint := solanaNativeMintOrAddr(req.TokenIn.Address)
	outMint := solanaNativeMintOrAddr(req.TokenOut.Address)

	resp, feeWaived, err := jupiterFetchOrderWithRetry(ctx, inMint, outMint, req.AmountIn, acct.GetAddress(), req.SlippageBps)
	if err != nil {
		return nil, err
	}
	// jupiterFetchOrderWithRetry guarantees Transaction + RequestId
	// are populated on a non-error return.
	rawTx, err := base64.StdEncoding.DecodeString(resp.Transaction)
	if err != nil {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("decode Jupiter transaction: %v", err))
	}

	amountOut, ok := new(big.Int).SetString(resp.OutAmount, 10)
	if !ok {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("parse outAmount %q", resp.OutAmount))
	}
	var minOut *big.Int
	if resp.OtherAmount != "" {
		minOut, _ = new(big.Int).SetString(resp.OtherAmount, 10)
	}
	if minOut == nil {
		minOut = new(big.Int).Set(amountOut)
	}
	var amountIn *big.Int
	if resp.InAmount != "" {
		amountIn, _ = new(big.Int).SetString(resp.InAmount, 10)
	}
	if amountIn == nil {
		amountIn, _ = new(big.Int).SetString(req.AmountIn, 10)
	}

	priceImpact := parseFloat(resp.PriceImpactPct)

	route := make([]RouteHop, 0, len(resp.RoutePlan))
	for _, p := range resp.RoutePlan {
		route = append(route, RouteHop{
			Venue: p.SwapInfo.Label,
			Share: p.Percent / 100,
		})
	}
	slippage := resp.SlippageBps
	if slippage == 0 {
		slippage = req.SlippageBps
	}

	// Quote.FeeBps and Quote.ReferralFee reflect what we actually
	// asked Jupiter for. When the no-fee retry kicked in (feeWaived),
	// we collected nothing and the host should reflect that on the
	// approval sheet ("no platform fee on this swap").
	feeBps := uint16(DefaultFeeBps)
	if feeWaived {
		feeBps = 0
	}
	q := &Quote{
		Provider:      "jupiter_ultra",
		ProviderLabel: "Jupiter Ultra",
		Chain:         "solana",
		TokenIn:       req.TokenIn,
		TokenOut:      req.TokenOut,
		AmountIn:      wltobj.NewAmountRaw(amountIn, req.TokenIn.Decimals),
		AmountOut:     wltobj.NewAmountRaw(amountOut, req.TokenOut.Decimals),
		MinAmountOut:  wltobj.NewAmountRaw(minOut, req.TokenOut.Decimals),
		PriceImpact:   priceImpact,
		FeeBps:        feeBps,
		SlippageBps:   slippage,
		ReferralFee:   computeReferralFee(amountIn, feeBps, req.TokenIn.Decimals),
		// Solana base fee is 5000 lamports; v1 doesn't surface
		// ComputeBudget priority fees the Jupiter tx may have set.
		NetworkFee:   wltobj.NewAmountRaw(big.NewInt(5000), 9),
		Route:        route,
		providerBlob: &jupiterBlob{RawTx: rawTx, RequestId: resp.RequestId},
	}
	return q, nil
}

// jupiterFetchOrderWithRetry hits Jupiter Ultra's /order endpoint
// once with the platform referralFee set, and on the specific
// "Failed to get quotes" no-route response retries once without the
// fee. Returns the successful response, a flag indicating whether
// the fee was waived, or the error from whichever attempt was made
// last (the no-fee attempt's error wins when both fail).
//
// Why retry-without-fee: on tiny swaps (typically under ~0.01 SOL),
// Jupiter's RFQ market makers (JupiterZ) will gladly fill the trade
// — they even subsidize the gas — but stacking our 50 bps platform
// fee on top makes the route stop penciling and Jupiter falls back
// to checking aggregator routes that can't handle the size. Letting
// our fee get in the way of the user completing a $1.50 swap is
// strictly worse than collecting nothing on dust trades, so we drop
// it on the retry. Larger swaps keep paying the fee on the first
// attempt's success.
func jupiterFetchOrderWithRetry(ctx context.Context, inMint, outMint, amount, taker string, slippageBps uint16) (*jupiterOrderResponse, bool, error) {
	build := func(withFee bool) url.Values {
		qs := url.Values{}
		qs.Set("inputMint", inMint)
		qs.Set("outputMint", outMint)
		qs.Set("amount", amount)
		qs.Set("taker", taker)
		if withFee {
			qs.Set("referralAccount", JupiterReferralAccount)
			qs.Set("referralFee", strconv.Itoa(int(DefaultFeeBps)))
		}
		if slippageBps > 0 {
			qs.Set("slippageBps", strconv.Itoa(int(slippageBps)))
		}
		return qs
	}

	// First attempt — with the platform fee.
	var resp jupiterOrderResponse
	err := httpGetJSON(ctx, JupiterOrderURL, build(true), jupiterHeader(), &resp)
	if err == nil && resp.Transaction != "" && resp.RequestId != "" {
		return &resp, false, nil
	}

	// "Failed to get quotes" arrives two ways: HTTP 400 with the
	// error in the body (httpRun wraps that as
	// ErrCodeProviderBadRequest with the body in the message), and
	// HTTP 200 with an empty Transaction + Error="Failed to get
	// quotes". Both are no-route signals; either triggers the retry.
	noRoute := false
	if err != nil {
		if sw, ok := AsSwapError(err); ok && sw.Code == ErrCodeProviderBadRequest &&
			strings.Contains(strings.ToLower(sw.Message), "failed to get quotes") {
			noRoute = true
		}
	} else if resp.Transaction == "" || resp.RequestId == "" {
		// Successful HTTP, empty order — also a no-route surface.
		msg := resp.ErrorMessage
		if msg == "" {
			msg = resp.Error
		}
		if strings.Contains(strings.ToLower(msg), "failed to get quotes") {
			noRoute = true
		}
	}
	if !noRoute {
		// Some other failure (transport error, decode failure,
		// genuine bad request, "insufficient funds" from the
		// aggregator). Don't retry — bubble what we know.
		if err != nil {
			return nil, false, err
		}
		// Empty-order / non-no-route — surface the upstream message
		// as no_liquidity for code symmetry with the original empty-
		// transaction path.
		msg := resp.ErrorMessage
		if msg == "" {
			msg = resp.Error
		}
		if msg == "" {
			msg = "Jupiter returned an empty order"
		}
		return nil, false, newErr(ErrCodeNoLiquidity, msg)
	}

	// Second attempt — without the fee. JupiterZ RFQ usually fills.
	var resp2 jupiterOrderResponse
	err2 := httpGetJSON(ctx, JupiterOrderURL, build(false), jupiterHeader(), &resp2)
	if err2 == nil && resp2.Transaction != "" && resp2.RequestId != "" {
		return &resp2, true, nil
	}
	// Both attempts failed — surface the no-route as no_liquidity.
	if err2 != nil {
		if sw, ok := AsSwapError(err2); ok && sw.Code == ErrCodeProviderBadRequest &&
			strings.Contains(strings.ToLower(sw.Message), "failed to get quotes") {
			return nil, false, newErr(ErrCodeNoLiquidity, sw.Message)
		}
		return nil, false, err2
	}
	// Empty 200 from the no-fee retry too — pass through the message.
	msg := resp2.ErrorMessage
	if msg == "" {
		msg = resp2.Error
	}
	if msg == "" {
		msg = "Jupiter returned an empty order on the no-fee retry"
	}
	return nil, false, newErr(ErrCodeNoLiquidity, msg)
}

func (jupiterProvider) Execute(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	blob, ok := q.providerBlob.(*jupiterBlob)
	if !ok || blob == nil {
		return nil, newErr(ErrCodeQuoteNotFound, "quote is missing its Jupiter payload")
	}

	signed, err := solanaSplicingSignLocal(ctx, acct, keys, blob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("sign Jupiter transaction: %w", err)
	}

	execReq := jupiterExecuteRequest{
		SignedTransaction: base64.StdEncoding.EncodeToString(signed),
		RequestId:         blob.RequestId,
	}
	var execResp jupiterExecuteResponse
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := httpPostJSON(execCtx, JupiterExecuteURL, execReq, jupiterHeader(), &execResp); err != nil {
		return nil, err
	}
	if execResp.Signature == "" {
		msg := execResp.ErrorMessage
		if msg == "" {
			msg = execResp.Error
		}
		if msg == "" {
			msg = "Jupiter execute returned empty signature"
		}
		return nil, newErr(ErrCodeProviderUnavailable, msg)
	}
	return &SwapResult{
		QuoteId:  q.QuoteId,
		Provider: "jupiter_ultra",
		Chain:    "solana",
		Hash:     execResp.Signature,
		URL:      n.TransactionUrl(execResp.Signature),
		Quote:    q,
	}, nil
}
