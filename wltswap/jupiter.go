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

	qs := url.Values{}
	qs.Set("inputMint", inMint)
	qs.Set("outputMint", outMint)
	qs.Set("amount", req.AmountIn)
	qs.Set("taker", acct.GetAddress())
	qs.Set("referralAccount", JupiterReferralAccount)
	qs.Set("referralFee", strconv.Itoa(int(DefaultFeeBps)))
	if req.SlippageBps > 0 {
		qs.Set("slippageBps", strconv.Itoa(int(req.SlippageBps)))
	}

	var resp jupiterOrderResponse
	if err := httpGetJSON(ctx, JupiterOrderURL, qs, jupiterHeader(), &resp); err != nil {
		return nil, err
	}
	// Jupiter sometimes returns an HTTP 200 with an empty transaction
	// when routing fails (insufficient funds, no route, slippage too
	// tight). Surface the upstream errorMessage instead of the
	// generic ErrCodeNoLiquidity we used to emit.
	if resp.Transaction == "" || resp.RequestId == "" {
		msg := resp.ErrorMessage
		if msg == "" {
			msg = resp.Error
		}
		if msg == "" {
			msg = "Jupiter returned an empty order"
		}
		return nil, newErr(ErrCodeNoLiquidity, msg)
	}
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
		FeeBps:        DefaultFeeBps,
		SlippageBps:   slippage,
		ReferralFee:   computeReferralFee(amountIn, DefaultFeeBps, req.TokenIn.Decimals),
		// Solana base fee is 5000 lamports; v1 doesn't surface
		// ComputeBudget priority fees the Jupiter tx may have set.
		NetworkFee:   wltobj.NewAmountRaw(big.NewInt(5000), 9),
		Route:        route,
		providerBlob: &jupiterBlob{RawTx: rawTx, RequestId: resp.RequestId},
	}
	return q, nil
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
