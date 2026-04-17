package wltswap

// Jupiter Ultra adapter.
//
// Flow:
//  POST /ultra/v1/order  → { transaction (b64), requestId, ... }
//  (we sign the transaction's message locally)
//  POST /ultra/v1/execute → { signature, status, ... }
//
// Jupiter returns a transaction with the account/instructions
// pre-built and signature slots allocated (zeroed for the user's
// fee-payer slot). We parse the wire format to locate where the
// message begins, sign those bytes with the user's Ed25519 key via
// the existing TSS pipeline, splice the signature back into slot 0,
// and post the result to /execute.

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
)

type jupiterProvider struct{}

func (jupiterProvider) Name() string  { return "jupiter_ultra" }
func (jupiterProvider) Chain() string { return "solana" }

// Request / response shapes — only the fields we read or write.
type jupiterOrderRequest struct {
	InputMint        string `json:"inputMint"`
	OutputMint       string `json:"outputMint"`
	Amount           string `json:"amount"`
	Taker            string `json:"taker"`
	ReferralAccount  string `json:"referralAccount,omitempty"`
	ReferralFee      string `json:"referralFee,omitempty"`
	SlippageBps      uint16 `json:"slippageBps,omitempty"`
}

type jupiterOrderResponse struct {
	Transaction    string               `json:"transaction"`
	RequestId      string               `json:"requestId"`
	InAmount       string               `json:"inAmount"`
	OutAmount      string               `json:"outAmount"`
	OtherAmount    string               `json:"otherAmountThreshold"` // min out w/ slippage
	SlippageBps    uint16               `json:"slippageBps"`
	PriceImpactPct string               `json:"priceImpactPct"`
	RoutePlan      []jupiterRoutePlan   `json:"routePlan"`
	SwapType       string               `json:"swapType"`
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

	body := jupiterOrderRequest{
		InputMint:       inMint,
		OutputMint:      outMint,
		Amount:          req.AmountIn,
		Taker:           acct.GetAddress(),
		ReferralAccount: JupiterReferralAccount,
		ReferralFee:     fmt.Sprintf("%d", DefaultFeeBps),
		SlippageBps:     req.SlippageBps,
	}

	var resp jupiterOrderResponse
	if err := httpPostJSON(ctx, JupiterOrderURL, body, jupiterHeader(), &resp); err != nil {
		return nil, err
	}
	if resp.Transaction == "" || resp.RequestId == "" {
		return nil, newErr(ErrCodeNoLiquidity, "Jupiter returned an empty order")
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
