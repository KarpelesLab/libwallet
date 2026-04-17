package wltswap

// dFlow adapter (Solana).
//
// Flow:
//   POST /quote → { quoteResponse, ... }
//   POST /swap   → { swapTransaction (b64) }
//   Sign the message locally, broadcast via sendTransaction to the
//   Solana RPC.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
)

type dflowProvider struct{}

func (dflowProvider) Name() string  { return "dflow" }
func (dflowProvider) Chain() string { return "solana" }

type dflowQuoteRequest struct {
	InputMint       string `json:"inputMint"`
	OutputMint      string `json:"outputMint"`
	Amount          string `json:"amount"`
	UserPublicKey   string `json:"userPublicKey"`
	SlippageBps     uint16 `json:"slippageBps"`
	PlatformFeeBps  string `json:"platformFeeBps,omitempty"`
}

type dflowQuoteResponse struct {
	// QuoteResponse is passed opaquely to /swap — we don't parse it.
	QuoteResponse   json.RawMessage `json:"quoteResponse"`
	InAmount        string          `json:"inAmount"`
	OutAmount       string          `json:"outAmount"`
	OtherAmount     string          `json:"otherAmountThreshold"`
	PriceImpactPct  string          `json:"priceImpactPct"`
	RoutePlan       []dflowRoute    `json:"routePlan"`
}

type dflowRoute struct {
	SwapInfo struct {
		Label      string `json:"label"`
		InputMint  string `json:"inputMint"`
		OutputMint string `json:"outputMint"`
	} `json:"swapInfo"`
	Percent float64 `json:"percent"`
}

type dflowSwapRequest struct {
	QuoteResponse json.RawMessage `json:"quoteResponse"`
	UserPublicKey string          `json:"userPublicKey"`
	FeeAccount    string          `json:"feeAccount,omitempty"`
}

type dflowSwapResponse struct {
	SwapTransaction string `json:"swapTransaction"`
}

// dflowBlob is the per-quote payload we need to drive Execute.
// Cached in Quote.providerBlob; contains the raw /swap transaction
// bytes (already signed by dFlow with any ephemeral keys the route
// requires, and with the user's signature slot left zeroed).
type dflowBlob struct {
	RawTx []byte
}

func (dflowProvider) Quote(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *QuoteRequest) (*Quote, error) {
	if n.Type != "solana" {
		return nil, newErr(ErrCodeUnsupportedChain, "dFlow only supports Solana")
	}

	inMint := solanaNativeMintOrAddr(req.TokenIn.Address)
	outMint := solanaNativeMintOrAddr(req.TokenOut.Address)

	// Step 1: /quote — pricing + route plan.
	qBody := dflowQuoteRequest{
		InputMint:      inMint,
		OutputMint:     outMint,
		Amount:         req.AmountIn,
		UserPublicKey:  acct.GetAddress(),
		SlippageBps:    req.SlippageBps,
		PlatformFeeBps: fmt.Sprintf("%d", DefaultFeeBps),
	}
	var qResp dflowQuoteResponse
	if err := httpPostJSON(ctx, DFlowQuoteURL, qBody, nil, &qResp); err != nil {
		return nil, err
	}
	if len(qResp.QuoteResponse) == 0 {
		return nil, newErr(ErrCodeNoLiquidity, "dFlow returned an empty quote")
	}

	// Step 2: /swap — serialized Solana transaction.
	sBody := dflowSwapRequest{
		QuoteResponse: qResp.QuoteResponse,
		UserPublicKey: acct.GetAddress(),
		FeeAccount:    DFlowFeeAccount,
	}
	var sResp dflowSwapResponse
	if err := httpPostJSON(ctx, DFlowSwapURL, sBody, nil, &sResp); err != nil {
		return nil, err
	}
	if sResp.SwapTransaction == "" {
		return nil, newErr(ErrCodeProviderUnavailable, "dFlow returned no swap transaction")
	}
	rawTx, err := base64.StdEncoding.DecodeString(sResp.SwapTransaction)
	if err != nil {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("decode dFlow transaction: %v", err))
	}

	// Parse amounts.
	amountIn, _ := new(big.Int).SetString(orFallback(qResp.InAmount, req.AmountIn), 10)
	amountOut, _ := new(big.Int).SetString(qResp.OutAmount, 10)
	if amountIn == nil || amountOut == nil {
		return nil, newErr(ErrCodeProviderUnavailable, "dFlow returned unparseable amounts")
	}
	var minOut *big.Int
	if qResp.OtherAmount != "" {
		minOut, _ = new(big.Int).SetString(qResp.OtherAmount, 10)
	}
	if minOut == nil {
		minOut = new(big.Int).Set(amountOut)
	}

	route := make([]RouteHop, 0, len(qResp.RoutePlan))
	for _, r := range qResp.RoutePlan {
		route = append(route, RouteHop{
			Venue: r.SwapInfo.Label,
			Share: r.Percent / 100,
		})
	}

	return &Quote{
		Provider:     "dflow",
		Chain:        "solana",
		TokenIn:      req.TokenIn,
		TokenOut:     req.TokenOut,
		AmountIn:     wltobj.NewAmountRaw(amountIn, req.TokenIn.Decimals),
		AmountOut:    wltobj.NewAmountRaw(amountOut, req.TokenOut.Decimals),
		MinAmountOut: wltobj.NewAmountRaw(minOut, req.TokenOut.Decimals),
		PriceImpact:  parseFloat(qResp.PriceImpactPct),
		FeeBps:       DefaultFeeBps,
		SlippageBps:  req.SlippageBps,
		Route:        route,
		providerBlob: &dflowBlob{RawTx: rawTx},
	}, nil
}

func (dflowProvider) Execute(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, q *Quote, keys []*wltsign.KeyDescription) (*SwapResult, error) {
	blob, ok := q.providerBlob.(*dflowBlob)
	if !ok || blob == nil {
		return nil, newErr(ErrCodeQuoteNotFound, "quote is missing its dFlow payload")
	}
	signed, err := solanaSplicingSignLocal(ctx, acct, keys, blob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("sign dFlow transaction: %w", err)
	}

	// Broadcast via standard sendTransaction. Encoding: base58 is
	// what signAndSendSolana in wlttx/solana.go uses, mirror that.
	txB58 := base58.Bitcoin.Encode(signed)
	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := n.DoRPCCtx(rpcCtx, "sendTransaction", txB58, map[string]any{"encoding": "base58"})
	if err != nil {
		wltlog.Errorf("swap/dflow: sendTransaction failed: %s", err)
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("broadcast dFlow tx: %v", err))
	}
	var sig string
	if err := json.Unmarshal(raw, &sig); err != nil {
		return nil, newErr(ErrCodeProviderUnavailable, fmt.Sprintf("parse sendTransaction response: %v", err))
	}
	return &SwapResult{
		QuoteId:  q.QuoteId,
		Provider: "dflow",
		Chain:    "solana",
		Hash:     sig,
		URL:      n.TransactionUrl(sig),
		Quote:    q,
	}, nil
}

func orFallback(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
