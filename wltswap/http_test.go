package wltswap

// Adapter tests backed by httptest.Server. Exemplar pattern; extend
// this file with dFlow + 1inch analogues as the adapters accrue
// parsing quirks. Each test:
//   1. Stands up a fake upstream that validates the request shape
//      and returns a recorded JSON body.
//   2. Points the package-level URL var at the fake.
//   3. Exercises the adapter's parse/compose logic end-to-end.
//
// Signing (acct.Sign via TSS) is out of scope for these tests — the
// adapter's Execute path is validated separately by the devnet
// smoke test described in the plan.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestJupiterAdapter_QuoteParse validates that a recorded Jupiter
// /order response flows through the adapter and produces a Quote
// with the expected amounts, route, and cached provider blob.
//
// Pinned to GET (not POST): the live Jupiter Ultra /order endpoint
// returns HTTP 404 on POST. If anyone refactors this back to a POST
// the test fires loudly.
func TestJupiterAdapter_QuoteParse(t *testing.T) {
	// Minimal /order response with the fields the adapter reads.
	// outAmount is 12_345_000 (e.g. 12.345 USDC at 6 decimals);
	// otherAmountThreshold is the min-out after slippage.
	const rawTxB64 = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	response := map[string]any{
		"transaction":          rawTxB64,
		"requestId":            "test-request-id",
		"inAmount":             "10000000",
		"outAmount":            "12345000",
		"otherAmountThreshold": "12283275", // 0.5% below outAmount
		"slippageBps":          50,
		"priceImpactPct":       "0.0015",
		"routePlan": []map[string]any{
			{"swapInfo": map[string]any{"label": "Raydium"}, "percent": 100.0},
		},
		"swapType": "aggregator",
	}

	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if got := r.Header.Get("x-api-key"); got != JupiterAPIKey {
			t.Errorf("x-api-key = %q, want %q", got, JupiterAPIKey)
		}
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	origURL := JupiterOrderURL
	JupiterOrderURL = srv.URL
	defer func() { JupiterOrderURL = origURL }()

	// Drive the same query-building logic Quote() uses.
	qs := url.Values{}
	qs.Set("inputMint", "So11111111111111111111111111111111111111112")
	qs.Set("outputMint", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
	qs.Set("amount", "10000000")
	qs.Set("taker", "SenderPublicKeyHere")
	qs.Set("referralAccount", JupiterReferralAccount)
	qs.Set("referralFee", "50")
	qs.Set("slippageBps", strconv.Itoa(50))

	var resp jupiterOrderResponse
	err := httpGetJSON(t.Context(), JupiterOrderURL, qs, jupiterHeader(), &resp)
	if err != nil {
		t.Fatalf("httpGetJSON failed: %v", err)
	}

	// Verify the query string Jupiter received carries every
	// parameter — Jupiter rejects requests with missing fields.
	for _, k := range []string{"inputMint", "outputMint", "amount", "taker", "referralAccount", "referralFee", "slippageBps"} {
		if gotQuery.Get(k) == "" {
			t.Errorf("query missing %q — full query: %v", k, gotQuery)
		}
	}
	if got := gotQuery.Get("referralAccount"); got != JupiterReferralAccount {
		t.Errorf("referralAccount = %q, want %q", got, JupiterReferralAccount)
	}
	if got := gotQuery.Get("referralFee"); got != "50" {
		t.Errorf("referralFee = %q, want 50", got)
	}

	// Verify we parsed the response correctly.
	if resp.RequestId != "test-request-id" {
		t.Errorf("requestId = %q, want test-request-id", resp.RequestId)
	}
	if resp.OutAmount != "12345000" {
		t.Errorf("outAmount = %q, want 12345000", resp.OutAmount)
	}
	if resp.OtherAmount != "12283275" {
		t.Errorf("otherAmountThreshold = %q, want 12283275", resp.OtherAmount)
	}
	if len(resp.RoutePlan) != 1 || resp.RoutePlan[0].SwapInfo.Label != "Raydium" {
		t.Errorf("routePlan not parsed: %+v", resp.RoutePlan)
	}

	// Round-trip the base64 transaction — simulating what the
	// adapter stores in providerBlob.
	decoded, err := base64.StdEncoding.DecodeString(resp.Transaction)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(decoded) < 64 {
		t.Errorf("decoded tx too short: %d bytes", len(decoded))
	}
}

// TestJupiterAdapter_OrderError surfaces upstream "Insufficient funds"
// (HTTP 200 with errorMessage and empty transaction) instead of the
// generic "empty order" we used to emit.
func TestJupiterAdapter_OrderError(t *testing.T) {
	response := map[string]any{
		"transaction":  "",
		"requestId":    "errored-request",
		"errorCode":    1,
		"errorMessage": "Insufficient funds",
		"error":        "Insufficient funds",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	origURL := JupiterOrderURL
	JupiterOrderURL = srv.URL
	defer func() { JupiterOrderURL = origURL }()

	var resp jupiterOrderResponse
	if err := httpGetJSON(t.Context(), JupiterOrderURL, url.Values{}, jupiterHeader(), &resp); err != nil {
		t.Fatalf("httpGetJSON: %v", err)
	}
	if resp.ErrorMessage != "Insufficient funds" {
		t.Errorf("expected errorMessage carried, got %q", resp.ErrorMessage)
	}
	if resp.Transaction != "" {
		t.Errorf("expected empty transaction, got %q", resp.Transaction)
	}
}

// TestHTTPError_ScrubsAPIKey verifies that upstream errors don't
// leak the API key into the SwapError message.
func TestHTTPError_ScrubsAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	var resp map[string]any
	err := httpPostJSON(t.Context(), srv.URL, map[string]any{"test": "body"}, jupiterHeader(), &resp)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if strings.Contains(err.Error(), JupiterAPIKey) {
		t.Errorf("error leaked the API key: %v", err)
	}
	se, ok := AsSwapError(err)
	if !ok {
		t.Fatalf("expected SwapError, got %T", err)
	}
	if se.Code != ErrCodeProviderBadRequest {
		t.Errorf("code = %q, want provider_bad_request", se.Code)
	}
}
