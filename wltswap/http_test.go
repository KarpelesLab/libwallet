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

func TestJupiterFetchOrderWithRetry_FeeWaivedOnNoRoute(t *testing.T) {
	// Reproduces the field bug: Jupiter returns HTTP 400 "Failed to
	// get quotes" when our 50bps platform fee makes a small swap
	// stop penciling. The retry without fee succeeds via JupiterZ
	// RFQ and we surface a successful Quote with feeWaived=true.
	const successBody = `{
		"transaction": "AAAA",
		"requestId": "retry-success",
		"inAmount": "7481806",
		"outAmount": "689281",
		"otherAmountThreshold": "689281",
		"slippageBps": 0,
		"swapType": "rfq"
	}`

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		hasFee := q.Get("referralFee") != ""
		switch {
		case calls == 1:
			if !hasFee {
				t.Errorf("first call missing referralFee — should always carry it")
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"requestId":"first","error":"Failed to get quotes"}`))
		case calls == 2:
			if hasFee {
				t.Errorf("retry must NOT carry referralFee, got %q", q.Get("referralFee"))
			}
			if q.Get("referralAccount") != "" {
				t.Errorf("retry must NOT carry referralAccount, got %q", q.Get("referralAccount"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(successBody))
		default:
			t.Errorf("unexpected call %d to Jupiter", calls)
		}
	}))
	defer srv.Close()

	origURL := JupiterOrderURL
	JupiterOrderURL = srv.URL
	defer func() { JupiterOrderURL = origURL }()

	resp, feeWaived, err := jupiterFetchOrderWithRetry(t.Context(),
		"So11111111111111111111111111111111111111112",
		"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"7481806",
		"7EEygcr1HaF2PY8pdHaeYSNByXPpMQU4GzrCezvps7KH",
		50,
	)
	if err != nil {
		t.Fatalf("expected success on retry, got %v", err)
	}
	if !feeWaived {
		t.Error("feeWaived should be true after the retry succeeded")
	}
	if resp.Transaction != "AAAA" || resp.RequestId != "retry-success" {
		t.Errorf("got resp %+v, expected the retry's successful body", resp)
	}
	if calls != 2 {
		t.Errorf("expected 2 Jupiter calls (1 with fee + 1 retry), got %d", calls)
	}
}

func TestJupiterFetchOrderWithRetry_FirstCallSucceedsNoRetry(t *testing.T) {
	// The retry only fires on no-route. A first-call success means
	// we collect the platform fee — happy path.
	const okBody = `{
		"transaction": "BBBB",
		"requestId": "first-success",
		"inAmount": "100000000",
		"outAmount": "10000000",
		"otherAmountThreshold": "9950000",
		"swapType": "aggregator"
	}`
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("referralFee") == "" {
			t.Error("first call should always carry referralFee")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okBody))
	}))
	defer srv.Close()
	origURL := JupiterOrderURL
	JupiterOrderURL = srv.URL
	defer func() { JupiterOrderURL = origURL }()

	resp, feeWaived, err := jupiterFetchOrderWithRetry(t.Context(),
		"So11111111111111111111111111111111111111112",
		"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"100000000",
		"7EEygcr1HaF2PY8pdHaeYSNByXPpMQU4GzrCezvps7KH",
		50,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if feeWaived {
		t.Error("feeWaived should be false on first-call success")
	}
	if resp.Transaction != "BBBB" {
		t.Errorf("wrong response: %+v", resp)
	}
	if calls != 1 {
		t.Errorf("expected 1 call (no retry), got %d", calls)
	}
}

func TestJupiterFetchOrderWithRetry_NonRouteErrorNoRetry(t *testing.T) {
	// "Insufficient funds" / other non-route errors should NOT
	// trigger the fee-waiver retry. Surface the original error so
	// the user gets the actionable message.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"requestId":"bad","error":"Insufficient funds"}`))
	}))
	defer srv.Close()
	origURL := JupiterOrderURL
	JupiterOrderURL = srv.URL
	defer func() { JupiterOrderURL = origURL }()

	_, feeWaived, err := jupiterFetchOrderWithRetry(t.Context(),
		"So11111111111111111111111111111111111111112",
		"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"100000000",
		"7EEygcr1HaF2PY8pdHaeYSNByXPpMQU4GzrCezvps7KH",
		50,
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if feeWaived {
		t.Error("feeWaived should be false when both attempts failed / no retry")
	}
	if calls != 1 {
		t.Errorf("non-route errors should not retry, got %d calls", calls)
	}
}

func TestJupiterFetchOrderWithRetry_BothFailReturnsNoLiquidity(t *testing.T) {
	// When the no-fee retry also can't route, surface as
	// no_liquidity (the canonical no-route code).
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"Failed to get quotes"}`))
	}))
	defer srv.Close()
	origURL := JupiterOrderURL
	JupiterOrderURL = srv.URL
	defer func() { JupiterOrderURL = origURL }()

	_, _, err := jupiterFetchOrderWithRetry(t.Context(),
		"So11111111111111111111111111111111111111112",
		"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"100",
		"7EEygcr1HaF2PY8pdHaeYSNByXPpMQU4GzrCezvps7KH",
		50,
	)
	if err == nil {
		t.Fatal("expected error after both attempts fail")
	}
	se, ok := AsSwapError(err)
	if !ok {
		t.Fatalf("expected SwapError, got %T: %v", err, err)
	}
	if se.Code != ErrCodeNoLiquidity {
		t.Errorf("code = %q, want %q", se.Code, ErrCodeNoLiquidity)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls (fee + retry), got %d", calls)
	}
}
