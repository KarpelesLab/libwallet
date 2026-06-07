package wltswap

// Minimal REST helper for the swap adapter. libwallet's existing
// network code is JSON-RPC only (wltnet.DoRPCCtx wraps the ethrpc
// package), so we need a separate thin wrapper here. Used by the
// OKX adapter (the only routed swap provider after the licensing
// migration); the helper stays generic so it's still useful for any
// future REST-style provider.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Fee / slippage defaults. All routed swaps use 50 bps (0.5%).
const (
	DefaultFeeBps      uint16 = 50
	DefaultSlippageBps uint16 = 50
)

// httpClient is a shared client with a sensible per-request timeout.
// Callers always pass a context too — the timeout here is just a
// belt-and-braces upper bound for the whole request.
var httpClient = &http.Client{
	Timeout: 20 * time.Second,
}

// httpPostJSON sends a JSON POST request, decoding the response into
// out. Headers are applied via the hdr callback so callers don't
// need to construct *http.Request themselves. Any 4xx / 5xx returns
// a SwapError with the upstream body as context.
func httpPostJSON(ctx context.Context, urlStr string, body any, hdr func(http.Header), out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return fmt.Errorf("encode body: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, &buf)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if hdr != nil {
		hdr(req.Header)
	}
	return httpRun(req, out)
}

// httpGetJSON sends a GET with query string params and decodes the
// response into out. Callers pass params pre-encoded in urlStr or
// supply them in query.
func httpGetJSON(ctx context.Context, urlStr string, query url.Values, hdr func(http.Header), out any) error {
	if len(query) > 0 {
		sep := "?"
		if strings.Contains(urlStr, "?") {
			sep = "&"
		}
		urlStr = urlStr + sep + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if hdr != nil {
		hdr(req.Header)
	}
	return httpRun(req, out)
}

// httpRun executes req, classifies the HTTP status, and decodes into
// out on success. Non-2xx bodies are clipped to 512 bytes and wrapped
// in the appropriate SwapError.
func httpRun(req *http.Request, out any) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return newErr(ErrCodeProviderUnavailable, fmt.Sprintf("transport error: %v", scrubErr(err.Error(), req.Header)))
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 1<<20) // cap at 1 MiB

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(limited, 512))
		code := ErrCodeProviderBadRequest
		if resp.StatusCode >= 500 {
			code = ErrCodeProviderUnavailable
		}
		return newErr(code, fmt.Sprintf("%s %s → HTTP %d: %s",
			req.Method, scrubURL(req.URL.String()), resp.StatusCode, truncate(string(body), 512)))
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return newErr(ErrCodeProviderUnavailable, fmt.Sprintf("decode response: %v", err))
	}
	return nil
}

// scrubErr removes any API key values that might have leaked into an
// error message via URL userinfo or header dumps from the transport.
func scrubErr(msg string, hdr http.Header) string {
	for _, h := range []string{"Authorization", "x-api-key"} {
		if v := hdr.Get(h); v != "" {
			msg = strings.ReplaceAll(msg, v, "<redacted>")
		}
	}
	return msg
}

// scrubURL removes query-string tokens that some providers accept as
// auth (we don't use any of these, but if a future adapter does
// they'd be redacted here).
func scrubURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := parsed.Query()
	for _, k := range []string{"api_key", "apikey", "key", "token"} {
		if q.Has(k) {
			q.Set(k, "<redacted>")
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
