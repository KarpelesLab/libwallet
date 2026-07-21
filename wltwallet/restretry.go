package wltwallet

// Transient-error retry for phplatform calls.
//
// The integration tests (TestRemoteWallet, TestEdDSALocalToRemoteReshare,
// TestWalletCreate) drive real Crypto/WalletSign:* endpoints through the
// rest package. phplatform's backend has periodic DB blips — typically
// a few seconds of HTTP 500 with `{"error":"There was a database error
// while processing your request, ref: <uuid>"}` — that show up as test
// failures even though libwallet's code is fine. The same blip hits any
// production caller that talks to phplatform, so retrying isn't just for
// test hygiene; it makes the runtime resilient.
//
// Policy: retry up to 3 attempts (1 initial + 2 retries) on HTTP >=500,
// with exponential backoff (500ms, 1s). 4xx errors (auth, validation,
// "not found") pass through immediately — those are deterministic and
// retrying just delays the inevitable failure. Total worst-case extra
// wait on a sustained outage is ~1.5s, then the call surfaces the error
// for the caller to handle.

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/KarpelesLab/rest"
)

const (
	restRetryAttempts = 3
	restRetryBase     = 500 * time.Millisecond
)

// isTransientRestError reports whether err looks like a transient
// upstream blip worth retrying. Matches *rest.Error with HTTP >=500
// (server-side: DB error, timeout, gateway issue, etc.). Anything else
// — including 4xx, network errors that rest classifies differently,
// nil — returns false.
func isTransientRestError(err error) bool {
	var re *rest.Error
	if !errors.As(err, &re) {
		return false
	}
	if re.Response == nil {
		return false
	}
	return re.Response.Code >= 500
}

// restApplyRetry wraps rest.Apply with bounded retry on transient
// errors. Same signature; same return type; safe drop-in for libwallet
// callers that talk to Crypto/WalletSign:* or other phplatform endpoints.
//
// Honours ctx cancellation between attempts — a Done ctx stops the
// retry loop immediately rather than sleeping out the backoff.
func restApplyRetry(ctx context.Context, req, method string, param rest.Param, target interface{}) error {
	var lastErr error
	for attempt := 0; attempt < restRetryAttempts; attempt++ {
		if attempt > 0 {
			wait := restRetryBase * time.Duration(1<<(attempt-1))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		err := rest.Apply(ctx, req, method, param, target)
		if err == nil {
			return nil
		}
		if !isTransientRestError(err) {
			return err
		}
		lastErr = err
	}
	return lastErr
}

// Tenacious retry for state-critical uploads (RemoteKey share upload via
// Crypto/WalletSign:setGeneratedKey). Unlike restDoRetry, this also retries
// TRANSPORT-level failures (http2 "timeout awaiting response headers",
// connection resets, …), because for this call giving up is worse than
// waiting: the request may already have been delivered, and an abandoned
// share upload leaves the server-side share out of sync with the local
// (unchanged) committee — the field-reported cause of a later reshare
// hanging mid-rounds. Deterministic 4xx still fails immediately.
const (
	criticalRetryBudget     = 5 * time.Minute
	criticalRetryBackoff    = 2 * time.Second
	criticalRetryBackoffMax = 30 * time.Second
)

// isRetryableCriticalError: retry 5xx AND anything that is not a definitive
// rest-level 4xx — a non-rest error means the transport failed and we cannot
// know whether the server processed the request.
func isRetryableCriticalError(err error) bool {
	if err == nil {
		return false
	}
	var re *rest.Error
	if errors.As(err, &re) {
		if re.Response == nil {
			return true
		}
		return re.Response.Code >= 500
	}
	return true
}

// restDoRetryCritical keeps attempting the call until it succeeds, hits a
// deterministic 4xx, the ctx dies, or criticalRetryBudget elapses.
func restDoRetryCritical(ctx context.Context, req, method string, param rest.Param) (*rest.Response, error) {
	deadline := time.Now().Add(criticalRetryBudget)
	backoff := criticalRetryBackoff
	var lastErr error
	for attempt := 1; ; attempt++ {
		resp, err := rest.Do(ctx, req, method, param)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		if !isRetryableCriticalError(err) {
			return resp, err
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		log.Printf("%s attempt %d failed (%s); retrying in %s", req, attempt, err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if backoff < criticalRetryBackoffMax {
			backoff *= 2
		}
	}
}

// restDoRetry is restApplyRetry's twin for callers using rest.Do.
// rest.Do returns (*rest.Response, error); we propagate both.
func restDoRetry(ctx context.Context, req, method string, param rest.Param) (*rest.Response, error) {
	var lastErr error
	for attempt := 0; attempt < restRetryAttempts; attempt++ {
		if attempt > 0 {
			wait := restRetryBase * time.Duration(1<<(attempt-1))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		resp, err := rest.Do(ctx, req, method, param)
		if err == nil {
			return resp, nil
		}
		if !isTransientRestError(err) {
			return resp, err
		}
		lastErr = err
	}
	return nil, lastErr
}
