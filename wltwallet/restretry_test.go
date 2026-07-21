package wltwallet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KarpelesLab/rest"
)

func TestIsTransientRestError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("connection refused"), false},
		{"rest 400 — client error", &rest.Error{Response: &rest.Response{Code: 400, Error: "bad params"}}, false},
		{"rest 403 — auth", &rest.Error{Response: &rest.Response{Code: 403, Error: "forbidden"}}, false},
		{"rest 404", &rest.Error{Response: &rest.Response{Code: 404, Error: "not found"}}, false},
		{"rest 422 — validation", &rest.Error{Response: &rest.Response{Code: 422, Error: "invalid"}}, false},
		// 5xx is the signature we retry on. The "database error" message
		// libwallet keeps seeing comes back as 500.
		{"rest 500 — DB error", &rest.Error{Response: &rest.Response{Code: 500, Error: "There was a database error while processing your request, ref: abc"}}, true},
		{"rest 502 — gateway", &rest.Error{Response: &rest.Response{Code: 502, Error: "bad gateway"}}, true},
		{"rest 503 — unavailable", &rest.Error{Response: &rest.Response{Code: 503, Error: "service unavailable"}}, true},
		{"rest 504 — timeout", &rest.Error{Response: &rest.Response{Code: 504, Error: "gateway timeout"}}, true},
		// Defensive: nil Response shouldn't crash, must not retry.
		{"rest error with nil response", &rest.Error{}, false},
		// errors.As traversal — a wrapped *rest.Error still classifies.
		{"wrapped 500", fmt.Errorf("downstream: %w", &rest.Error{Response: &rest.Response{Code: 500}}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientRestError(tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// stubFn is the function shape both restApplyRetry and restDoRetry use
// internally — abstracted here so we can drive the loop without a real
// rest.Apply / rest.Do (which would need an http server).
type stubFn struct {
	calls   atomic.Int32
	errsOut []error
}

func (s *stubFn) next() error {
	i := int(s.calls.Add(1)) - 1
	if i >= len(s.errsOut) {
		return nil
	}
	return s.errsOut[i]
}

// TestRetryLoopBehaviour reproduces the retry policy without driving
// real rest.Apply / rest.Do. The loop logic is identical between the
// two wrappers; we factor the contract via an inline shim.
func TestRetryLoopBehaviour(t *testing.T) {
	transient := &rest.Error{Response: &rest.Response{Code: 500, Error: "There was a database error"}}
	permanent := &rest.Error{Response: &rest.Response{Code: 403, Error: "forbidden"}}

	runLoop := func(ctx context.Context, errs []error) (callsMade int, lastErr error) {
		s := &stubFn{errsOut: errs}
		for attempt := 0; attempt < restRetryAttempts; attempt++ {
			if attempt > 0 {
				// Skip the real backoff in tests by using a tiny tick.
				select {
				case <-time.After(1 * time.Millisecond):
				case <-ctx.Done():
					return int(s.calls.Load()), ctx.Err()
				}
			}
			err := s.next()
			if err == nil {
				return int(s.calls.Load()), nil
			}
			if !isTransientRestError(err) {
				return int(s.calls.Load()), err
			}
			lastErr = err
		}
		return int(s.calls.Load()), lastErr
	}

	t.Run("first-call success: no retry", func(t *testing.T) {
		calls, err := runLoop(context.Background(), []error{nil})
		if err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
		if calls != 1 {
			t.Errorf("calls = %d, want 1", calls)
		}
	})

	t.Run("transient then success: 1 retry", func(t *testing.T) {
		calls, err := runLoop(context.Background(), []error{transient, nil})
		if err != nil {
			t.Fatalf("expected eventual success, got %v", err)
		}
		if calls != 2 {
			t.Errorf("calls = %d, want 2", calls)
		}
	})

	t.Run("two transients then success: 2 retries", func(t *testing.T) {
		calls, err := runLoop(context.Background(), []error{transient, transient, nil})
		if err != nil {
			t.Fatalf("expected eventual success, got %v", err)
		}
		if calls != 3 {
			t.Errorf("calls = %d, want 3", calls)
		}
	})

	t.Run("permanent error short-circuits: no retry", func(t *testing.T) {
		// Auth failures, validation failures, "not found" — retrying
		// only delays the inevitable. Surface immediately.
		calls, err := runLoop(context.Background(), []error{permanent})
		if !errors.Is(err, permanent) {
			t.Errorf("err = %v, want permanent", err)
		}
		if calls != 1 {
			t.Errorf("calls = %d, want 1 (no retry)", calls)
		}
	})

	t.Run("all attempts transient: returns last error", func(t *testing.T) {
		calls, err := runLoop(context.Background(), []error{transient, transient, transient})
		if err == nil {
			t.Fatal("expected error after exhausting retries")
		}
		if !isTransientRestError(err) {
			t.Errorf("returned err should be the transient one, got %v", err)
		}
		if calls != restRetryAttempts {
			t.Errorf("calls = %d, want %d", calls, restRetryAttempts)
		}
	})

	t.Run("context cancellation aborts retry loop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		// Cancel mid-loop so the second attempt's backoff aborts.
		go func() {
			time.Sleep(500 * time.Microsecond)
			cancel()
		}()
		_, err := runLoop(ctx, []error{transient, transient, transient})
		if !errors.Is(err, context.Canceled) {
			// Could also be the last transient if cancel raced past
			// the backoff; either way the loop must terminate quickly.
			if !isTransientRestError(err) {
				t.Errorf("unexpected err: %v", err)
			}
		}
	})
}

func TestIsRetryableCriticalError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		// Deterministic 4xx must not be retried.
		{"rest 400", &rest.Error{Response: &rest.Response{Code: 400}}, false},
		{"rest 404", &rest.Error{Response: &rest.Response{Code: 404}}, false},
		// 5xx retried, as in the plain retry path.
		{"rest 500", &rest.Error{Response: &rest.Response{Code: 500}}, true},
		{"rest 503", &rest.Error{Response: &rest.Response{Code: 503}}, true},
		// The critical difference vs isTransientRestError: transport-level
		// failures ARE retried — the request may have been delivered and
		// abandoning it risks desyncing the server-side share (the field
		// case was an http2 header timeout after 90s).
		{"transport http2 timeout", errors.New(`Post "https://…/WalletSign:setGeneratedKey": http2: timeout awaiting response headers`), true},
		{"connection reset", errors.New("read tcp: connection reset by peer"), true},
		{"rest error with nil response", &rest.Error{}, true},
		{"wrapped 404", fmt.Errorf("x: %w", &rest.Error{Response: &rest.Response{Code: 404}}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableCriticalError(tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReshareRoundsContext(t *testing.T) {
	t.Run("nil error passes through", func(t *testing.T) {
		_, cancel, wrap, _ := reshareRoundsContext(context.Background())
		defer cancel()
		if wrap(nil) != nil {
			t.Fatal("wrap(nil) must be nil")
		}
	})
	t.Run("own deadline becomes descriptive error", func(t *testing.T) {
		_, cancel, wrap, _ := reshareRoundsContext(context.Background())
		defer cancel()
		err := wrap(context.DeadlineExceeded)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("must keep DeadlineExceeded in chain, got %v", err)
		}
		if !strings.Contains(err.Error(), "stopped responding") {
			t.Fatalf("expected descriptive message, got %q", err.Error())
		}
	})
	t.Run("caller cancel passes through untouched", func(t *testing.T) {
		parent, parentCancel := context.WithCancel(context.Background())
		_, cancel, wrap, _ := reshareRoundsContext(parent)
		defer cancel()
		parentCancel()
		// Host cancelled: even a DeadlineExceeded from the derived ctx
		// must not be re-labelled as a participant failure.
		if err := wrap(context.DeadlineExceeded); strings.Contains(err.Error(), "stopped responding") {
			t.Fatalf("caller cancel must pass through, got %q", err.Error())
		}
		if err := wrap(context.Canceled); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected Canceled, got %v", err)
		}
	})
	t.Run("other errors unchanged", func(t *testing.T) {
		_, cancel, wrap, _ := reshareRoundsContext(context.Background())
		defer cancel()
		e := errors.New("vss verification failed")
		if wrap(e) != e {
			t.Fatal("non-deadline errors must pass through unchanged")
		}
	})
	t.Run("remote-reported failure surfaces its reason", func(t *testing.T) {
		ctx, cancel, wrap, fail := reshareRoundsContext(context.Background())
		defer cancel()
		fail("reshare eddsa: stored share belongs to party key 123 (stale share)")
		<-ctx.Done() // fail cancels the rounds ctx
		err := wrap(ctx.Err())
		if err == nil || !strings.Contains(err.Error(), "stale share") {
			t.Fatalf("expected remote reason to surface, got %v", err)
		}
		if strings.Contains(err.Error(), "stopped responding") {
			t.Fatalf("remote failure must not be mislabelled as a timeout, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "committee is unchanged") {
			t.Fatalf("expected committee-unchanged assurance, got %q", err.Error())
		}
	})
}
