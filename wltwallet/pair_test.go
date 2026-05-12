package wltwallet

import (
	"errors"
	"fmt"
	"testing"
)

func TestParseClawdPairURL(t *testing.T) {
	const goodAgent = "k.AAAA0123456"
	const goodToken = "abcdefghijklmnopqrstuv"

	cases := []struct {
		name      string
		url       string
		wantAgent string
		wantToken string
		wantErr   error
	}{
		{
			name:      "valid",
			url:       "clawd://pair?agent=" + goodAgent + "&token=" + goodToken,
			wantAgent: goodAgent,
			wantToken: goodToken,
		},
		{
			name:      "valid extra params ignored",
			url:       "clawd://pair?agent=" + goodAgent + "&token=" + goodToken + "&v=1",
			wantAgent: goodAgent,
			wantToken: goodToken,
		},
		{name: "empty", url: "", wantErr: errPairURLMalformed},
		{name: "wrong scheme", url: "https://pair?agent=" + goodAgent + "&token=" + goodToken, wantErr: errPairURLMalformed},
		{name: "wrong path", url: "clawd://other?agent=" + goodAgent + "&token=" + goodToken, wantErr: errPairURLMalformed},
		{name: "missing agent", url: "clawd://pair?token=" + goodToken, wantErr: errPairURLMalformed},
		{name: "missing token", url: "clawd://pair?agent=" + goodAgent, wantErr: errPairURLMalformed},
		{name: "agent without k. prefix", url: "clawd://pair?agent=zzzz&token=" + goodToken, wantErr: errPairURLMalformed},
		{name: "garbage", url: ":::not a url", wantErr: errPairURLMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent, tok, err := parseClawdPairURL(tc.url)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if agent != tc.wantAgent {
				t.Errorf("agent = %q, want %q", agent, tc.wantAgent)
			}
			if tok != tc.wantToken {
				t.Errorf("token = %q, want %q", tok, tc.wantToken)
			}
		})
	}
}

func TestDispatchPairResponse(t *testing.T) {
	const agent = "k.AAAA12345"
	const otherAgent = "k.BBBB67890"

	t.Run("success", func(t *testing.T) {
		body := []byte(`{"v":1,"agent_spot_id":"` + agent + `","suggested_name":"laptop","agent_version":"v0.1.0","capabilities":{"x":1}}`)
		got, err := dispatchPairResponse(body, agent)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got.AgentSpotID != agent {
			t.Errorf("AgentSpotID = %q, want %q", got.AgentSpotID, agent)
		}
		if got.SuggestedName != "laptop" {
			t.Errorf("SuggestedName = %q", got.SuggestedName)
		}
		if got.AgentVersion != "v0.1.0" {
			t.Errorf("AgentVersion = %q", got.AgentVersion)
		}
		if v, _ := got.Capabilities["x"].(float64); v != 1 {
			t.Errorf("Capabilities[x] = %v", got.Capabilities["x"])
		}
	})

	t.Run("success with nil capabilities normalised", func(t *testing.T) {
		body := []byte(`{"v":1,"agent_spot_id":"` + agent + `","capabilities":null}`)
		got, err := dispatchPairResponse(body, agent)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got.Capabilities == nil {
			t.Errorf("Capabilities should be normalised to empty map, got nil")
		}
	})

	errorCases := []struct {
		name string
		code string
		want error
	}{
		{"token_invalid", "token_invalid", errPairTokenInvalid},
		{"token_expired", "token_expired", errPairTokenExpired},
		{"token_consumed", "token_consumed", errPairTokenConsumed},
		{"bad_request", "bad_request", errPairBadRequest},
		{"unknown code falls back to bad_request", "i_made_this_up", errPairBadRequest},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"v":1,"error":"` + tc.code + `","message":"detail"}`)
			_, err := dispatchPairResponse(body, agent)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("identity mismatch", func(t *testing.T) {
		body := []byte(`{"v":1,"agent_spot_id":"` + otherAgent + `","capabilities":{}}`)
		_, err := dispatchPairResponse(body, agent)
		if !errors.Is(err, errPairIdentityMismatch) {
			t.Fatalf("err = %v, want errPairIdentityMismatch", err)
		}
	})

	t.Run("missing agent_spot_id is bad_request", func(t *testing.T) {
		body := []byte(`{"v":1,"capabilities":{}}`)
		_, err := dispatchPairResponse(body, agent)
		if !errors.Is(err, errPairBadRequest) {
			t.Fatalf("err = %v, want errPairBadRequest", err)
		}
	})

	t.Run("wrong protocol version is bad_request", func(t *testing.T) {
		body := []byte(`{"v":99,"agent_spot_id":"` + agent + `","capabilities":{}}`)
		_, err := dispatchPairResponse(body, agent)
		if !errors.Is(err, errPairBadRequest) {
			t.Fatalf("err = %v, want errPairBadRequest", err)
		}
	})

	t.Run("garbage JSON is bad_request", func(t *testing.T) {
		_, err := dispatchPairResponse([]byte("{not json"), agent)
		if !errors.Is(err, errPairBadRequest) {
			t.Fatalf("err = %v, want errPairBadRequest", err)
		}
	})

	t.Run("empty body is bad_request", func(t *testing.T) {
		_, err := dispatchPairResponse(nil, agent)
		if !errors.Is(err, errPairBadRequest) {
			t.Fatalf("err = %v, want errPairBadRequest", err)
		}
	})
}

// TestSentinelErrorStrings pins the wire-level error codes Dart dispatches
// on. Renaming a sentinel without updating the Dart switch is an API break;
// this test catches that.
func TestSentinelErrorStrings(t *testing.T) {
	cases := map[error]string{
		errPairURLMalformed:     "url_malformed",
		errPairAgentUnreachable: "agent_unreachable",
		errPairTokenInvalid:     "token_invalid",
		errPairTokenExpired:     "token_expired",
		errPairTokenConsumed:    "token_consumed",
		errPairBadRequest:       "bad_request",
		errPairIdentityMismatch: "identity_mismatch",
	}
	for err, want := range cases {
		if got := err.Error(); got != want {
			t.Errorf("err = %q, want %q", got, want)
		}
		// apiClawdWalletPair wraps with %w in places (e.g. agent_unreachable
		// gets the underlying transport error appended). Confirm that a %w
		// wrap still matches the sentinel via errors.Is — the Dart side
		// dispatches on the unwrapped sentinel string.
		wrapped := fmt.Errorf("wrapper: %w", err)
		if !errors.Is(wrapped, err) {
			t.Errorf("%%w-wrapped %v doesn't match original via errors.Is", err)
		}
	}
}
