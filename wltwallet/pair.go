package wltwallet

// ClawdWallet pairing — Stage 1.
//
// The mobile app receives a `tibane://pair?agent=<spot-id>&token=<token>`
// URL out-of-band, hands it to libwallet, and gets back a verified agent
// identity (or a typed error). The handshake is one Spot round trip:
// mobile → agent's `pair` endpoint with {v, token, mobile_spot_id};
// agent replies with {v, agent_spot_id, suggested_name?, agent_version?,
// capabilities} or {v, error, message?}.
//
// Wire contract: ~/projects/tibaneapp/docs/clawdwallet-pairing.md.
//
// Errors are returned as `errors.New("<code>")` so the code string is the
// marshalled error message and the Dart side can dispatch to a typed
// exception in a single switch. Codes are the closed set from the contract
// (token_invalid / token_expired / token_consumed / bad_request) plus three
// libwallet-internal codes for failures that happen before or around the
// Spot call: url_malformed (URL never made it to the wire), agent_unreachable
// (Spot timeout / transport error), identity_mismatch (response's
// agent_spot_id ≠ URL's agent param — treat as redirection attack).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
)

func init() {
	pobj.RegisterStatic("ClawdWallet:pair", apiClawdWalletPair)
}

const (
	pairProtocolVersion = 1
	pairSpotEndpoint    = "pair"        // suffix appended to the agent's spot id
	pairQueryTimeout    = 15 * time.Second
)

// Sentinel errors. Each Error() string is the wire-level code surfaced to
// Dart — keep them as plain `errors.New(code)` so the dispatcher there can
// branch on the message verbatim.
var (
	errPairURLMalformed     = errors.New("url_malformed")
	errPairAgentUnreachable = errors.New("agent_unreachable")
	errPairTokenInvalid     = errors.New("token_invalid")
	errPairTokenExpired     = errors.New("token_expired")
	errPairTokenConsumed    = errors.New("token_consumed")
	errPairBadRequest       = errors.New("bad_request")
	errPairIdentityMismatch = errors.New("identity_mismatch")
)

// pairInput is the API surface — a single URL string.
type pairInput struct {
	URL string `json:"url"`
}

// pairRequestBody is the JSON sent to the agent's pair Spot endpoint.
// Field order/tags match the contract verbatim.
type pairRequestBody struct {
	V            int    `json:"v"`
	Token        string `json:"token"`
	MobileSpotID string `json:"mobile_spot_id"`
}

// pairSuccessBody mirrors the contract's pair-response success shape and
// is also the value returned to the API caller. Capabilities is opaque —
// kept as `map[string]any` so unknown keys round-trip through Dart.
type pairSuccessBody struct {
	V             int            `json:"v"`
	AgentSpotID   string         `json:"agent_spot_id"`
	SuggestedName string         `json:"suggested_name,omitempty"`
	AgentVersion  string         `json:"agent_version,omitempty"`
	Capabilities  map[string]any `json:"capabilities"`
}

// pairErrorBody mirrors the contract's error response. We only inspect the
// `error` field; the optional `message` is logged but not surfaced to the
// app (the typed Dart exception already conveys the meaning).
type pairErrorBody struct {
	V       int    `json:"v"`
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// parseClawdPairURL validates a tibane://pair?... URL and extracts the
// agent spot id and pairing token. Returns errPairURLMalformed for any
// validation failure — callers don't need to distinguish the sub-reasons,
// the Dart side surfaces the same exception class either way.
func parseClawdPairURL(raw string) (agentSpotID, token string, err error) {
	if raw == "" {
		return "", "", errPairURLMalformed
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", errPairURLMalformed
	}
	if u.Scheme != "tibane" {
		return "", "", errPairURLMalformed
	}
	// `tibane://pair?...` parses as scheme=tibane, host=pair, path="" — the
	// "pair" segment lives in u.Host. Accept either, since some URL
	// libraries normalise differently.
	target := u.Host
	if target == "" {
		target = strings.TrimPrefix(u.Path, "/")
	}
	if target != "pair" {
		return "", "", errPairURLMalformed
	}
	q := u.Query()
	agent := q.Get("agent")
	tok := q.Get("token")
	if agent == "" || tok == "" {
		return "", "", errPairURLMalformed
	}
	// Sanity-check the agent id format. Spot ids are `k.<base64url>`; we
	// don't decode, just reject obvious garbage so we fail before the
	// QueryTimeout call.
	if !strings.HasPrefix(agent, "k.") || len(agent) < 4 {
		return "", "", errPairURLMalformed
	}
	return agent, tok, nil
}

// dispatchPairResponse parses the raw Spot response body. Tries the success
// shape first, falls back to the error shape. Anything else (malformed
// JSON, unexpected fields, wrong v) collapses to bad_request — the Dart
// side already treats unknown / malformed as "fail closed".
//
// Exposed as a package-private function (not a method) so the unit tests
// can drive it without a live spotlib client.
func dispatchPairResponse(raw []byte, expectedAgentID string) (*pairSuccessBody, error) {
	if len(raw) == 0 {
		return nil, errPairBadRequest
	}

	// Probe the body to decide which shape to decode into. We can't decode
	// straight into pairSuccessBody because an error body's missing
	// `agent_spot_id` would deserialize as zero-value and pass — peek at
	// the keys instead.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, errPairBadRequest
	}

	if _, hasError := probe["error"]; hasError {
		var eb pairErrorBody
		if err := json.Unmarshal(raw, &eb); err != nil {
			return nil, errPairBadRequest
		}
		switch eb.Error {
		case "token_invalid":
			return nil, errPairTokenInvalid
		case "token_expired":
			return nil, errPairTokenExpired
		case "token_consumed":
			return nil, errPairTokenConsumed
		case "bad_request":
			return nil, errPairBadRequest
		default:
			// Unknown code — fail closed.
			return nil, errPairBadRequest
		}
	}

	var sb pairSuccessBody
	if err := json.Unmarshal(raw, &sb); err != nil {
		return nil, errPairBadRequest
	}
	if sb.V != pairProtocolVersion {
		// Unsupported version → contract says reply with bad_request. We
		// got a success-shaped body but with the wrong v; same response
		// from our perspective.
		return nil, errPairBadRequest
	}
	if sb.AgentSpotID == "" {
		return nil, errPairBadRequest
	}
	// Tolerate a nil capabilities map — the contract says it's required
	// in the wire format, but the Dart side wants a defined object so the
	// app can call .containsKey freely. Normalise to empty.
	if sb.Capabilities == nil {
		sb.Capabilities = map[string]any{}
	}

	if sb.AgentSpotID != expectedAgentID {
		return nil, errPairIdentityMismatch
	}
	return &sb, nil
}

// apiClawdWalletPair is the Dart-facing entry point. Validates the URL,
// builds the pair-request body, sends it over Spot, and dispatches the
// response into either a verified identity or a typed error.
func apiClawdWalletPair(ctx *apirouter.Context, in pairInput) (any, error) {
	agentSpotID, token, err := parseClawdPairURL(in.URL)
	if err != nil {
		return nil, err
	}

	spot, err := envSpot(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: spot client unavailable: %v", errPairAgentUnreachable, err)
	}
	// We don't gate on WaitOnline here. QueryTimeout already fails with a
	// transport error if the relay isn't reachable, and forcing every
	// pair() call to pay a 15s WaitOnline plus the 15s query budget
	// doubles the worst-case wait for no real benefit — the pair UX is
	// "tap link, see result", not "tap link, then WAIT for spot to
	// initialise then see result".
	mobileSpotID := spot.TargetId()

	body, err := json.Marshal(&pairRequestBody{
		V:            pairProtocolVersion,
		Token:        token,
		MobileSpotID: mobileSpotID,
	})
	if err != nil {
		// Marshal of a fixed shape with string fields shouldn't fail —
		// if it does, treat as a libwallet bug, not a contract error.
		return nil, fmt.Errorf("failed to encode pair request: %w", err)
	}

	target := agentSpotID + "/" + pairSpotEndpoint
	queryCtx, cancel := context.WithTimeout(context.Background(), pairQueryTimeout)
	defer cancel()
	resp, err := spot.Query(queryCtx, target, body)
	if err != nil {
		// Anything from the spotlib transport collapses into the single
		// "agent unreachable" code. Distinguishing context.DeadlineExceeded
		// from "no route" doesn't help the app — both surface as a
		// timeout-style retry button.
		return nil, fmt.Errorf("%w: %v", errPairAgentUnreachable, err)
	}

	return dispatchPairResponse(resp, agentSpotID)
}
