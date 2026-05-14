package wltswap

// Typed errors surfaced by Swap:quote and Swap:execute. Apps pattern-
// match on the Code field to drive UI copy (retry, re-quote, show a
// slippage slider, etc.). The human-readable Message is appropriate
// for fallback display but apps should prefer their own localized
// strings keyed off Code.

import "errors"

// SwapError is a machine-readable failure. Code values are stable
// across versions — apps in the wild depend on them.
//
// JSON-marshallable because Swap:quotes (plural) returns one
// SwapError per failed provider attempt inside its response shape.
type SwapError struct {
	Code    string `json:"code"`    // stable code; see constants below
	Message string `json:"message"` // human-readable description
}

func (e *SwapError) Error() string { return e.Message }

// Stable error codes.
const (
	// ErrCodeQuoteExpired — the QuoteId is older than its ExpiresAt.
	// Re-quote and try again.
	ErrCodeQuoteExpired = "quote_expired"

	// ErrCodeQuoteNotFound — the QuoteId was never issued, or was
	// evicted from the in-memory cache (server restart, cache full).
	ErrCodeQuoteNotFound = "quote_not_found"

	// ErrCodeNoLiquidity — the provider returned no routes for the
	// token pair + size.
	ErrCodeNoLiquidity = "no_liquidity"

	// ErrCodeSlippageExceeded — the execute step would settle at a
	// price worse than the quote's minAmountOut. Surfaces both at
	// simulate time (provider-reported) and at broadcast time (chain
	// reverts / rejects).
	ErrCodeSlippageExceeded = "slippage_exceeded"

	// ErrCodeProviderUnavailable — a 5xx / timeout / network failure
	// talking to the aggregator. For quote this triggers the auto-
	// fallback (Jupiter → dFlow); for execute it's surfaced to the
	// caller to retry manually.
	ErrCodeProviderUnavailable = "provider_unavailable"

	// ErrCodeProviderBadRequest — a 4xx from the aggregator after we
	// built a request. Usually means the token pair or amount was
	// rejected; we don't auto-fallback on this one.
	ErrCodeProviderBadRequest = "provider_bad_request"

	// ErrCodeUnsupportedChain — the current network's Type isn't
	// covered by any provider (e.g. bitcoin).
	ErrCodeUnsupportedChain = "unsupported_chain"

	// ErrCodeUnsupportedTokenPair — the caller asked for a token
	// pair no enabled provider routes (EVM aggregator on a chain we
	// don't have configured, Solana pair with only provider-banned
	// mints, etc.).
	ErrCodeUnsupportedTokenPair = "unsupported_token_pair"

	// ErrCodeMissingAPIKey — a provider we were asked to use has its
	// API key left blank in this build. 1inch ships without a key
	// until the integrator fills it in.
	ErrCodeMissingAPIKey = "missing_api_key"

	// ErrCodeInvalidRequest — the caller passed malformed input
	// (non-decimal amount, empty token address, unknown provider
	// name, …). Distinct from ProviderBadRequest which comes from
	// the upstream.
	ErrCodeInvalidRequest = "invalid_request"
)

// newErr is the internal constructor — keep the Code/Message pair
// in one place so adapters don't invent new free-form strings.
func newErr(code, msg string) *SwapError {
	return &SwapError{Code: code, Message: msg}
}

// AsSwapError unwraps err and returns the underlying SwapError if
// any. Apps can also use errors.As directly.
func AsSwapError(err error) (*SwapError, bool) {
	var se *SwapError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}
