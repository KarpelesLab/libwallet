package wltswap

// Fee / slippage defaults and bounds for the swap adapters.
//
// NOTE: this file previously also carried a generic REST helper
// (httpGetJSON / httpPostJSON / httpRun) used by an earlier
// direct-to-provider adapter. After the migration to the server-side
// Crypto/Okx:* proxy (every call now goes through rest.Apply, which
// enforces the platform's host allow-list and auth) those helpers had
// no callers. They were removed in the audit hardening pass because a
// generic, redirect-following HTTP client with no host validation is a
// standing SSRF / token-exfiltration risk even while dormant. If a
// future provider genuinely needs raw REST, reintroduce it with an
// explicit host allow-list and CheckRedirect that refuses cross-host
// redirects — do NOT restore the old unbounded client.

// Fee / slippage defaults. All routed swaps use 50 bps (0.5%).
const (
	DefaultFeeBps      uint16 = 50
	DefaultSlippageBps uint16 = 50
)

// MaxSlippageBps is the hard ceiling libwallet accepts for caller-
// supplied slippage. 5000 bps (50%) is already far beyond any sane
// trade; anything higher is almost certainly a bug or an attempt to
// drive the provider's MinReceive to near-zero, so we clamp to it.
// Clamping (rather than rejecting) keeps legitimate high-slippage
// trades on illiquid pairs working while removing the unbounded /
// uint16-underflow hazard in the bps-factor math.
const MaxSlippageBps uint16 = 5000

// normalizeSlippageBps applies the default-on-zero and the upper-bound
// clamp in one place. Call it at every API boundary that accepts a
// caller-supplied SlippageBps so downstream math (1 - bps/10_000) can
// never see an out-of-range value.
func normalizeSlippageBps(bps uint16) uint16 {
	if bps == 0 {
		return DefaultSlippageBps
	}
	if bps > MaxSlippageBps {
		return MaxSlippageBps
	}
	return bps
}
