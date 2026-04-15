package wltwallet

// Wallet-app identity plumbing for Crypto/WalletSign:* calls.
//
// Host wallets register themselves once at startup via Info:setWalletInfo.
// Fields are stored in package-global atomics so remote-call helpers can
// pick them up without each endpoint threading them through.
//
// Current use: the Sec-ClientId HTTP header, which the WalletSign backend
// maps to branded SMS/email copy, per-app rate limits, and audit logs.
// Future fields (app name, version, platform) will plug into the same
// struct so adding new metadata doesn't require a new endpoint.

import (
	"context"
	"net/http"
	"sync/atomic"
)

// WalletInfo is the identity block host wallets pass to libwallet so
// downstream services can tell which app a request came from.
type WalletInfo struct {
	// ClientID maps to the Sec-ClientId HTTP header. Pre-registered with
	// the WalletSign backend operator. Required for any RemoteKey flow
	// once the backend enforces it.
	ClientID string `json:"clientId"`

	// Name is a short human-readable name (e.g. "MyWallet"). Optional —
	// reserved for future use (e.g. untrusted display strings on
	// approval prompts where the server wants to echo "$Name is asking
	// for your signature").
	Name string `json:"name,omitempty"`

	// Version is the host app's version string (e.g. "1.4.2"). Optional,
	// diagnostic only.
	Version string `json:"version,omitempty"`
}

var walletInfo atomic.Pointer[WalletInfo]

// SetWalletInfo replaces the current wallet-identity record. Pass a
// zero-value struct to clear.
func SetWalletInfo(info WalletInfo) {
	if info == (WalletInfo{}) {
		walletInfo.Store(nil)
		return
	}
	walletInfo.Store(&info)
}

// GetWalletInfo returns the currently configured wallet-identity record
// (zero value when none has been set).
func GetWalletInfo() WalletInfo {
	if p := walletInfo.Load(); p != nil {
		return *p
	}
	return WalletInfo{}
}

// withClientID wraps ctx so the rest library's per-request hook
// (rest.go:165 `ctx.Value(r)`) sees the *http.Request and attaches
// Sec-ClientId. No-op when no wallet info has been registered.
func withClientID(ctx context.Context) context.Context {
	info := GetWalletInfo()
	if info.ClientID == "" {
		return ctx
	}
	return &clientIDCtx{Context: ctx, id: info.ClientID}
}

type clientIDCtx struct {
	context.Context
	id string
}

// Value satisfies context.Context; when the rest library calls
// ctx.Value(*http.Request{...}) just before dispatching, we intercept
// and stamp the header onto the request. For every other key we
// delegate to the parent.
func (c *clientIDCtx) Value(key any) any {
	if req, ok := key.(*http.Request); ok && req != nil {
		req.Header.Set("Sec-ClientId", c.id)
		return nil
	}
	return c.Context.Value(key)
}
