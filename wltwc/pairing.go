package wltwc

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// pairingURI is the parsed form of wc:TOPIC@VERSION?relay-protocol=...&symKey=...
//
// Only the fields libwallet actually uses are promoted to struct fields;
// future query params (methods, expiry) fall through to the Extras map
// without causing parsing to fail.
type pairingURI struct {
	Topic    string    // 64-char hex sha256(symKey) — confirmed after parsing
	Version  string    // "2" for v2 URIs
	Protocol string    // relay-protocol, always "irn" in v2
	SymKey   []byte    // 32 raw bytes
	Expiry   time.Time // from expiryTimestamp param if present
	Extras   url.Values
}

// parsePairingURI decodes a wc:... URI and validates the shape libwallet
// supports. Only WalletConnect v2 URIs are accepted.
func parsePairingURI(raw string) (*pairingURI, error) {
	if !strings.HasPrefix(raw, "wc:") {
		return nil, errors.New("not a wc: URI")
	}
	// wc:{topic}@{version}?{query}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse URI: %w", err)
	}
	if u.Scheme != "wc" {
		return nil, fmt.Errorf("scheme %q, want wc", u.Scheme)
	}
	// u.Opaque is "topic@version" (no authority, no slashes).
	opaque := u.Opaque
	if opaque == "" {
		// some URIs end up with topic in Host via "wc://"
		opaque = u.Host
	}
	at := strings.IndexByte(opaque, '@')
	if at == -1 {
		return nil, errors.New("URI missing @version")
	}
	topic := opaque[:at]
	version := opaque[at+1:]
	if version != "2" {
		return nil, fmt.Errorf("unsupported WalletConnect version %q", version)
	}
	q := u.Query()
	symKeyHex := q.Get("symKey")
	if symKeyHex == "" {
		return nil, errors.New("symKey query param missing")
	}
	symKey, err := hex.DecodeString(symKeyHex)
	if err != nil {
		return nil, fmt.Errorf("symKey not valid hex: %w", err)
	}
	if len(symKey) != symKeySize {
		return nil, fmt.Errorf("symKey length %d, want %d", len(symKey), symKeySize)
	}
	proto := q.Get("relay-protocol")
	if proto == "" {
		proto = "irn"
	}
	derivedTopic := topicFromSymKey(symKey)
	if topic != derivedTopic {
		return nil, fmt.Errorf("topic mismatch: URI says %s, derives to %s", topic, derivedTopic)
	}
	res := &pairingURI{
		Topic:    topic,
		Version:  version,
		Protocol: proto,
		SymKey:   symKey,
		Extras:   q,
	}
	if exp := q.Get("expiryTimestamp"); exp != "" {
		var ts int64
		if _, err := fmt.Sscanf(exp, "%d", &ts); err == nil && ts > 0 {
			res.Expiry = time.Unix(ts, 0)
		}
	}
	if res.Expiry.IsZero() {
		// WC v2 pairing URIs default to 5-minute validity.
		res.Expiry = time.Now().Add(5 * time.Minute)
	}
	return res, nil
}

// b64url returns base64.RawURLEncoding for 32-byte keys.
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
