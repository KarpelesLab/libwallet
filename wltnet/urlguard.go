package wltnet

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// urlguard.go centralizes validation of caller-/dApp-supplied URLs that
// libwallet will dereference on the user's behalf. A Network.RPC is used
// verbatim both for read-only queries AND for broadcasting signed
// transactions, so an unvalidated value lets a malicious dApp repoint a
// plausibly-named chain at an attacker-controlled endpoint (credential
// relay, tx censorship, balance spoofing) or at an internal service the
// host can reach but the attacker cannot (SSRF / port fingerprinting).
//
// The policy here is deliberately conservative: it must keep allowing the
// large set of legitimate public RPC / metadata hosts while rejecting the
// obvious internal-network and scheme-downgrade abuses. Full DNS-rebinding
// protection for the actual outbound fetch lives in the central
// wltbase.CacheGet fetcher; these helpers are the URL-shape gate.

// isInternalIP reports whether ip is in a range that must never be the
// target of a caller-supplied RPC / metadata URL: loopback, RFC1918
// private, IPv6 unique-local (ULA, fc00::/7 — covered by IsPrivate),
// link-local, multicast, unspecified, carrier-grade NAT (100.64/10) or
// the 0.0.0.0/8 "this host" block.
func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 carrier-grade NAT
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return true
		}
		// 0.0.0.0/8 "this host on this network"
		if v4[0] == 0 {
			return true
		}
	}
	return false
}

// isLocalhostName reports whether host is the explicit localhost dev
// endpoint (the development escape hatch): the literal name "localhost"
// or a "*.localhost" subname.
func isLocalhostName(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// validateNetworkRPC validates a Network.RPC value. The sentinels "" and
// "auto" mean "pick automatically from the chain registry" and are always
// allowed; any concrete URL must pass validateRPCURL.
func validateNetworkRPC(rpc string) error {
	rpc = strings.TrimSpace(rpc)
	if rpc == "" || rpc == "auto" {
		return nil
	}
	return validateRPCURL(rpc)
}

// validateRPCURL validates a concrete RPC URL before it is used for
// queries or signed-transaction broadcast.
//
// Policy:
//   - scheme must be http or https;
//   - https is required for any public host;
//   - http is allowed ONLY for an explicit localhost / loopback endpoint
//     (the local-development escape hatch);
//   - literal loopback / RFC1918 / link-local / ULA / multicast IPs are
//     rejected (loopback is permitted only through the localhost hatch);
//   - "*.local" mDNS names are rejected.
func validateRPCURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("empty RPC URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid RPC URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("RPC URL scheme %q not allowed (want https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("RPC URL has no host")
	}
	lhost := strings.ToLower(strings.TrimSuffix(host, "."))

	// Development escape hatch: explicit localhost name or loopback
	// literal IP. These keep local dev RPCs working over http or https.
	if isLocalhostName(lhost) {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}

	if scheme != "https" {
		return errors.New("RPC URL must use https (http is allowed only for localhost)")
	}
	if strings.HasSuffix(lhost, ".local") {
		return fmt.Errorf("RPC URL host %q (.local mDNS) not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if isInternalIP(ip) {
			return fmt.Errorf("RPC URL points at internal address %s", ip)
		}
	}
	return nil
}

// validateMetadataURL validates an http(s) URL that libwallet is about to
// fetch NFT / token metadata from. Unlike RPC URLs, metadata is read-only
// and frequently served over plain http, so both schemes are allowed —
// but the target must not be an internal address. Both literal-IP hosts
// and resolved hostnames are checked; the resolved-host / redirect-hop /
// body-size enforcement for the actual transfer is owned by the central
// hardened wltbase.CacheGet fetcher.
func validateMetadataURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("empty metadata URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid metadata URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("metadata URL scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("metadata URL has no host")
	}
	lhost := strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.HasSuffix(lhost, ".local") {
		return fmt.Errorf("metadata URL host %q (.local mDNS) not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if isInternalIP(ip) {
			return fmt.Errorf("metadata URL points at internal address %s", ip)
		}
		return nil
	}
	// Hostname: best-effort resolve and reject any internal answer.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("metadata URL host %q does not resolve: %w", host, err)
	}
	for _, ip := range ips {
		if isInternalIP(ip) {
			return fmt.Errorf("metadata URL host %q resolves to internal address %s", host, ip)
		}
	}
	return nil
}

// validIPFSCID reports whether cid is a plausible bare IPFS CID or CID
// path so it can be safely concatenated onto a gateway base URL. Real
// CIDs are restricted to the base32/base58/base36 alphabets plus '/' for
// in-CID paths; rejecting everything else stops a contract-controlled
// value from smuggling '..', '?', '#', '@' or another scheme into the
// composed request.
func validIPFSCID(cid string) bool {
	if cid == "" || len(cid) > 512 {
		return false
	}
	if strings.Contains(cid, "..") {
		return false
	}
	for _, r := range cid {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == '_':
		default:
			return false
		}
	}
	// must not start with a path separator
	return !strings.HasPrefix(cid, "/")
}
