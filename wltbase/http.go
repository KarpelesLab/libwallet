package wltbase

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// maxCacheGetBytes caps how much of a caller/contract-supplied URL
// (NFT tokenURI, asset metadata, …) we'll read into memory. Metadata
// JSON is small; this just bounds a hostile or buggy endpoint.
const maxCacheGetBytes = 8 << 20 // 8 MiB

var errBlockedHost = errors.New("refusing to fetch from a private, loopback, or link-local network address")

// isBlockedIP reports whether ip is an internal / non-routable target
// that an SSRF attacker could use to reach wallet-host internal
// services or cloud metadata endpoints.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsPrivate() || // RFC1918 + IPv6 ULA (fc00::/7)
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || // 169.254/16, fe80::/10
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 — carrier-grade NAT / shared address space.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		// 192.0.0.0/24 — IETF protocol assignments.
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 {
			return true
		}
	}
	return false
}

// safeDialControl runs after DNS resolution with the concrete IP the
// transport is about to dial (address is "ip:port"), so it also
// defeats DNS-rebinding — every hop and every resolved address is
// checked against the denylist.
func safeDialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if isBlockedIP(ip) {
		return fmt.Errorf("%w (%s)", errBlockedHost, host)
	}
	return nil
}

// cacheHTTPClient is the hardened client used for all caller-supplied
// URL fetches: IP-denylisted dialing (incl. redirects), a bounded
// redirect chain that stays on http(s), and a connect timeout. The
// body size cap is applied at read time by CacheGet.
var cacheHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: safeDialControl,
		}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-http(s) scheme %q", req.URL.Scheme)
		}
		return nil
	},
}

func (e *env) CacheGet(ctx context.Context, u string, timeout, refresh time.Duration) ([]byte, error) {
	cacheKey := "http:" + fmt.Sprintf("%x", sha256.Sum256([]byte(u)))

	// check if in cache
	cachebuf, err := e.CacheLoad(cacheKey)

	if err == nil && cachebuf != nil {
		// found and not expired, return it
		return cachebuf, nil
	}

	// Reject anything that isn't a plain http(s) URL before we even
	// build the request — no file://, ftp://, data:, etc.
	parsed, perr := url.Parse(u)
	if perr != nil {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, fmt.Errorf("invalid URL: %w", perr)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}

	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, err
	}

	resp, err := cacheHTTPClient.Do(req)
	if err != nil {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	// Cap how much we read so a hostile endpoint can't exhaust memory.
	// +1 byte to detect overflow past the limit.
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxCacheGetBytes+1))
	if err != nil {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, err
	}
	if len(buf) > maxCacheGetBytes {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, fmt.Errorf("response exceeds %d byte limit", maxCacheGetBytes)
	}

	if resp.StatusCode >= 300 {
		if cachebuf != nil {
			return cachebuf, nil
		}
		if len(buf) > 512 {
			buf = buf[:512]
		}
		return nil, fmt.Errorf("HTTP status %s on GET: %s", resp.Status, buf)
	}

	// save in cache with the refresh duration as TTL
	e.CacheStore(cacheKey, buf, refresh)

	return buf, nil
}
