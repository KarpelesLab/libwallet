package wltbase

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"
)

func (e *env) CacheGet(ctx context.Context, u string, timeout, refresh time.Duration) ([]byte, error) {
	cacheKey := "http:" + fmt.Sprintf("%x", sha256.Sum256([]byte(u)))

	// check if in cache
	cachebuf, err := e.CacheLoad(cacheKey)

	if err == nil && cachebuf != nil {
		// found and not expired, return it
		return cachebuf, nil
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		if cachebuf != nil {
			return cachebuf, nil
		}
		return nil, err
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
