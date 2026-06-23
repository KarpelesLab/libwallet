package wltbase

import (
	"sync"
	"time"
)

// assetCacheTTL is the default lifetime of a cached asset snapshot. Kept
// short: it only needs to span the burst of near-simultaneous callers one
// balance change fans out into — the poller's own poll, the Asset:list
// endpoint, and the host-side refresh the poller's broadcast triggers.
const assetCacheTTL = 2 * time.Second

// assetSnapshotCache memoizes the most recent currentAssets result for a
// single (account, network) key, collapsing the redundant upstream RPC
// scans one logical refresh produces:
//
//   - the balance poller calls currentAssets every tick;
//   - that broadcast makes the host call Asset:list, which calls it again;
//   - the host's own dashboard load may call it a third time.
//
// Without memoization each is a fresh getBalance +
// getMinimumBalanceForRentExemption + getTokenAccountsByOwner round-trip.
//
// Two mechanisms cooperate:
//   - a TTL serves callers arriving shortly AFTER a fetch completes (the
//     poll -> broadcast -> host-refresh echo lands a beat later);
//   - an in-flight latch serves callers arriving DURING a fetch (e.g. a
//     pull-to-refresh firing two loads at once) — they block on and share
//     the leader's single result.
//
// The zero value is ready to use; ttl defaults to assetCacheTTL when unset
// (overridable in tests).
type assetSnapshotCache struct {
	mu       sync.Mutex
	ttl      time.Duration
	key      string
	snap     *assetSnapshot
	expiry   time.Time
	inflight map[string]*assetFetch
}

// assetFetch is one in-progress computeAssets call other callers can await.
type assetFetch struct {
	done chan struct{}
	snap *assetSnapshot
	err  error
}

// get returns the cached snapshot for key while it's still fresh, joins an
// in-flight fetch for the same key when one is running, or otherwise runs
// fetch as the leader and memoizes its result. Errors are never cached.
//
// The returned snapshot is the shared cached instance — callers that mutate
// it (e.g. ConvertTo) must clone first; currentAssets does.
func (c *assetSnapshotCache) get(key string, fetch func() (*assetSnapshot, error)) (*assetSnapshot, error) {
	c.mu.Lock()
	ttl := c.ttl
	if ttl <= 0 {
		ttl = assetCacheTTL
	}
	if c.snap != nil && c.key == key && time.Now().Before(c.expiry) {
		snap := c.snap
		c.mu.Unlock()
		return snap, nil
	}
	if f := c.inflight[key]; f != nil {
		c.mu.Unlock()
		<-f.done
		return f.snap, f.err
	}
	f := &assetFetch{done: make(chan struct{})}
	if c.inflight == nil {
		c.inflight = make(map[string]*assetFetch)
	}
	c.inflight[key] = f
	c.mu.Unlock()

	snap, err := fetch()

	c.mu.Lock()
	f.snap, f.err = snap, err
	if err == nil {
		c.snap, c.key, c.expiry = snap, key, time.Now().Add(ttl)
	}
	delete(c.inflight, key)
	c.mu.Unlock()
	close(f.done)
	return snap, err
}

// invalidate drops any cached snapshot so the next get runs a fresh fetch.
// Exposed to the host via Asset:invalidateCache and called internally after
// a tx broadcast (post-send balances must not serve a pre-send snapshot).
// An in-flight fetch is left to finish — its result is the latest anyway.
func (c *assetSnapshotCache) invalidate() {
	c.mu.Lock()
	c.snap = nil
	c.key = ""
	c.expiry = time.Time{}
	c.mu.Unlock()
}
