package wltbase

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fetch counts invocations so each test can assert how many real
// computeAssets-equivalent calls the cache let through.
func countingFetch(calls *int32, delay time.Duration) func() (*assetSnapshot, error) {
	return func() (*assetSnapshot, error) {
		atomic.AddInt32(calls, 1)
		if delay > 0 {
			time.Sleep(delay)
		}
		return &assetSnapshot{}, nil
	}
}

func TestAssetCache_CollapsesConcurrentCallers(t *testing.T) {
	c := &assetSnapshotCache{ttl: time.Second}
	var calls int32
	fetch := countingFetch(&calls, 20*time.Millisecond) // widen the in-flight window

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.get("k", fetch); err != nil {
				t.Errorf("get: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("8 concurrent callers ran fetch %d times, want 1", got)
	}
}

func TestAssetCache_ServesSequentialWithinTTL(t *testing.T) {
	c := &assetSnapshotCache{ttl: time.Minute}
	var calls int32
	fetch := countingFetch(&calls, 0)

	for i := 0; i < 5; i++ {
		if _, err := c.get("k", fetch); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("5 sequential callers within TTL ran fetch %d times, want 1", got)
	}
}

func TestAssetCache_RefetchesAfterTTL(t *testing.T) {
	c := &assetSnapshotCache{ttl: 15 * time.Millisecond}
	var calls int32
	fetch := countingFetch(&calls, 0)

	if _, err := c.get("k", fetch); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := c.get("k", fetch); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expired entry ran fetch %d times, want 2", got)
	}
}

func TestAssetCache_InvalidateForcesRefetch(t *testing.T) {
	c := &assetSnapshotCache{ttl: time.Minute}
	var calls int32
	fetch := countingFetch(&calls, 0)

	if _, err := c.get("k", fetch); err != nil {
		t.Fatal(err)
	}
	c.invalidate()
	if _, err := c.get("k", fetch); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("after invalidate fetch ran %d times, want 2", got)
	}
}

func TestAssetCache_DistinctKeysDoNotShare(t *testing.T) {
	c := &assetSnapshotCache{ttl: time.Minute}
	var calls int32
	fetch := countingFetch(&calls, 0)

	if _, err := c.get("acctA/net", fetch); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get("acctB/net", fetch); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("distinct keys ran fetch %d times, want 2", got)
	}
}

func TestAssetCache_ErrorsAreNotCached(t *testing.T) {
	c := &assetSnapshotCache{ttl: time.Minute}
	var calls int32
	fetch := func() (*assetSnapshot, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("rpc down")
	}

	if _, err := c.get("k", fetch); err == nil {
		t.Fatal("want error from first get")
	}
	if _, err := c.get("k", fetch); err == nil {
		t.Fatal("want error from second get")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("errors must not be cached: fetch ran %d times, want 2", got)
	}
}
