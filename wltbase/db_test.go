package wltbase

import (
	"os"
	"testing"
	"time"
)

// TestConfigGetSet tests the ConfigGet/ConfigSet methods
func TestConfigGetSet(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer CleanupTempEnv(tempEnv)

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	// Test that version was set during init
	v, err := e.ConfigGet("version")
	if err != nil {
		t.Errorf("ConfigGet returned error for version: %v", err)
	}
	if len(v) != 4 {
		t.Errorf("Expected 4-byte version, got %d bytes", len(v))
	}

	// Test set and get a custom key
	err = e.ConfigSet("test_key", []byte("test_value"))
	if err != nil {
		t.Errorf("ConfigSet returned error: %v", err)
	}

	val, err := e.ConfigGet("test_key")
	if err != nil {
		t.Errorf("ConfigGet returned error: %v", err)
	}
	if string(val) != "test_value" {
		t.Errorf("Expected 'test_value', got '%s'", string(val))
	}

	// Test non-existent key
	_, err = e.ConfigGet("nonexistent")
	if err == nil {
		t.Errorf("Expected error for non-existent key")
	}
}

// TestCacheStoreLoad tests the cache with expiration
func TestCacheStoreLoad(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer CleanupTempEnv(tempEnv)

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	// Store a value with 1 hour TTL
	err = e.CacheStore("test:key1", []byte("cached_value"), 1*time.Hour)
	if err != nil {
		t.Errorf("CacheStore returned error: %v", err)
	}

	// Load it back
	val, err := e.CacheLoad("test:key1")
	if err != nil {
		t.Errorf("CacheLoad returned error: %v", err)
	}
	if string(val) != "cached_value" {
		t.Errorf("Expected 'cached_value', got '%s'", string(val))
	}

	// Store a value that's already expired
	err = e.CacheStore("test:expired", []byte("old_value"), -1*time.Second)
	if err != nil {
		t.Errorf("CacheStore returned error: %v", err)
	}

	// Try to load expired value
	_, err = e.CacheLoad("test:expired")
	if err == nil {
		t.Errorf("Expected error for expired cache entry")
	}

	// Test cache cleanup removes expired entries
	e.cacheCleanup()

	// Test CacheDelete
	err = e.CacheDelete("test:key1")
	if err != nil {
		t.Errorf("CacheDelete returned error: %v", err)
	}
	_, err = e.CacheLoad("test:key1")
	if err == nil {
		t.Errorf("Expected error after CacheDelete")
	}
}

// TestInitTempEnv tests the initialization and cleanup of a temporary environment
func TestInitTempEnv(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	if e.sqlCtx == nil {
		t.Errorf("SQLite context was not initialized")
	}

	if _, err := os.Stat(e.dataDir); os.IsNotExist(err) {
		t.Errorf("Temporary directory was not created: %v", err)
	}

	err = CleanupTempEnv(tempEnv)
	if err != nil {
		t.Errorf("Failed to clean up temporary environment: %v", err)
	}

	if _, err := os.Stat(e.dataDir); !os.IsNotExist(err) {
		t.Errorf("Temporary directory was not removed")
		os.RemoveAll(e.dataDir)
	}
}
