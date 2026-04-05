package wltbase

import (
	"testing"
)

func TestSetCurrentGetCurrent(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer CleanupTempEnv(tempEnv)

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	// Set a current item
	err = e.SetCurrent("network", "net-abc123")
	if err != nil {
		t.Fatalf("SetCurrent error: %v", err)
	}

	// Get it back
	val, err := e.GetCurrent("network")
	if err != nil {
		t.Fatalf("GetCurrent error: %v", err)
	}
	if val != "net-abc123" {
		t.Errorf("expected net-abc123, got %s", val)
	}

	// Update the current item
	err = e.SetCurrent("network", "net-xyz789")
	if err != nil {
		t.Fatalf("SetCurrent update error: %v", err)
	}
	val, err = e.GetCurrent("network")
	if err != nil {
		t.Fatalf("GetCurrent error: %v", err)
	}
	if val != "net-xyz789" {
		t.Errorf("expected net-xyz789, got %s", val)
	}

	// Get non-existent key
	_, err = e.GetCurrent("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestMultipleCurrentItems(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer CleanupTempEnv(tempEnv)

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	// Set multiple items
	e.SetCurrent("network", "net1")
	e.SetCurrent("account", "acct1")
	e.SetCurrent("wallet", "wal1")

	// Verify each
	v1, _ := e.GetCurrent("network")
	v2, _ := e.GetCurrent("account")
	v3, _ := e.GetCurrent("wallet")

	if v1 != "net1" {
		t.Errorf("expected net1, got %s", v1)
	}
	if v2 != "acct1" {
		t.Errorf("expected acct1, got %s", v2)
	}
	if v3 != "wal1" {
		t.Errorf("expected wal1, got %s", v3)
	}
}

func TestCacheGetNonExistent(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer CleanupTempEnv(tempEnv)

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	// CacheLoad for non-existent key
	_, err = e.CacheLoad("nonexistent:key")
	if err == nil {
		t.Error("expected error for non-existent cache key")
	}
}

func TestCacheDeleteMultiple(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer CleanupTempEnv(tempEnv)

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	// Store two keys
	e.CacheStore("test:a", []byte("aaa"), 3600*1e9)
	e.CacheStore("test:b", []byte("bbb"), 3600*1e9)

	// Delete both
	err = e.CacheDelete("test:a", "test:b")
	if err != nil {
		t.Fatalf("CacheDelete error: %v", err)
	}

	_, err = e.CacheLoad("test:a")
	if err == nil {
		t.Error("expected error after deleting test:a")
	}
	_, err = e.CacheLoad("test:b")
	if err == nil {
		t.Error("expected error after deleting test:b")
	}
}

func TestCleanupTempEnvInvalid(t *testing.T) {
	err := CleanupTempEnv("not an env")
	if err == nil {
		t.Error("expected error for invalid environment type")
	}
}

func TestEmitterAndSpot(t *testing.T) {
	tempEnv, err := InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer CleanupTempEnv(tempEnv)

	e, ok := tempEnv.(*env)
	if !ok {
		t.Fatalf("Returned environment is not a valid *env")
	}

	if e.Emitter() == nil {
		t.Error("expected non-nil emitter")
	}
	if e.Spot() == nil {
		t.Error("expected non-nil spot client")
	}
}
