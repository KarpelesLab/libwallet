package wltbase

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"time"

	"github.com/portablesql/psql"
)

// kvConfig stores simple key-value configuration data
type kvConfig struct {
	psql.Name `sql:"KvConfig"`
	Key       string `sql:",key=PRIMARY,type=VARCHAR,size=255"`
	Value     []byte `sql:",type=BLOB"`
}

// cacheEntry stores cached data with automatic expiration
type cacheEntry struct {
	psql.Name `sql:"Cache"`
	Key       string    `sql:",key=PRIMARY,type=VARCHAR,size=255"`
	Value     []byte    `sql:",type=BLOB"`
	ExpiresAt time.Time `sql:",type=DATETIME,key=INDEX"`
}

// ConfigGet retrieves a config value by key
func (e *env) ConfigGet(key string) ([]byte, error) {
	kv, err := psql.Get[kvConfig](e.sqlCtx, map[string]any{"Key": key})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("failed to get config key %s: %w", key, err)
	}
	return kv.Value, nil
}

// ConfigSet stores a config key-value pair
func (e *env) ConfigSet(key string, value []byte) error {
	return psql.Replace(e.sqlCtx, &kvConfig{Key: key, Value: value})
}

// CacheStore saves a value in the cache with a time-to-live duration
func (e *env) CacheStore(key string, value []byte, ttl time.Duration) error {
	return psql.Replace(e.sqlCtx, &cacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	})
}

// CacheLoad retrieves a non-expired value from the cache
func (e *env) CacheLoad(key string) ([]byte, error) {
	entries, err := psql.Fetch[cacheEntry](e.sqlCtx, map[string]any{"Key": key})
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fs.ErrNotExist
	}
	entry := entries[0]
	if time.Now().After(entry.ExpiresAt) {
		return nil, fs.ErrNotExist
	}
	return entry.Value, nil
}

// CacheDelete removes one or more keys from the cache
func (e *env) CacheDelete(keys ...string) error {
	for _, key := range keys {
		psql.ForceDelete[cacheEntry](e.sqlCtx, map[string]any{"Key": key})
	}
	return nil
}

// byPrimaryKey fetches a record by primary key using the env's sqlCtx
func byPrimaryKey[T any](e *env, id any) (*T, error) {
	return psql.Get[T](e.sqlCtx, map[string]any{"Id": id})
}

// cacheCleanup removes all expired cache entries
func (e *env) cacheCleanup() {
	_, err := psql.ForceDelete[cacheEntry](e.sqlCtx, psql.Lt(psql.F("ExpiresAt"), time.Now()))
	if err != nil {
		log.Printf("cache cleanup error: %v", err)
	}
}
