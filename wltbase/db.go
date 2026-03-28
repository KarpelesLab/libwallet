package wltbase

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// kvConfig stores simple key-value configuration data (replaces BoltDB "info" bucket)
type kvConfig struct {
	Key   string `gorm:"primaryKey"`
	Value []byte
}

// cacheEntry stores cached data with automatic expiration (replaces BoltDB "http_cache" and "rest_cache")
type cacheEntry struct {
	Key       string    `gorm:"primaryKey"`
	Value     []byte
	ExpiresAt time.Time `gorm:"index"`
}

// ConfigGet retrieves a config value by key
func (e *env) ConfigGet(key string) ([]byte, error) {
	var kv kvConfig
	tx := e.sql.First(&kv, "\"Key\" = ?", key)
	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("failed to get config key %s: %w", key, tx.Error)
	}
	return kv.Value, nil
}

// ConfigSet stores a config key-value pair
func (e *env) ConfigSet(key string, value []byte) error {
	kv := kvConfig{Key: key, Value: value}
	tx := e.sql.Clauses(clause.OnConflict{UpdateAll: true}).Create(&kv)
	if tx.Error != nil {
		return fmt.Errorf("failed to set config key %s: %w", key, tx.Error)
	}
	return nil
}

// CacheStore saves a value in the cache with a time-to-live duration
func (e *env) CacheStore(key string, value []byte, ttl time.Duration) error {
	entry := cacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}
	tx := e.sql.Clauses(clause.OnConflict{UpdateAll: true}).Create(&entry)
	if tx.Error != nil {
		return fmt.Errorf("failed to store cache key %s: %w", key, tx.Error)
	}
	return nil
}

// CacheLoad retrieves a non-expired value from the cache
func (e *env) CacheLoad(key string) ([]byte, error) {
	var entry cacheEntry
	tx := e.sql.Where("\"Key\" = ? AND \"ExpiresAt\" > ?", key, time.Now()).First(&entry)
	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("failed to load cache key %s: %w", key, tx.Error)
	}
	return entry.Value, nil
}

// CacheDelete removes one or more keys from the cache
func (e *env) CacheDelete(keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	tx := e.sql.Where("\"Key\" IN ?", keys).Delete(&cacheEntry{})
	if tx.Error != nil {
		return fmt.Errorf("failed to delete cache keys: %w", tx.Error)
	}
	return nil
}

// cacheCleanup removes all expired cache entries
func (e *env) cacheCleanup() {
	tx := e.sql.Where("\"ExpiresAt\" < ?", time.Now()).Delete(&cacheEntry{})
	if tx.Error != nil {
		log.Printf("cache cleanup error: %v", tx.Error)
	}
}

// FirstId retrieves the first record with the given ID and populates the result
// Translates GORM's ErrRecordNotFound to fs.ErrNotExist for consistent error handling
// Returns nil on success or error with context for other failures
func (e *env) FirstId(res, id any) error {
	tx := e.sql.First(res, id)

	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return fs.ErrNotExist
		}
		return fmt.Errorf("failed to find record with ID %v: %w", id, tx.Error)
	}

	return nil
}

// FirstWhere retrieves the first record matching the conditions in the where map
// Returns any error encountered during the operation with added context
func (e *env) FirstWhere(res any, where map[string]any) error {
	tx := e.sql.Where(where).First(res)
	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return fs.ErrNotExist
		}
		return fmt.Errorf("failed to find record with conditions %v: %w", where, tx.Error)
	}
	return nil
}

// Count returns the number of records for a given model type
// Uses the provided object to determine the table
// Note: This method ignores errors to match the interface requirement
// TODO: Consider updating the interface to handle errors
func (e *env) Count(obj any) int64 {
	var count int64
	result := e.sql.Model(obj).Count(&count)
	if result.Error != nil {
		// Log the error but continue with count=0 to maintain interface compatibility
		log.Printf("failed to count records of type %T: %v", obj, result.Error)
		return 0
	}
	return count
}

// CountWithError returns the number of records for a given model type
// Uses the provided object to determine the table
// Returns the count and any error encountered during the query
func (e *env) CountWithError(obj any) (int64, error) {
	var count int64
	result := e.sql.Model(obj).Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count records of type %T: %w", obj, result.Error)
	}
	return count, nil
}

// Delete removes a record from the database
// The object should contain a primary key value to determine what to delete
// Returns error with context if deletion fails
func (e *env) Delete(obj any) error {
	tx := e.sql.Delete(obj)
	if tx.Error != nil {
		return fmt.Errorf("failed to delete object of type %T: %w", obj, tx.Error)
	}
	return nil
}

// AutoMigrate creates or updates the database schema based on the struct definition
// Used to ensure the database structure matches the Go structs
func (e *env) AutoMigrate(obj any) {
	e.sql.AutoMigrate(obj)
}

// DeleteAll removes all records of a specific type
// Uses a WHERE 1=1 condition to match all records
// Returns error with context if deletion fails
func (e *env) DeleteAll(obj any) error {
	tx := e.sql.Where("1 = 1").Delete(obj)
	if tx.Error != nil {
		return fmt.Errorf("failed to delete all records of type %T: %w", obj, tx.Error)
	}
	return nil
}

// DeleteWhere removes records matching the conditions in the where map
// Returns error with context if deletion fails
func (e *env) DeleteWhere(obj any, where map[string]any) error {
	tx := e.sql.Where(where).Delete(obj)
	if tx.Error != nil {
		return fmt.Errorf("failed to delete records of type %T with conditions %v: %w", obj, where, tx.Error)
	}
	return nil
}

// Find retrieves all records matching the conditions in the where map
// Populates the target slice with the results
// Returns error with context if the query fails
func (e *env) Find(target any, where map[string]any) error {
	tx := e.sql.Where(where).Find(target)
	if tx.Error != nil {
		return fmt.Errorf("failed to find records with conditions %v: %w", where, tx.Error)
	}
	return nil
}

// First retrieves the first record for a model
// Populates the target with the result
// Returns fs.ErrNotExist if no record is found, or error with context for other failures
func (e *env) First(target any) error {
	tx := e.sql.First(target)
	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return fs.ErrNotExist
		}
		return fmt.Errorf("failed to find first record of type %T: %w", target, tx.Error)
	}
	return nil
}

// byPrimaryKey is a generic function to retrieve a record by its primary key
// Returns a pointer to the record and nil error on success
// Returns nil and fs.ErrNotExist if the record is not found
// Returns nil and error with context for other failures
func byPrimaryKey[T any](e *env, id any) (*T, error) {
	var res *T
	tx := e.sql.First(&res, id)

	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("failed to find record of type %T with ID %v: %w", *new(T), id, tx.Error)
	}

	return res, nil
}

// Save creates or updates a record in the database
// Uses OnConflict clause to update all fields if the record already exists
// Returns any error encountered during the save operation
func (e *env) Save(v any) error {
	res := e.sql.Clauses(clause.OnConflict{UpdateAll: true}).Create(v)
	if res.Error != nil {
		return fmt.Errorf("failed to save object of type %T: %w", v, res.Error)
	}
	return nil
}
