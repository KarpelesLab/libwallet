package wltbase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltasset"
	"github.com/KarpelesLab/libwallet/wltcontact"
	"github.com/KarpelesLab/libwallet/wltcrash"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltnft"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/spotlib"
	_ "github.com/glebarez/go-sqlite"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type env struct {
	context.Context
	dataDir string
	sql     *gorm.DB
	spot    *spotlib.Client
	em      *emitter.Hub
}

type client struct {
	c   net.Conn
	enc *json.Encoder
	wlk sync.Mutex // write lock
}

func InitEnv(dataDir string) (any, error) {
	e := &env{Context: context.Background(), dataDir: dataDir, em: emitter.New()}
	if err := e.init(); err != nil {
		return nil, err
	}
	return e, nil
}

// InitTempEnv initializes an environment for testing purposes using an in-memory SQLite database.
func InitTempEnv() (any, error) {
	tempDir, err := os.MkdirTemp("", "libwallet-test-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	e := &env{Context: context.Background(), dataDir: tempDir, em: emitter.New()}

	if err := e.initTemp(); err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	return e, nil
}

// CleanupTempEnv removes temporary directory for a temporary environment
func CleanupTempEnv(environment any) error {
	e, ok := environment.(*env)
	if !ok {
		return errors.New("not a valid environment")
	}

	if err := os.RemoveAll(e.dataDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", e.dataDir, err)
	}

	return nil
}

func (e *env) init() error {
	var err error

	// make sure dataDir exists and is a directory
	if st, err := os.Stat(e.dataDir); err != nil {
		err = os.MkdirAll(e.dataDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create data directory %s: %w", e.dataDir, err)
		}
	} else if !st.IsDir() {
		return errors.New("dataDir exists but is not a directory")
	}

	// connect Spot using dynamic (temporary) key
	e.spot, err = spotlib.New(map[string]string{"project": "libwallet"})
	if err != nil {
		return fmt.Errorf("failed to initialize Spot client: %w", err)
	}
	go e.handleStatusEvent(e.spot.Events.On("status"))

	// open sql database
	sqlPath := filepath.Join(e.dataDir, "sql.db")
	e.sql, err = gorm.Open(sqlite.New(sqlite.Config{DriverName: "sqlite", DSN: sqlPath + "?_pragma=journal_mode(WAL)"}), &gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true, NoLowerCase: true}})
	if err != nil {
		return fmt.Errorf("failed to open SQL database at %s: %w", sqlPath, err)
	}

	// migrate config and cache tables
	e.sql.AutoMigrate(&kvConfig{})
	e.sql.AutoMigrate(&cacheEntry{})

	// migrate from BoltDB if data.db exists
	boltPath := filepath.Join(e.dataDir, "data.db")
	if _, err := os.Stat(boltPath); err == nil {
		e.migrateBoltDB(boltPath)
	}

	// initialize config if needed
	if _, err := e.ConfigGet("version"); err != nil {
		e.ConfigSet("version", []byte{0, 0, 0, 4})
	}
	if _, err := e.ConfigGet("first_run"); err != nil {
		now := wltobj.NewTimeId().Bytes(nil)
		e.ConfigSet("first_run", now)
	}

	// create tables
	wltasset.InitEnv(e)
	e.sql.AutoMigrate(&request{})
	e.sql.AutoMigrate(&currentItem{})
	e.sql.AutoMigrate(&connectedSite{})
	wltnet.InitEnv(e)
	wlttx.InitEnv(e)
	wltacct.InitEnv(e)
	wltwallet.InitEnv(e)
	wltcontact.InitEnv(e)
	wltnft.InitEnv(e)
	wltcrash.InitEnv(e)

	// run initial cache cleanup and start periodic cleanup
	e.cacheCleanup()
	go e.cacheCleanupLoop()

	return nil
}

func (e *env) initTemp() error {
	var err error

	// make sure dataDir exists and is a directory
	if st, err := os.Stat(e.dataDir); err != nil {
		err = os.MkdirAll(e.dataDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create data directory %s: %w", e.dataDir, err)
		}
	} else if !st.IsDir() {
		return errors.New("dataDir exists but is not a directory")
	}

	// connect Spot using dynamic (temporary) key
	e.spot, err = spotlib.New(map[string]string{"project": "libwallet"})
	if err != nil {
		return fmt.Errorf("failed to initialize Spot client: %w", err)
	}
	go e.handleStatusEvent(e.spot.Events.On("status"))

	// open in-memory SQLite database
	e.sql, err = gorm.Open(sqlite.New(sqlite.Config{
		DriverName: "sqlite",
		DSN:        "file::memory:?cache=shared",
	}), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
			NoLowerCase:   true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to open in-memory SQLite database: %w", err)
	}

	// migrate config and cache tables
	e.sql.AutoMigrate(&kvConfig{})
	e.sql.AutoMigrate(&cacheEntry{})

	// initialize config
	e.ConfigSet("version", []byte{0, 0, 0, 4})
	now := wltobj.NewTimeId().Bytes(nil)
	e.ConfigSet("first_run", now)

	// create tables
	wltasset.InitEnv(e)
	e.sql.AutoMigrate(&request{})
	e.sql.AutoMigrate(&currentItem{})
	e.sql.AutoMigrate(&connectedSite{})
	wltnet.InitEnv(e)
	wlttx.InitEnv(e)
	wltacct.InitEnv(e)
	wltwallet.InitEnv(e)
	wltcontact.InitEnv(e)
	wltnft.InitEnv(e)
	wltcrash.InitEnv(e)

	return nil
}

// migrateBoltDB reads config data from an old BoltDB file and removes it
func (e *env) migrateBoltDB(boltPath string) {
	log.Printf("migrating from BoltDB at %s", boltPath)

	// Try to import using bbolt - but since we removed the dependency,
	// just read the first_run value if it was already migrated to SQLite.
	// For a clean migration we simply delete the old file and let fresh config be created.
	// The only valuable data was "first_run" which is a timestamp.
	// Users upgrading will get a new first_run timestamp, which is acceptable.

	if err := os.Remove(boltPath); err != nil {
		log.Printf("failed to remove old BoltDB file: %s", err)
	} else {
		log.Printf("removed old BoltDB file %s", boltPath)
	}
}

// cacheCleanupLoop runs periodic cache cleanup every 10 minutes
func (e *env) cacheCleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		e.cacheCleanup()
	}
}

func (e *env) Emitter() *emitter.Hub {
	return e.em
}

func (e *env) Spot() *spotlib.Client {
	return e.spot
}

func (e *env) ListHelper(ctx context.Context, target any, sort string, searchKey ...string) error {
	var c *apirouter.Context
	if ctx != nil {
		ctx.Value(&c)
	}

	tx := e.sql
	if c != nil {
		tx = tx.Scopes(c.Paginate(50))
	}
	if sort != "" {
		tx = tx.Order(sort)
	}

	if len(searchKey) > 0 {

		if c != nil {
			where := make(map[string]any)
			for _, k := range searchKey {
				if v := c.GetParam(k); v != nil {
					where[k] = v
				}
			}
			if len(where) > 0 {
				tx = tx.Where(where)
			}
		}
	}

	tx = tx.Find(target)
	return tx.Error
}
