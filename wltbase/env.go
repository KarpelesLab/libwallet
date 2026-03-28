package wltbase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

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
	bolt "go.etcd.io/bbolt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type env struct {
	context.Context
	dataDir string
	db      *bolt.DB
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

// InitTempEnv initializes an environment for testing purposes using an in-memory SQLite database
// and a temporary file for BoltDB.
func InitTempEnv() (any, error) {
	// Create temp directory for bolt DB
	tempDir, err := os.MkdirTemp("", "libwallet-test-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	e := &env{Context: context.Background(), dataDir: tempDir, em: emitter.New()}

	// Override init to use in-memory SQLite
	if err := e.initTemp(); err != nil {
		os.RemoveAll(tempDir) // Clean up on error
		return nil, err
	}

	return e, nil
}

// CleanupTempEnv closes databases and removes temporary directory for a temporary environment
func CleanupTempEnv(environment any) error {
	e, ok := environment.(*env)
	if !ok {
		return errors.New("not a valid environment")
	}

	// Close bolt DB
	if e.db != nil {
		if err := e.db.Close(); err != nil {
			return fmt.Errorf("failed to close bolt database: %w", err)
		}
	}

	// Clean up temp directory
	if err := os.RemoveAll(e.dataDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", e.dataDir, err)
	}

	return nil
}

func (e *env) init() error {
	// open or create db
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

	// open bolt db
	dbPath := filepath.Join(e.dataDir, "data.db")
	e.db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return fmt.Errorf("failed to open bolt database at %s: %w", dbPath, err)
	}

	currentVersion := []byte{0, 0, 0, 3}

	if v, err := e.DBSimpleGet([]byte("info"), []byte("version")); err == nil && bytes.Equal(v, currentVersion) {
		// all good
	} else {
		// set version
		e.DBSimpleSet([]byte("info"), []byte("version"), currentVersion)
		// because previously we had invalid wallets created, erase it
		e.dbDeleteBucket([]byte("wallet"))
		e.dbDeleteBucket([]byte("account"))
		e.dbDeleteBucket([]byte("network"))
	}

	if _, err := e.DBSimpleGet([]byte("info"), []byte("first_run")); err != nil {
		// first run?
		now := wltobj.NewTimeId().Bytes(nil)
		e.DBSimpleSet([]byte("info"), []byte("first_run"), now)
	}

	// open sql database
	sqlPath := filepath.Join(e.dataDir, "sql.db")
	e.sql, err = gorm.Open(sqlite.New(sqlite.Config{DriverName: "sqlite", DSN: sqlPath + "?_pragma=journal_mode(WAL)"}), &gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true, NoLowerCase: true}})
	if err != nil {
		return fmt.Errorf("failed to open SQL database at %s: %w", sqlPath, err)
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

	return nil
}

func (e *env) initTemp() error {
	// open or create db
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

	// open bolt db with temp file
	dbPath := filepath.Join(e.dataDir, "data.db")
	e.db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return fmt.Errorf("failed to open bolt database at %s: %w", dbPath, err)
	}

	currentVersion := []byte{0, 0, 0, 3}

	// set version
	e.DBSimpleSet([]byte("info"), []byte("version"), currentVersion)

	// Set first run timestamp
	now := wltobj.NewTimeId().Bytes(nil)
	e.DBSimpleSet([]byte("info"), []byte("first_run"), now)

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
