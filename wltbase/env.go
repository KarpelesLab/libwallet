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

	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltasset"
	"github.com/KarpelesLab/libwallet/wltcontact"
	"github.com/KarpelesLab/libwallet/wltcrash"
	_ "github.com/KarpelesLab/libwallet/wltnames" // registers Names:resolve API
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltnft"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wlttoken"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/libwallet/wltwc"
	"github.com/KarpelesLab/spotlib"
	"github.com/portablesql/psql"
	_ "github.com/portablesql/psql-sqlite"
)

type env struct {
	context.Context
	dataDir string
	sqlCtx  context.Context // context with psql backend plugged in
	spot    *spotlib.Client
	em      *emitter.Hub
	poller  *balancePoller // nil until init finishes
}

type client struct {
	c   net.Conn
	enc *json.Encoder
	wlk sync.Mutex // write lock
}

func InitEnv(dataDir string) (any, error) {
	e := &env{dataDir: dataDir, em: emitter.New()}
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

	e := &env{dataDir: tempDir, em: emitter.New()}

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

	// open sql database via psql
	sqlPath := filepath.Join(e.dataDir, "sql.db")
	be, err := psql.New("sqlite:" + sqlPath)
	if err != nil {
		return fmt.Errorf("failed to open SQL database at %s: %w", sqlPath, err)
	}
	e.sqlCtx = be.Plug(context.Background())
	e.Context = e.sqlCtx

	// migrate from BoltDB if data.db exists
	boltPath := filepath.Join(e.dataDir, "data.db")
	if _, err := os.Stat(boltPath); err == nil {
		log.Printf("removing old BoltDB file %s", boltPath)
		os.Remove(boltPath)
	}

	// initialize config if needed
	if _, err := e.ConfigGet("version"); err != nil {
		e.ConfigSet("version", []byte{0, 0, 0, 4})
	}
	if _, err := e.ConfigGet("first_run"); err != nil {
		now := wltobj.NewTimeId().Bytes(nil)
		e.ConfigSet("first_run", now)
	}

	// initialize sub-packages (no AutoMigrate needed, psql auto-creates tables)
	wltasset.InitEnv(e)
	wltnet.InitEnv(e)
	wlttx.InitEnv(e)
	wltacct.InitEnv(e)
	wltwallet.InitEnv(e)
	wltcontact.InitEnv(e)
	wltnft.InitEnv(e)
	wlttoken.InitEnv(e)
	wltcrash.InitEnv(e)
	wltwc.InitEnv(e)

	// run initial cache cleanup and start periodic cleanup
	e.cacheCleanup()
	go e.cacheCleanupLoop()

	// start background balance polling — emits `balances_changed`
	// every 60 s when the current account / network balances change.
	// The host uses Lifecycle:update to pause it while backgrounded.
	e.poller = newBalancePoller(e)
	go e.poller.run()

	// Subscribe to current-account / current-network changes and
	// run a tx-history backfill for the live (account, network)
	// via modchain_historyByAddress / ots_searchTransactionsAfter.
	watchCurrentChanges(e)

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

	// open in-memory SQLite database via psql
	be, err := psql.New(":memory:")
	if err != nil {
		return fmt.Errorf("failed to open in-memory SQLite database: %w", err)
	}
	e.sqlCtx = be.Plug(context.Background())
	e.Context = e.sqlCtx

	// initialize config
	e.ConfigSet("version", []byte{0, 0, 0, 4})
	now := wltobj.NewTimeId().Bytes(nil)
	e.ConfigSet("first_run", now)

	// initialize sub-packages
	wltasset.InitEnv(e)
	wltnet.InitEnv(e)
	wlttx.InitEnv(e)
	wltacct.InitEnv(e)
	wltwallet.InitEnv(e)
	wltcontact.InitEnv(e)
	wltnft.InitEnv(e)
	wlttoken.InitEnv(e)
	wltcrash.InitEnv(e)

	return nil
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
