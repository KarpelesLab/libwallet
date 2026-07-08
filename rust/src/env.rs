//! The libwallet environment — port of `wltbase/env.go`.
//!
//! Phase 1 owns the database and configuration lifecycle. The spotlib client,
//! emitter hub, balance poller and asset cache land in later phases.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::db::{Db, SqlValue};
use crate::error::{Error, Result};
use crate::walletconnect::RelayTransport;
use crate::wcmanager::WcManager;

/// A host event sink — receives server-pushed event JSON (the Rust analogue of
/// Go's BroadcastJson → event FD → host callback).
pub type EventSink = Box<dyn Fn(&str) + Send + Sync>;

/// The WalletConnect manager over a boxed relay transport (stored in the Env so
/// the connection persists across FFI requests).
type BoxedWcManager = WcManager<Box<dyn RelayTransport + Send>>;

/// The running WalletConnect connection: the shared manager plus its relay
/// reader thread and stop flag.
struct WcRuntime {
    manager: Arc<Mutex<BoxedWcManager>>,
    stop: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

pub struct Env {
    pub data_dir: PathBuf,
    db: Db,
    event_sink: Mutex<Option<EventSink>>,
    wc: Mutex<Option<WcRuntime>>,
    /// Waiters for pending user-approval requests, keyed by request id. `run`
    /// registers a sender here and blocks on the receiver; `Request:approve`/
    /// `reject` looks it up and delivers the terminal status.
    request_waiters: Mutex<std::collections::HashMap<String, std::sync::mpsc::Sender<String>>>,
    /// The Spot network client (lazily started on first use), for cross-device
    /// ceremonies + `Spot:status`. Closed on Destroy.
    spot: Mutex<Option<std::sync::Arc<spotlib::Client>>>,
}

impl Env {
    /// Initialize the environment rooted at `data_dir`: ensure the directory
    /// exists, open `sql.db`, create the base tables, and seed initial config.
    pub fn init(data_dir: &str) -> Result<Env> {
        if data_dir.is_empty() {
            return Err(Error::Env("data directory must not be empty".into()));
        }
        let dir = PathBuf::from(data_dir);
        ensure_dir(&dir)?;

        let sql_path = dir.join("sql.db");
        let sql_path = sql_path
            .to_str()
            .ok_or_else(|| Error::Env(format!("non-UTF8 data path: {dir:?}")))?;
        let db = Db::open(sql_path)?;

        let env = Env {
            data_dir: dir,
            db,
            event_sink: Mutex::new(None),
            wc: Mutex::new(None),
            request_waiters: Mutex::new(std::collections::HashMap::new()),
            spot: Mutex::new(None),
        };
        env.init_config()?;
        Ok(env)
    }

    /// In-memory environment for tests (mirrors Go `InitTempEnv`).
    pub fn init_memory() -> Result<Env> {
        let env = Env {
            data_dir: PathBuf::new(),
            db: Db::open_memory()?,
            event_sink: Mutex::new(None),
            wc: Mutex::new(None),
            request_waiters: Mutex::new(std::collections::HashMap::new()),
            spot: Mutex::new(None),
        };
        env.init_config()?;
        Ok(env)
    }

    /// Register a waiter for a pending approval request and return the receiver
    /// to block on. A pre-existing waiter for the same id is dropped (its
    /// receiver then sees a disconnect, matching Go's channel-close semantics).
    pub fn request_register(&self, id: &str) -> std::sync::mpsc::Receiver<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.request_waiters.lock().unwrap().insert(id.to_owned(), tx);
        rx
    }

    /// Deliver the terminal status to a request's waiter. Returns false if no
    /// waiter is registered (timed out / already resolved).
    pub fn request_resolve(&self, id: &str, status: &str) -> bool {
        let sender = self.request_waiters.lock().unwrap().remove(id);
        match sender {
            Some(tx) => tx.send(status.to_owned()).is_ok(),
            None => false,
        }
    }

    /// Whether a request is still awaiting a response (its waiter exists).
    pub fn request_pending(&self, id: &str) -> bool {
        self.request_waiters.lock().unwrap().contains_key(id)
    }

    /// Drop a request's waiter (on timeout cleanup).
    pub fn request_take(&self, id: &str) {
        self.request_waiters.lock().unwrap().remove(id);
    }

    /// The Spot client, lazily started on first use (Go `spotlib.New(project=
    /// libwallet)`). `build()` spawns the connection thread and returns
    /// immediately; connectivity is polled via [`Self::spot_status`].
    pub fn spot_client(&self) -> Result<Arc<spotlib::Client>> {
        let mut guard = self.spot.lock().unwrap();
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let client = spotlib::Client::builder()
            .meta("project", "libwallet")
            .build()
            .map_err(|e| Error::Env(format!("spot client: {e}")))?;
        let arc = Arc::new(client);
        *guard = Some(arc.clone());
        Ok(arc)
    }

    /// `(online, target_id, total_conns, online_conns)` for the Spot client,
    /// starting it if needed (Go `Spot:status`).
    pub fn spot_status(&self) -> Result<(bool, String, u32, u32)> {
        let c = self.spot_client()?;
        let (total, online) = c.connection_count();
        Ok((online > 0, c.target_id(), total, online))
    }

    /// Close the Spot client if running (called on Destroy).
    pub fn spot_close(&self) {
        if let Some(c) = self.spot.lock().unwrap().take() {
            c.close();
        }
    }

    /// Start the WalletConnect relay connection (`WalletConnect:start`): install
    /// the manager over `transport` and spawn a reader thread that pumps inbound
    /// relay frames and broadcasts them to the host. The reader holds a `Weak`
    /// self-reference so it exits when the Env is dropped (or on `wc_stop`).
    pub fn wc_start(self: &Arc<Self>, transport: Box<dyn RelayTransport + Send>) -> Result<()> {
        let mut guard = self.wc.lock().unwrap();
        if guard.is_some() {
            return Err(Error::Env("walletconnect already started".into()));
        }
        let manager = Arc::new(Mutex::new(WcManager::new(transport)));
        let stop = Arc::new(AtomicBool::new(false));
        let weak: Weak<Env> = Arc::downgrade(self);
        let (mgr, stop2) = (manager.clone(), stop.clone());
        let reader = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                let env = match weak.upgrade() {
                    Some(e) => e,
                    None => break,
                };
                let got = mgr.lock().unwrap().pump(&env);
                if let Ok(Some((topic, msg))) = got {
                    env.broadcast(&crate::wcmanager::inbound_event(&topic, &msg));
                }
                drop(env);
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        *guard = Some(WcRuntime { manager, stop, reader: Some(reader) });
        Ok(())
    }

    /// Stop the WalletConnect connection and join its reader (`WalletConnect:stop`;
    /// also called on Destroy).
    pub fn wc_stop(&self) {
        if let Some(mut rt) = self.wc.lock().unwrap().take() {
            rt.stop.store(true, Ordering::SeqCst);
            if let Some(h) = rt.reader.take() {
                let _ = h.join();
            }
        }
    }

    /// The running WalletConnect manager, if started — for the pair/approve/respond
    /// endpoints.
    pub fn wc_manager(&self) -> Option<Arc<Mutex<BoxedWcManager>>> {
        self.wc.lock().unwrap().as_ref().map(|rt| rt.manager.clone())
    }

    /// Register (or, with None, clear) the host event sink.
    pub fn set_event_sink(&self, sink: Option<EventSink>) {
        *self.event_sink.lock().unwrap() = sink;
    }

    /// Push a server-side event JSON to the host, if a sink is registered.
    /// Mirrors Go apirouter.BroadcastJson.
    pub fn broadcast(&self, event_json: &str) {
        if let Some(sink) = self.event_sink.lock().unwrap().as_ref() {
            sink(event_json);
        }
    }

    /// Seed `version` and `first_run` on first launch, exactly as the Go env
    /// does: version is the 4-byte marker `{0,0,0,4}`, first_run is a 16-byte
    /// TimeId (Unix u64 BE | Nano u32 BE | Index u32 BE).
    fn init_config(&self) -> Result<()> {
        if self.db.config_get("version")?.is_none() {
            self.db.config_set("version", &[0, 0, 0, 4])?;
        }
        if self.db.config_get("first_run")?.is_none() {
            self.db.config_set("first_run", &time_id_now_bytes())?;
        }
        Ok(())
    }

    // --- generic query layer (for model crates) ---------------------------

    pub fn ensure_table(&self, ddl: &str) -> Result<()> {
        self.db.ensure_table(ddl)
    }

    pub fn query(&self, sql: &str, args: Vec<SqlValue>) -> Result<Vec<Vec<SqlValue>>> {
        self.db.query(sql, args)
    }

    pub fn exec(&self, sql: &str, args: Vec<SqlValue>) -> Result<usize> {
        self.db.exec(sql, args)
    }

    // --- config / cache / current: thin delegations to the DB layer -------

    pub fn config_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.db.config_get(key)
    }

    pub fn config_set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.db.config_set(key, value)
    }

    pub fn cache_store(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        self.db.cache_store(key, value, ttl)
    }

    pub fn cache_load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.db.cache_load(key)
    }

    pub fn cache_delete(&self, keys: &[&str]) -> Result<()> {
        self.db.cache_delete(keys)
    }

    pub fn cache_cleanup(&self) -> Result<usize> {
        self.db.cache_cleanup()
    }

    pub fn get_current(&self, key: &str) -> Result<Option<String>> {
        self.db.current_get(key)
    }

    pub fn set_current(&self, key: &str, value: &str) -> Result<()> {
        self.db.current_set(key, value)
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        if !dir.is_dir() {
            return Err(Error::Env(format!("data path {dir:?} exists and is not a directory")));
        }
    } else {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// 16-byte TimeId for the current instant: `Unix(u64 BE) | Nano(u32 BE) |
/// Index(u32 BE)`, matching `wltobj.NewTimeId().Bytes()`.
fn time_id_now_bytes() -> Vec<u8> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&now.as_secs().to_be_bytes()); // Unix, u64
    b.extend_from_slice(&now.subsec_nanos().to_be_bytes()); // Nano, u32
    b.extend_from_slice(&0u32.to_be_bytes()); // Index, u32
    b
}
