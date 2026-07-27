//! The libwallet environment — port of `wltbase/env.go`.
//!
//! Phase 1 owns the database and configuration lifecycle. The spotlib client,
//! emitter hub, balance poller and asset cache land in later phases.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Weak};
use std::time::Duration;
// The browser build's single-threaded Spot client lives in an `Rc`/`RefCell`
// (the wasm spotlib `Client` is `!Send`) instead of native's `Arc`/`Mutex`.
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;

use crate::db::{Db, SqlValue};
use crate::error::Result;
// `Error` is constructed in the native filesystem/transport paths and, on wasm,
// by the Spot client lifecycle (`spot_start`).
use crate::error::Error;
#[cfg(not(target_arch = "wasm32"))]
use crate::walletconnect::RelayTransport;
#[cfg(not(target_arch = "wasm32"))]
use crate::wcmanager::WcManager;

/// A host event sink — receives server-pushed event JSON (the Rust analogue of
/// Go's BroadcastJson → event FD → host callback). On native it crosses the FFI
/// worker threads, so it is `Send + Sync`; the single-threaded browser build
/// wires it to a `js_sys::Function`, which is neither.
#[cfg(not(target_arch = "wasm32"))]
pub type EventSink = Box<dyn Fn(&str) + Send + Sync>;
#[cfg(target_arch = "wasm32")]
pub type EventSink = Box<dyn Fn(&str)>;

/// The WalletConnect manager over a boxed relay transport (stored in the Env so
/// the connection persists across FFI requests).
#[cfg(not(target_arch = "wasm32"))]
type BoxedWcManager = WcManager<Box<dyn RelayTransport + Send>>;

/// The running WalletConnect connection: the shared manager plus its relay
/// reader thread and stop flag.
#[cfg(not(target_arch = "wasm32"))]
struct WcRuntime {
    manager: Arc<Mutex<BoxedWcManager>>,
    stop: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

pub struct Env {
    pub data_dir: PathBuf,
    db: Db,
    event_sink: Mutex<Option<EventSink>>,
    // The networking/cross-device machinery below is native-only. The browser
    // build runs single-threaded with no Spot/WalletConnect transport (and its
    // approval flow is driven directly by the user, not a blocking channel).
    #[cfg(not(target_arch = "wasm32"))]
    wc: Mutex<Option<WcRuntime>>,
    /// Waiters for pending user-approval requests, keyed by request id. `run`
    /// registers a sender here and blocks on the receiver; `Request:approve`/
    /// `reject` looks it up and delivers the terminal status.
    #[cfg(not(target_arch = "wasm32"))]
    request_waiters: Mutex<std::collections::HashMap<String, std::sync::mpsc::Sender<String>>>,
    /// The Spot network client (lazily started on first use), for cross-device
    /// ceremonies + `Spot:status`. Closed on Destroy. Native shares an `Arc`
    /// behind a `Mutex` across FFI worker threads; the single-threaded browser
    /// build holds an `Rc` in a `RefCell` (the wasm spotlib `Client` is `!Send`,
    /// so no atomics/locks are needed or possible).
    #[cfg(not(target_arch = "wasm32"))]
    spot: Mutex<Option<std::sync::Arc<spotlib::Client>>>,
    #[cfg(target_arch = "wasm32")]
    spot: RefCell<Option<Rc<spotlib::Client>>>,
    /// Active device-transfer export sessions keyed by sid (the source side of
    /// Wallet:exportToDevice — the `transfer` Spot handler resolves them).
    #[cfg(not(target_arch = "wasm32"))]
    transfer_sessions: Mutex<std::collections::HashMap<String, Arc<TransferSession>>>,
}

/// One in-flight `Wallet:exportToDevice` session: the pairing token, the wallet
/// being exported, and a channel the host's confirm/cancel delivers into (the
/// `transfer` Spot handler blocks on it before sealing the payload).
#[cfg(not(target_arch = "wasm32"))]
struct TransferSession {
    token: Vec<u8>,
    wallet_id: String,
    confirm_tx: std::sync::mpsc::Sender<Option<serde_json::Value>>,
    confirm_rx: Mutex<Option<std::sync::mpsc::Receiver<Option<serde_json::Value>>>>,
    claimed: AtomicBool,
}

impl Env {
    /// Initialize the environment rooted at `data_dir`: ensure the directory
    /// exists, open `sql.db`, create the base tables, and seed initial config.
    /// Native-only — the browser build has no filesystem; it uses `init_memory`.
    #[cfg(not(target_arch = "wasm32"))]
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
            transfer_sessions: Mutex::new(std::collections::HashMap::new()),
        };
        env.init_config()?;
        Ok(env)
    }

    /// In-memory environment (mirrors Go `InitTempEnv`). The browser build uses
    /// this as its only `Env` constructor (in-memory DB; persistence is the
    /// host's concern).
    pub fn init_memory() -> Result<Env> {
        let env = Env {
            data_dir: PathBuf::new(),
            db: Db::open_memory()?,
            event_sink: Mutex::new(None),
            #[cfg(not(target_arch = "wasm32"))]
            wc: Mutex::new(None),
            #[cfg(not(target_arch = "wasm32"))]
            request_waiters: Mutex::new(std::collections::HashMap::new()),
            #[cfg(not(target_arch = "wasm32"))]
            spot: Mutex::new(None),
            #[cfg(target_arch = "wasm32")]
            spot: RefCell::new(None),
            #[cfg(not(target_arch = "wasm32"))]
            transfer_sessions: Mutex::new(std::collections::HashMap::new()),
        };
        env.init_config()?;
        Ok(env)
    }
}

// ── Native-only: cross-device (Spot), WalletConnect, and the blocking
// approval/transfer machinery — none of which exist in the single-threaded,
// transport-less browser build. ─────────────────────────────────────────────
#[cfg(not(target_arch = "wasm32"))]
impl Env {
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

    /// Start (or return) the Spot client, carrying the persistent `transfer`
    /// handler bound to a `Weak<Env>` (Go `spotlib.New` + the InitEnv transfer
    /// handler). `build()` spawns the connection thread and returns immediately.
    pub fn spot_start(self: &Arc<Self>) -> Result<Arc<spotlib::Client>> {
        let mut guard = self.spot.lock().unwrap();
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let weak: Weak<Env> = Arc::downgrade(self);
        let client = spotlib::Client::builder()
            .meta("project", "libwallet")
            .handler("transfer", move |msg: &spotlib::Message| match weak.upgrade() {
                Some(env) => env.handle_transfer_query(msg),
                None => Err("env gone".into()),
            })
            .build()
            .map_err(|e| Error::Env(format!("spot client: {e}")))?;
        let arc = Arc::new(client);
        *guard = Some(arc.clone());
        Ok(arc)
    }

    /// The Spot client if started (no auto-start; for read-only status).
    pub fn spot_client_opt(&self) -> Option<Arc<spotlib::Client>> {
        self.spot.lock().unwrap().clone()
    }

    /// Close the Spot client if running (called on Destroy).
    pub fn spot_close(&self) {
        if let Some(c) = self.spot.lock().unwrap().take() {
            c.close();
        }
    }

    /// Register an export session (Wallet:exportToDevice). Returns nothing; the
    /// `transfer` handler resolves it by sid when the peer queries.
    pub fn transfer_register(&self, sid: &str, token: Vec<u8>, wallet_id: &str) {
        let (tx, rx) = std::sync::mpsc::channel();
        let s = Arc::new(TransferSession {
            token,
            wallet_id: wallet_id.to_owned(),
            confirm_tx: tx,
            confirm_rx: Mutex::new(Some(rx)),
            claimed: AtomicBool::new(false),
        });
        self.transfer_sessions.lock().unwrap().insert(sid.to_owned(), s);
    }

    /// Deliver the host's confirm (`Some(device_shares)`) or cancel (`None`) to a
    /// transfer session. Returns false if the session is unknown/gone.
    pub fn transfer_resolve(&self, sid: &str, confirm: Option<serde_json::Value>) -> bool {
        let s = self.transfer_sessions.lock().unwrap().get(sid).cloned();
        match s {
            Some(s) => s.confirm_tx.send(confirm).is_ok(),
            None => false,
        }
    }

    /// The `transfer` Spot handler: demux by sid, validate the token, emit the
    /// pair-received event, block on the host's confirm/cancel, then seal and
    /// return the wallet payload (Go `transferHandle`).
    fn handle_transfer_query(&self, msg: &spotlib::Message) -> std::result::Result<Option<Vec<u8>>, String> {
        let body: serde_json::Value = serde_json::from_slice(&msg.body).map_err(|_| "bad_request".to_string())?;
        if body.get("v").and_then(|v| v.as_i64()) != Some(crate::transfer::PROTOCOL_VERSION) {
            return Err("bad_request".into());
        }
        let sid = body.get("sid").and_then(|v| v.as_str()).unwrap_or("");
        if sid.is_empty() {
            return Err("session_not_found".into());
        }
        let session = self.transfer_sessions.lock().unwrap().get(sid).cloned().ok_or("session_not_found")?;
        if session.claimed.swap(true, Ordering::SeqCst) {
            return Err("session_not_found".into());
        }
        let token_b64 = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
        let got = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_b64).map_err(|_| "bad_request".to_string())?;
        if got != session.token {
            self.transfer_sessions.lock().unwrap().remove(sid);
            return Err("token_invalid".into());
        }
        let peer = body.get("newSpotID").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or(&msg.sender);
        self.broadcast(&crate::response::event(
            "wallet:transfer:pair_received",
            serde_json::json!({ "sid": sid, "wallet_id": session.wallet_id, "peer_spot_id": peer }),
        ));

        let rx = session.confirm_rx.lock().unwrap().take().ok_or("session_not_found")?;
        let confirm = rx.recv_timeout(Duration::from_secs(90)).map_err(|_| "timeout".to_string());
        self.transfer_sessions.lock().unwrap().remove(sid);
        let shares = confirm?.ok_or("declined".to_string())?;

        let payload = crate::models::wallet::build_transfer_payload(self, &session.wallet_id, &shares).map_err(|e| e.to_string())?;
        let sealed = crate::transfer::seal(&session.token, sid, &payload).map_err(|e| e.to_string())?;
        Ok(Some(sealed))
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
}

// ── Wasm-only: the Spot client lifecycle (build / read / close). Phase 2
// groundwork so later passes can drive TSS ceremonies from the browser. The
// wasm spotlib `Client` keeps SYNC `builder`/`build`/`close`/`target_id`
// signatures (only `query`/`send_to`/`wait_online` are async — not used here),
// so this mirrors the native lifecycle without any threads. Only these three
// methods are un-gated for wasm; the rest of the native block above (approval
// waiters, device-transfer sessions, WalletConnect) stays native-only. ────────
#[cfg(target_arch = "wasm32")]
impl Env {
    /// Start (or return) the Spot client. `build()` starts the connection on
    /// the browser event loop and returns immediately.
    ///
    /// Unlike native — where the `transfer` handler captures a `Weak<Env>` and
    /// routes into `handle_transfer_query` — the browser build registers a
    /// capture-free stub. Two reasons this is the smallest cut that compiles:
    ///   1. Device-to-device transfer has no host confirm/cancel channel in the
    ///      browser, so there is nothing for a real handler to do yet.
    ///   2. spotlib's `ClientBuilder::handler` bound is `Fn + Send + Sync +
    ///      'static` on *both* targets (the `MessageHandler` type alias is
    ///      shared), but the wasm `Env` is `!Send + !Sync` (its `EventSink` is a
    ///      `js_sys::Function`). A closure capturing `Weak<Env>` could therefore
    ///      never satisfy `Send + Sync`. A capture-free stub sidesteps that; a
    ///      later pass that needs the handler to touch `Env` would first have to
    ///      make the wasm `Env` shareable (out of scope here).
    /// The stub rejects so peers fail fast rather than hanging.
    pub fn spot_start(&self) -> Result<Rc<spotlib::Client>> {
        if let Some(c) = self.spot.borrow().as_ref() {
            return Ok(c.clone());
        }
        let client = spotlib::Client::builder()
            .meta("project", "libwallet")
            .handler("transfer", |_msg: &spotlib::Message| {
                Err("device transfer not supported in browser".to_string())
            })
            .build()
            .map_err(|e| Error::Env(format!("spot client: {e}")))?;
        let rc = Rc::new(client);
        *self.spot.borrow_mut() = Some(rc.clone());
        Ok(rc)
    }

    /// The Spot client if started (no auto-start; for read-only status).
    pub fn spot_client_opt(&self) -> Option<Rc<spotlib::Client>> {
        self.spot.borrow().clone()
    }

    /// Close the Spot client if running (called on Destroy).
    pub fn spot_close(&self) {
        if let Some(c) = self.spot.borrow_mut().take() {
            c.close();
        }
    }
}

impl Env {
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

#[cfg(not(target_arch = "wasm32"))]
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
/// Index(u32 BE)`, matching `wltobj.NewTimeId().Bytes()`. Uses chrono so the
/// clock works on wasm (js Date via `wasmbind`) as well as native.
fn time_id_now_bytes() -> Vec<u8> {
    let now = chrono::Utc::now();
    let secs = now.timestamp().max(0) as u64;
    let nanos = now.timestamp_subsec_nanos();
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&secs.to_be_bytes()); // Unix, u64
    b.extend_from_slice(&nanos.to_be_bytes()); // Nano, u32
    b.extend_from_slice(&0u32.to_be_bytes()); // Index, u32
    b
}
