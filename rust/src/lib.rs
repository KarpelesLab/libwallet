//! C-ABI boundary for libwallet — the Rust replacement for `cshared/ffi.go`.
//!
//! Exports the exact five symbols the Dart client (`dart/lib/src/client/
//! ffi_transport.dart`) looks up: `LibwalletInit`, `LibwalletRequest`,
//! `LibwalletSetEventCallback`, `LibwalletDestroy`, `LibwalletFree` (plus
//! `LibwalletShowDebug`). The request/response contract is JSON in, JSON out,
//! over a single entrypoint — apirouter/pobj are gone, replaced by a flat
//! match in `handlers::route`.
//!
//! Safety notes:
//! - Every extern "C" body is wrapped in `catch_unwind`: a panic must never
//!   unwind across the FFI boundary (UB + host crash).
//! - Strings handed to the consumer are `CString::into_raw`; the consumer
//!   returns them via `LibwalletFree`, which reconstructs and drops them
//!   (same allocator on both sides).

// Core infrastructure (ported from Go wltbase).
mod db;
mod env;
mod error;
// Value types (ported from Go wltobj).
mod amount;
mod timeid;
// Key-share storage crypto (bottlers/purecrypto).
pub mod keystore;
// Key descriptions (wltsign).
pub mod sign;
// HD public-key derivation for accounts (secp256k1/ecckd).
pub mod hdderive;
// EVM transaction building + threshold signing (wlttx EVM path).
pub mod evm;
// Solana transaction building (wlttx Solana path).
pub mod solana;
// Bitcoin transaction building + threshold signing (wlttx Bitcoin path).
pub mod bitcoin;
// Blocking JSON-RPC client for blockchain nodes (wltnet).
pub mod rpc;
// Blocking client for the KarpelesLab REST backend (rest.Do).
pub mod rest;
// Market-quote lookup via the REST backend (wltquote).
pub mod quote;
// Coin metadata lookup via the REST backend (wltasset CoinInfo).
pub mod coininfo;
// Token-swap quotes via the OKX DEX proxy (wltswap).
pub mod swap;
// Name resolution — ENS/SNS (wltnames).
pub mod names;
// Curated contract labels (wltcontract).
pub mod contract;
// Threshold-signature ceremonies (tsslib).
pub mod tss;
// Object models (ported from the Go wlt* packages).
pub mod models;
// FFI boundary + request dispatch.
mod dispatch;
mod handle;
mod handlers;
mod response;

pub use amount::{Amount, AmountError};
pub use db::{now_rfc3339, SqlValue};
pub use env::Env;
pub use error::{Error, Result};
pub use timeid::{ParseTimeIdError, TimeId};

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use handle::Handle;

/// `void (*)(const char* response_json, uintptr_t user_data)`
pub type ResponseCallback = unsafe extern "C" fn(response_json: *const c_char, user_data: usize);
/// `void (*)(const char* event_json, uintptr_t user_data)`
pub type EventCallback = unsafe extern "C" fn(event_json: *const c_char, user_data: usize);

static REGISTRY: LazyLock<Mutex<HashMap<usize, Arc<Handle>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HANDLE_SEQ: AtomicUsize = AtomicUsize::new(0);

fn get_handle(h: usize) -> Option<Arc<Handle>> {
    REGISTRY.lock().unwrap().get(&h).cloned()
}

/// Read a C string into an owned Rust String. Returns Err on null / non-UTF8.
/// (Uses std Result explicitly — the crate root re-exports the wltbase Result
/// alias, which would otherwise shadow it here.)
unsafe fn cstr_to_string(ptr: *const c_char) -> std::result::Result<String, String> {
    if ptr.is_null() {
        return Err("null pointer".into());
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(str::to_owned)
        .map_err(|e| format!("invalid utf-8 in argument: {e}"))
}

/// Hand a JSON string to the consumer via `cb`. The consumer frees it with
/// `LibwalletFree`. An interior NUL (which cannot occur in serde_json output,
/// but guard anyway) degrades to a minimal error envelope.
fn respond(cb: ResponseCallback, user_data: usize, json: &str) {
    let cstr = CString::new(json).unwrap_or_else(|_| {
        CString::new(r#"{"result":"error","error":"response contained NUL","code":500}"#).unwrap()
    });
    let ptr = cstr.into_raw();
    unsafe { cb(ptr, user_data) };
}

/// Initialize the environment; returns an opaque handle (>0) or 0 on failure.
#[no_mangle]
pub extern "C" fn LibwalletInit(data_dir: *const c_char) -> usize {
    catch_unwind(AssertUnwindSafe(|| {
        let dir = match unsafe { cstr_to_string(data_dir) } {
            Ok(d) => d,
            Err(e) => {
                eprintln!("LibwalletInit: {e}");
                return 0;
            }
        };
        match Env::init(&dir) {
            Ok(env) => {
                // Create model tables (mirrors the Go per-package InitEnv).
                if let Err(e) = handlers::init_models(&env) {
                    eprintln!("LibwalletInit: model init failed: {e}");
                    return 0;
                }
                let id = HANDLE_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
                REGISTRY.lock().unwrap().insert(id, Arc::new(Handle::new(env)));
                id
            }
            Err(e) => {
                eprintln!("LibwalletInit failed: {e}");
                0
            }
        }
    }))
    .unwrap_or(0)
}

/// Dispatch a JSON request. Processed on a worker thread; `cb` is invoked with
/// the response JSON (and, later, any progress updates before it).
#[no_mangle]
pub extern "C" fn LibwalletRequest(
    h: usize,
    request_json: *const c_char,
    cb: Option<ResponseCallback>,
    user_data: usize,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(cb) = cb else { return };

        let Some(handle) = get_handle(h) else {
            respond(cb, user_data, &response::error("invalid handle", 500));
            return;
        };

        let req = match unsafe { cstr_to_string(request_json) } {
            Ok(s) => s,
            Err(e) => {
                respond(cb, user_data, &response::error(&e, 400));
                return;
            }
        };

        // Gate new work behind the shutdown barrier and register the worker so
        // Destroy waits for it before returning.
        let Some(guard) = handle.begin_request() else {
            respond(cb, user_data, &response::error("handle is shutting down", 503));
            return;
        };

        let worker = handle.clone();
        std::thread::spawn(move || {
            let _guard = guard; // decrements in-flight count on return/panic
            let out = catch_unwind(AssertUnwindSafe(|| dispatch::handle_request(&worker, &req)))
                .unwrap_or_else(|_| response::error("internal panic", 500));
            if worker.shutdown.load(Ordering::SeqCst) {
                return; // don't call back after shutdown
            }
            respond(cb, user_data, &out);
        });
    }));
}

/// Register (or, with a null `cb`, clear) the host event callback.
#[no_mangle]
pub extern "C" fn LibwalletSetEventCallback(h: usize, cb: Option<EventCallback>, user_data: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(handle) = get_handle(h) else { return };
        if handle.shutdown.load(Ordering::SeqCst) {
            return;
        }
        *handle.event_cb.lock().unwrap() = cb.map(|c| (c, user_data));

        // Wire the env broadcast sink to the C event callback: env.broadcast()
        // from any handler forwards the event JSON to the host.
        let sink: Option<Box<dyn Fn(&str) + Send + Sync>> = cb.map(|c| {
            let ud = user_data;
            Box::new(move |json: &str| {
                let cstr = CString::new(json)
                    .unwrap_or_else(|_| CString::new(r#"{"result":"event"}"#).unwrap());
                let ptr = cstr.into_raw();
                unsafe { c(ptr, ud) };
            }) as Box<dyn Fn(&str) + Send + Sync>
        });
        handle.env.set_event_sink(sink);
    }));
}

/// Enable debug logging on stderr. Process-global (see the same caveat as the
/// Go version). Phase 0: no structured logger yet, so this is a no-op stub.
#[no_mangle]
pub extern "C" fn LibwalletShowDebug() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        eprintln!("libwallet: debug logging requested");
    }));
}

/// Tear down a handle: flip the shutdown flag, drop the event callback, and
/// wait for all in-flight workers so no callback fires after this returns.
#[no_mangle]
pub extern "C" fn LibwalletDestroy(h: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let handle = REGISTRY.lock().unwrap().remove(&h);
        if let Some(handle) = handle {
            handle.env.set_event_sink(None);
            handle.shutdown_and_wait();
        }
    }));
}

/// Free a C string previously returned by the library.
#[no_mangle]
pub extern "C" fn LibwalletFree(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !ptr.is_null() {
            unsafe { drop(CString::from_raw(ptr)) };
        }
    }));
}
