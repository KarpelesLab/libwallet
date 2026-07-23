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

// ── Always compiled, including the browser-WASM build ───────────────────────
// Offline crypto only: the error type, BIP-39, HD derivation, Solana tx
// building, and the single-key wallet core (mnemonic / addresses / vault /
// raw-key signing). None of these touch the DB, network, or threads.
mod error;
pub mod bip39;
pub mod hdderive;
pub mod solana;
pub mod walletcore;
// SQLite persistence — graphitesql is pure Rust with a wasm in-memory VFS.
// (Compiled for wasm now; its consumers migrate in later steps — hence the
// transitional dead-code allowance on the browser target.)
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod db;
// Environment: DB + config/cache/events are common; the Spot/WalletConnect/
// approval machinery inside is gated native-only.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod env;
// Object models (wallet/account/transaction/network/token/…): mostly DB CRUD
// (wasm-OK); the per-model networking/TSS methods are gated native-only.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod models;

pub use db::{now_rfc3339, SqlValue};
pub use env::Env;
pub use error::{Error, Result};

// wasm-bindgen bindings for the browser wallet (thin wrappers over walletcore).
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// ── Native only (excluded from wasm32) ──────────────────────────────────────
// Everything below needs the DB (graphitesql), networking (rsurl / tungstenite),
// OS threads, or the TSS stack — none of which run in the browser. The C-ABI FFI
// boundary at the bottom of this file is likewise native-only.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod amount;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod timeid;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod keystore;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod sign;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod evm;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod eip712;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod solana_spl;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod bitcoin;
#[cfg(not(target_arch = "wasm32"))]
pub mod rpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod rest;
#[cfg(not(target_arch = "wasm32"))]
pub mod quote;
#[cfg(not(target_arch = "wasm32"))]
pub mod coininfo;
#[cfg(not(target_arch = "wasm32"))]
pub mod swap;
#[cfg(not(target_arch = "wasm32"))]
pub mod counterparty;
#[cfg(not(target_arch = "wasm32"))]
pub mod walletconnect;
#[cfg(not(target_arch = "wasm32"))]
pub mod wcmanager;
#[cfg(not(target_arch = "wasm32"))]
pub mod erc20;
#[cfg(not(target_arch = "wasm32"))]
pub mod remotekey;
#[cfg(not(target_arch = "wasm32"))]
pub mod spotbroker;
#[cfg(not(target_arch = "wasm32"))]
pub mod transfer;
#[cfg(not(target_arch = "wasm32"))]
pub mod clawdpair;
#[cfg(not(target_arch = "wasm32"))]
pub mod walletsign;
#[cfg(not(target_arch = "wasm32"))]
pub mod reshare;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod curated;
#[cfg(not(target_arch = "wasm32"))]
pub mod probe;
#[cfg(not(target_arch = "wasm32"))]
pub mod txhistory;
#[cfg(not(target_arch = "wasm32"))]
pub mod names;
#[cfg(not(target_arch = "wasm32"))]
pub mod contract;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod tss;
// Request dispatch — the offline handler surface compiles for wasm; the
// networking handlers/route-arms inside are gated native-only.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod dispatch;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub mod handle;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod handlers;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod response;

#[cfg_attr(target_arch = "wasm32", allow(unused_imports))]
pub use amount::{Amount, AmountError};
#[cfg(not(target_arch = "wasm32"))]
pub use timeid::{ParseTimeIdError, TimeId};

// The remaining FFI machinery in this file is native-only.
#[cfg(not(target_arch = "wasm32"))]
mod ffi_boundary {

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use crate::{dispatch, handle::Handle, handlers, response, Env};

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

            // Progress sink: long-running handlers (e.g. Wallet create keygen)
            // call `dispatch::emit_progress`, which forwards here as extra
            // `{"result":"progress",...}` callbacks BEFORE the final response.
            // The Dart client keeps the request's response stream open until a
            // non-progress envelope arrives (see ffi_transport `_onResponse`),
            // so these surface as `Progress` events ahead of the `Complete`.
            let sink_handle = worker.clone();
            let sink: Box<dyn Fn(f64)> = Box::new(move |fraction: f64| {
                if sink_handle.shutdown.load(Ordering::SeqCst) {
                    return; // don't call back after shutdown
                }
                respond(cb, user_data, &response::progress(fraction));
            });

            let out = catch_unwind(AssertUnwindSafe(|| {
                dispatch::with_progress_sink(sink, || dispatch::handle_request(&worker, &req))
            }))
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
            handle.env.wc_stop(); // stop the relay reader before tearing down
            handle.env.spot_close(); // disconnect the Spot client if running
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
} // end of ffi_boundary::LibwalletFree
} // mod ffi_boundary

// Surface the C-ABI entry points + callback types at the crate root: the
// exported symbols come from #[no_mangle] regardless of module, but Rust
// consumers (the integration tests, and `handle` via `crate::EventCallback`)
// reference them by path.
#[cfg(not(target_arch = "wasm32"))]
pub use ffi_boundary::{
    EventCallback, LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest,
    LibwalletSetEventCallback, LibwalletShowDebug, ResponseCallback,
};
