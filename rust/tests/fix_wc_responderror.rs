//! Regression: `WalletConnect:respondError` on an unknown/inactive topic must
//! fail with an error message containing "unknown topic" (matching Go's
//! `RespondSessionError`, wltwc/manager.go). The Dart integration test
//! "respondError on unknown topic fails clearly" asserts exactly this.
//!
//! The bug: the Rust handler required an `Id` param and read it under the key
//! "Id", but the Dart client sends "ID". The missing key made the handler
//! reject with "Id required" *before* the topic was ever looked up. Go never
//! validates the id in the handler; it defers to the manager, which checks the
//! topic first. This test drives the real FFI to confirm the fixed order.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};

// --- helpers copied from tests/ffi_roundtrip.rs -----------------------------

extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    tx.send(json).unwrap();
}

fn request(h: usize, body: &str) -> serde_json::Value {
    let (tx, rx) = channel::<String>();
    let boxed: Box<Sender<String>> = Box::new(tx);
    let ud = Box::into_raw(boxed) as usize;

    let req = CString::new(body).unwrap();
    let cb: ResponseCallback = capture;
    LibwalletRequest(h, req.as_ptr(), Some(cb), ud);

    let json = rx.recv_timeout(Duration::from_secs(30)).expect("callback fired");
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    serde_json::from_str(&json).expect("valid JSON envelope")
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-fixwc-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

// --- test --------------------------------------------------------------------

#[test]
fn respond_error_unknown_topic_reports_unknown_topic() {
    use std::net::TcpListener;

    // Minimal loopback relay: accept the wallet's WS handshake so
    // `WalletConnect:start` succeeds, then just drain frames until the socket
    // closes on teardown. respondError errors during the session lookup, before
    // any publish, so no relay protocol is exercised here.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(mut ws) = tungstenite::accept(stream) {
                while ws.read().is_ok() {}
            }
        }
    });

    let h = new_env();

    let started = request(h, &format!(r#"{{"path":"WalletConnect:start","params":{{"RelayUrl":"ws://{addr}/"}}}}"#));
    assert_eq!(started["result"], "success", "start failed: {started}");

    // A 64-char hex topic that is not a known session — mirrors the Dart test's
    // 'deadbeef' * 8, and sends the id under the key "ID" like the Dart client.
    let bogus = "deadbeef".repeat(8);
    let resp = request(
        h,
        &format!(
            r#"{{"path":"WalletConnect:respondError","params":{{"Topic":"{bogus}","ID":1,"Code":5000,"Message":"test"}}}}"#
        ),
    );

    assert_eq!(resp["result"], "error", "expected an error envelope: {resp}");
    let msg = resp["error"].as_str().unwrap_or("");
    assert!(
        msg.contains("unknown topic"),
        "error message must contain 'unknown topic', got: {msg:?} (full: {resp})"
    );

    LibwalletDestroy(h);
}
