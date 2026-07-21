//! Regression test: `Info:first_run` must return the TimeId as Go's JSON
//! *string* form — `json.Marshal(TimeId.String())` → `"nil:<unix>:<nano>:<idx>"`
//! (empty type renders as `nil`) — not a `{type,unix,nano,idx}` object. The
//! Dart client (`info_api.dart`) casts the result to `String?`, so an object
//! throws a `_Map is not a subtype of String?` error.
//!
//! Helpers (request/new_env/capture) are copied from ffi_roundtrip.rs so this
//! file drives the real C-ABI end to end.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};

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
    let dir =
        std::env::temp_dir().join(format!("libwallet-fixfr-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

#[test]
fn first_run_is_go_format_json_string() {
    let h = new_env();
    let resp = request(h, r#"{"path":"Info:first_run"}"#);
    assert_eq!(resp["result"], "success");

    // Must be a JSON string, NOT an object — this is the Dart `String?` contract.
    let s = resp["data"]
        .as_str()
        .expect("Info:first_run data must be a JSON string, matching Go's TimeId.MarshalJSON");

    // Go String() for an empty type: "nil:<unix>:<nano>:<idx>".
    let parts: Vec<&str> = s.split(':').collect();
    assert_eq!(parts.len(), 4, "expected type:unix:nano:idx, got {s:?}");
    assert_eq!(parts[0], "nil", "empty type must render as 'nil'");
    let unix: u64 = parts[1].parse().expect("unix is a base-10 integer");
    assert!(unix > 1_700_000_000, "first_run unix looks unseeded: {unix}");
    let _nano: u32 = parts[2].parse().expect("nano is a base-10 integer");
    let idx: u32 = parts[3].parse().expect("idx is a base-10 integer");
    assert_eq!(idx, 0, "freshly seeded first_run has index 0");

    LibwalletDestroy(h);
}
