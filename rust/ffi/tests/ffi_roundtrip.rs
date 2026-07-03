//! End-to-end exercise of the C-ABI: init a handle, dispatch requests through
//! the real async worker path, capture the callback output, and tear down.
//! This validates the envelope shape, threading, and string ownership without
//! needing the Dart side.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::{
    LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback,
};

/// C callback: copy the JSON out, free the library string, forward the copy
/// over a channel whose Sender pointer we passed as user_data.
extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char); // consumer owns the string
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

    let json = rx.recv_timeout(Duration::from_secs(5)).expect("callback fired");
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    serde_json::from_str(&json).expect("valid JSON envelope")
}

fn new_env() -> usize {
    let dir = std::env::temp_dir().join(format!("libwallet-ffi-test-{}", std::process::id()));
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

#[test]
fn ping_roundtrip() {
    let h = new_env();
    let resp = request(h, r#"{"path":"Info:ping","verb":"GET"}"#);
    assert_eq!(resp["result"], "success");
    assert_eq!(resp["data"], "pong");
    LibwalletDestroy(h);
}

#[test]
fn version_shape() {
    let h = new_env();
    let resp = request(h, r#"{"path":"Info:version"}"#);
    assert_eq!(resp["result"], "success");
    // Fields are present (empty in a dev build) — matches the Dart contract.
    assert!(resp["data"].get("version").is_some());
    assert!(resp["data"].get("gitTag").is_some());
    assert!(resp["data"].get("dateTag").is_some());
    LibwalletDestroy(h);
}

#[test]
fn unknown_endpoint_is_404() {
    let h = new_env();
    let resp = request(h, r#"{"path":"Nope:nope"}"#);
    assert_eq!(resp["result"], "error");
    assert_eq!(resp["code"], 404);
    LibwalletDestroy(h);
}

#[test]
fn bad_json_is_400() {
    let h = new_env();
    let resp = request(h, "not json at all");
    assert_eq!(resp["result"], "error");
    assert_eq!(resp["code"], 400);
    LibwalletDestroy(h);
}

#[test]
fn invalid_handle_errors() {
    let resp = request(999_999, r#"{"path":"Info:ping"}"#);
    assert_eq!(resp["result"], "error");
    assert_eq!(resp["code"], 500);
}
