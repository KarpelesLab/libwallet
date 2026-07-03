//! End-to-end exercise of the C-ABI: init a handle, dispatch requests through
//! the real async worker path, capture the callback output, and tear down.
//! This validates the envelope shape, threading, and string ownership without
//! needing the Dart side.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
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

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Fresh, unique data dir per call — tests run in parallel and must not share
/// one sql.db (concurrent opens race to Busy/Corrupt).
fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-ffi-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
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
fn first_run_is_db_backed() {
    let h = new_env();
    let resp = request(h, r#"{"path":"Info:first_run"}"#);
    assert_eq!(resp["result"], "success");
    // Seeded on first init; shape is the TimeId {type,unix,nano,idx}.
    assert!(resp["data"]["unix"].as_u64().unwrap() > 1_700_000_000);
    assert!(resp["data"].get("nano").is_some());
    assert_eq!(resp["data"]["type"], "");
    LibwalletDestroy(h);
}

#[test]
fn paths_reports_datadir() {
    let h = new_env();
    let resp = request(h, r#"{"path":"Info:paths"}"#);
    assert_eq!(resp["result"], "success");
    assert!(resp["data"]["DataDir"].as_str().unwrap().contains("libwallet-ffi-test"));
    assert!(resp["data"].get("TempDir").is_some());
    LibwalletDestroy(h);
}

#[test]
fn account_create_from_wallet_via_ffi() {
    let h = new_env();
    // Need a wallet first.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"W","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap();

    let created = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    assert_eq!(created["result"], "success");
    assert_eq!(created["data"]["Type"], "solana");
    assert_eq!(created["data"]["Path"], "m");
    assert!(created["data"]["Id"].as_str().unwrap().starts_with("acct-"));
    assert!(created["data"]["Address"].as_str().unwrap().len() > 30);

    let listed = request(h, r#"{"path":"Account","verb":"GET"}"#);
    assert_eq!(listed["data"].as_array().unwrap().len(), 1);
    LibwalletDestroy(h);
}

#[test]
fn contact_create_then_list() {
    let h = new_env();
    // Create
    let created = request(
        h,
        r#"{"path":"Contact","verb":"POST","params":{"Name":"Bob","Address":"0x1","Type":"ethereum","Memo":"m"}}"#,
    );
    assert_eq!(created["result"], "success");
    let id = created["data"]["Id"].as_str().unwrap();
    assert!(id.starts_with("ct-"));
    assert_eq!(created["data"]["Name"], "Bob");

    // List includes it
    let listed = request(h, r#"{"path":"Contact","verb":"GET"}"#);
    assert_eq!(listed["result"], "success");
    let arr = listed["data"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["Id"], id);

    // Fetch by Id
    let fetched = request(h, &format!(r#"{{"path":"Contact","verb":"GET","params":{{"Id":"{id}"}}}}"#));
    assert_eq!(fetched["data"]["Name"], "Bob");
    LibwalletDestroy(h);
}

#[test]
fn crash_list_empty_on_fresh_env() {
    let h = new_env();
    let resp = request(h, r#"{"path":"Crash","verb":"GET"}"#);
    assert_eq!(resp["result"], "success");
    assert_eq!(resp["data"].as_array().unwrap().len(), 0);
    LibwalletDestroy(h);
}

#[test]
fn wallet_create_then_list_via_ffi() {
    let h = new_env();
    let listed = request(h, r#"{"path":"Wallet","verb":"GET"}"#);
    assert_eq!(listed["result"], "success");
    assert_eq!(listed["data"].as_array().unwrap().len(), 0);

    // Create an all-local ed25519 wallet with three password-protected shares.
    let created = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"Main","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    assert_eq!(created["result"], "success");
    let id = created["data"]["Id"].as_str().unwrap();
    assert!(id.starts_with("wlt-"));
    assert_eq!(created["data"]["Curve"], "ed25519");
    assert_eq!(created["data"]["Keys"].as_array().unwrap().len(), 3);
    assert_eq!(created["data"]["Pubkey"].as_str().unwrap().len(), 43);
    // The encrypted share must never cross the FFI.
    assert!(created["data"]["Keys"][0].get("Data").is_none());

    let listed = request(h, r#"{"path":"Wallet","verb":"GET"}"#);
    assert_eq!(listed["data"].as_array().unwrap().len(), 1);
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
