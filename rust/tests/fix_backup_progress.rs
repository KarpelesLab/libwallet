//! Verifies two Dart-integration fixes, driven through the real C-ABI:
//!
//!  (a) `Wallet:backup` emits the entry envelope with **lowercase** `filename`
//!      and `data` string keys — matching Go's `backupDataEntry` json tags and
//!      the Dart `WalletBackupEntry.fromJson`, which reads `json['filename']`
//!      as a non-null String (the previous capitalised `Filename`/`Data` made
//!      that field null and threw `type 'Null' is not a subtype of String`).
//!      `Wallet:restore` accepts those lowercase keys back (the Dart client
//!      sends `{files:[{filename,data}]}`).
//!
//!  (b) `Wallet` POST (create) streams ≥1 `{"result":"progress"}` envelope
//!      before the final `{"result":"success"}`, so the Dart
//!      `wallets.create(...)` stream yields a `Progress` before `Complete`.
//!
//! NOTE the streaming helper here (`request_stream`) drains ALL callbacks for a
//! request until the terminal (non-progress) one, unlike the read-one `request`
//! helper in `ffi_roundtrip.rs`. Progress emission means a create request now
//! fires the response callback more than once; a read-one consumer would only
//! see the first (progress) callback. That is the intended, Dart-compatible
//! behaviour (its `_onResponse` keeps the stream open on progress).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};

/// C callback: copy the JSON out, free the library string, forward the copy
/// over a channel whose Sender pointer we passed as user_data. (Copied from
/// `ffi_roundtrip.rs`.)
extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    let _ = tx.send(json);
}

/// Drive one request and collect EVERY response envelope it produces, in order,
/// stopping after the terminal (non-progress) envelope. Safe against the
/// multi-callback create path: we only free the user_data box after the
/// terminal callback, which is the worker thread's last action for the request.
fn request_stream(h: usize, body: &str) -> Vec<serde_json::Value> {
    let (tx, rx) = channel::<String>();
    let boxed: Box<Sender<String>> = Box::new(tx);
    let ud = Box::into_raw(boxed) as usize;

    let req = CString::new(body).unwrap();
    let cb: ResponseCallback = capture;
    LibwalletRequest(h, req.as_ptr(), Some(cb), ud);

    let mut out = Vec::new();
    loop {
        let json = rx.recv_timeout(Duration::from_secs(60)).expect("callback fired");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON envelope");
        let is_progress = v["result"] == "progress";
        out.push(v);
        if !is_progress {
            break;
        }
    }
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    out
}

/// The terminal (last) envelope of a request.
fn final_of(v: &[serde_json::Value]) -> &serde_json::Value {
    v.last().expect("at least one envelope")
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Fresh, unique data dir per call. (Copied from `ffi_roundtrip.rs`.)
fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-fixbp-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

const CREATE: &str = r#"{"path":"Wallet","verb":"POST","params":{"Name":"Fix","Curve":"ed25519","Keys":[
    {"Type":"Password","Key":"passwordone"},
    {"Type":"Password","Key":"passwordtwo"},
    {"Type":"Password","Key":"passwordthree"}]}}"#;

#[test]
fn wallet_create_streams_progress_before_success() {
    let h = new_env();
    let envelopes = request_stream(h, CREATE);

    // (b) At least one well-formed progress envelope precedes the success.
    let progress: Vec<&serde_json::Value> =
        envelopes.iter().filter(|e| e["result"] == "progress").collect();
    assert!(
        !progress.is_empty(),
        "expected >=1 progress envelope before completion, got: {envelopes:?}"
    );
    for p in &progress {
        let f = p["data"]["progress"]
            .as_f64()
            .expect("progress envelope carries data.progress as a number");
        assert!((0.0..=1.0).contains(&f), "progress fraction in range: {f}");
    }

    // The terminal envelope is the created wallet.
    let done = final_of(&envelopes);
    assert_eq!(done["result"], "success", "final envelope is success: {done}");
    assert!(done["data"]["Id"].as_str().unwrap().starts_with("wlt-"));
    assert_eq!(done["data"]["Keys"].as_array().unwrap().len(), 3);

    LibwalletDestroy(h);
}

#[test]
fn wallet_backup_entry_uses_lowercase_string_keys() {
    let h = new_env();
    let created = request_stream(h, CREATE);
    let wallet_id = final_of(&created)["data"]["Id"].as_str().unwrap().to_string();

    // (a) Backup entry envelope: lowercase `filename` + `data`, both Strings.
    let backup = request_stream(h, &format!(r#"{{"path":"Wallet:backup","params":{{"Id":"{wallet_id}"}}}}"#));
    let done = final_of(&backup);
    assert_eq!(done["result"], "success", "{done}");
    let entry = &done["data"][0];

    let filename = entry["filename"].as_str().expect("entry has a `filename` String");
    assert!(filename.starts_with("wallet_"), "filename shape: {filename}");
    let data = entry["data"].as_str().expect("entry has a `data` String");
    assert!(!data.is_empty(), "data is a non-empty base64url payload");

    // The old capitalised keys must be gone (Go emits only lowercase).
    assert!(entry.get("Filename").is_none(), "no legacy capitalised Filename");
    assert!(entry.get("Data").is_none(), "no legacy capitalised Data");

    LibwalletDestroy(h);
}

#[test]
fn wallet_restore_accepts_lowercase_files_and_data() {
    // Full round-trip through the exact wire shape the Dart client sends:
    // backup on one env, then restore `{files:[{filename,data}]}` on a fresh
    // env (lowercase keys, as `WalletBackupEntry.toJson` produces).
    let src = new_env();
    let wallet_id = final_of(&request_stream(src, CREATE))["data"]["Id"]
        .as_str()
        .unwrap()
        .to_string();
    let backup = request_stream(src, &format!(r#"{{"path":"Wallet:backup","params":{{"Id":"{wallet_id}"}}}}"#));
    let entry = &final_of(&backup)["data"][0];
    let filename = entry["filename"].as_str().unwrap().to_string();
    let data = entry["data"].as_str().unwrap().to_string();
    LibwalletDestroy(src);

    let dst = new_env();
    let restored = request_stream(
        dst,
        &format!(
            r#"{{"path":"Wallet:restore","params":{{"files":[{{"filename":"{filename}","data":"{data}"}}]}}}}"#
        ),
    );
    let done = final_of(&restored);
    assert_eq!(done["result"], "success", "restore failed: {done}");
    assert_eq!(done["data"]["restored"][0], wallet_id);

    // The restored wallet is really there.
    let got = request_stream(dst, &format!(r#"{{"path":"Wallet","verb":"GET","params":{{"Id":"{wallet_id}"}}}}"#));
    assert_eq!(final_of(&got)["data"]["Id"], wallet_id);
    LibwalletDestroy(dst);
}
