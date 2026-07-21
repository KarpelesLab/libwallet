//! Regression: `Nft` GET (list) must return the Go object wrapper shape
//! `{"network":…, "account":…, "nfts":[…]}` — NOT a bare JSON array — so the
//! Dart `NftListing.fromJson` (dart/lib/src/api/nft_api.dart) can cast the
//! payload to `Map<String, dynamic>`. Drives the real C-ABI end to end.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::{
    LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback,
};

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
    let dir = std::env::temp_dir().join(format!("libwallet-fixnft-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

#[test]
fn nft_list_returns_object_wrapper_not_bare_array() {
    let h = new_env();

    // A wallet + Solana account gives us a "current account" (create() sets it),
    // which the Nft list handler resolves just like Go's CurrentAccount.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"W","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let created = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    assert_eq!(created["result"], "success", "account create: {created}");

    // GET Nft (list). Must succeed and return an OBJECT, not a bare array.
    let listed = request(h, r#"{"path":"Nft","verb":"GET"}"#);
    assert_eq!(listed["result"], "success", "Nft list: {listed}");
    let data = &listed["data"];

    // This is the exact failure the Dart client hit: a bare `List` cannot be
    // cast to `Map<String, dynamic>`. Assert we now emit an object.
    assert!(data.is_object(), "Nft list must be a JSON object, got: {data}");
    assert!(!data.is_array(), "Nft list must not be a bare array");

    // Keys the Dart NftListing.fromJson reads (lowercase, matching Go).
    assert!(data.get("network").is_some(), "missing `network` key: {data}");
    assert!(data.get("account").is_some(), "missing `account` key: {data}");
    assert!(data.get("nfts").is_some(), "missing `nfts` key: {data}");

    // The wrapped sub-objects match what the Dart Network/Account models parse.
    assert!(data["network"].is_object(), "network must be an object");
    assert!(data["account"].is_object(), "account must be an object");
    assert!(data["nfts"].is_array(), "nfts must be an array");

    // Fresh account has no indexed NFTs.
    assert_eq!(data["nfts"].as_array().unwrap().len(), 0);
    // The account echoed back is the one we just created (and set current).
    assert_eq!(data["account"]["Type"], "solana");

    LibwalletDestroy(h);
}
