//! Regression coverage for the three account fixes that bring the Rust FFI in
//! line with Go (validated against the Dart integration suite):
//!
//!   1. `Account:setCurrent` then `Account/@` GET round-trips the account.
//!   2. `Account:createView` accepts an `Xpub` (no `Address`) for bitcoin.
//!   3. A bitcoin account created while a monacoin network is current yields a
//!      "mona1…" bech32 (P2WPKH) address.
//!
//! Drives the real C-ABI (helpers copied from `ffi_roundtrip.rs`).

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

    let value = loop {
        let json = rx.recv_timeout(Duration::from_secs(30)).expect("callback fired");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON envelope");
        if v["result"] == "progress" { continue; }
        break v;
    };
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    value
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-fixacct-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

fn make_wallet(h: usize, curve: &str) -> String {
    let w = request(
        h,
        &format!(
            r#"{{"path":"Wallet","verb":"POST","params":{{"Name":"W","Curve":"{curve}","Keys":[
                {{"Type":"Password","Key":"passwordone"}},
                {{"Type":"Password","Key":"passwordtwo"}},
                {{"Type":"Password","Key":"passwordthree"}}]}}}}"#
        ),
    );
    w["data"]["Id"].as_str().unwrap().to_string()
}

/// Fix 1: setCurrent → getCurrent ("@") round-trips the same account.
#[test]
fn set_current_then_get_current_roundtrips() {
    let h = new_env();
    let wallet_id = make_wallet(h, "ed25519");
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    // Object-scoped path, exactly as the Dart client sends it.
    let set = request(h, &format!(r#"{{"path":"Account/{account_id}:setCurrent","verb":"POST"}}"#));
    assert_eq!(set["result"], "success", "setCurrent failed: {set}");

    let cur = request(h, r#"{"path":"Account/@","verb":"GET"}"#);
    assert_eq!(cur["result"], "success", "getCurrent (@) failed: {cur}");
    assert_eq!(cur["data"]["Id"], account_id, "current account should round-trip");
    LibwalletDestroy(h);
}

/// Fix 2: createView from an xpub succeeds with no Address, populating
/// pubkey + chaincode so xpub() round-trips.
#[test]
fn create_view_from_xpub_without_address() {
    let h = new_env();
    // Known mainnet xpub (BIP-32 test vector), same one the Dart suite uses.
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let view = request(
        h,
        &format!(
            r#"{{"path":"Account:createView","verb":"POST","params":{{"Type":"bitcoin","Name":"BTC watch","Xpub":"{XPUB}"}}}}"#
        ),
    );
    assert_eq!(view["result"], "success", "createView(xpub) failed: {view}");
    assert_eq!(view["data"]["Wallet"], "", "view account has no wallet");
    assert!(!view["data"]["Pubkey"].as_str().unwrap().is_empty(), "pubkey populated");
    assert!(!view["data"]["Chaincode"].as_str().unwrap().is_empty(), "chaincode populated");
    let id = view["data"]["Id"].as_str().unwrap().to_string();

    let xp = request(h, &format!(r#"{{"path":"Account/{id}:xpub","verb":"POST"}}"#));
    assert_eq!(xp["result"], "success", "xpub() failed: {xp}");
    assert!(!xp["data"]["xpub"].as_str().unwrap().is_empty(), "derived xpub round-trips");

    // Both address and xpub → rejected; neither → rejected.
    let both = request(
        h,
        &format!(r#"{{"path":"Account:createView","verb":"POST","params":{{"Type":"bitcoin","Address":"bc1qxyz","Xpub":"{XPUB}"}}}}"#),
    );
    assert_eq!(both["result"], "error", "both address+xpub must be rejected: {both}");
    LibwalletDestroy(h);
}

/// Fix 3: a bitcoin account created while the monacoin network is current has a
/// "mona1…" bech32 address, both on the create response and on fetch.
#[test]
fn monacoin_bitcoin_account_uses_mona_bech32() {
    let h = new_env();
    let wallet_id = make_wallet(h, "secp256k1");

    // Ephemeral monacoin network selected as current.
    let set = request(h, r#"{"path":"Network:setCurrent","params":{"Id":"bitcoin.monacoin"}}"#);
    assert_eq!(set["result"], "success", "setCurrent(monacoin) failed: {set}");

    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"bitcoin","Index":5}}}}"#),
    );
    assert_eq!(a["result"], "success", "account create failed: {a}");
    let created_addr = a["data"]["Address"].as_str().unwrap().to_string();
    assert!(created_addr.starts_with("mona1"), "create address should be mona1…, got {created_addr}");

    // Fetch returns the same address (create/fetch stay consistent).
    let id = a["data"]["Id"].as_str().unwrap();
    let got = request(h, &format!(r#"{{"path":"Account/{id}","verb":"GET"}}"#));
    assert_eq!(got["data"]["Address"], created_addr, "fetch address matches create");
    LibwalletDestroy(h);
}
