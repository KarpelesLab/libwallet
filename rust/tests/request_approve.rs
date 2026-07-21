//! End-to-end exercise of the Request approval state machine through the real
//! FFI worker path. A blocking request (`Request:test`, or a Web3 method that
//! raises an approval) parks a worker thread on the in-memory waiter; a second
//! `Request:approve` / `Request:reject` call then claims the row, runs the
//! type-specific side effects, and resolves the waiter. This validates the
//! claim → side-effect → respond flow for `test`, `connect`, and `chain_switch`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use libwallet::{
    EventCallback, LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest,
    LibwalletSetEventCallback, ResponseCallback,
};

/// C response callback: copy the JSON out, free the library string, forward the
/// copy over a Sender whose pointer we passed as user_data.
extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    let _ = tx.send(json);
}

/// C event callback: same shape, but fed by env.broadcast() host events.
extern "C" fn capture_event(json: *const c_char, user_data: usize) {
    let s = unsafe { CStr::from_ptr(json) }.to_str().unwrap().to_owned();
    LibwalletFree(json as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    let _ = tx.send(s);
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Fresh, unique data dir per handle (parallel tests must not share one sql.db).
fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("libwallet-req-approve-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

/// A parked (blocking) dispatch: fire the request and hand back the response
/// receiver without waiting — the worker thread parks on the approval waiter.
/// The returned raw Sender pointer must be freed once the response arrives.
fn dispatch(h: usize, body: &str) -> (Receiver<String>, *mut Sender<String>) {
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx));
    let req = CString::new(body).unwrap();
    LibwalletRequest(h, req.as_ptr(), Some(capture as ResponseCallback), ud as usize);
    (rx, ud)
}

/// A synchronous dispatch: fire and block for the terminal response envelope,
/// draining any streamed `progress` envelopes first (Wallet:create streams).
fn request(h: usize, body: &str) -> serde_json::Value {
    let (rx, ud) = dispatch(h, body);
    let value = loop {
        let json = rx.recv_timeout(Duration::from_secs(30)).expect("callback fired");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON envelope");
        if v["result"] == "progress" {
            continue;
        }
        break v;
    };
    drop(unsafe { Box::from_raw(ud) });
    value
}

/// Register the host event sink and return the receiver plus the raw Sender
/// pointer (freed after LibwalletDestroy, once no more events can fire).
fn hook_events(h: usize) -> (Receiver<String>, *mut Sender<String>) {
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx));
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), ud as usize);
    (rx, ud)
}

/// Block until the `request` host event fires and yield its request_id.
fn wait_for_request_id(erx: &Receiver<String>) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match erx.recv_timeout(Duration::from_secs(15)) {
            Ok(ev) => {
                let v: serde_json::Value = serde_json::from_str(&ev).unwrap();
                if v["event"] == "request" {
                    return v["data"]["request_id"].as_str().unwrap().to_string();
                }
            }
            Err(_) => break,
        }
    }
    panic!("no `request` host event received");
}

/// `Request:test` → `Request:approve`: the parked test request resolves with the
/// accepted status, and the approve response echoes the accepted row.
#[test]
fn request_test_approve_roundtrip() {
    let h = new_env();
    let (erx, eud) = hook_events(h);

    // Blocking Request:test parks a worker on the approval waiter.
    let (rx, ud) = dispatch(h, r#"{"path":"Request:test"}"#);
    let id = wait_for_request_id(&erx);

    let approved = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{id}"}}}}"#));
    assert_eq!(approved["result"], "success", "{approved}");
    assert_eq!(approved["data"]["Type"], "test");
    assert_eq!(approved["data"]["Status"], "accepted");

    // The parked Request:test now unblocks with the resolved (accepted) row.
    let done = rx.recv_timeout(Duration::from_secs(10)).expect("test returned");
    let done: serde_json::Value = serde_json::from_str(&done).unwrap();
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["Status"], "accepted");
    drop(unsafe { Box::from_raw(ud) });

    LibwalletDestroy(h);
    drop(unsafe { Box::from_raw(eud) });
}

/// `Request:test` → `Request:reject`: the parked request resolves with the
/// rejected status.
#[test]
fn request_test_reject_roundtrip() {
    let h = new_env();
    let (erx, eud) = hook_events(h);

    let (rx, ud) = dispatch(h, r#"{"path":"Request:test"}"#);
    let id = wait_for_request_id(&erx);

    let rejected = request(h, &format!(r#"{{"path":"Request:reject","params":{{"Id":"{id}"}}}}"#));
    assert_eq!(rejected["result"], "success", "{rejected}");
    assert_eq!(rejected["data"]["Status"], "rejected");

    let done = rx.recv_timeout(Duration::from_secs(10)).expect("test returned");
    let done: serde_json::Value = serde_json::from_str(&done).unwrap();
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["Status"], "rejected");
    drop(unsafe { Box::from_raw(ud) });

    // A second approve on the resolved row must fail (waiter is gone).
    let again = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{id}"}}}}"#));
    assert_eq!(again["result"], "error", "{again}");

    LibwalletDestroy(h);
    drop(unsafe { Box::from_raw(eud) });
}

/// `wallet_switchEthereumChain` → `Request:approve`: approving a `chain_switch`
/// request applies the target network as the current one and records the applied
/// selection on the request Result.
#[test]
fn chain_switch_approve_switches_current_network() {
    let h = new_env();
    let (erx, eud) = hook_events(h);

    // Default current network is Ethereum mainnet (chain 1). Switch to Polygon
    // (0x89 = 137), which is in the static chain registry so the request is
    // raised rather than rejected with 4902.
    let body = r#"{"path":"Web3:request","params":{"origin":"https://dapp.example","query":{"method":"wallet_switchEthereumChain","params":[{"chainId":"0x89"}]}}}"#;
    let (rx, ud) = dispatch(h, body);
    let id = wait_for_request_id(&erx);

    let approved = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{id}"}}}}"#));
    assert_eq!(approved["result"], "success", "{approved}");
    assert_eq!(approved["data"]["Type"], "chain_switch");
    assert_eq!(approved["data"]["Status"], "accepted");
    assert_eq!(approved["data"]["Result"]["network"], "evm.137");

    // The parked Web3 call returns now that the switch has been applied.
    let done = rx.recv_timeout(Duration::from_secs(10)).expect("web3 returned");
    let done: serde_json::Value = serde_json::from_str(&done).unwrap();
    assert_eq!(done["result"], "success", "{done}");
    drop(unsafe { Box::from_raw(ud) });

    // The current network is now Polygon.
    let cur = request(h, r#"{"path":"Network","verb":"GET","params":{"Id":"@"}}"#);
    assert_eq!(cur["result"], "success", "{cur}");
    assert_eq!(cur["data"]["Type"], "evm");
    assert_eq!(cur["data"]["ChainId"], "137");

    LibwalletDestroy(h);
    drop(unsafe { Box::from_raw(eud) });
}

/// `solana_connect` → `Request:approve` with Accounts: approving a `connect`
/// request persists the site↔account link and the parked provider call returns
/// the connected address.
#[test]
fn connect_approve_links_site_and_returns_account() {
    let h = new_env();
    let (erx, eud) = hook_events(h);

    // A wallet + Solana account to connect.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"SOL","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    // Blocking solana_connect raises a `connect` request.
    let body = r#"{"path":"Web3:request","params":{"origin":"https://dapp.example","query":{"method":"solana_connect","params":[]}}}"#;
    let (rx, ud) = dispatch(h, body);
    let id = wait_for_request_id(&erx);

    // Approve, choosing the created account.
    let approved = request(
        h,
        &format!(r#"{{"path":"Request:approve","params":{{"Id":"{id}","Accounts":["{account_id}"]}}}}"#),
    );
    assert_eq!(approved["result"], "success", "{approved}");
    assert_eq!(approved["data"]["Type"], "connect");
    assert_eq!(approved["data"]["Status"], "accepted");

    // The parked solana_connect returns the connected public key(s).
    let done = rx.recv_timeout(Duration::from_secs(10)).expect("connect returned");
    let done: serde_json::Value = serde_json::from_str(&done).unwrap();
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["publicKey"][0], serde_json::json!(address));
    drop(unsafe { Box::from_raw(ud) });

    // The connection was persisted and is queryable via Web3/Connection.
    let conns = request(h, r#"{"path":"Web3/Connection","verb":"GET","params":{"Host":"https://dapp.example"}}"#);
    assert_eq!(conns["result"], "success", "{conns}");
    let arr = conns["data"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["Account"], serde_json::json!(account_id));

    LibwalletDestroy(h);
    drop(unsafe { Box::from_raw(eud) });
}
