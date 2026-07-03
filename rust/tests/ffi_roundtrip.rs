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
    EventCallback, LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest,
    LibwalletSetEventCallback, ResponseCallback,
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
fn full_flow_create_wallet_account_and_sign_message() {
    let h = new_env();
    // 1. Create wallet.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"W","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk0 = w["data"]["Keys"][0]["Id"].as_str().unwrap().to_string();
    let wk1 = w["data"]["Keys"][1]["Id"].as_str().unwrap().to_string();

    // 2. Create account.
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    // 3. Sign a message ("hello" = base64 aGVsbG8=) with two password shares.
    let signed = request(
        h,
        &format!(
            r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[
                {{"Type":"Password","Id":"{wk0}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{wk1}","Key":"passwordtwo"}}]}}}}"#
        ),
    );
    assert_eq!(signed["result"], "success", "signMessage failed: {signed:?}");
    let sig = signed["data"]["signature"].as_str().unwrap();
    // base58 Ed25519 signature (~88 chars for 64 bytes).
    assert!(sig.len() > 80, "signature looks too short: {sig}");
    assert!(!sig.contains(['0', 'O', 'I', 'l']));
    LibwalletDestroy(h);
}

#[test]
fn evm_wallet_account_and_sign_transaction_via_ffi() {
    let h = new_env();
    // Create a secp256k1 wallet.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> =
        (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();

    // Derive an ethereum account.
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    assert!(a["data"]["Address"].as_str().unwrap().starts_with("0x"));

    // Sign a legacy transaction (all shares unlocked for DKLs).
    let signed = request(
        h,
        &format!(
            r#"{{"path":"Account:signTransaction","params":{{"Id":"{account_id}",
                "Transaction":{{"nonce":0,"gas":21000,"gasPrice":"20000000000","to":"0x000000000000000000000000000000000000dEaD","value":"1000000000000000000","chainId":1}},
                "Keys":[{{"Type":"Password","Id":"{}","Key":"passwordone"}},
                        {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                        {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    assert_eq!(signed["result"], "success", "signTransaction failed: {signed:?}");
    let raw = signed["data"]["raw"].as_str().unwrap();
    assert!(raw.starts_with("0x"));
    assert!(raw.len() > 60); // a real signed tx
    LibwalletDestroy(h);
}

/// One-shot mock JSON-RPC node returning `response_json`; yields its URL.
fn mock_node(response_json: &str) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = response_json.to_string();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}/")
}

#[test]
fn evm_sign_and_send_via_ffi() {
    let h = new_env();
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> =
        (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    // Mock node accepts the broadcast and returns a tx hash.
    let rpc = mock_node(r#"{"jsonrpc":"2.0","id":1,"result":"0xabc123txhash"}"#);
    let sent = request(
        h,
        &format!(
            r#"{{"path":"Account:signAndSendTransaction","params":{{"Id":"{account_id}","RPC":"{rpc}",
                "Transaction":{{"nonce":0,"gas":21000,"gasPrice":"20000000000","to":"0x000000000000000000000000000000000000dEaD","value":"1","chainId":1}},
                "Keys":[{{"Type":"Password","Id":"{}","Key":"passwordone"}},
                        {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                        {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    assert_eq!(sent["result"], "success", "signAndSend failed: {sent:?}");
    assert_eq!(sent["data"]["hash"], "0xabc123txhash");
    assert!(sent["data"]["raw"].as_str().unwrap().starts_with("0x"));
    LibwalletDestroy(h);
}

#[test]
fn account_balance_via_ffi() {
    let h = new_env();
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    // Mock node reports 1 ETH (0xde0b6b3a7640000 wei).
    let rpc = mock_node(r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#);
    let bal = request(
        h,
        &format!(r#"{{"path":"Account:balance","params":{{"Id":"{account_id}","RPC":"{rpc}"}}}}"#),
    );
    assert_eq!(bal["result"], "success", "balance failed: {bal:?}");
    assert_eq!(bal["data"]["balance"], "1000000000000000000");
    LibwalletDestroy(h);
}

#[test]
fn solana_balance_subtracts_rent_via_ffi() {
    let h = new_env();
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

    // getBalance = 0.01 SOL (10_000_000 lamports), rent-exempt min = 890_880.
    // Spendable = 10_000_000 - 890_880 = 9_109_120.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"value":10000000}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":890880}"#.to_string(),
    ]);
    let bal = request(
        h,
        &format!(r#"{{"path":"Account:balance","params":{{"Id":"{account_id}","RPC":"{rpc}"}}}}"#),
    );
    assert_eq!(bal["result"], "success", "balance failed: {bal:?}");
    assert_eq!(bal["data"]["balance"], "9109120");
    LibwalletDestroy(h);
}

/// Mock node serving `responses` in order (one request each).
fn mock_multi(responses: Vec<String>) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for body in responses {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        }
    });
    format!("http://{addr}/")
}

#[test]
fn solana_sign_and_send_via_ffi() {
    let h = new_env();
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"SOL","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> =
        (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    // Node: getLatestBlockhash then sendTransaction.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"11111111111111111111111111111111"}}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":"soLtxSignature123"}"#.to_string(),
    ]);
    let sent = request(
        h,
        &format!(
            r#"{{"path":"Account:signAndSendTransaction","params":{{"Id":"{account_id}","RPC":"{rpc}",
                "Transaction":{{"to":"11111111111111111111111111111111","value":"1000000"}},
                "Keys":[{{"Type":"Password","Id":"{}","Key":"passwordone"}},
                        {{"Type":"Password","Id":"{}","Key":"passwordtwo"}}]}}}}"#,
            wk[0], wk[1]
        ),
    );
    assert_eq!(sent["result"], "success", "solana signAndSend failed: {sent:?}");
    assert_eq!(sent["data"]["signature"], "soLtxSignature123");
    LibwalletDestroy(h);
}

extern "C" fn capture_event(json: *const c_char, user_data: usize) {
    let s = unsafe { CStr::from_ptr(json) }.to_str().unwrap().to_owned();
    LibwalletFree(json as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    let _ = tx.send(s);
}

#[test]
fn event_bridge_delivers_wallet_created() {
    let h = new_env();

    // Register an event callback that forwards events over a channel.
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx)) as usize;
    let cb: EventCallback = capture_event;
    LibwalletSetEventCallback(h, Some(cb), ud);

    // Creating a wallet broadcasts a "wallet:created" event.
    let _ = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"W","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );

    let event = rx.recv_timeout(Duration::from_secs(5)).expect("event delivered");
    let j: serde_json::Value = serde_json::from_str(&event).unwrap();
    assert_eq!(j["result"], "event");
    assert_eq!(j["event"], "wallet:created");
    assert!(j["data"]["id"].as_str().unwrap().starts_with("wlt-"));

    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn network_test_rpc_and_set_current() {
    let h = new_env();
    // testRPC: mock node reports net_version "1" -> Ethereum Mainnet metadata.
    let rpc = mock_node(r#"{"jsonrpc":"2.0","id":1,"result":"1"}"#);
    let probed = request(
        h,
        &format!(r#"{{"path":"Network:testRPC","params":{{"URL":"{rpc}","Type":"evm"}}}}"#),
    );
    assert_eq!(probed["result"], "success", "testRPC failed: {probed:?}");
    assert_eq!(probed["data"]["ChainId"], 1);
    assert_eq!(probed["data"]["Name"], "Ethereum Mainnet");
    assert_eq!(probed["data"]["CurrencySymbol"], "ETH");

    // setCurrent on an ephemeral network id.
    let set = request(h, r#"{"path":"Network:setCurrent","params":{"Id":"net-xyz"}}"#);
    assert_eq!(set["result"], "success");
    assert_eq!(set["data"]["network"], "net-xyz");
    // Fetching @ (current) now resolves that selection (ephemeral fetch still works).
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

#[test]
fn network_resolve_rpc_via_ffi() {
    let h = new_env();
    // Ephemeral bitcoin.bitcoin resolves to the modchain endpoint.
    let resp = request(h, r#"{"path":"Network:resolveRPC","params":{"Id":"bitcoin.bitcoin"}}"#);
    assert_eq!(resp["result"], "success", "{resp}");
    let rpc = resp["data"]["rpc"].as_str().unwrap();
    assert!(rpc.starts_with("https://rpc.modchain.net/api/"), "{rpc}");
    assert!(rpc.ends_with("/bitcoin/rpc"), "{rpc}");

    // Auto EVM is not resolvable locally -> error.
    let ev = request(h, r#"{"path":"Network:resolveRPC","params":{"Id":"evm.1"}}"#);
    assert_eq!(ev["result"], "error");
    LibwalletDestroy(h);
}

#[test]
fn quote_get_via_ffi() {
    let h = new_env();
    let base = mock_node(
        r#"{"result":"success","data":[{"id":1,"name":"Bitcoin","symbol":"BTC","quote":{"USD":{"price":65000.5}}}]}"#,
    );
    let base = base.trim_end_matches('/');
    let resp = request(
        h,
        &format!(r#"{{"path":"Quote:get","params":{{"Symbol":"BTC","Currency":"USD","Backend":"{base}"}}}}"#),
    );
    assert_eq!(resp["result"], "success", "{resp}");
    assert_eq!(resp["data"]["symbol"], "BTC");
    assert_eq!(resp["data"]["price"], 65000.5);
    assert_eq!(resp["data"]["quote"]["price"], 65000.5);

    // An unknown symbol is a 404 (served from the now-warm cache).
    let miss = request(
        h,
        &format!(r#"{{"path":"Quote:get","params":{{"Symbol":"ZZZ","Backend":"{base}"}}}}"#),
    );
    assert_eq!(miss["result"], "error");
    assert_eq!(miss["code"], 404);
    LibwalletDestroy(h);
}
