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

    // Generous timeout: a Wallet POST runs a full DKLs/FROST keygen (several
    // seconds), which can be slower under parallel test load.
    let json = rx.recv_timeout(Duration::from_secs(30)).expect("callback fired");
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

    // Fetch object-scoped by path (`Contact/<id>`) — the wire form the Dart
    // client sends. Must resolve to the same record, not 404.
    let by_path = request(h, &format!(r#"{{"path":"Contact/{id}","verb":"GET"}}"#));
    assert_eq!(by_path["result"], "success", "object-scoped path routed: {by_path}");
    assert_eq!(by_path["data"]["Id"], id);
    assert_eq!(by_path["data"]["Name"], "Bob");
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
fn wallet_key_recrypt_changes_password_via_ffi() {
    let h = new_env();
    // Create a 2-of-3 Password wallet + a Solana account.
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

    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    // Recrypt key 0: passwordone -> newpassword1 (object-scoped path).
    let rec = request(
        h,
        &format!(
            r#"{{"path":"Wallet/Key/{wk0}:recrypt","verb":"POST","params":{{"Old":{{"Type":"Password","Key":"passwordone"}},"New":{{"Type":"Password","Key":"newpassword1"}}}}}}"#
        ),
    );
    assert_eq!(rec["result"], "success", "recrypt failed: {rec}");
    assert_eq!(rec["data"]["Id"], wk0);
    assert_eq!(rec["data"]["Type"], "Password");
    assert!(rec["data"].get("Data").is_none(), "encrypted Data must never cross FFI");

    // The OLD password must no longer unlock key 0.
    let old_fail = request(
        h,
        &format!(
            r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[
                {{"Type":"Password","Id":"{wk0}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{wk1}","Key":"passwordtwo"}}]}}}}"#
        ),
    );
    assert_eq!(old_fail["result"], "error", "old password should no longer work: {old_fail}");

    // The NEW password unlocks it and the 2-of-3 signature verifies.
    let signed = request(
        h,
        &format!(
            r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[
                {{"Type":"Password","Id":"{wk0}","Key":"newpassword1"}},
                {{"Type":"Password","Id":"{wk1}","Key":"passwordtwo"}}]}}}}"#
        ),
    );
    assert_eq!(signed["result"], "success", "signMessage with new password failed: {signed}");
    assert!(signed["data"]["signature"].as_str().unwrap().len() > 80);
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

#[test]
fn transaction_sign_and_send_evm_backfills_and_broadcasts() {
    let h = new_env();
    // secp256k1 wallet + ethereum account.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#),
    );
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    // Mock node answers, in call order: nonce, gasPrice, estimateGas, sendRaw.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":"0x5"}"#.into(),          // eth_getTransactionCount = 5
        r#"{"jsonrpc":"2.0","id":1,"result":"0x4a817c800"}"#.into(),  // eth_gasPrice = 20 gwei
        r#"{"jsonrpc":"2.0","id":1,"result":"0x5208"}"#.into(),       // eth_estimateGas = 21000
        r#"{"jsonrpc":"2.0","id":1,"result":"0xdeadbeef"}"#.into(),   // eth_sendRawTransaction = hash
    ]);

    // No nonce/gas/gasPrice supplied → all backfilled from the node.
    let sent = request(
        h,
        &format!(
            r#"{{"path":"Transaction:signAndSend","params":{{
                "from":"{address}","type":"transfer","to":"0x000000000000000000000000000000000000dEaD",
                "amount":{{"v":"1000000000000000000","e":0}},"RPC":"{rpc}",
                "Keys":[{{"Type":"Password","Id":"{}","Key":"passwordone"}},
                        {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                        {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    assert_eq!(sent["result"], "success", "signAndSend failed: {sent}");
    assert_eq!(sent["data"]["hash"], "0xdeadbeef");
    assert_eq!(sent["data"]["nonce"], 5);
    assert_eq!(sent["data"]["gas"], 21000);
    assert_eq!(sent["data"]["gasPrice"], "20000000000");
    assert_eq!(sent["data"]["format"], "legacy");
    let id = sent["data"]["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("tx-"));
    let raw = sent["data"]["raw"].as_str().unwrap();
    assert!(raw.starts_with("0x") && raw.len() > 60);

    // The broadcast tx was persisted and is fetchable.
    let got = request(h, &format!(r#"{{"path":"Transaction","verb":"GET","params":{{"Id":"{id}"}}}}"#));
    assert_eq!(got["data"]["hash"], "0xdeadbeef");
    assert_eq!(got["data"]["from"], address);
    LibwalletDestroy(h);
}

#[test]
fn transaction_simulate_evm_decodes_erc20_and_effects() {
    let h = new_env();
    // ERC-20 transfer(0x…aa, 1000) calldata against token 0x…bb.
    let token = "0x00000000000000000000000000000000000000bb";
    let data = "0xa9059cbb\
        00000000000000000000000000000000000000000000000000000000000000aa\
        00000000000000000000000000000000000000000000000000000000000003e8";
    // callTracer frame with a Transfer log; then prestateTracer (no diff).
    let call_tracer = r#"{"jsonrpc":"2.0","id":1,"result":{"type":"CALL","from":"0x1111111111111111111111111111111111111111","to":"0x00000000000000000000000000000000000000bb","value":"0x0","gasUsed":"0x5208","logs":[{"address":"0x00000000000000000000000000000000000000BB","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000001111111111111111111111111111111111111111","0x00000000000000000000000000000000000000000000000000000000000000aa"],"data":"0x00000000000000000000000000000000000000000000000000000000000003e8"}],"calls":[]}}"#;
    let prestate = r#"{"jsonrpc":"2.0","id":1,"result":{"pre":{},"post":{}}}"#;
    let rpc = mock_multi(vec![call_tracer.into(), prestate.into()]);

    let sim = request(
        h,
        &format!(
            r#"{{"path":"Transaction:simulate","params":{{"type":"erc20_transfer","from":"0x1111111111111111111111111111111111111111","to":"{token}","data":"{data}","RPC":"{rpc}"}}}}"#
        ),
    );
    assert_eq!(sim["result"], "success", "{sim}");
    assert_eq!(sim["data"]["chain"], "evm");
    assert_eq!(sim["data"]["willRevert"], false);
    assert_eq!(sim["data"]["decodedMethod"], "erc20_transfer");
    assert_eq!(sim["data"]["decodedArgs"]["token"], token);
    assert_eq!(sim["data"]["decodedArgs"]["amount"], "1000");
    assert_eq!(sim["data"]["gasEstimate"], 21000);
    let eff = &sim["data"]["effects"][0];
    assert_eq!(eff["type"], "erc20_transfer");
    assert_eq!(eff["amount"], "1000");
    assert_eq!(eff["token"], token); // lowercased
    LibwalletDestroy(h);
}

#[test]
fn transaction_simulate_evm_reports_revert() {
    let h = new_env();
    // callTracer frame carrying an Error(string) revert of "Boom".
    let revert_data = "0x08c379a0\
        0000000000000000000000000000000000000000000000000000000000000020\
        0000000000000000000000000000000000000000000000000000000000000004\
        426f6f6d00000000000000000000000000000000000000000000000000000000";
    let call_tracer = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"type":"CALL","from":"0x1111111111111111111111111111111111111111","to":"0x00000000000000000000000000000000000000bb","error":"execution reverted","revertReason":"{revert_data}","calls":[]}}}}"#
    );
    let prestate = r#"{"jsonrpc":"2.0","id":1,"result":{"pre":{},"post":{}}}"#;
    let rpc = mock_multi(vec![call_tracer, prestate.into()]);

    let sim = request(
        h,
        &format!(
            r#"{{"path":"Transaction:simulate","params":{{"type":"evm","from":"0x1111111111111111111111111111111111111111","to":"0x00000000000000000000000000000000000000bb","data":"0xdeadbeef","RPC":"{rpc}"}}}}"#
        ),
    );
    assert_eq!(sim["result"], "success", "{sim}");
    assert_eq!(sim["data"]["willRevert"], true);
    assert_eq!(sim["data"]["revertReason"], "Boom");
    LibwalletDestroy(h);
}

#[test]
fn transaction_simulate_evm_fallback_and_unlimited_approve_warning() {
    let h = new_env();
    // Unlimited approve(spender, 2^256-1) — no callTracer support on the node,
    // so simulate falls back to eth_call + eth_estimateGas.
    let max = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let data = format!(
        "0x095ea7b3\
        00000000000000000000000000000000000000000000000000000000000000cc{max}"
    );
    // debug_traceCall errors (method not found) → fallback; eth_call ok;
    // eth_estimateGas → 0xabcd; second debug_traceCall (prestate) errors.
    let err = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#;
    let ok = r#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#;
    let gas = r#"{"jsonrpc":"2.0","id":1,"result":"0xabcd"}"#;
    let rpc = mock_multi(vec![err.into(), ok.into(), gas.into(), err.into()]);

    let sim = request(
        h,
        &format!(
            r#"{{"path":"Transaction:simulate","params":{{"type":"erc20_approve","from":"0x1111111111111111111111111111111111111111","to":"0x00000000000000000000000000000000000000bb","data":"{data}","RPC":"{rpc}"}}}}"#
        ),
    );
    assert_eq!(sim["result"], "success", "{sim}");
    assert_eq!(sim["data"]["decodedMethod"], "erc20_approve");
    assert_eq!(sim["data"]["gasEstimate"], 0xabcd);
    // Fallback synthesizes one effect from the decode.
    assert_eq!(sim["data"]["effects"][0]["type"], "erc20_approve");
    // The unlimited-approve warning fires.
    let warns = sim["data"]["warnings"].as_array().unwrap();
    assert!(warns.iter().any(|w| w["code"] == "erc20_approve_unlimited"), "{sim}");
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
fn native_asset_via_ffi() {
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

    // Current network defaults to the ephemeral evm.1; pass an explicit RPC.
    // 2 ETH = 0x1bc16d674ec80000 wei.
    let rpc = mock_node(r#"{"jsonrpc":"2.0","id":1,"result":"0x1bc16d674ec80000"}"#);
    let asset = request(
        h,
        &format!(r#"{{"path":"Account:nativeAsset","params":{{"Id":"{account_id}","RPC":"{rpc}"}}}}"#),
    );
    assert_eq!(asset["result"], "success", "nativeAsset failed: {asset:?}");
    assert_eq!(asset["data"]["key"], "evm.1.NATIVE");
    assert_eq!(asset["data"]["symbol"], "ETH");
    assert_eq!(asset["data"]["amount"]["v"], "2000000000000000000");
    LibwalletDestroy(h);
}

#[test]
fn bitcoin_xpub_via_ffi() {
    let h = new_env();
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"BTC","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"bitcoin","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    let resp = request(h, &format!(r#"{{"path":"Account:xpub","params":{{"Id":"{account_id}"}}}}"#));
    assert_eq!(resp["result"], "success", "{resp}");
    let xpub = resp["data"]["xpub"].as_str().unwrap();
    assert!(xpub.starts_with("xpub"), "got {xpub}");
    assert_eq!(xpub.len(), 111);
    LibwalletDestroy(h);
}

#[test]
fn bitcoin_balance_via_ffi() {
    let h = new_env();
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"BTC","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"bitcoin","Index":0}}}}"#),
    );
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    // modchain_assets reports 0.005 + 0.00000123 BTC of NATIVE.
    let rpc = mock_node(
        r#"{"jsonrpc":"2.0","id":1,"result":{"assets":[{"asset":"NATIVE","decimals":8,"balance":"0.00500123"}]}}"#,
    );
    let bal = request(
        h,
        &format!(r#"{{"path":"Account:balance","params":{{"Id":"{account_id}","RPC":"{rpc}"}}}}"#),
    );
    assert_eq!(bal["result"], "success", "balance failed: {bal:?}");
    assert_eq!(bal["data"]["balance"], "500123");
    LibwalletDestroy(h);
}

#[test]
fn max_sendable_via_ffi() {
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

    // balance = 1 ETH (0xde0b6b3a7640000 wei); gasPrice = 20 gwei
    // (0x4a817c800). fee = 21000 * 20e9 = 4.2e14 wei; max = 1e18 - 4.2e14.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":"0x4a817c800"}"#.to_string(),
    ]);
    let resp = request(
        h,
        &format!(r#"{{"path":"Account:maxSendable","params":{{"Id":"{account_id}","RPC":"{rpc}"}}}}"#),
    );
    assert_eq!(resp["result"], "success", "{resp}");
    assert_eq!(resp["data"]["chain"], "evm");
    assert_eq!(resp["data"]["balance"]["v"], "1000000000000000000");
    assert_eq!(resp["data"]["fee"]["v"], "420000000000000"); // 21000 * 20e9
    assert_eq!(resp["data"]["max"]["v"], "999580000000000000"); // 1e18 - fee
    LibwalletDestroy(h);
}

#[test]
fn eip1559_max_sendable_via_ffi() {
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

    // balance 1 ETH; baseFee 10 gwei (0x2540be400), tip 2 gwei (0x77359400).
    // perGas = 2*10 + 2 = 22 gwei; fee = 21000 * 22e9 = 4.62e14; max = 1e18-fee.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#.to_string(), // eth_getBalance
        r#"{"jsonrpc":"2.0","id":1,"result":{"baseFeePerGas":"0x2540be400"}}"#.to_string(), // block
        r#"{"jsonrpc":"2.0","id":1,"result":"0x77359400"}"#.to_string(), // maxPriorityFeePerGas
    ]);
    let resp = request(
        h,
        &format!(r#"{{"path":"Account:maxSendable","params":{{"Id":"{account_id}","RPC":"{rpc}","Eip1559":true}}}}"#),
    );
    assert_eq!(resp["result"], "success", "{resp}");
    assert_eq!(resp["data"]["fee"]["v"], "462000000000000"); // 21000 * 22 gwei
    assert_eq!(resp["data"]["max"]["v"], "999538000000000000");
    LibwalletDestroy(h);
}

#[test]
fn solana_max_sendable_via_ffi() {
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

    // balance = 0.01 SOL (10_000_000), rent = 890880. max = 10_000_000 - 5000
    // - 890880 = 9_104_120.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"value":10000000}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":890880}"#.to_string(),
    ]);
    let resp = request(
        h,
        &format!(r#"{{"path":"Account:maxSendable","params":{{"Id":"{account_id}","RPC":"{rpc}"}}}}"#),
    );
    assert_eq!(resp["result"], "success", "{resp}");
    assert_eq!(resp["data"]["chain"], "solana");
    assert_eq!(resp["data"]["balance"]["v"], "10000000");
    assert_eq!(resp["data"]["fee"]["v"], "5000");
    assert_eq!(resp["data"]["max"]["v"], "9104120");
    assert_eq!(resp["data"]["reserved"][0]["kind"], "sender_rent");
    LibwalletDestroy(h);
}

#[test]
fn solana_max_sendable_reserves_recipient_rent_via_ffi() {
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

    // balance 0.01 SOL, rent 890880, recipient does NOT exist (value=null) so an
    // extra rent is reserved: max = 10_000_000 - 5000 - 890880 - 890880 = 8_213_240.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"value":10000000}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":890880}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"value":null}}"#.to_string(), // getAccountInfo: absent
    ]);
    let resp = request(
        h,
        &format!(r#"{{"path":"Account:maxSendable","params":{{"Id":"{account_id}","RPC":"{rpc}","To":"SomeNewRecipient"}}}}"#),
    );
    assert_eq!(resp["result"], "success", "{resp}");
    assert_eq!(resp["data"]["max"]["v"], "8213240");
    assert_eq!(resp["data"]["reserved"][1]["kind"], "recipient_rent");
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
fn web3_injection_script_substitutes_config() {
    let h = new_env();

    // Missing required fields → 400.
    let bad = request(h, r#"{"path":"Web3:injectionScript","params":{"Name":"W"}}"#);
    assert_eq!(bad["result"], "error");
    assert_eq!(bad["code"], 400);

    let ok = request(
        h,
        r#"{"path":"Web3:injectionScript","params":{"Name":"MyWallet","Rdns":"co.echelle.wallet","Uuid":"abc-123","Bridge":"__hostBridge","Icon":"data:image/png;base64,AA"}}"#,
    );
    assert_eq!(ok["result"], "success", "{ok}");
    let script = ok["data"]["script"].as_str().expect("script string");
    // Placeholder was substituted with the real config JSON.
    assert!(!script.contains("__LIBWALLET_CONFIG__"), "placeholder must be replaced");
    assert!(script.contains(r#""bridge":"__hostBridge""#), "config injected");
    assert!(script.contains(r#""rdns":"co.echelle.wallet""#));
    // No network selected → default ephemeral EVM chain 1 → initialChainId 0x1.
    assert!(script.contains(r#""initialChainId":"0x1""#), "seeds current chain id");

    LibwalletDestroy(h);
}

#[test]
fn walletconnect_ffi_pair_and_approve_over_loopback() {
    use libwallet::walletconnect as wc;
    use std::net::TcpListener;

    // A local WS relay + dApp: accept the wallet, echo/collect its frames, push a
    // sessionPropose, and confirm the wallet's approve publishes a settle.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let sym: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
    let topic = wc::derive_topic(&sym);
    let sym_hex: String = sym.iter().map(|b| format!("{b:02x}")).collect();
    let (dapp_priv, dapp_pub) = wc::new_x25519_keypair();
    let dapp_pub_hex: String = dapp_pub.iter().map(|b| format!("{b:02x}")).collect();

    let topic_srv = topic.clone();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut ws = tungstenite::accept(stream).unwrap();
        // 1. wallet subscribes to the pairing topic.
        let sub = ws.read().unwrap().into_text().unwrap();
        assert!(sub.contains("irn_subscribe") && sub.contains(&topic_srv), "sub: {sub}");
        // 2. push a Type-0 sessionPropose on the pairing topic.
        let propose = format!(
            r#"{{"id":100,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{{"proposer":{{"publicKey":"{dapp_pub_hex}","metadata":{{"name":"dApp"}}}},"requiredNamespaces":{{"eip155":{{"chains":["eip155:1"],"methods":["personal_sign"],"events":["chainChanged"]}}}}}}}}"#
        );
        let env0 = wc::seal_type0_with_nonce(&sym, &[1u8; 12], propose.as_bytes());
        ws.send(tungstenite::Message::Text(format!(
            r#"{{"id":1,"method":"irn_subscription","params":{{"data":{{"topic":"{topic_srv}","message":"{env0}","tag":1100}}}}}}"#
        )))
        .unwrap();
        // 3. collect the wallet's remaining frames until we see a sessionSettle
        // publish (the approve). Ack subscriptions/publishes with {result:true}.
        let mut saw_settle = false;
        for _ in 0..8 {
            match ws.read() {
                Ok(m) if m.is_text() => {
                    let t = m.into_text().unwrap();
                    if t.contains("wc_sessionSettle") || (t.contains("irn_publish") && t.contains("\"tag\":1102")) {
                        saw_settle = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(saw_settle, "wallet must publish a sessionSettle after approve");
    });

    let h = new_env();
    // Capture host events (the reader thread broadcasts the inbound proposal).
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), ud);

    // start + pair.
    let started = request(h, &format!(r#"{{"path":"WalletConnect:start","params":{{"RelayUrl":"ws://{addr}/"}}}}"#));
    assert_eq!(started["result"], "success", "{started}");
    let uri = format!("wc:{topic}@2?relay-protocol=irn&symKey={sym_hex}");
    let paired = request(h, &format!(r#"{{"path":"WalletConnect:pair","params":{{"Uri":"{uri}"}}}}"#));
    assert_eq!(paired["result"], "success", "{paired}");
    assert_eq!(paired["data"]["pairingTopic"], topic);

    // The reader thread pumps the pushed proposal and broadcasts it as an event.
    let mut proposal_event = None;
    for _ in 0..40 {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(200)) {
            let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
            if j["event"] == "wc_sessionPropose" {
                proposal_event = Some(j);
                break;
            }
        }
    }
    let pe = proposal_event.expect("sessionPropose event delivered");
    assert_eq!(pe["data"]["payload"]["id"], 100);

    // Approve the proposal — publishes settle + response.
    let proposal = &pe["data"]["payload"]["params"];
    let approve = request(
        h,
        &format!(
            r#"{{"path":"WalletConnect:approveSession","params":{{"PairingTopic":"{topic}","ProposalId":100,"Proposal":{proposal},"Accounts":["eip155:1:0xabc"],"Methods":["personal_sign"]}}}}"#
        ),
    );
    assert_eq!(approve["result"], "success", "{approve}");
    assert!(approve["data"]["sessionTopic"].as_str().unwrap().len() == 64);

    server.join().unwrap();
    let _ = dapp_priv;
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

/// Fire a request WITHOUT blocking for its response; returns the response
/// channel + the user_data box pointer (free it after collecting the response).
fn request_async(h: usize, body: &str) -> (std::sync::mpsc::Receiver<String>, usize) {
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx)) as usize;
    let req = CString::new(body).unwrap();
    LibwalletRequest(h, req.as_ptr(), Some(capture as ResponseCallback), ud);
    (rx, ud)
}

#[test]
fn request_approve_round_trip() {
    let h = new_env();
    // Capture host events to learn the request id.
    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);

    // Request:test blocks until approved — fire it async.
    let (rrx, rud) = request_async(h, r#"{"path":"Request:test"}"#);

    // The pending request surfaces as a "request" host event.
    let mut req_id = None;
    for _ in 0..50 {
        if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
            let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
            if j["event"] == "request" {
                req_id = j["data"]["request_id"].as_str().map(str::to_owned);
                break;
            }
        }
    }
    let req_id = req_id.expect("request event delivered");

    // Approve it; the blocked Request:test then resolves as accepted.
    let appr = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{req_id}"}}}}"#));
    assert_eq!(appr["result"], "success", "{appr}");
    assert_eq!(appr["data"]["Status"], "accepted");

    let resp = rrx.recv_timeout(Duration::from_secs(5)).expect("Request:test resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    assert_eq!(j["data"]["Status"], "accepted");
    assert_eq!(j["data"]["Type"], "test");

    drop(unsafe { Box::from_raw(rud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn request_reject_round_trip() {
    let h = new_env();
    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);

    let (rrx, rud) = request_async(h, r#"{"path":"Request:test"}"#);

    let mut req_id = None;
    for _ in 0..50 {
        if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
            let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
            if j["event"] == "request" {
                req_id = j["data"]["request_id"].as_str().map(str::to_owned);
                break;
            }
        }
    }
    let req_id = req_id.expect("request event delivered");

    let rej = request(h, &format!(r#"{{"path":"Request:reject","params":{{"Id":"{req_id}"}}}}"#));
    assert_eq!(rej["result"], "success", "{rej}");

    // The blocked Request:test resolves with status "rejected".
    let resp = rrx.recv_timeout(Duration::from_secs(5)).expect("Request:test resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["data"]["Status"], "rejected", "{j}");

    // Approving an already-resolved request now fails.
    let again = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{req_id}"}}}}"#));
    assert_eq!(again["result"], "error");

    drop(unsafe { Box::from_raw(rud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_request_read_methods_and_connect_flow() {
    let h = new_env();
    let site = "https://app.example.com";

    // Read-only methods (default network = ephemeral EVM chain 1).
    let chain = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}/x","query":{{"method":"eth_chainId","params":[]}}}}}}"#));
    assert_eq!(chain["data"], "0x1", "{chain}");
    let netv = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"net_version","params":[]}}}}}}"#));
    assert_eq!(netv["data"], "1");
    let cv = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"web3_clientVersion","params":[]}}}}}}"#));
    assert!(cv["data"].as_str().unwrap().starts_with("libwallet/"));
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let sha3 = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"web3_sha3","params":["0x"]}}}}}}"#));
    assert_eq!(sha3["data"], "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    // No connections yet.
    let acc0 = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_accounts","params":[]}}}}}}"#));
    assert_eq!(acc0["data"], serde_json::json!([]));

    // Set up an EVM account to connect.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    // eth_requestAccounts raises a connect approval; capture it and approve.
    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);

    let (rrx, rud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_requestAccounts","params":[]}}}}}}"#));

    let mut req_id = None;
    for _ in 0..50 {
        if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
            let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
            if j["event"] == "request" {
                // The connect request carries the rich Value payload.
                assert_eq!(j["data"]["request"]["Value"]["method"], "eth_requestAccounts");
                req_id = j["data"]["request_id"].as_str().map(str::to_owned);
                break;
            }
        }
    }
    let req_id = req_id.expect("connect request event");
    let appr = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{req_id}","Accounts":["{account_id}"]}}}}"#));
    assert_eq!(appr["result"], "success", "{appr}");

    // eth_requestAccounts now resolves with the connected address.
    let resp = rrx.recv_timeout(Duration::from_secs(5)).expect("eth_requestAccounts resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    assert_eq!(j["data"][0], address);

    // And eth_accounts reflects the persisted connection.
    let acc1 = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_accounts","params":[]}}}}}}"#));
    assert_eq!(acc1["data"][0], address);

    drop(unsafe { Box::from_raw(rud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_personal_sign_via_message_approval() {
    let h = new_env();
    let site = "https://dapp.example.com";

    // EVM wallet + ethereum account.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);

    // Helper: block until the next "request" host event, returning its id.
    let next_request_id = |erx: &std::sync::mpsc::Receiver<String>| -> String {
        for _ in 0..50 {
            if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
                let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
                if j["event"] == "request" {
                    return j["data"]["request_id"].as_str().unwrap().to_owned();
                }
            }
        }
        panic!("no request event");
    };

    // 1. Connect the account to the site.
    let (_c, cud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_requestAccounts","params":[]}}}}}}"#));
    let cid = next_request_id(&erx);
    let ca = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{cid}","Accounts":["{account_id}"]}}}}"#));
    assert_eq!(ca["result"], "success", "{ca}");

    // 2. personal_sign "hello" (0x68656c6c6f) → message_sign approval.
    let (srx, sud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"personal_sign","params":["0x68656c6c6f"]}}}}}}"#));
    let sid = next_request_id(&erx);
    let sa = request(
        h,
        &format!(
            r#"{{"path":"Request:approve","params":{{"Id":"{sid}","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    assert_eq!(sa["result"], "success", "message_sign approve failed: {sa}");

    // personal_sign resolves with the 0x R‖S‖V signature.
    let resp = srx.recv_timeout(Duration::from_secs(30)).expect("personal_sign resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    let sig = j["data"].as_str().unwrap();
    assert!(sig.starts_with("0x"), "sig: {sig}");
    assert_eq!(sig.len(), 132, "65-byte R||S||V signature"); // 0x + 130 hex
    let v = &sig[sig.len() - 2..];
    assert!(v == "1b" || v == "1c", "EIP-191 V must be 27/28, got {v}");

    drop(unsafe { Box::from_raw(cud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_eth_send_transaction_via_approval() {
    let h = new_env();
    let site = "https://dex.example.com";

    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let next_request_id = |erx: &std::sync::mpsc::Receiver<String>| -> String {
        for _ in 0..50 {
            if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
                let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
                if j["event"] == "request" {
                    return j["data"]["request_id"].as_str().unwrap().to_owned();
                }
            }
        }
        panic!("no request event");
    };

    // Connect the account.
    let (_c, cud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_requestAccounts","params":[]}}}}}}"#));
    let cid = next_request_id(&erx);
    request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{cid}","Accounts":["{account_id}"]}}}}"#));

    // eth_sendTransaction with all fees pinned (only the broadcast hits the node).
    let mock = mock_multi(vec![r#"{"jsonrpc":"2.0","id":1,"result":"0xhashbeef"}"#.into()]);
    let tx = format!(
        r#"{{"from":"{address}","to":"0x000000000000000000000000000000000000dEaD","value":"0xde0b6b3a7640000","gas":"0x5208","gasPrice":"0x4a817c800","nonce":"0x1"}}"#
    );
    let (srx, sud) = request_async(
        h,
        &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_sendTransaction","params":[{tx}]}}}}}}"#),
    );
    let sid = next_request_id(&erx);
    // The approval carries the normalized transaction (hex quantities decoded).
    let approve = request(
        h,
        &format!(
            r#"{{"path":"Request:approve","params":{{"Id":"{sid}","RPC":"{mock}","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    assert_eq!(approve["result"], "success", "tx approve failed: {approve}");

    let resp = srx.recv_timeout(Duration::from_secs(30)).expect("eth_sendTransaction resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    assert_eq!(j["data"], "0xhashbeef");

    drop(unsafe { Box::from_raw(cud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_solana_connect_and_sign_message() {
    let h = new_env();
    let site = "https://sol.example.com";

    // ed25519 wallet + solana account.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"SOL","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let next_request_id = |erx: &std::sync::mpsc::Receiver<String>| -> String {
        for _ in 0..50 {
            if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
                let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
                if j["event"] == "request" {
                    return j["data"]["request_id"].as_str().unwrap().to_owned();
                }
            }
        }
        panic!("no request event");
    };

    // solana_connect → connect approval → {publicKey:[address]}.
    let (crx, cud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"solana_connect","params":[]}}}}}}"#));
    let cid = next_request_id(&erx);
    request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{cid}","Accounts":["{account_id}"]}}}}"#));
    let cresp = crx.recv_timeout(Duration::from_secs(5)).expect("solana_connect resolved");
    let cj: serde_json::Value = serde_json::from_str(&cresp).unwrap();
    assert_eq!(cj["data"]["publicKey"][0], address, "{cj}");

    // solana_signMessage {message: base64("hello")} → message_sign → FROST sign.
    let (srx, sud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"solana_signMessage","params":[{{"message":"aGVsbG8="}}]}}}}}}"#));
    let sid = next_request_id(&erx);
    request(
        h,
        &format!(
            r#"{{"path":"Request:approve","params":{{"Id":"{sid}","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}}]}}}}"#,
            wk[0], wk[1]
        ),
    );
    let sresp = srx.recv_timeout(Duration::from_secs(30)).expect("solana_signMessage resolved");
    let sj: serde_json::Value = serde_json::from_str(&sresp).unwrap();
    assert_eq!(sj["result"], "success", "{sj}");
    assert_eq!(sj["data"]["publicKey"], address);
    let sig = sj["data"]["signature"].as_str().unwrap();
    assert!(sig.len() > 80, "base58 ed25519 signature: {sig}"); // ~88 chars for 64 bytes

    drop(unsafe { Box::from_raw(cud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_wallet_switch_ethereum_chain() {
    let h = new_env();
    let site = "https://app.example.com";

    // Starts on ephemeral EVM chain 1.
    let c0 = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_chainId","params":[]}}}}}}"#));
    assert_eq!(c0["data"], "0x1");

    // Unknown chain → 4902 synchronously (no approval raised).
    let bad = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"wallet_switchEthereumChain","params":[{{"chainId":"0xdeadbeef"}}]}}}}}}"#));
    assert_eq!(bad["result"], "error", "{bad}");
    assert_eq!(bad["code"], 4902);

    // Switch to Polygon (0x89 = 137, in the static registry) via chain_switch.
    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);

    let (rx, ud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"wallet_switchEthereumChain","params":[{{"chainId":"0x89"}}]}}}}}}"#));
    let mut req_id = None;
    for _ in 0..50 {
        if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
            let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
            if j["event"] == "request" {
                assert_eq!(j["data"]["request"]["Value"]["targetNetwork"], "evm.137");
                req_id = j["data"]["request_id"].as_str().map(str::to_owned);
                break;
            }
        }
    }
    let req_id = req_id.expect("chain_switch request");
    let appr = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{req_id}"}}}}"#));
    assert_eq!(appr["result"], "success", "{appr}");
    let resp = rx.recv_timeout(Duration::from_secs(5)).expect("switch resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "{j}");

    // eth_chainId now reflects the switch.
    let c1 = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_chainId","params":[]}}}}}}"#));
    assert_eq!(c1["data"], "0x89");

    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_wallet_add_ethereum_chain() {
    let h = new_env();
    let site = "https://app.example.com";
    // A chain id that is NOT in the static registry (proves add persists it).
    let chain_hex = "0x5ca1ab1e"; // 1554472222

    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let next_request_id = |erx: &std::sync::mpsc::Receiver<String>| -> String {
        for _ in 0..50 {
            if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
                let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
                if j["event"] == "request" {
                    return j["data"]["request_id"].as_str().unwrap().to_owned();
                }
            }
        }
        panic!("no request event");
    };

    // Before adding, switching to it is 4902 (unknown chain).
    let bad = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"wallet_switchEthereumChain","params":[{{"chainId":"{chain_hex}"}}]}}}}}}"#));
    assert_eq!(bad["code"], 4902, "{bad}");

    // Add the chain via add_network approval.
    let add_body = format!(
        r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"wallet_addEthereumChain","params":[{{"chainId":"{chain_hex}","chainName":"Cake Testnet","nativeCurrency":{{"symbol":"CAKE","decimals":18}},"rpcUrls":["https://rpc.cake.example"]}}]}}}}}}"#
    );
    let (arx, aud) = request_async(h, &add_body);
    let aid = next_request_id(&erx);
    let aa = request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{aid}"}}}}"#));
    assert_eq!(aa["result"], "success", "add approve: {aa}");
    let aresp = arx.recv_timeout(Duration::from_secs(5)).expect("add resolved");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&aresp).unwrap()["result"], "success");

    // Now switching to it is known → chain_switch (no 4902).
    let (srx, sud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"wallet_switchEthereumChain","params":[{{"chainId":"{chain_hex}"}}]}}}}}}"#));
    let sid = next_request_id(&erx);
    request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{sid}"}}}}"#));
    let sresp = srx.recv_timeout(Duration::from_secs(5)).expect("switch resolved");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&sresp).unwrap()["result"], "success");

    // eth_chainId reflects the added+switched chain.
    let cid = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_chainId","params":[]}}}}}}"#));
    assert_eq!(cid["data"], chain_hex);

    drop(unsafe { Box::from_raw(aud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_solana_sign_transaction() {
    use base64::Engine;
    let h = new_env();
    let site = "https://sol-dapp.example.com";

    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"SOL","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();

    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let next_request_id = |erx: &std::sync::mpsc::Receiver<String>| -> String {
        for _ in 0..50 {
            if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
                let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
                if j["event"] == "request" {
                    return j["data"]["request_id"].as_str().unwrap().to_owned();
                }
            }
        }
        panic!("no request event");
    };

    // Connect.
    let (_c, cud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"solana_connect","params":[]}}}}}}"#));
    let cid = next_request_id(&erx);
    request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{cid}","Accounts":["{account_id}"]}}}}"#));

    // A serialized tx: [compact-u16 sig count = 1][64-byte zero placeholder][message].
    let mut raw = vec![1u8];
    raw.extend_from_slice(&[0u8; 64]);
    raw.extend_from_slice(b"a-solana-message-to-sign-0123456"); // 32-byte "message"
    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&raw);

    let (srx, sud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"solana_signTransaction","params":[{{"transaction":"{tx_b64}"}}]}}}}}}"#));
    let sid = next_request_id(&erx);
    request(
        h,
        &format!(
            r#"{{"path":"Request:approve","params":{{"Id":"{sid}","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}}]}}}}"#,
            wk[0], wk[1]
        ),
    );
    let sresp = srx.recv_timeout(Duration::from_secs(30)).expect("solana_signTransaction resolved");
    let j: serde_json::Value = serde_json::from_str(&sresp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    let signed_b64 = j["data"]["transaction"].as_str().unwrap();
    let signed = base64::engine::general_purpose::STANDARD.decode(signed_b64).unwrap();
    // The signature slot (bytes 1..65) is now populated (was all zeros).
    assert_eq!(signed.len(), raw.len());
    assert!(signed[1..65].iter().any(|&b| b != 0), "signature slot must be filled");
    // The message tail is preserved.
    assert_eq!(&signed[65..], b"a-solana-message-to-sign-0123456");

    drop(unsafe { Box::from_raw(cud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_eth_sign_typed_data() {
    let h = new_env();
    let site = "https://permit.example.com";

    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let next_request_id = |erx: &std::sync::mpsc::Receiver<String>| -> String {
        for _ in 0..50 {
            if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
                let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
                if j["event"] == "request" {
                    return j["data"]["request_id"].as_str().unwrap().to_owned();
                }
            }
        }
        panic!("no request event");
    };

    // Connect.
    let (_c, cud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_requestAccounts","params":[]}}}}}}"#));
    let cid = next_request_id(&erx);
    request(h, &format!(r#"{{"path":"Request:approve","params":{{"Id":"{cid}","Accounts":["{account_id}"]}}}}"#));

    // eth_signTypedData_v4 with the canonical Mail typed data.
    let typed = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"#;
    let (srx, sud) = request_async(
        h,
        &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_signTypedData_v4","params":["{address}",{typed}]}}}}}}"#),
    );
    let sid = next_request_id(&erx);
    request(
        h,
        &format!(
            r#"{{"path":"Request:approve","params":{{"Id":"{sid}","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    let sresp = srx.recv_timeout(Duration::from_secs(30)).expect("eth_signTypedData resolved");
    let j: serde_json::Value = serde_json::from_str(&sresp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    let sig = j["data"].as_str().unwrap();
    assert!(sig.starts_with("0x") && sig.len() == 132, "sig: {sig}");
    let v = &sig[sig.len() - 2..];
    assert!(v == "1b" || v == "1c", "V must be 27/28, got {v}");

    drop(unsafe { Box::from_raw(cud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn web3_personal_ec_recover_round_trip() {
    let h = new_env();
    // EVM wallet + account.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    // personal_sign "hello" (aGVsbG8=) via Account:signMessage.
    let signed = request(
        h,
        &format!(
            r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    let sig = signed["data"]["signature"].as_str().unwrap().to_string();

    // personal_ecRecover [msg=0x68656c6c6f, sig] recovers the signer address.
    let rec = request(
        h,
        &format!(r#"{{"path":"Web3:request","params":{{"origin":"https://x.example.com","query":{{"method":"personal_ecRecover","params":["0x68656c6c6f","{sig}"]}}}}}}"#),
    );
    assert_eq!(rec["result"], "success", "{rec}");
    assert_eq!(
        rec["data"].as_str().unwrap().to_lowercase(),
        address.to_lowercase(),
        "recovered signer must equal the signing account"
    );
    LibwalletDestroy(h);
}

#[test]
fn web3_connection_crud() {
    let h = new_env();
    let site = "https://managed.example.com";

    // Wallet + ethereum account.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    // Create a connection directly (Web3/Connection POST).
    let created = request(h, &format!(r#"{{"path":"Web3/Connection","verb":"POST","params":{{"Host":"{site}","Account":"{account_id}"}}}}"#));
    assert_eq!(created["result"], "success", "{created}");
    let cnx_id = created["data"]["Id"].as_str().unwrap().to_string();
    assert!(cnx_id.starts_with("cnx-"));
    assert_eq!(created["data"]["AccountInfo"]["Address"], address);

    // List (filtered by Host).
    let list = request(h, &format!(r#"{{"path":"Web3/Connection","verb":"GET","params":{{"Host":"{site}"}}}}"#));
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(list["data"][0]["Host"], site);

    // Fetch by id.
    let got = request(h, &format!(r#"{{"path":"Web3/Connection/{cnx_id}","verb":"GET"}}"#));
    assert_eq!(got["data"]["Account"], account_id);

    // Delete, then the list is empty.
    let del = request(h, &format!(r#"{{"path":"Web3/Connection/{cnx_id}","verb":"DELETE"}}"#));
    assert_eq!(del["data"]["deleted"], true);
    let list2 = request(h, &format!(r#"{{"path":"Web3/Connection","verb":"GET","params":{{"Host":"{site}"}}}}"#));
    assert_eq!(list2["data"].as_array().unwrap().len(), 0);

    LibwalletDestroy(h);
}

#[test]
fn web3_request_rpc_passthrough() {
    let h = new_env();
    let site = "https://app.example.com";
    // eth_getBalance is not a wallet method → forwarded to the node (open relay).
    let node = mock_node(r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#);
    let resp = request(
        h,
        &format!(
            r#"{{"path":"Web3:request","params":{{"origin":"{site}","RPC":"{node}","query":{{"method":"eth_getBalance","params":["0x0000000000000000000000000000000000000001","latest"]}}}}}}"#
        ),
    );
    assert_eq!(resp["result"], "success", "{resp}");
    assert_eq!(resp["data"], "0xde0b6b3a7640000");

    // A wallet method is still handled locally (not forwarded).
    let chain = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"eth_chainId","params":[]}}}}}}"#));
    assert_eq!(chain["data"], "0x1");
    LibwalletDestroy(h);
}

#[test]
fn web3_mpurse_get_address_and_sign_message() {
    use base64::Engine;
    let h = new_env();
    let site = "https://mona.example.com";

    // secp256k1 wallet + bitcoin account; current network = bitcoin.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"BTC","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    request(h, r#"{"path":"Network:setCurrent","params":{"Id":"bitcoin.bitcoin"}}"#);
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"bitcoin","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    // Connect directly, then mpurse_getAddress returns it without prompting.
    request(h, &format!(r#"{{"path":"Web3/Connection","verb":"POST","params":{{"Host":"{site}","Account":"{account_id}"}}}}"#));
    let addr = request(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"mpurse_getAddress","params":[]}}}}}}"#));
    assert_eq!(addr["data"], address, "{addr}");

    // mpurse_signMessage → message_sign approval → 65-byte compact base64 sig.
    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let (srx, sud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"mpurse_signMessage","params":["hello monacoin"]}}}}}}"#));
    let mut sid = None;
    for _ in 0..50 {
        if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
            let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
            if j["event"] == "request" {
                sid = j["data"]["request_id"].as_str().map(str::to_owned);
                break;
            }
        }
    }
    let sid = sid.expect("message_sign request");
    request(
        h,
        &format!(
            r#"{{"path":"Request:approve","params":{{"Id":"{sid}","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    let sresp = srx.recv_timeout(Duration::from_secs(30)).expect("mpurse_signMessage resolved");
    let j: serde_json::Value = serde_json::from_str(&sresp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    let sig = base64::engine::general_purpose::STANDARD.decode(j["data"].as_str().unwrap()).unwrap();
    assert_eq!(sig.len(), 65, "compact signature is 65 bytes");
    // Header byte = 31 + recid for a compressed-address message signature.
    assert!((31..=34).contains(&sig[0]), "header byte {} out of range", sig[0]);

    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
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
fn lifecycle_update_echoes_status() {
    let h = new_env();
    let r = request(h, r#"{"path":"Lifecycle:update","params":{"Status":"background"}}"#);
    assert_eq!(r["result"], "success", "{r}");
    assert_eq!(r["data"]["status"], "background");
    // Empty/absent status is accepted (resume default).
    let r2 = request(h, r#"{"path":"Lifecycle:update","params":{}}"#);
    assert_eq!(r2["result"], "success");
    assert_eq!(r2["data"]["status"], "");
    LibwalletDestroy(h);
}

#[test]
fn spot_status_reports_client_state() {
    let h = new_env();
    // Spot:status starts the client lazily and reports its connection state.
    let s = request(h, r#"{"path":"Spot:status"}"#);
    assert_eq!(s["result"], "success", "{s}");
    // target_id is derived from the (ephemeral) identity key immediately.
    assert!(s["data"]["target_id"].as_str().unwrap().starts_with("k."), "{s}");
    // The connections object is present (online value depends on network reach,
    // so we only assert structure, not connectivity).
    assert!(s["data"]["connections"]["total"].is_number());
    assert!(s["data"]["connections"]["online"].is_number());
    assert!(s["data"]["online"].is_boolean());
    LibwalletDestroy(h);
}

#[test]
fn device_transfer_over_live_spot() {
    // Real device↔device wallet transfer over the live Spot relay. Gated behind
    // SPOT_LIVE=1 since it needs relay connectivity.
    if std::env::var("SPOT_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let ha = new_env(); // source device
    let hb = new_env(); // new device

    // Source: create a wallet to transfer.
    // ed25519 (FROST) shares are small (~KB); a secp256k1 DKLs23 wallet carries
    // ~120 KB of Paillier material per share and its ~365 KB sealed payload
    // exceeds the Spot relay's ~200 KB per-message cap (the Go design ships the
    // whole wallet in one Query round-trip too, so that limit applies equally).
    let w = request(
        ha,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"Move","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let pubkey = w["data"]["Pubkey"].as_str().unwrap().to_string();

    // Source: start the export → pairing code.
    let exp = request(ha, &format!(r#"{{"path":"Wallet:exportToDevice","params":{{"WalletId":"{wallet_id}"}}}}"#));
    assert_eq!(exp["result"], "success", "{exp}");
    let sid = exp["data"]["sid"].as_str().unwrap().to_string();
    let pairing = exp["data"]["pairingCode"].as_str().unwrap().to_string();

    // Source: confirm the transfer (buffered until the new device's query lands).
    let cf = request(ha, &format!(r#"{{"path":"Wallet:exportToDeviceConfirm","params":{{"Sid":"{sid}","DeviceShares":[]}}}}"#));
    assert_eq!(cf["result"], "success", "{cf}");

    // New device: import via the pairing code (queries the source over Spot).
    let (irx, iud) = request_async(hb, &format!(r#"{{"path":"Wallet:importFromDevice","params":{{"PairingCode":"{pairing}"}}}}"#));
    let resp = irx.recv_timeout(Duration::from_secs(90)).expect("import resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "import failed: {j}");
    let new_wallet = j["data"]["wallet_id"].as_str().unwrap().to_string();

    // The new device now holds the same wallet (identical group pubkey).
    let got = request(hb, &format!(r#"{{"path":"Wallet","verb":"GET","params":{{"Id":"{new_wallet}"}}}}"#));
    assert_eq!(got["data"]["Pubkey"], pubkey, "transferred wallet must match");

    drop(unsafe { Box::from_raw(iud as *mut Sender<String>) });
    LibwalletDestroy(ha);
    LibwalletDestroy(hb);
}

#[test]
fn clawd_build_new_agent_body_fills_spot_id() {
    // Purely local: echoes name/agent_spot_id/policy + this device's spot id.
    let h = new_env();
    let r = request(
        h,
        r#"{"path":"Wallet:buildNewAgentBody","params":{"name":"laptop","agent_spot_id":"k.agent123","policy":{"quorum":2}}}"#,
    );
    assert_eq!(r["result"], "success", "{r}");
    assert_eq!(r["data"]["name"], "laptop");
    assert_eq!(r["data"]["agent_spot_id"], "k.agent123");
    assert_eq!(r["data"]["policy"]["quorum"], 2);
    assert!(r["data"]["mobile_spot_id"].as_str().unwrap().starts_with("k."), "{r}");

    // Missing policy is rejected (server requires it; shape is opaque here).
    let bad = request(h, r#"{"path":"Wallet:buildNewAgentBody","params":{"name":"x","agent_spot_id":"k.a"}}"#);
    assert_eq!(bad["result"], "error");
    assert_eq!(bad["code"], 400);
    LibwalletDestroy(h);
}

#[test]
fn clawd_pair_over_live_spot() {
    // Real ClawdWallet:pair against a mock agent peer over the live Spot relay.
    // Gated behind SPOT_LIVE=1 since it needs relay connectivity.
    if std::env::var("SPOT_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    use std::time::Duration;
    // Mock agent: a spotlib client with a "pair" handler that validates the
    // token and returns the contract success body echoing its own spot id.
    let agent = std::sync::Arc::new(
        spotlib::Client::builder()
            .meta("project", "libwallet")
            .handler("pair", |m: &spotlib::Message| {
                let body: serde_json::Value = serde_json::from_slice(&m.body).map_err(|_| "bad_request".to_string())?;
                if body.get("token").and_then(|v| v.as_str()) != Some("good-token") {
                    return Ok(Some(br#"{"v":1,"error":"token_invalid"}"#.to_vec()));
                }
                Ok(None) // filled in below once we know the agent's own id
            })
            .build()
            .unwrap(),
    );
    agent.wait_online(Duration::from_secs(30)).expect("agent online");
    let agent_id = agent.target_id();
    // Reinstall the handler now that we know the agent's own id, so it can echo
    // it in the success body (the identity the pairing must match).
    let aid = agent_id.clone();
    agent.set_handler(
        "pair",
        Some(move |m: &spotlib::Message| {
            let body: serde_json::Value = serde_json::from_slice(&m.body).map_err(|_| "bad_request".to_string())?;
            if body.get("token").and_then(|v| v.as_str()) != Some("good-token") {
                return Ok(Some(br#"{"v":1,"error":"token_invalid"}"#.to_vec()));
            }
            let resp = serde_json::json!({
                "v": 1,
                "agent_spot_id": aid,
                "suggested_name": "clawd-agent",
                "capabilities": { "sign": true },
            });
            Ok(Some(serde_json::to_vec(&resp).unwrap()))
        }),
    );

    let h = new_env();
    // Start this device's spot client and wait for it to reach the relay.
    let st = request(h, r#"{"path":"Spot:status"}"#);
    assert_eq!(st["result"], "success", "{st}");

    let url = format!("tibane://pair?agent={agent_id}&token=good-token");
    let (rx, ud) = request_async(h, &format!(r#"{{"path":"ClawdWallet:pair","params":{{"url":"{url}"}}}}"#));
    let resp = rx.recv_timeout(Duration::from_secs(30)).expect("pair resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "pair failed: {j}");
    assert_eq!(j["data"]["agent_spot_id"], agent_id);
    assert_eq!(j["data"]["suggested_name"], "clawd-agent");
    assert_eq!(j["data"]["capabilities"]["sign"], true);

    // Wrong token → token_invalid wire code surfaced as an error.
    let bad_url = format!("tibane://pair?agent={agent_id}&token=nope");
    let (rx2, ud2) = request_async(h, &format!(r#"{{"path":"ClawdWallet:pair","params":{{"url":"{bad_url}"}}}}"#));
    let resp2 = rx2.recv_timeout(Duration::from_secs(30)).expect("pair2 resolved");
    let j2: serde_json::Value = serde_json::from_str(&resp2).unwrap();
    assert_eq!(j2["result"], "error");
    assert_eq!(j2["error"], "token_invalid", "{j2}");

    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(ud2 as *mut Sender<String>) });
    LibwalletDestroy(h);
    agent.close();
}

#[test]
fn remotekey_endpoints_post_to_walletsign_backend() {
    use std::io::{Read, Write};
    use std::sync::mpsc;

    // Capturing mock: records the raw HTTP request (so we can assert the
    // Sec-ClientId header + JSON body) and returns a canned KLB envelope.
    fn mock_capture(body: &'static str) -> (String, mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                // Accumulate until we've read the headers + the full body (a
                // single read() can catch only the first TCP segment under load).
                s.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut acc: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            acc.extend_from_slice(&chunk[..n]);
                            // Stop once headers are complete and the declared
                            // Content-Length body has fully arrived.
                            let text = String::from_utf8_lossy(&acc);
                            if let Some(hdr_end) = text.find("\r\n\r\n") {
                                let clen = text
                                    .lines()
                                    .find_map(|l| l.strip_prefix("Content-Length:").or_else(|| l.strip_prefix("content-length:")))
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                                    .unwrap_or(0);
                                if acc.len() >= hdr_end + 4 + clen {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&acc).into_owned());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        // No trailing slash — matches the real DEFAULT_HOST shape.
        (format!("http://{addr}"), rx)
    }

    let h = new_env();
    // Register the host wallet identity → Sec-ClientId on subsequent calls.
    let wi = request(h, r#"{"path":"Info:setWalletInfo","params":{"ClientId":"app-xyz","Name":"Test"}}"#);
    assert_eq!(wi["result"], "success", "{wi}");

    // RemoteKey:new → POST Crypto/WalletSign:new {number}, passthrough res.data.
    let (base, rx) = mock_capture(r#"{"result":"success","data":{"session":"sess-1","format":"all-digits","length":6}}"#);
    let r = request(h, &format!(r#"{{"path":"RemoteKey:new","params":{{"email":"a@b.co","Backend":"{base}"}}}}"#));
    assert_eq!(r["result"], "success", "{r}");
    assert_eq!(r["data"]["session"], "sess-1");
    assert_eq!(r["data"]["length"], 6);
    let req = rx.recv_timeout(Duration::from_secs(5)).expect("mock saw request");
    assert!(req.starts_with("POST /_special/rest/Crypto/WalletSign:new"), "{req}");
    assert!(req.contains("Sec-ClientId: app-xyz"), "missing client id header: {req}");
    assert!(req.contains(r#""number":"a@b.co""#), "body: {req}");

    // RemoteKey:reshare → fixed threshold/count, key passed through.
    let (base2, rx2) = mock_capture(r#"{"result":"success","data":{"session":"sess-2","format":"all-digits","length":6}}"#);
    let rr = request(h, &format!(r#"{{"path":"RemoteKey:reshare","params":{{"key":"crws-1:crwsv-2","Backend":"{base2}"}}}}"#));
    assert_eq!(rr["result"], "success", "{rr}");
    let req2 = rx2.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(req2.contains(r#""key":"crws-1:crwsv-2""#) && req2.contains(r#""threshold":1"#) && req2.contains(r#""count":3"#), "{req2}");

    // RemoteKey:validate → verify session+code, returns {RemoteKey}.
    let (base3, _rx3) = mock_capture(r#"{"result":"success","data":{"RemoteKey":"crws-9:crwsv-9"}}"#);
    let rv = request(h, &format!(r#"{{"path":"RemoteKey:validate","params":{{"session":"s","code":"123456","Backend":"{base3}"}}}}"#));
    assert_eq!(rv["result"], "success", "{rv}");
    assert_eq!(rv["data"]["RemoteKey"], "crws-9:crwsv-9");

    // Missing required params are rejected before any network call.
    let bad = request(h, r#"{"path":"RemoteKey:new","params":{}}"#);
    assert_eq!(bad["result"], "error");
    assert_eq!(bad["code"], 400);
    LibwalletDestroy(h);
}

#[test]
fn remotekey_wallet_create_over_live_backend() {
    // Real end-to-end against the live WalletSign backend + wdrone fleet, using
    // the documented test account (+14045551234 / code 000000, ClientId
    // com.ellipx.walletapp — see wltwallet/testmain_test.go). Creates an
    // ed25519 FROST wallet whose third share is a RemoteKey: the share is
    // sealed to the fleet's decrypt keys and uploaded via
    // Crypto/WalletSign:setGeneratedKey. Gated behind SPOT_LIVE=1.
    if std::env::var("SPOT_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let h = new_env();
    let wi = request(h, r#"{"path":"Info:setWalletInfo","params":{"ClientId":"com.ellipx.walletapp","Name":"libwallet-tests"}}"#);
    assert_eq!(wi["result"], "success", "{wi}");

    let n = request(h, r#"{"path":"RemoteKey:new","params":{"number":"+14045551234"}}"#);
    assert_eq!(n["result"], "success", "RemoteKey:new failed: {n}");
    let session = n["data"]["session"].as_str().expect("session").to_string();

    let v = request(h, &format!(r#"{{"path":"RemoteKey:validate","params":{{"session":"{session}","code":"000000"}}}}"#));
    assert_eq!(v["result"], "success", "RemoteKey:validate failed: {v}");
    let rk = v["data"]["RemoteKey"].as_str().expect("RemoteKey").to_string();
    assert!(rk.contains(':'), "RemoteKey should be crws:crwsv, got {rk}");

    // Create an ed25519 wallet: 2 local Plain shares + 1 RemoteKey (uploaded).
    let body = format!(
        r#"{{"path":"Wallet","verb":"POST","params":{{"Name":"Remote","Curve":"ed25519","Keys":[{{"Type":"Plain"}},{{"Type":"Plain"}},{{"Type":"RemoteKey","Key":"{rk}"}}]}}}}"#
    );
    let w = request(h, &body);
    assert_eq!(w["result"], "success", "RemoteKey wallet create failed: {w}");
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    assert_eq!(w["data"]["Curve"], "ed25519");
    assert!(w["data"]["Pubkey"].as_str().unwrap().len() > 10, "{w}");

    // The wallet persists with a RemoteKey-typed share carrying the session.
    let got = request(h, &format!(r#"{{"path":"Wallet","verb":"GET","params":{{"Id":"{wallet_id}"}}}}"#));
    let keys = got["data"]["Keys"].as_array().unwrap();
    assert!(keys.iter().any(|k| k["Type"] == "RemoteKey"), "wallet should carry a RemoteKey share: {got}");

    // The wallet is usable: sign with the two local Plain shares (2-of-3,
    // threshold 1) — the wdrone-held RemoteKey share is a backup, not needed at
    // sign time. This is the tested Go behavior (subSign opens local shares;
    // the opener has no RemoteKey arm).
    let plain_ids: Vec<String> = keys
        .iter()
        .filter(|k| k["Type"] == "Plain")
        .map(|k| k["Id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(plain_ids.len(), 2, "expected 2 Plain shares: {got}");

    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let (p0, p1) = (&plain_ids[0], &plain_ids[1]);
    let signed = request(
        h,
        &format!(
            r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[
                {{"Type":"Plain","Id":"{p0}","Key":""}},
                {{"Type":"Plain","Id":"{p1}","Key":""}}]}}}}"#
        ),
    );
    assert_eq!(signed["result"], "success", "Plain-share signMessage failed: {signed}");
    assert!(signed["data"]["signature"].as_str().unwrap().len() > 80, "{signed}");
    LibwalletDestroy(h);
}

#[test]
fn remotekey_reshare_over_live_wdrone() {
    // Full interactive wdrone ceremony against the live WalletSign fleet, mirroring
    // Go TestRemoteWallet: create an ed25519 wallet with a RemoteKey share, then
    // reshare a committee that includes the RemoteKey so the wdrone co-participates
    // over the walletsign Spot transport. Gated behind SPOT_LIVE=1.
    if std::env::var("SPOT_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let h = new_env();
    let wi = request(h, r#"{"path":"Info:setWalletInfo","params":{"ClientId":"com.ellipx.walletapp","Name":"libwallet-tests"}}"#);
    assert_eq!(wi["result"], "success", "{wi}");

    // 2FA → first RemoteKey.
    let n = request(h, r#"{"path":"RemoteKey:new","params":{"number":"+14045551234"}}"#);
    let session = n["data"]["session"].as_str().expect("session").to_string();
    let v = request(h, &format!(r#"{{"path":"RemoteKey:validate","params":{{"session":"{session}","code":"000000"}}}}"#));
    let rk1 = v["data"]["RemoteKey"].as_str().expect("RemoteKey").to_string();

    // Create the ed25519 [Plain,Plain,RemoteKey] wallet.
    let body = format!(
        r#"{{"path":"Wallet","verb":"POST","params":{{"Name":"Reshare","Curve":"ed25519","Keys":[{{"Type":"Plain"}},{{"Type":"Plain"}},{{"Type":"RemoteKey","Key":"{rk1}"}}]}}}}"#
    );
    let w = request(h, &body);
    assert_eq!(w["result"], "success", "create failed: {w}");
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let orig_pubkey = w["data"]["Pubkey"].as_str().unwrap().to_string();
    let keys = w["data"]["Keys"].as_array().unwrap();
    let plain0 = keys.iter().find(|k| k["Type"] == "Plain").unwrap()["Id"].as_str().unwrap().to_string();
    let rk_wk = keys.iter().find(|k| k["Type"] == "RemoteKey").unwrap()["Id"].as_str().unwrap().to_string();

    // Reshare the session (fresh 2FA) → rk2, used for both old + new RemoteKey.
    let rn = request(h, &format!(r#"{{"path":"RemoteKey:reshare","params":{{"key":"{rk1}"}}}}"#));
    assert_eq!(rn["result"], "success", "RemoteKey:reshare failed: {rn}");
    let session2 = rn["data"]["session"].as_str().expect("session2").to_string();
    let v2 = request(h, &format!(r#"{{"path":"RemoteKey:validate","params":{{"session":"{session2}","code":"000000"}}}}"#));
    let rk2 = v2["data"]["RemoteKey"].as_str().expect("rk2").to_string();

    // Reshare: old committee = 1 Plain + the RemoteKey (T+1=2, forces the wdrone);
    // new committee = 2 Plain + 1 RemoteKey. Long timeout — spot init + TSS rounds.
    let reshare_body = format!(
        r#"{{"path":"Wallet/{wallet_id}:reshare","params":{{"Old":[{{"Id":"{plain0}"}},{{"Type":"RemoteKey","Id":"{rk_wk}","Key":"{rk2}"}}],"New":[{{"Type":"Plain"}},{{"Type":"Plain"}},{{"Type":"RemoteKey","Key":"{rk2}"}}]}}}}"#
    );
    let (rx, ud) = request_async(h, &reshare_body);
    let resp = rx.recv_timeout(Duration::from_secs(180)).expect("reshare resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "reshare failed: {j}");

    // The reshare preserves the group pubkey and rebuilds the committee.
    assert_eq!(j["data"]["Pubkey"], orig_pubkey, "reshare must preserve the group pubkey");
    let new_keys = j["data"]["Keys"].as_array().unwrap();
    assert_eq!(new_keys.len(), 3, "{j}");
    assert!(new_keys.iter().any(|k| k["Type"] == "RemoteKey"), "{j}");

    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn remotekey_reshare_dkls_over_live_wdrone() {
    // Same interactive wdrone ceremony as the FROST test, but for a secp256k1
    // DKLs23 wallet (Go Wallet.ReshareDkls). Gated behind SPOT_LIVE=1.
    if std::env::var("SPOT_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let h = new_env();
    let wi = request(h, r#"{"path":"Info:setWalletInfo","params":{"ClientId":"com.ellipx.walletapp","Name":"libwallet-tests"}}"#);
    assert_eq!(wi["result"], "success", "{wi}");

    let n = request(h, r#"{"path":"RemoteKey:new","params":{"number":"+14045551234"}}"#);
    let session = n["data"]["session"].as_str().expect("session").to_string();
    let v = request(h, &format!(r#"{{"path":"RemoteKey:validate","params":{{"session":"{session}","code":"000000"}}}}"#));
    let rk1 = v["data"]["RemoteKey"].as_str().expect("RemoteKey").to_string();

    // secp256k1 [Plain,Plain,RemoteKey] wallet (uploads the DKLs share).
    let body = format!(
        r#"{{"path":"Wallet","verb":"POST","params":{{"Name":"ReshareDkls","Curve":"secp256k1","Keys":[{{"Type":"Plain"}},{{"Type":"Plain"}},{{"Type":"RemoteKey","Key":"{rk1}"}}]}}}}"#
    );
    let w = request(h, &body);
    assert_eq!(w["result"], "success", "dkls create failed: {w}");
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let orig_pubkey = w["data"]["Pubkey"].as_str().unwrap().to_string();
    let keys = w["data"]["Keys"].as_array().unwrap();
    let plain0 = keys.iter().find(|k| k["Type"] == "Plain").unwrap()["Id"].as_str().unwrap().to_string();
    let rk_wk = keys.iter().find(|k| k["Type"] == "RemoteKey").unwrap()["Id"].as_str().unwrap().to_string();

    let rn = request(h, &format!(r#"{{"path":"RemoteKey:reshare","params":{{"key":"{rk1}"}}}}"#));
    assert_eq!(rn["result"], "success", "RemoteKey:reshare failed: {rn}");
    let session2 = rn["data"]["session"].as_str().expect("session2").to_string();
    let v2 = request(h, &format!(r#"{{"path":"RemoteKey:validate","params":{{"session":"{session2}","code":"000000"}}}}"#));
    let rk2 = v2["data"]["RemoteKey"].as_str().expect("rk2").to_string();

    // DKLs requires exactly T+1=2 old signers: 1 Plain + the RemoteKey.
    let reshare_body = format!(
        r#"{{"path":"Wallet/{wallet_id}:reshare","params":{{"Old":[{{"Id":"{plain0}"}},{{"Type":"RemoteKey","Id":"{rk_wk}","Key":"{rk2}"}}],"New":[{{"Type":"Plain"}},{{"Type":"Plain"}},{{"Type":"RemoteKey","Key":"{rk2}"}}]}}}}"#
    );
    let (rx, ud) = request_async(h, &reshare_body);
    let resp = rx.recv_timeout(Duration::from_secs(180)).expect("reshare resolved");
    let j: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(j["result"], "success", "dkls reshare failed: {j}");
    assert_eq!(j["data"]["Pubkey"], orig_pubkey, "reshare must preserve the group pubkey");
    assert_eq!(j["data"]["Keys"].as_array().unwrap().len(), 3, "{j}");

    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn promote_imported_wallet_to_mpc_in_place() {
    // Wallet:promote — convert a 1-of-1 mnemonic-keep wallet into an in-place
    // N-of-T DKLs committee, preserving the master pubkey. Fully local (Password
    // shares), so no backend needed.
    let h = new_env();
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let src = request(
        h,
        &format!(r#"{{"path":"Wallet:importMnemonic","params":{{"Name":"Seed","Curve":"secp256k1","Mnemonic":"{m}","Keys":[{{"Type":"Password","Key":"password1"}}]}}}}"#),
    );
    assert_eq!(src["result"], "success", "{src}");
    let src_id = src["data"]["Id"].as_str().unwrap().to_string();
    let src_wk = src["data"]["Keys"][0]["Id"].as_str().unwrap().to_string();
    let master_pubkey = src["data"]["Pubkey"].as_str().unwrap().to_string();

    // Promote in place → 2-of-3 (threshold 1). Master pubkey must be preserved.
    let promoted = request(
        h,
        &format!(
            r#"{{"path":"Wallet/{src_id}:promote","verb":"POST","params":{{
                "Old":[{{"Type":"Password","Id":"{src_wk}","Key":"password1"}}],
                "New":[{{"Type":"Password","Key":"passworda"}},{{"Type":"Password","Key":"passwordb"}},{{"Type":"Password","Key":"passwordc"}}],
                "Threshold":1}}}}"#
        ),
    );
    assert_eq!(promoted["result"], "success", "promote failed: {promoted}");
    assert_eq!(promoted["data"]["Id"], src_id, "promote is in place (same wallet id)");
    assert_eq!(promoted["data"]["Protocol"], "dkls23");
    assert_eq!(promoted["data"]["Threshold"], 1);
    assert_eq!(promoted["data"]["Pubkey"], master_pubkey, "promote must preserve the master pubkey");
    let nwk: Vec<String> = (0..3).map(|i| promoted["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();

    // The promoted wallet is a real 2-of-3 DKLs wallet: sign a message with all
    // three shares and check the signature comes back.
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{src_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let signed = request(
        h,
        &format!(
            r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passworda"}},
                {{"Type":"Password","Id":"{}","Key":"passwordb"}},
                {{"Type":"Password","Id":"{}","Key":"passwordc"}}]}}}}"#,
            nwk[0], nwk[1], nwk[2]
        ),
    );
    assert_eq!(signed["result"], "success", "post-promote sign failed: {signed}");
    LibwalletDestroy(h);
}

#[test]
fn clawd_keygen_and_sign_endpoints_are_wired() {
    // The ClawdWallet Stage-1 multi-device endpoints exist and validate input
    // (the full ceremony needs a live agent + phplatform session). They must
    // reject bad input with 400, not 404.
    let h = new_env();
    let ik = request(h, r#"{"path":"Wallet:initiateKeygen","params":{"remote_key":"crws-a:crwsv-b"}}"#);
    assert_eq!(ik["result"], "error");
    assert_eq!(ik["code"], 400, "initiateKeygen should validate (not 404): {ik}");

    let js = request(h, r#"{"path":"Wallet:joinSign","params":{"peers":[{"id":"k.a","moniker":"m","key":"AAA"}]}}"#);
    assert_eq!(js["result"], "error");
    assert_eq!(js["code"], 400, "joinSign should validate (not 404): {js}");
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
fn balance_without_rpc_or_network_errors_cleanly() {
    // With no RPC param and no current network selected, balance resolution
    // fails with a clear 400 rather than panicking.
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
    // No current network is set, and evm-auto isn't locally resolvable.
    let bal = request(
        h,
        &format!(r#"{{"path":"Account:balance","params":{{"Id":"{account_id}"}}}}"#),
    );
    // evm-auto isn't locally resolvable -> a clean error (not a panic/crash).
    assert_eq!(bal["result"], "error", "{bal}");
    assert!(bal["error"].as_str().unwrap().to_lowercase().contains("rpc"), "{bal}");
    LibwalletDestroy(h);
}

#[test]
fn onboarding_view_account_and_wc_sessions_alias_via_ffi() {
    let h = new_env();
    // Fresh env: no wallet, no account.
    let ob0 = request(h, r#"{"path":"Info:onboarding"}"#);
    assert_eq!(ob0["data"]["has_wallet"], false);
    assert_eq!(ob0["data"]["has_account"], false);

    // A view-only account needs no wallet.
    let v = request(
        h,
        r#"{"path":"Account:createView","params":{"Type":"ethereum","Address":"0x000000000000000000000000000000000000dEaD","Name":"Watch"}}"#,
    );
    assert_eq!(v["result"], "success", "{v}");
    assert_eq!(v["data"]["Type"], "ethereum");
    assert_eq!(v["data"]["Address"], "0x000000000000000000000000000000000000dEaD");
    assert_eq!(v["data"]["Wallet"], ""); // view-only
    assert_eq!(v["data"]["Curve"], "secp256k1");

    // Now onboarding reports an account.
    let ob1 = request(h, r#"{"path":"Info:onboarding"}"#);
    assert_eq!(ob1["data"]["has_account"], true);

    // WalletConnect:sessions is the Go name for the active-session list.
    let s = request(h, r#"{"path":"WalletConnect:sessions"}"#);
    assert_eq!(s["result"], "success", "{s}");
    assert_eq!(s["data"].as_array().unwrap().len(), 0);
    LibwalletDestroy(h);
}

#[test]
fn transaction_validate_via_ffi() {
    let h = new_env();
    // A well-formed transfer validates.
    let ok = request(
        h,
        r#"{"path":"Transaction:validate","params":{"type":"transfer","amount":{"v":"100","e":0},"asset":"evm.1.NATIVE"}}"#,
    );
    assert_eq!(ok["result"], "success", "{ok}");
    assert_eq!(ok["data"]["valid"], true);

    // Missing asset / zero amount / bad type are rejected.
    assert_eq!(request(h, r#"{"path":"Transaction:validate","params":{"type":"transfer","amount":{"v":"100","e":0}}}"#)["code"], 400);
    assert_eq!(request(h, r#"{"path":"Transaction:validate","params":{"type":"transfer","amount":{"v":"0","e":0},"asset":"x"}}"#)["code"], 400);
    assert_eq!(request(h, r#"{"path":"Transaction:validate","params":{"type":"bogus"}}"#)["code"], 400);
    // erc20_transfer requires asset + to.
    assert_eq!(request(h, r#"{"path":"Transaction:validate","params":{"type":"erc20_transfer","amount":{"v":"1","e":0},"asset":"x"}}"#)["code"], 400);
    let erc20 = request(h, r#"{"path":"Transaction:validate","params":{"type":"erc20_transfer","amount":{"v":"1","e":0},"asset":"x","to":"0xabc"}}"#);
    assert_eq!(erc20["data"]["valid"], true);
    // raw evm needs no fields.
    assert_eq!(request(h, r#"{"path":"Transaction:validate","params":{"type":"evm"}}"#)["data"]["valid"], true);
    LibwalletDestroy(h);
}

#[test]
fn wallet_multi_create_via_ffi() {
    let h = new_env();
    let r = request(
        h,
        r#"{"path":"Wallet:multiCreate","params":{"Name":"Multi","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    assert_eq!(r["result"], "success", "{r}");
    // Both curves created with the same key set.
    assert_eq!(r["data"]["secp256k1"]["Protocol"], "dkls23");
    assert_eq!(r["data"]["ed25519"]["Protocol"], "frost");
    assert_eq!(r["data"]["secp256k1"]["Pubkey"].as_str().unwrap().len(), 44);
    assert_eq!(r["data"]["ed25519"]["Pubkey"].as_str().unwrap().len(), 43);
    // Both are persisted.
    let listed = request(h, r#"{"path":"Wallet","verb":"GET"}"#);
    assert_eq!(listed["data"].as_array().unwrap().len(), 2);
    LibwalletDestroy(h);
}

#[test]
fn wallet_backup_restore_roundtrip_via_ffi() {
    let src = new_env();
    // Create a wallet + capture its pubkey and key ids.
    let w = request(
        src,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"Backup","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let pubkey = w["data"]["Pubkey"].as_str().unwrap().to_string();

    // Back it up — the entry carries the encrypted shares (Data).
    let backup = request(src, &format!(r#"{{"path":"Wallet:backup","params":{{"Id":"{wallet_id}"}}}}"#));
    assert_eq!(backup["result"], "success", "{backup}");
    let entry = &backup["data"][0];
    assert!(entry["Filename"].as_str().unwrap().starts_with("wallet_"));
    let data = entry["Data"].as_str().unwrap().to_string();
    LibwalletDestroy(src);

    // Restore into a FRESH environment.
    let dst = new_env();
    let restored = request(
        dst,
        &format!(r#"{{"path":"Wallet:restore","params":{{"Files":[{{"Data":"{data}"}}]}}}}"#),
    );
    assert_eq!(restored["result"], "success", "{restored}");
    assert_eq!(restored["data"]["restored"][0], wallet_id);

    // The restored wallet has the same pubkey...
    let got = request(dst, &format!(r#"{{"path":"Wallet","verb":"GET","params":{{"Id":"{wallet_id}"}}}}"#));
    assert_eq!(got["data"]["Pubkey"], pubkey);

    // ...and still signs — proving the encrypted shares survived the roundtrip.
    let a = request(
        dst,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#),
    );
    let acct = a["data"]["Id"].as_str().unwrap().to_string();
    let wk0 = got["data"]["Keys"][0]["Id"].as_str().unwrap().to_string();
    let wk1 = got["data"]["Keys"][1]["Id"].as_str().unwrap().to_string();
    let sig = request(
        dst,
        &format!(r#"{{"path":"Account:signMessage","params":{{"Id":"{acct}","Message":"aGk=","Keys":[{{"Type":"Password","Id":"{wk0}","Key":"passwordone"}},{{"Type":"Password","Id":"{wk1}","Key":"passwordtwo"}}]}}}}"#),
    );
    assert_eq!(sig["result"], "success", "restored wallet must sign: {sig}");
    LibwalletDestroy(dst);
}

#[test]
fn wallet_import_mnemonic_via_ffi() {
    let h = new_env();
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let body = format!(
        r#"{{"path":"Wallet:importMnemonic","params":{{"Name":"M","Curve":"secp256k1","Mnemonic":"{m}","Keys":[{{"Type":"Password","Key":"password1"}}]}}}}"#
    );
    let w = request(h, &body);
    assert_eq!(w["result"], "success", "{w}");
    // Mnemonic-keep wallet (byte-compatible with Go): stores the MnemonicKeyShare.
    assert_eq!(w["data"]["Protocol"], "mnemonic");
    assert_eq!(w["data"]["Threshold"], 0);
    assert_eq!(w["data"]["Keys"][0]["Schema"], "mnemonic");
    let pubkey = w["data"]["Pubkey"].as_str().unwrap().to_string();
    // The wallet chaincode is the derived BIP-32 master chain code.
    let cc = w["data"]["Chaincode"].as_str().unwrap();
    assert!(!cc.is_empty());

    // Deterministic: the same mnemonic yields the same wallet key.
    assert_eq!(request(h, &body)["data"]["Pubkey"], pubkey);

    // A passphrase changes the derived key.
    let with_pass = format!(
        r#"{{"path":"Wallet:importMnemonic","params":{{"Curve":"secp256k1","Mnemonic":"{m}","Passphrase":"TREZOR","Keys":[{{"Type":"Password","Key":"password1"}}]}}}}"#
    );
    assert_ne!(request(h, &with_pass)["data"]["Pubkey"], pubkey);

    // A bad-checksum mnemonic errors.
    let bad = r#"{"path":"Wallet:importMnemonic","params":{"Curve":"secp256k1","Mnemonic":"abandon abandon abandon","Keys":[{"Type":"Password","Key":"password1"}]}}"#;
    assert_eq!(request(h, bad)["result"], "error");
    LibwalletDestroy(h);
}

#[test]
fn mnemonic_import_account_sign_ecrecover_roundtrip() {
    let h = new_env();
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    // Import as a mnemonic-keep wallet.
    let w = request(
        h,
        &format!(r#"{{"path":"Wallet:importMnemonic","params":{{"Name":"M","Curve":"secp256k1","Mnemonic":"{m}","Keys":[{{"Type":"Password","Key":"password1"}}]}}}}"#),
    );
    assert_eq!(w["data"]["Protocol"], "mnemonic", "{w}");
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk = w["data"]["Keys"][0]["Id"].as_str().unwrap().to_string();

    // Derive an ethereum account and sign a message with the mnemonic key.
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();

    let signed = request(
        h,
        &format!(r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[{{"Type":"Password","Id":"{wk}","Key":"password1"}}]}}}}"#),
    );
    assert_eq!(signed["result"], "success", "sign failed: {signed}");
    let sig = signed["data"]["signature"].as_str().unwrap().to_string();

    // personal_ecRecover of the signature returns exactly the account address —
    // proving import(mnemonic) → account → sign works end to end.
    let rec = request(
        h,
        &format!(r#"{{"path":"Web3:request","params":{{"origin":"https://x.example.com","query":{{"method":"personal_ecRecover","params":["0x68656c6c6f","{sig}"]}}}}}}"#),
    );
    assert_eq!(rec["data"].as_str().unwrap().to_lowercase(), address.to_lowercase(), "{rec}");
    LibwalletDestroy(h);
}

#[test]
fn promote_mnemonic_to_mpc_wallet_and_sign() {
    let h = new_env();
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    // Source mnemonic-keep wallet.
    let src = request(
        h,
        &format!(r#"{{"path":"Wallet:importMnemonic","params":{{"Name":"Seed","Curve":"secp256k1","Mnemonic":"{m}","Keys":[{{"Type":"Password","Key":"password1"}}]}}}}"#),
    );
    let src_id = src["data"]["Id"].as_str().unwrap().to_string();
    let src_wk = src["data"]["Keys"][0]["Id"].as_str().unwrap().to_string();

    // Promote the ethereum chain into a fresh 2-of-3 (threshold 1) MPC wallet.
    let promoted = request(
        h,
        &format!(
            r#"{{"path":"Wallet/{src_id}:promoteMnemonic","verb":"POST","params":{{
                "Old":[{{"Type":"Password","Id":"{src_wk}","Key":"password1"}}],
                "Chains":[{{"network":"ethereum","derivationPath":"m/44'/60'/0'/0/0","curve":"secp256k1"}}],
                "New":[{{"Type":"Password","Key":"passworda"}},{{"Type":"Password","Key":"passwordb"}},{{"Type":"Password","Key":"passwordc"}}],
                "Threshold":1}}}}"#
        ),
    );
    assert_eq!(promoted["result"], "success", "promote failed: {promoted}");
    let nw = &promoted["data"][0];
    assert_eq!(nw["Protocol"], "dkls23");
    assert_eq!(nw["Threshold"], 1);
    let new_wallet = nw["Id"].as_str().unwrap().to_string();
    let nwk: Vec<String> = (0..3).map(|i| nw["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();

    // The promoted MPC wallet is a real 2-of-3 DKLs wallet: derive an account
    // and sign a tx that ecrecovers to it (needs all shares for DKLs sign).
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{new_wallet}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let signed = request(
        h,
        &format!(
            r#"{{"path":"Account:signMessage","params":{{"Id":"{account_id}","Message":"aGVsbG8=","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passworda"}},
                {{"Type":"Password","Id":"{}","Key":"passwordb"}},
                {{"Type":"Password","Id":"{}","Key":"passwordc"}}]}}}}"#,
            nwk[0], nwk[1], nwk[2]
        ),
    );
    assert_eq!(signed["result"], "success", "sign failed: {signed}");
    let sig = signed["data"]["signature"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();
    let rec = request(
        h,
        &format!(r#"{{"path":"Web3:request","params":{{"origin":"https://x.example.com","query":{{"method":"personal_ecRecover","params":["0x68656c6c6f","{sig}"]}}}}}}"#),
    );
    assert_eq!(rec["data"].as_str().unwrap().to_lowercase(), address.to_lowercase(), "{rec}");
    LibwalletDestroy(h);
}

#[test]
fn web3_mpurse_sign_raw_transaction() {
    let h = new_env();
    let site = "https://mona.example.com";

    // secp256k1 wallet + bitcoin account; current network = bitcoin.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"BTC","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let wk: Vec<String> = (0..3).map(|i| w["data"]["Keys"][i]["Id"].as_str().unwrap().to_string()).collect();
    request(h, r#"{"path":"Network:setCurrent","params":{"Id":"bitcoin.bitcoin"}}"#);
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"bitcoin","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    request(h, &format!(r#"{{"path":"Web3/Connection","verb":"POST","params":{{"Host":"{site}","Account":"{account_id}"}}}}"#));

    // A raw tx spending one P2WPKH input (txid 32×0x11, vout 0) owned by the
    // account at m/0/0; the modchain mock supplies that UTXO.
    let raw = "0200000001\
        1111111111111111111111111111111111111111111111111111111111111111\
        0000000000fdffffff\
        0180f0fa020000000000\
        00000000";
    let node = mock_node(
        r#"{"jsonrpc":"2.0","id":1,"result":{"assets":[{"asset":"NATIVE","txo":[{"txo":"1111111111111111111111111111111111111111111111111111111111111111:0","amt":"1.0","path":"m/0/0","script":"p2wpkh","spent":null}]}]}}"#,
    );

    // mpurse_signRawTransaction → transaction_sign approval → signed hex.
    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let (srx, sud) = request_async(h, &format!(r#"{{"path":"Web3:request","params":{{"origin":"{site}","query":{{"method":"mpurse_signRawTransaction","params":["{raw}"]}}}}}}"#));
    let mut sid = None;
    for _ in 0..50 {
        if let Ok(ev) = erx.recv_timeout(Duration::from_millis(200)) {
            let j: serde_json::Value = serde_json::from_str(&ev).unwrap();
            if j["event"] == "request" {
                sid = j["data"]["request_id"].as_str().map(str::to_owned);
                break;
            }
        }
    }
    let sid = sid.expect("transaction_sign request");
    request(
        h,
        &format!(
            r#"{{"path":"Request:approve","params":{{"Id":"{sid}","RPC":"{node}","Keys":[
                {{"Type":"Password","Id":"{}","Key":"passwordone"}},
                {{"Type":"Password","Id":"{}","Key":"passwordtwo"}},
                {{"Type":"Password","Id":"{}","Key":"passwordthree"}}]}}}}"#,
            wk[0], wk[1], wk[2]
        ),
    );
    let sresp = srx.recv_timeout(Duration::from_secs(60)).expect("mpurse_signRawTransaction resolved");
    let j: serde_json::Value = serde_json::from_str(&sresp).unwrap();
    assert_eq!(j["result"], "success", "{j}");
    let signed = j["data"].as_str().unwrap();
    // A signed P2WPKH tx carries a witness, so it's longer than the raw tx and
    // uses the segwit marker/flag (0001 after the 4-byte version).
    assert!(signed.len() > raw.replace(['\n', ' '], "").len(), "witness must be added");
    assert!(signed.starts_with("020000000001"), "segwit marker/flag: {signed}");

    drop(unsafe { Box::from_raw(sud as *mut Sender<String>) });
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
    LibwalletDestroy(h);
}

#[test]
fn transaction_backfill_solana_signatures() {
    let h = new_env();
    // ed25519 wallet + solana account, set as current; current network = solana.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"SOL","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"solana","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    let address = a["data"]["Address"].as_str().unwrap().to_string();
    request(h, &format!(r#"{{"path":"Account:setCurrent","params":{{"Id":"{account_id}"}}}}"#));
    request(h, r#"{"path":"Network:setCurrent","params":{"Id":"solana.mainnet"}}"#);

    // Sequence: getSignaturesForAddress → getTransaction(sig) → empty page.
    let sigs = r#"{"jsonrpc":"2.0","id":1,"result":[{"signature":"sigAAA","blockTime":1610612736}]}"#.to_string();
    let get_tx = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"transaction":{{"message":{{"instructions":[{{"program":"system","parsed":{{"type":"transfer","info":{{"source":"{address}","destination":"DestSol1111111111111111111111111111111111","lamports":1000000000}}}}}}],"accountKeys":["{address}"]}}}},"meta":{{"preBalances":[2000000000],"postBalances":[1000000000]}},"blockTime":1610612736}}}}"#
    );
    let empty = r#"{"jsonrpc":"2.0","id":1,"result":[]}"#.to_string();
    let node = mock_multi(vec![sigs, get_tx, empty]);

    let bf = request(h, &format!(r#"{{"path":"Transaction:backfill","params":{{"RPC":"{node}"}}}}"#));
    assert_eq!(bf["result"], "success", "{bf}");
    assert_eq!(bf["data"]["provider"], "signatures");
    assert_eq!(bf["data"]["count"], 1);

    let list = request(h, r#"{"path":"Transaction","verb":"GET"}"#);
    let txs = list["data"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0]["hash"], "sigAAA");
    assert_eq!(txs[0]["type"], "transfer");
    assert_eq!(txs[0]["from"], address);
    LibwalletDestroy(h);
}

#[test]
fn transaction_backfill_evm_modchain() {
    let h = new_env();
    // Wallet + ethereum account, set as current.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let a = request(h, &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#));
    let account_id = a["data"]["Id"].as_str().unwrap().to_string();
    request(h, &format!(r#"{{"path":"Account:setCurrent","params":{{"Id":"{account_id}"}}}}"#));

    // Mock modchain_historyByAddress: one page, one tx, no continuation.
    let node = mock_node(
        r#"{"jsonrpc":"2.0","id":1,"result":{"results":[{"blk":100,"tx":"0xABC123","data":{"from":"0xFrom0000000000000000000000000000000000aa","to":"0xTo00000000000000000000000000000000000bb","value":"0xde0b6b3a7640000","gas":"0x5208","gasPrice":"0x4a817c800","timestamp":"0x60000000"}}],"continueKey":""}}"#,
    );
    let bf = request(h, &format!(r#"{{"path":"Transaction:backfill","params":{{"RPC":"{node}"}}}}"#));
    assert_eq!(bf["result"], "success", "{bf}");
    assert_eq!(bf["data"]["provider"], "modchain");
    assert_eq!(bf["data"]["count"], 1);

    // The swept tx is persisted and fetchable.
    let list = request(h, r#"{"path":"Transaction","verb":"GET"}"#);
    let txs = list["data"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0]["hash"], "0xabc123");
    assert_eq!(txs[0]["from"], "0xfrom0000000000000000000000000000000000aa");
    assert_eq!(txs[0]["type"], "transfer");
    LibwalletDestroy(h);
}

#[test]
fn wallet_import_private_key_via_ffi() {
    let h = new_env();
    // Import a raw 32-byte secp256k1 key as a 1-of-1 wallet.
    let priv_hex = "0a11111111111111111111111111111111111111111111111111111111111111";
    let body = format!(
        r#"{{"path":"Wallet:importPrivateKey","params":{{"Name":"Imported","Curve":"secp256k1","PrivateKey":"{priv_hex}","Keys":[{{"Type":"Password","Key":"mypassword"}}]}}}}"#
    );
    let w = request(h, &body);
    assert_eq!(w["result"], "success", "{w}");
    assert_eq!(w["data"]["Protocol"], "dkls23");
    assert_eq!(w["data"]["Curve"], "secp256k1");
    assert_eq!(w["data"]["Threshold"], 0);
    assert_eq!(w["data"]["Keys"].as_array().unwrap().len(), 1);
    // 33-byte compressed secp pubkey -> 44 base64url chars.
    let pubkey = w["data"]["Pubkey"].as_str().unwrap().to_string();
    assert_eq!(pubkey.len(), 44);
    // The encrypted share is stored but never serialized.
    assert!(w["data"]["Keys"][0].get("Data").is_none());

    // Import is deterministic: the same key yields the same group pubkey.
    let w2 = request(h, &body);
    assert_eq!(w2["data"]["Pubkey"], pubkey);

    // A different key -> a different pubkey.
    let other = format!(
        r#"{{"path":"Wallet:importPrivateKey","params":{{"Curve":"secp256k1","PrivateKey":"0b22222222222222222222222222222222222222222222222222222222222222","Keys":[{{"Type":"Password","Key":"password1"}}]}}}}"#
    );
    assert_ne!(request(h, &other)["data"]["Pubkey"], pubkey);

    // Bad length is rejected.
    let bad = request(h, r#"{"path":"Wallet:importPrivateKey","params":{"Curve":"secp256k1","PrivateKey":"0x1234","Keys":[{"Type":"Password","Key":"password1"}]}}"#);
    assert_eq!(bad["result"], "error");
    LibwalletDestroy(h);
}

#[test]
fn storekey_create_and_unlock_via_ffi() {
    let h = new_env();
    // Generate a device store key + its derived public key.
    let sk = request(h, r#"{"path":"StoreKey:create"}"#);
    assert_eq!(sk["result"], "success", "{sk}");
    let private = sk["data"]["private"].as_str().unwrap().to_string();
    let public = sk["data"]["public"].as_str().unwrap().to_string();
    assert_eq!(private.len(), 86, "64-byte store key -> 86 base64url chars");
    assert!(!public.is_empty());

    // Build a StoreKey wallet whose recipient is that public key, then sign by
    // unlocking with the store key — end-to-end proof of the StoreKey scheme.
    let body = format!(
        r#"{{"path":"Wallet","verb":"POST","params":{{"Name":"SK","Curve":"ed25519","Keys":[
            {{"Type":"StoreKey","Key":"{public}"}},
            {{"Type":"StoreKey","Key":"{public}"}},
            {{"Type":"StoreKey","Key":"{public}"}}]}}}}"#
    );
    let w = request(h, &body);
    assert_eq!(w["result"], "success", "{w}");
    let k0 = w["data"]["Keys"][0]["Id"].as_str().unwrap().to_string();
    let k1 = w["data"]["Keys"][1]["Id"].as_str().unwrap().to_string();
    let account_id = w["data"]["Id"].as_str().unwrap().to_string();

    let sign = request(
        h,
        &format!(r#"{{"path":"Account:signMessage","params":{{"Id":"NEEDACCT"}}}}"#),
    );
    let _ = sign; // signMessage needs an account; sign via the model path instead below.

    // Sign the wallet directly through a solana account.
    let a = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{account_id}","Type":"solana","Index":0}}}}"#),
    );
    let acct = a["data"]["Id"].as_str().unwrap().to_string();
    let msg_b64 = "aGVsbG8="; // "hello"
    let signed = request(
        h,
        &format!(r#"{{"path":"Account:signMessage","params":{{"Id":"{acct}","Message":"{msg_b64}","Keys":[{{"Type":"StoreKey","Id":"{k0}","Key":"{private}"}},{{"Type":"StoreKey","Id":"{k1}","Key":"{private}"}}]}}}}"#),
    );
    assert_eq!(signed["result"], "success", "StoreKey unlock+sign: {signed}");
    assert!(signed["data"]["signature"].as_str().unwrap().len() > 40);
    LibwalletDestroy(h);
}

#[test]
fn storekey_derive_password_matches_wallet_key_via_ffi() {
    let h = new_env();
    // A Password wallet stores each key's derived PKIX pubkey in WalletKey.Key;
    // StoreKey:derivePassword must reproduce it from the password + wkey id.
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"W","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wkey_id = w["data"]["Keys"][0]["Id"].as_str().unwrap().to_string();
    let wkey_pub = w["data"]["Keys"][0]["Key"].as_str().unwrap().to_string();

    let d = request(
        h,
        &format!(r#"{{"path":"StoreKey:derivePassword","params":{{"Password":"passwordone","WalletKeyId":"{wkey_id}"}}}}"#),
    );
    assert_eq!(d["result"], "success", "{d}");
    assert_eq!(d["data"]["Public_Key"], wkey_pub, "derived pubkey must match the wallet key recipient");

    // A wrong password derives a different key.
    let bad = request(
        h,
        &format!(r#"{{"path":"StoreKey:derivePassword","params":{{"Password":"WRONGWRONG","WalletKeyId":"{wkey_id}"}}}}"#),
    );
    assert_ne!(bad["data"]["Public_Key"], wkey_pub);
    LibwalletDestroy(h);
}

#[test]
fn wallet_info_roundtrip_via_ffi() {
    let h = new_env();
    // Set then get the wallet identity record.
    let set = request(
        h,
        r#"{"path":"Info:setWalletInfo","params":{"ClientId":"cid-123","Name":"MyWallet","LogLevel":"debug"}}"#,
    );
    assert_eq!(set["result"], "success", "{set}");
    assert_eq!(set["data"]["clientId"], "cid-123");

    let got = request(h, r#"{"path":"Info:getWalletInfo"}"#);
    assert_eq!(got["data"]["clientId"], "cid-123");
    assert_eq!(got["data"]["name"], "MyWallet");
    assert_eq!(got["data"]["logLevel"], "debug");
    assert_eq!(got["data"]["effectiveLogLevel"], "debug");

    // Empty logLevel resolves to the "info" effective default.
    request(h, r#"{"path":"Info:setWalletInfo","params":{"LogLevel":""}}"#);
    let d = request(h, r#"{"path":"Info:getWalletInfo"}"#);
    assert_eq!(d["data"]["effectiveLogLevel"], "info");
    LibwalletDestroy(h);
}

#[test]
fn canonical_go_endpoint_names_via_ffi() {
    // The Dart client calls Go's plural names — they must route.
    let h = new_env();
    let n = request(h, r#"{"path":"Names:resolve","params":{"Name":"x","RPC":"http://127.0.0.1:1"}}"#);
    // Resolves the route (errors on the unreachable RPC, not "unknown endpoint").
    assert_eq!(n["result"], "error");
    assert_ne!(n["code"], 404, "Names:resolve must be a known endpoint");
    let c = request(h, r#"{"path":"Contracts:lookup","params":{}}"#);
    assert_ne!(c["code"], 404, "Contracts:lookup must be a known endpoint");

    // Asset:invalidateCache clears the quote cache and reports success.
    let inv = request(h, r#"{"path":"Asset:invalidateCache"}"#);
    assert_eq!(inv["result"], "success", "{inv}");
    assert_eq!(inv["data"]["invalidated"], true);

    // Transaction:maxSendable is an alias for Account:maxSendable (known route):
    // with no account it hits the handler's 400, not the router's 404.
    let tms = request(h, r#"{"path":"Transaction:maxSendable","params":{}}"#);
    assert_eq!(tms["result"], "error");
    assert_eq!(tms["code"], 400, "known endpoint -> handler validation, not 404");
    LibwalletDestroy(h);
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
fn swap_max_spendable_via_ffi() {
    let h = new_env();
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let acc = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#),
    );
    let account_id = acc["data"]["Id"].as_str().unwrap().to_string();

    // Node: balance 1 ETH, gasPrice 20 gwei -> max = 1e18 - 4.2e14.
    let node = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":"0x4a817c800"}"#.to_string(),
    ]);
    // OKX proxy: quote for that max amountIn.
    let okx = mock_node(
        r#"{"result":"success","data":[{"fromTokenAmount":"999580000000000000","toTokenAmount":"2000000000"}]}"#,
    );
    let okx = okx.trim_end_matches('/');
    let body = format!(
        r#"{{"path":"Swap:maxSpendable","params":{{"Account":"{account_id}","TokenIn":{{"address":"NATIVE","decimals":18}},"TokenOut":{{"address":"0xOUT","decimals":6}},"SlippageBps":50,"RPC":"{node}","KeyId":"k","Secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Backend":"{okx}"}}}}"#
    );
    let resp = request(h, &body);
    assert_eq!(resp["result"], "success", "{resp}");
    // The quote was taken at the computed max amountIn.
    assert_eq!(resp["data"]["amountIn"]["v"], "999580000000000000");
    assert_eq!(resp["data"]["amountOut"]["v"], "2000000000");
    LibwalletDestroy(h);
}

#[test]
fn swap_build_approval_via_ffi() {
    let h = new_env();
    let w = request(
        h,
        r#"{"path":"Wallet","verb":"POST","params":{"Name":"EVM","Curve":"secp256k1","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}"#,
    );
    let wallet_id = w["data"]["Id"].as_str().unwrap().to_string();
    let acc = request(
        h,
        &format!(r#"{{"path":"Account","verb":"POST","params":{{"Wallet":"{wallet_id}","Type":"ethereum","Index":0}}}}"#),
    );
    let account_id = acc["data"]["Id"].as_str().unwrap().to_string();

    // Node: nonce=5, gasPrice=20 gwei, estimateGas=46000.
    let rpc = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":"0x5"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":"0x4a817c800"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":"0xb3b0"}"#.to_string(), // 46000
    ]);
    let body = format!(
        r#"{{"path":"Swap:buildApproval","params":{{"Account":"{account_id}","Token":"0x1111111111111111111111111111111111111111","Spender":"0x2222222222222222222222222222222222222222","Unlimited":true,"RPC":"{rpc}"}}}}"#
    );
    let resp = request(h, &body);
    assert_eq!(resp["result"], "success", "{resp}");
    let tx = &resp["data"]["tx"];
    assert_eq!(tx["to"], "0x1111111111111111111111111111111111111111");
    assert_eq!(tx["nonce"], 5);
    assert_eq!(tx["gas"], 46000);
    assert_eq!(tx["gasPrice"], "20000000000");
    // Unlimited approval: calldata ends in an all-Fs amount word.
    assert!(tx["data"].as_str().unwrap().starts_with("0x095ea7b3"));
    assert!(tx["data"].as_str().unwrap().ends_with(&"f".repeat(64)));
    assert_eq!(resp["data"]["isUnlimited"], true);
    LibwalletDestroy(h);
}

#[test]
fn swap_quotes_via_ffi() {
    let h = new_env();
    // Default current network = ephemeral evm.1. Mock OKX proxy returns a quote.
    let okx = mock_node(
        r#"{"result":"success","data":[{"fromTokenAmount":"1000000","toTokenAmount":"2000000","priceImpactPercent":"0.1"}]}"#,
    );
    let okx = okx.trim_end_matches('/');
    let body = format!(
        r#"{{"path":"Swap:quotes","params":{{"TokenIn":{{"address":"0xIN","decimals":6}},"TokenOut":{{"address":"0xOUT","decimals":6}},"AmountIn":"1000000","SlippageBps":50,"KeyId":"k","Secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Backend":"{okx}"}}}}"#
    );
    let resp = request(h, &body);
    assert_eq!(resp["result"], "success", "{resp}");
    let att = &resp["data"]["attempts"][0];
    assert_eq!(att["provider"], "okx_evm");
    assert_eq!(att["providerLabel"], "OKX");
    assert_eq!(att["quote"]["amountOut"]["v"], "2000000");
    LibwalletDestroy(h);
}

#[test]
fn swap_availability_via_ffi() {
    let h = new_env();
    // Current network defaults to ephemeral evm.1 (Ethereum) — swaps available.
    let resp = request(h, r#"{"path":"Swap:availability"}"#);
    assert_eq!(resp["result"], "success", "{resp}");
    assert_eq!(resp["data"]["available"], true);
    assert_eq!(resp["data"]["network"], "evm.1");
    assert_eq!(resp["data"]["providers"][0], "okx_evm");

    // An unsupported chain via the Network param.
    let sol = request(h, r#"{"path":"Swap:availability","params":{"Network":"solana.devnet"}}"#);
    assert_eq!(sol["data"]["available"], false);
    assert_eq!(sol["data"]["reason"], "unsupported_chain");
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
