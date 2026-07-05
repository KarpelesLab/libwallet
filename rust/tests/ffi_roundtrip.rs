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
    assert_eq!(w["data"]["Protocol"], "dkls23");
    assert_eq!(w["data"]["Threshold"], 0);
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
