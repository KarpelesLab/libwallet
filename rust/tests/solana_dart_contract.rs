//! The Dart `TransactionApi` contract for `Transaction:maxSendable`,
//! `Transaction:validate` and `Transaction:simulate` (issue #4): params shaped
//! exactly as the Dart client sends them (camelCase `from`/`to`/`asset`/
//! `network`, `type: "transfer"`), driven through the C-ABI against a local mock
//! node that dispatches on the JSON-RPC method.

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};
use serde_json::{json, Value};

extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    tx.send(json).unwrap();
}

fn request(h: usize, body: &Value) -> Value {
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx)) as usize;
    let req = CString::new(body.to_string()).unwrap();
    let cb: ResponseCallback = capture;
    LibwalletRequest(h, req.as_ptr(), Some(cb), ud);
    let value = loop {
        let json = rx.recv_timeout(Duration::from_secs(30)).expect("callback fired");
        let v: Value = serde_json::from_str(&json).unwrap();
        if v["result"] != "progress" {
            break v;
        }
    };
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    value
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-dart-contract-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0);
    h
}

/// Create a wallet of `curve` and one `kind` account; returns (id, address).
fn account(h: usize, curve: &str, kind: &str) -> (String, String) {
    let (id, address, _) = account_with_keys(h, curve, kind);
    (id, address)
}

/// [`account`] plus the signing `Keys` descriptors for its wallet.
fn account_with_keys(h: usize, curve: &str, kind: &str) -> (String, String, Value) {
    let w = request(
        h,
        &json!({"path":"Wallet","verb":"POST","params":{"Name":"W","Curve":curve,"Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}),
    );
    let wallet_id = w["data"]["Id"].as_str().expect("wallet created").to_string();
    let keys: Vec<Value> = ["passwordone", "passwordtwo", "passwordthree"]
        .iter()
        .enumerate()
        .map(|(i, pw)| json!({"Type":"Password","Id":w["data"]["Keys"][i]["Id"],"Key":pw}))
        .collect();
    let a = request(h, &json!({"path":"Account","verb":"POST","params":{"Wallet":wallet_id,"Type":kind,"Index":0}}));
    (
        a["data"]["Id"].as_str().unwrap().to_string(),
        a["data"]["Address"].as_str().unwrap().to_string(),
        Value::Array(keys),
    )
}

const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // USDC, 6 decimals
const RECIPIENT: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const BALANCE: u64 = 10_000_000; // 0.01 SOL
const RENT: u64 = 890_880;

/// Mock node: dispatches on the JSON-RPC method and records every request body.
/// Solana: the only existing account is the USDC mint (Token-1, 6 decimals), so
/// the recipient and every ATA read as new. EVM: 1 ETH balance, 20 gwei gas,
/// and an ERC-20 answering balanceOf = 5_000_000 / decimals = 6.
fn mock_node() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = log2.clone();
            std::thread::spawn(move || {
                // Read the headers, then exactly Content-Length body bytes.
                let mut acc = Vec::new();
                let mut buf = [0u8; 8192];
                let body = loop {
                    let n = match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    acc.extend_from_slice(&buf[..n]);
                    let txt = String::from_utf8_lossy(&acc).to_string();
                    if let Some(end) = txt.find("\r\n\r\n") {
                        let len = txt[..end]
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if acc.len() >= end + 4 + len {
                            break serde_json::from_slice::<Value>(&acc[end + 4..end + 4 + len]).unwrap_or(Value::Null);
                        }
                    }
                };
                log.lock().unwrap().push(body.clone());
                let result = respond(&body);
                let out = json!({"jsonrpc":"2.0","id":body["id"].clone(),"result":result}).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    out.len(),
                    out
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
            });
        }
    });
    (format!("http://{addr}/"), log)
}

fn respond(req: &Value) -> Value {
    let params = &req["params"];
    match req["method"].as_str().unwrap_or("") {
        "getBalance" => json!({"context":{"slot":1},"value":BALANCE}),
        "getMinimumBalanceForRentExemption" => match params[0].as_u64() {
            Some(165) => json!(2_039_280u64),
            _ => json!(RENT),
        },
        "getAccountInfo" if params[0] == MINT => {
            let mut data = vec![0u8; 82];
            data[44] = 6; // decimals
            data[45] = 1; // is_initialized
            json!({"context":{"slot":1},"value":{
                "lamports":1, "owner": libwallet::solana_spl::SPL_TOKEN_PROGRAM_B58,
                "data":[base64::engine::general_purpose::STANDARD.encode(data), "base64"]}})
        }
        "getAccountInfo" => json!({"context":{"slot":1},"value":null}),
        "getLatestBlockhash" => json!({"context":{"slot":1},"value":{
            "blockhash": bs58::encode([5u8; 32]).into_string(), "lastValidBlockHeight": 100}}),
        "getTokenAccountsByOwner" => json!({"context":{"slot":1},"value":[
            {"account":{"data":{"parsed":{"info":{"tokenAmount":{"amount":"2500000","decimals":6}}}}}}]}),
        "simulateTransaction" => json!({"context":{"slot":1},"value":{
            "err":null, "logs":["Program log: Instruction: TransferChecked"], "unitsConsumed":6200}}),
        "sendTransaction" => json!("5igSent"),
        "eth_getBalance" => json!("0xde0b6b3a7640000"),
        "eth_gasPrice" => json!("0x4a817c800"),
        "eth_call" => {
            let data = params[0]["data"].as_str().or(params[0]["input"].as_str()).unwrap_or("");
            if data.starts_with("0x313ce567") {
                json!(format!("0x{:064x}", 6))
            } else {
                json!(format!("0x{:064x}", 5_000_000))
            }
        }
        _ => Value::Null,
    }
}

fn simulate_requests(log: &Arc<Mutex<Vec<Value>>>) -> Vec<Value> {
    log.lock().unwrap().iter().filter(|r| r["method"] == "simulateTransaction").cloned().collect()
}

#[test]
fn max_sendable_native_sol_dart_shape() {
    let h = new_env();
    let (id, _) = account(h, "ed25519", "solana");
    let (rpc, _log) = mock_node();
    // Exactly what TransactionApi.maxSendable(from:, to:, asset:) sends.
    let r = request(
        h,
        &json!({"path":"Transaction:maxSendable","params":{
            "from": id, "to": RECIPIENT, "asset": "solana.mainnet.NATIVE", "RPC": rpc}}),
    );
    assert_eq!(r["result"], "success", "{r}");
    let d = &r["data"];
    assert_eq!(d["chain"], "solana");
    assert_eq!(d["balance"]["v"], BALANCE.to_string());
    assert_eq!(d["fee"]["v"], "5000");
    // New recipient: fee + sender rent + recipient rent are all held back.
    assert_eq!(d["max"]["v"], (BALANCE - 5000 - 2 * RENT).to_string());
    assert_eq!(d["max"]["e"], 9);
    assert_eq!(d["reserved"][0]["kind"], "sender_rent");
    assert_eq!(d["reserved"][1]["kind"], "recipient_rent");
    LibwalletDestroy(h);
}

#[test]
fn max_sendable_spl_dart_shape() {
    let h = new_env();
    let (id, _) = account(h, "ed25519", "solana");
    let (rpc, _log) = mock_node();
    let r = request(
        h,
        &json!({"path":"Transaction:maxSendable","params":{
            "from": id, "to": RECIPIENT, "asset": format!("solana.mainnet.{MINT}"), "RPC": rpc}}),
    );
    assert_eq!(r["result"], "success", "{r}");
    let d = &r["data"];
    assert_eq!(d["chain"], "solana");
    assert_eq!(d["token"], MINT);
    // The whole token balance, in the mint's decimals (read on-chain: the mint
    // isn't in the Token table).
    assert_eq!(d["max"]["v"], "2500000");
    assert_eq!(d["max"]["e"], 6);
    assert_eq!(d["balance"]["v"], "2500000");
    // Fee and the new recipient ATA's rent are SOL.
    assert_eq!(d["fee"]["v"], "5000");
    assert_eq!(d["fee"]["e"], 9);
    assert_eq!(d["reserved"][0]["kind"], "recipient_rent");
    assert_eq!(d["reserved"][0]["amount"]["v"], "2039280");
    LibwalletDestroy(h);
}

#[test]
fn max_sendable_evm_dart_shape() {
    let h = new_env();
    let (id, _) = account(h, "secp256k1", "ethereum");
    let (rpc, _log) = mock_node();
    let native = request(
        h,
        &json!({"path":"Transaction:maxSendable","params":{"from": id, "asset": "evm.1.NATIVE", "RPC": rpc}}),
    );
    assert_eq!(native["result"], "success", "{native}");
    assert_eq!(native["data"]["chain"], "evm");
    assert_eq!(native["data"]["fee"]["v"], "420000000000000"); // 21000 × 20 gwei
    assert_eq!(native["data"]["max"]["v"], "999580000000000000");

    let token = "0x00000000000000000000000000000000000000aa";
    let erc20 = request(
        h,
        &json!({"path":"Transaction:maxSendable","params":{"from": id, "asset": format!("evm.1.{token}"), "RPC": rpc}}),
    );
    assert_eq!(erc20["result"], "success", "{erc20}");
    assert_eq!(erc20["data"]["token"], token);
    assert_eq!(erc20["data"]["max"]["v"], "5000000");
    assert_eq!(erc20["data"]["max"]["e"], 6);
    // Native gas for the token transfer is reported (MaxSendableResult.fee is required).
    assert_eq!(erc20["data"]["fee"]["v"], "1300000000000000"); // 65000 × 20 gwei
    LibwalletDestroy(h);
}

#[test]
fn simulate_spl_transfer_routes_to_solana() {
    let h = new_env();
    let (id, address) = account(h, "ed25519", "solana");
    let (rpc, log) = mock_node();
    // UnsignedTransaction(type: 'transfer', from, to, amount, asset, network) — the
    // issue's reproduction, which used to hit eth_call.
    let r = request(
        h,
        &json!({"path":"Transaction:simulate","params":{
            "type": "transfer", "from": id, "to": RECIPIENT,
            "amount": {"v": "1500000", "e": 6, "f": 1.5},
            "asset": format!("solana.mainnet.{MINT}"), "network": "solana.mainnet", "RPC": rpc}}),
    );
    assert_eq!(r["result"], "success", "{r}");
    let d = &r["data"];
    assert_eq!(d["chain"], "solana");
    assert_eq!(d["willRevert"], false);
    assert_eq!(d["unitsConsumed"], 6200);
    assert_eq!(d["decodedMethod"], "spl_transfer");
    assert_eq!(d["effects"][0]["type"], "spl_transfer");
    assert_eq!(d["effects"][0]["token"], MINT);
    assert_eq!(d["effects"][0]["from"], address);
    assert_eq!(d["effects"][0]["to"], RECIPIENT);
    assert_eq!(d["effects"][0]["amount"], "1500000");
    assert_eq!(d["fee"]["v"], "5000");
    assert_eq!(d["warnings"][0]["code"], "recipient_new_account");

    // The node was asked to simulate an unsigned, server-built tx.
    let sims = simulate_requests(&log);
    assert_eq!(sims.len(), 1);
    let cfg = &sims[0]["params"][1];
    assert_eq!(cfg["sigVerify"], false);
    assert_eq!(cfg["replaceRecentBlockhash"], true);
    let raw = base64::engine::general_purpose::STANDARD.decode(sims[0]["params"][0].as_str().unwrap()).unwrap();
    assert_eq!(raw[0], 1, "one signature slot");
    assert!(raw[1..65].iter().all(|b| *b == 0), "unsigned");
    let owner: [u8; 32] = bs58::decode(&address).into_vec().unwrap().try_into().unwrap();
    assert_eq!(libwallet::solana::find_signer_slot(&raw[65..], &owner), Some(0));
    assert!(!log.lock().unwrap().iter().any(|r| r["method"].as_str().unwrap_or("").starts_with("eth_")));
    LibwalletDestroy(h);
}

#[test]
fn simulate_native_sol_transfer_follows_from_account() {
    let h = new_env();
    let (id, _) = account(h, "ed25519", "solana");
    let (rpc, log) = mock_node();
    // No network, no asset: the Solana `from` account alone picks the chain.
    let r = request(
        h,
        &json!({"path":"Transaction:simulate","params":{
            "type": "transfer", "from": id, "to": RECIPIENT, "amount": {"v": "1000000", "e": 9}, "RPC": rpc}}),
    );
    assert_eq!(r["result"], "success", "{r}");
    assert_eq!(r["data"]["chain"], "solana");
    assert_eq!(r["data"]["decodedMethod"], "native_transfer");
    assert_eq!(r["data"]["decodedArgs"]["amount"], "1000000");
    assert_eq!(r["data"]["effects"][0]["type"], "native_transfer");
    assert_eq!(r["data"]["warnings"][0]["code"], "recipient_new_account");
    assert_eq!(simulate_requests(&log).len(), 1);
    LibwalletDestroy(h);
}

#[test]
fn validate_builds_unsigned_solana_tx() {
    let h = new_env();
    let (id, address) = account(h, "ed25519", "solana");
    let (rpc, _log) = mock_node();
    let r = request(
        h,
        &json!({"path":"Transaction:validate","params":{
            "type": "transfer", "from": id, "to": RECIPIENT,
            "amount": {"v": "1500000", "e": 6}, "asset": format!("solana.mainnet.{MINT}"),
            "network": "solana.mainnet", "RPC": rpc}}),
    );
    assert_eq!(r["result"], "success", "{r}");
    let d = &r["data"];
    assert_eq!(d["valid"], true);
    assert_eq!(d["from"], address);
    assert_eq!(d["to"], RECIPIENT);
    assert_eq!(d["amount"]["v"], "1500000");
    assert_eq!(d["amount"]["e"], 6);
    assert_eq!(d["fee"]["v"], "5000");
    assert_eq!(d["recentBlockhash"], bs58::encode([5u8; 32]).into_string());
    let raw = base64::engine::general_purpose::STANDARD.decode(d["raw"].as_str().unwrap()).unwrap();
    assert_eq!(raw[0], 1);
    assert!(raw.len() > 65 + 3);

    // Native SOL needs no asset on Solana.
    let n = request(
        h,
        &json!({"path":"Transaction:validate","params":{
            "type": "transfer", "from": id, "to": RECIPIENT, "amount": {"v": "1000", "e": 9}, "RPC": rpc}}),
    );
    assert_eq!(n["result"], "success", "{n}");
    assert_eq!(n["data"]["amount"]["v"], "1000");
    assert!(n["data"]["raw"].as_str().is_some());
    LibwalletDestroy(h);
}

#[test]
fn sign_and_send_spl_uses_the_same_builder() {
    let h = new_env();
    let (id, address, keys) = account_with_keys(h, "ed25519", "solana");
    let (rpc, log) = mock_node();
    let r = request(
        h,
        &json!({"path":"Transaction:signAndSend","params":{
            "type": "transfer", "from": id, "to": RECIPIENT,
            "amount": {"v": "1500000", "e": 6}, "asset": format!("solana.mainnet.{MINT}"),
            "network": "solana.mainnet", "RPC": rpc, "Keys": keys}}),
    );
    assert_eq!(r["result"], "success", "{r}");
    assert_eq!(r["data"]["hash"], "5igSent");
    assert_eq!(r["data"]["from"], address);
    assert_eq!(r["data"]["amount"]["v"], "1500000");
    assert_eq!(r["data"]["amount"]["e"], 6);
    // The broadcast tx is signed (slot 0 no longer zero) and verifies.
    let sent = log.lock().unwrap().iter().find(|r| r["method"] == "sendTransaction").cloned().unwrap();
    let raw = bs58::decode(sent["params"][0].as_str().unwrap()).into_vec().unwrap();
    let sig: [u8; 64] = raw[1..65].try_into().unwrap();
    let owner: [u8; 32] = bs58::decode(&address).into_vec().unwrap().try_into().unwrap();
    assert!(libwallet::tss::ed25519_verify(&owner, &raw[65..], &sig));
    LibwalletDestroy(h);
}
