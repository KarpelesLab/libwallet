//! `Bitfi:*` over the C-ABI, against a mock node: sessions, balances, and sends
//! that are signed but never broadcast until asked. The secrets are made up.
//!
//! Set `BITFI_DUMP` to a file to write each signed transaction there, so another
//! implementation can check the signatures.

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};
use serde_json::{json, Value};

extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    tx.send(json).unwrap();
}

fn raw_request(h: usize, body: &Value) -> Value {
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

fn request(h: usize, path: &str, params: Value) -> Value {
    raw_request(h, &json!({ "path": path, "verb": "POST", "params": params }))
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-bitfi-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let h = LibwalletInit(CString::new(dir.to_str().unwrap()).unwrap().as_ptr());
    assert!(h > 0);
    h
}

/// A JSON-RPC node answering each method with `answer(method, params)`, or a
/// "method not found" error when that returns `None`. Returns its URL and a log
/// of the methods called.
fn mock_node(answer: impl Fn(&str, &Value) -> Option<Value> + Send + 'static) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let body = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if buf.len() >= end + 4 + length {
                    break Some(buf[end + 4..end + 4 + length].to_vec());
                }
            };
            let Some(body) = body else { continue };
            let call: Value = serde_json::from_slice(&body).unwrap();
            let method = call["method"].as_str().unwrap().to_owned();
            seen.lock().unwrap().push(method.clone());
            let reply = match answer(&method, &call["params"]) {
                Some(result) => json!({ "jsonrpc": "2.0", "id": call["id"], "result": result }),
                None => json!({ "jsonrpc": "2.0", "id": call["id"], "error": { "code": -32601, "message": "Method not found" } }),
            };
            let text = reply.to_string();
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len());
        }
    });
    (url, log)
}

const SALT: &str = "test-salt-0001";
const SECRET: &str = "correct horse battery staple is thirty+ chars";

fn open(h: usize) -> String {
    let r = request(h, "Bitfi:open", json!({ "Salt": SALT, "Secret": SECRET }));
    assert_eq!(r["result"], "success", "{r}");
    r["data"]["Session"].as_str().unwrap().to_owned()
}

/// Two outputs worth `sats` each, at an address.
fn utxos(sats: f64) -> Value {
    json!({ "assets": [{ "asset": "NATIVE", "balance": sats * 2.0 / 1e8, "decimals": 8, "type": "spendable_outputs", "txo": [
        { "txo": format!("{}:0", "ab".repeat(32)), "amt": sats / 1e8, "height": 100 },
        { "txo": format!("{}:1", "cd".repeat(32)), "amt": sats / 1e8, "height": 101 },
        { "txo": format!("{}:0", "ef".repeat(32)), "amt": 1.0, "height": 102, "spent": { "tx": "x" } },
    ]}]})
}

fn bitcoin_node(sats: f64) -> (String, Arc<Mutex<Vec<String>>>) {
    mock_node(move |method, _| match method {
        "modchain_assets" => Some(utxos(sats)),
        "estimatesmartfee" => Some(json!({ "feerate": 0.00010000, "blocks": 6 })),
        _ => None,
    })
}

fn dump(label: &str, data: &Value) {
    if let Ok(path) = std::env::var("BITFI_DUMP") {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
        writeln!(f, "{}", json!({ "label": label, "data": data })).unwrap();
    }
}

#[test]
fn every_address_kind_signs_without_broadcasting() {
    let h = new_env();
    let session = open(h);
    let (url, log) = bitcoin_node(100_000_000.0);
    for (coin, kind, to) in [
        ("btc", "legacy", "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4"),
        ("btc", "segwit", "17T2SFMtkaX1joxyntCU9vjnhAgSvjKNmQ"),
        ("ltc", "legacy", "ltc1q9h8zz9l6c4el0upxs676xursl8fj5w0k85c0g3"),
        ("ltc", "segwit", "LedMh3fzwX1fkARCsq2NNr1hAKBh8aLAD2"),
        ("doge", "legacy", "DJtFzcEGr73unEKkyqfdmaG8ANog12MMCM"),
        ("mona", "legacy", "mona1qp36jtvre4lxy8g4pfwa9fvdc7wfu9fj8cxnyz9"),
        ("mona", "segwit", "MMV2Yq91K2MaFRXkHhNcKVhpUArYp1gyPA"),
        ("bch", "legacy", "bitcoincash:qz7xc0vl85nck65ffrsx5wvewjznp9lflgktxc5878"),
    ] {
        let r = request(h, "Bitfi:prepareSend", json!({
            "Session": session, "Coin": coin, "Position": 1, "Kind": kind, "To": to, "Amount": "max", "RPC": url,
        }));
        assert_eq!(r["result"], "success", "{coin} {kind}: {r}");
        let d = &r["data"];
        let (amount, fee): (u64, u64) = (d["Amount"].as_str().unwrap().parse().unwrap(), d["Fee"].as_str().unwrap().parse().unwrap());
        assert_eq!(amount + fee, 200_000_000, "{coin} {kind}: spent outputs must not count");
        assert_eq!(d["Change"], "0");
        assert_eq!(d["FeeRate"], 10);
        // Two inputs, sized for the input type: an uncompressed key is much larger.
        assert_eq!(fee, if kind == "segwit" { (11 + 2 * 68 + 43) * 10 } else { (10 + 2 * 180 + 43) * 10 }, "{coin} {kind}");
        dump(&format!("{coin}/{kind}"), d);
    }
    assert!(!log.lock().unwrap().iter().any(|m| m == "sendrawtransaction"), "prepareSend must not broadcast");
    LibwalletDestroy(h);
}

#[test]
fn exact_amount_returns_change() {
    let h = new_env();
    let session = open(h);
    let (url, _) = bitcoin_node(100_000_000.0);
    let r = request(h, "Bitfi:prepareSend", json!({
        "Session": session, "Coin": "btc", "Position": 1, "Kind": "legacy", "To": "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4",
        "Amount": "150000000", "FeeRate": 2, "RPC": url,
    }));
    assert_eq!(r["result"], "success", "{r}");
    let d = &r["data"];
    let fee: u64 = d["Fee"].as_str().unwrap().parse().unwrap();
    assert_eq!(fee, (10 + 2 * 180 + 2 * 43) * 2);
    assert_eq!(d["Change"].as_str().unwrap().parse::<u64>().unwrap(), 50_000_000 - fee);
    dump("btc/legacy-change", d);
    LibwalletDestroy(h);
}

/// Paying another chain's address would send the funds somewhere unspendable.
#[test]
fn refuses_a_recipient_on_another_chain() {
    let h = new_env();
    let session = open(h);
    let (url, _) = bitcoin_node(100_000_000.0);
    for (coin, kind, to) in [
        ("btc", "legacy", "LedMh3fzwX1fkARCsq2NNr1hAKBh8aLAD2"),
        ("btc", "legacy", "ltc1q9h8zz9l6c4el0upxs676xursl8fj5w0k85c0g3"),
        ("btc", "legacy", "DJtFzcEGr73unEKkyqfdmaG8ANog12MMCM"),
        ("btc", "legacy", "0xf45a414dbc4eef65d7ea540db0aa6fa0fa6f9b3f"),
        ("ltc", "legacy", "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4"),
        ("doge", "legacy", "17T2SFMtkaX1joxyntCU9vjnhAgSvjKNmQ"),
        ("bch", "legacy", "DJtFzcEGr73unEKkyqfdmaG8ANog12MMCM"),
        ("btc", "legacy", "bitcoincash:qz7xc0vl85nck65ffrsx5wvewjznp9lflgktxc5878"),
        ("btc", "legacy", "not an address"),
    ] {
        let r = request(h, "Bitfi:prepareSend", json!({
            "Session": session, "Coin": coin, "Position": 1, "Kind": kind, "To": to, "Amount": "max", "RPC": url,
        }));
        assert_eq!(r["result"], "error", "{coin} paying {to}: {r}");
    }
    LibwalletDestroy(h);
}

#[test]
fn refuses_amounts_it_cannot_send() {
    let h = new_env();
    let session = open(h);
    let (url, _) = bitcoin_node(1000.0);
    let send = |coin: &str, kind: &str, amount: &str| {
        request(h, "Bitfi:prepareSend", json!({
            "Session": session, "Coin": coin, "Position": 1, "Kind": kind, "Amount": amount, "FeeRate": 1, "RPC": url,
            "To": match coin { "btc" => "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4", _ => "DJtFzcEGr73unEKkyqfdmaG8ANog12MMCM" },
        }))
    };
    assert_eq!(send("btc", "legacy", "5000")["result"], "error", "more than it holds");
    assert_eq!(send("btc", "legacy", "100")["result"], "error", "below dust");
    assert_eq!(send("btc", "legacy", "ten")["result"], "error", "not a number");
    assert_eq!(send("doge", "segwit", "max")["result"], "error", "Dogecoin has no SegWit");
    assert_eq!(send("doge", "legacy", "max")["result"], "error", "below Dogecoin's dust");
    LibwalletDestroy(h);
}

/// A server failure must never read as an empty wallet.
#[test]
fn balances_report_failures_rather_than_empty() {
    let h = new_env();
    let session = open(h);
    let (url, _) = mock_node(|method, params| match method {
        "modchain_assets" if params[0].as_str().unwrap().starts_with("bc1") => None,
        "modchain_assets" => Some(utxos(5000.0)),
        _ => None,
    });
    let r = request(h, "Bitfi:balances", json!({ "Session": session, "Coin": "btc", "Positions": [1], "RPC": url }));
    assert_eq!(r["result"], "success", "{r}");
    let rows = r["data"]["Addresses"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["Kind"], "legacy");
    assert_eq!(rows[0]["Assets"][0]["Balance"], "10000");
    assert_eq!(rows[1]["Kind"], "segwit");
    assert!(rows[1].get("Assets").is_none() && rows[1]["Error"].is_string(), "{r}");
    LibwalletDestroy(h);
}

fn ethereum_node() -> (String, Arc<Mutex<Vec<String>>>) {
    mock_node(|method, _| match method {
        "modchain_assets" => Some(json!({ "assets": [
            { "asset": "NATIVE", "balance": "0x56bc75e2d63100000", "decimals": 18, "type": "balance" },
            { "asset": "0x6b175474e89094c44da98b954eedeac495271d0f", "balance": "0x3e8", "decimals": 18, "symbol": "DAI", "type": "erc20" },
            { "asset": "0xdac17f958d2ee523a2206206994597c13d831ec7", "balance": "0x0", "decimals": 6, "symbol": "USDT", "type": "erc20" },
        ]})),
        "eth_getTransactionCount" => Some(json!("0x5")),
        "eth_estimateGas" => Some(json!("0xc350")),
        "eth_getBlockByNumber" => Some(json!({ "baseFeePerGas": "0x3b9aca00" })),
        "eth_maxPriorityFeePerGas" => Some(json!("0x3b9aca00")),
        "eth_sendRawTransaction" => Some(json!("0xfeed")),
        _ => None,
    })
}

#[test]
fn ethereum_sends_native_and_tokens() {
    let h = new_env();
    let session = open(h);
    let (url, log) = ethereum_node();
    let to = "0x000000000000000000000000000000000000dEaD";
    let dai = "0x6b175474e89094c44da98b954eedeac495271d0f";
    let send = |extra: Value| {
        let mut params = json!({ "Session": session, "Coin": "eth", "Position": 1, "To": to, "RPC": url });
        params.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        request(h, "Bitfi:prepareSend", params)
    };

    let balances = request(h, "Bitfi:balances", json!({ "Session": session, "Coin": "eth", "Positions": [1], "RPC": url }));
    let assets = balances["data"]["Addresses"][0]["Assets"].as_array().unwrap().clone();
    assert_eq!(assets.len(), 2, "the empty token is left out: {balances}");
    assert_eq!(assets[0]["Balance"], "100000000000000000000");
    assert_eq!(assets[1]["Symbol"], "DAI");

    // Everything: balance less the worst-case fee (21000 * (2 * 1 gwei + 1 gwei)).
    let max = send(json!({ "Amount": "max" }));
    assert_eq!(max["result"], "success", "{max}");
    assert_eq!(max["data"]["Fee"], "63000000000000");
    assert_eq!(max["data"]["Amount"], "99999937000000000000");
    dump("eth/max", &max["data"]);

    let token = send(json!({ "Amount": "max", "Token": dai }));
    assert_eq!(token["result"], "success", "{token}");
    assert_eq!(token["data"]["Amount"], "1000");
    dump("eth/token", &token["data"]);

    assert_eq!(send(json!({ "Amount": "2000", "Token": dai }))["result"], "error", "more of the token than held");
    // 20 ETH doesn't fit in 64 bits of wei.
    let large = send(json!({ "Amount": "20000000000000000000" }));
    assert_eq!(large["data"]["Amount"], "20000000000000000000", "{large}");
    dump("eth/large", &large["data"]);
    assert_eq!(send(json!({ "Amount": "100000000000000000000" }))["result"], "error", "no room for the fee");
    assert_eq!(send(json!({ "Amount": "-5" }))["result"], "error", "negative");
    assert_eq!(request(h, "Bitfi:prepareSend", json!({
        "Session": session, "Coin": "eth", "Position": 1, "To": "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4", "Amount": "max", "RPC": url,
    }))["result"], "error", "not an Ethereum address");
    assert!(!log.lock().unwrap().iter().any(|m| m == "eth_sendRawTransaction"), "prepareSend must not broadcast");

    let sent = request(h, "Bitfi:broadcast", json!({ "Coin": "eth", "Raw": max["data"]["Raw"], "RPC": url }));
    assert_eq!(sent["data"]["Txid"], "0xfeed", "{sent}");
    LibwalletDestroy(h);
}

#[test]
fn closing_forgets_the_session() {
    let h = new_env();
    let session = open(h);
    let addresses = |s: &str| request(h, "Bitfi:addresses", json!({ "Session": s, "Coin": "btc", "Positions": [0, 1] }));
    let r = addresses(&session);
    assert_eq!(r["data"]["Positions"].as_array().unwrap().len(), 2, "{r}");
    assert!(r.to_string().find(SECRET).is_none() && r.to_string().find(SALT).is_none());

    let keys = request(h, "Bitfi:export", json!({ "Session": session, "Coin": "xmr", "Position": 1 }));
    assert_eq!(keys["data"]["SpendKey"].as_str().unwrap().len(), 64, "{keys}");

    assert_eq!(request(h, "Bitfi:close", json!({ "Session": session }))["result"], "success");
    assert_eq!(addresses(&session)["code"], 404);
    LibwalletDestroy(h);
}

/// Nothing about a session reaches the database.
#[test]
fn a_session_writes_nothing_to_disk() {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-bitfi-disk-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let h = LibwalletInit(CString::new(dir.to_str().unwrap()).unwrap().as_ptr());
    let session = open(h);
    let key = request(h, "Bitfi:export", json!({ "Session": session, "Coin": "btc", "Position": 1 }));
    let secret = key["data"]["PrivateKey"].as_str().unwrap().to_owned();
    LibwalletDestroy(h);
    for entry in std::fs::read_dir(&dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap_or_default();
        for needle in [SALT, SECRET, secret.as_str()] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_bytes()), "{needle} found on disk");
        }
    }
}

#[test]
fn monero_says_so_rather_than_reporting_empty() {
    let h = new_env();
    let session = open(h);
    let r = request(h, "Bitfi:balances", json!({ "Session": session, "Coin": "xmr", "Positions": [1] }));
    assert_eq!(r["code"], 501, "{r}");
    LibwalletDestroy(h);
}
