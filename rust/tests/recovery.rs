//! `Recovery:*`: open each kind of source, derive and scan its addresses, and
//! sweep them, through the C ABI against mock nodes. Signed transactions are
//! checked against the recovered key, not just their shape.

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
        let json = rx.recv_timeout(Duration::from_secs(60)).expect("callback fired");
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

/// The data of a successful request.
fn ok(h: usize, path: &str, params: Value) -> Value {
    let r = request(h, path, params.clone());
    assert_eq!(r["result"], "success", "{path} {params}: {r}");
    r["data"].clone()
}

/// The error message of a failed request.
fn err(h: usize, path: &str, params: Value) -> String {
    let r = request(h, path, params.clone());
    assert_eq!(r["result"], "error", "{path} {params} should fail: {r}");
    r["error"].as_str().unwrap_or_default().to_owned()
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-recovery-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let h = LibwalletInit(CString::new(dir.to_str().unwrap()).unwrap().as_ptr());
    assert!(h > 0);
    h
}

/// A node answering JSON-RPC (`POST /`) and java-tron REST (`POST
/// /wallet/<method>`) with `answer(method, params or body)`; `None` answers
/// "method not found". Returns its URL and a log of the methods called.
fn mock_node(answer: impl Fn(&str, &Value) -> Option<Value> + Send + 'static) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let request = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let length: usize = head
                    .to_lowercase()
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:").map(str::to_owned))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if buf.len() >= end + 4 + length {
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    break Some((path, buf[end + 4..end + 4 + length].to_vec()));
                }
            };
            let Some((path, body)) = request else { continue };
            let call: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let text = if let Some(method) = path.strip_prefix("/wallet/") {
                seen.lock().unwrap().push(method.to_owned());
                answer(method, &call).unwrap_or_else(|| json!({ "Error": format!("no {method}") })).to_string()
            } else {
                let method = call["method"].as_str().unwrap_or_default().to_owned();
                seen.lock().unwrap().push(method.clone());
                match answer(&method, &call["params"]) {
                    Some(result) => json!({ "jsonrpc": "2.0", "id": call["id"], "result": result }),
                    None => json!({ "jsonrpc": "2.0", "id": call["id"], "error": { "code": -32601, "message": "Method not found" } }),
                }
                .to_string()
            };
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len());
        }
    });
    (url, log)
}

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The official Web3 Secret Storage PBKDF2 vector (password "testpassword").
const KEYSTORE: &str = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},
"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2",
"kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}"#;

fn open(h: usize, params: Value) -> String {
    ok(h, "Recovery:open", params)["Session"].as_str().unwrap().to_owned()
}

fn addresses(h: usize, session: &str, extra: Value) -> Vec<Value> {
    let mut params = json!({ "Session": session });
    params.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    ok(h, "Recovery:addresses", params)["Addresses"].as_array().unwrap().clone()
}

fn find<'a>(list: &'a [Value], id: &str) -> &'a Value {
    list.iter().find(|a| a["Id"] == id).unwrap_or_else(|| panic!("no {id} in {list:?}"))
}

#[test]
fn mnemonic_derives_every_wallet_layout() {
    let h = new_env();
    let opened = ok(h, "Recovery:open", json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    assert_eq!(opened["Type"], "mnemonic");
    let chains: Vec<&str> = opened["Chains"].as_array().unwrap().iter().map(|c| c["Chain"].as_str().unwrap()).collect();
    assert_eq!(chains, ["bitcoin", "litecoin", "dogecoin", "bitcoin-cash", "monacoin", "ethereum", "solana", "tron"]);
    let session = opened["Session"].as_str().unwrap();

    let list = addresses(h, session, json!({ "Count": 2 }));
    // BIP-84's own test vectors, and the widely published BIP-44 / Ethereum /
    // Solana / Tron addresses of this phrase.
    for (id, address) in [
        ("bitcoin:p2wpkh:m/84'/0'/0'/0/0", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
        ("bitcoin:p2wpkh:m/84'/0'/0'/0/1", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
        ("bitcoin:p2wpkh:m/84'/0'/0'/1/0", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),
        ("bitcoin:p2pkh:m/44'/0'/0'/0/0", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
        ("ethereum:evm:m/44'/60'/0'/0/0", "0x9858effd232b4033e47d90003d41ec34ecaeda94"),
        ("solana:solana:m/44'/501'/0'/0'", "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"),
        ("tron:tron:m/44'/195'/0'/0/0", "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),
    ] {
        assert_eq!(find(&list, id)["Address"].as_str().unwrap().to_lowercase(), address.to_lowercase(), "{id}");
    }
    assert!(find(&list, "bitcoin:p2sh:p2wpkh:m/49'/0'/0'/0/0")["Address"].as_str().unwrap().starts_with('3'));
    assert!(find(&list, "litecoin:p2wpkh:m/84'/2'/0'/0/0")["Address"].as_str().unwrap().starts_with("ltc1"));
    assert!(find(&list, "dogecoin:p2pkh:m/44'/3'/0'/0/0")["Address"].as_str().unwrap().starts_with('D'));
    assert!(find(&list, "solana:solana:seed32")["Label"].as_str().unwrap().contains("Sollet"));
    find(&list, "solana:solana:m/44'/501'/1'");
    find(&list, "ethereum:evm:m/44'/60'/1'/0/0"); // Ledger Live, account 1

    // Index 0 of Ethereum's two layouts is the same address: listed once.
    let eth0 = list.iter().filter(|a| a["Address"] == find(&list, "ethereum:evm:m/44'/60'/0'/0/0")["Address"]).count();
    assert_eq!(eth0, 1);

    // Paging and filtering.
    let page = addresses(h, session, json!({ "Chains": ["bitcoin"], "Start": 1, "Count": 1 }));
    assert!(page.iter().all(|a| a["Chain"] == "bitcoin" && a["Index"] == 1), "{page:?}");
    assert_eq!(page.len(), 6, "3 script types × receive/change");
    assert!(err(h, "Recovery:addresses", json!({ "Session": session, "Chains": ["monero"] })).contains("nothing on monero"));
    assert!(err(h, "Recovery:addresses", json!({ "Session": session, "Count": 101 })).contains("at most"));

    // A passphrase is a different wallet.
    let other = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC, "Passphrase": "TREZOR" }));
    let other = addresses(h, &other, json!({ "Chains": ["bitcoin"], "Count": 1 }));
    assert_ne!(find(&other, "bitcoin:p2wpkh:m/84'/0'/0'/0/0")["Address"], find(&list, "bitcoin:p2wpkh:m/84'/0'/0'/0/0")["Address"]);
    LibwalletDestroy(h);
}

#[test]
fn layouts_cover_non_standard_wallets() {
    let h = new_env();
    let opened = ok(h, "Recovery:open", json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    let s = opened["Session"].as_str().unwrap();
    let layouts = opened["Layouts"].as_array().unwrap();
    let standard: Vec<&str> = layouts.iter().filter(|l| l["Standard"] == true).map(|l| l["Id"].as_str().unwrap()).collect();
    assert_eq!(standard, ["bip84", "bip49", "bip44", "ledger-live", "ledger-legacy", "phantom", "trust", "sollet"]);

    // The standard set includes Ledger's legacy Ethereum path and Ledger Live
    // on Tron, but not the non-standard Bitcoin layouts.
    let std = addresses(h, s, json!({ "Count": 2 }));
    assert_eq!(find(&std, "ethereum:evm:m/44'/60'/0'/1")["Layout"], "ledger-legacy");
    assert_eq!(find(&std, "tron:tron:m/44'/195'/1'/0/0")["Layout"], "ledger-live");
    assert_eq!(find(&std, "bitcoin:p2wpkh:m/84'/0'/0'/0/0")["Layout"], "bip84");
    assert!(std.iter().all(|a| a["Id"] != "bitcoin:p2wpkh:m/44'/0'/0'/0/0"));

    let all = addresses(h, s, json!({ "Chains": ["bitcoin", "litecoin"], "Count": 2, "Layouts": "all" }));
    for (id, layout) in [
        ("bitcoin:p2wpkh:m/44'/0'/0'/0/0", "mixed-scripts"),      // the BIP-44 path as native SegWit
        ("bitcoin:p2sh:p2wpkh:m/44'/0'/0'/1/1", "mixed-scripts"), // … and as wrapped SegWit
        ("bitcoin:p2pkh:m/84'/0'/0'/0/0", "mixed-scripts"),
        ("bitcoin:p2pkh:m/44'/0'/0'/1", "blockchain-info"),
        ("bitcoin:p2sh:p2wpkh:m/0'/0'/1'", "bitcoin-core"),
        ("bitcoin:p2wpkh:m/0'/1'/0'", "bitcoin-core"),
        ("litecoin:p2wpkh:m/0'/0'/0'", "bitcoin-core"),
        ("bitcoin:p2pkh:m/0'/0/1", "multibit"),
        ("bitcoin:p2wpkh:m/84'/0'/2147483646'/0/0", "samourai"),
        ("litecoin:p2wpkh:m/44'/2'/0'/0/0", "mixed-scripts"),
    ] {
        assert_eq!(find(&all, id)["Layout"], layout, "{id}");
    }
    // MultiBit and Samourai were Bitcoin-only.
    assert!(all.iter().all(|a| a["Chain"] == "bitcoin" || (a["Layout"] != "multibit" && a["Layout"] != "samourai")));

    // A mixed-script address is the same key as the standard one on that path.
    let legacy = ok(h, "Recovery:export", json!({ "Session": s, "Address": "bitcoin:p2pkh:m/44'/0'/0'/0/0" }));
    let segwit = ok(h, "Recovery:export", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/44'/0'/0'/0/0" }));
    assert_eq!(legacy["PrivateKey"], segwit["PrivateKey"]);
    assert_ne!(legacy["Address"], segwit["Address"]);
    assert!(segwit["Address"].as_str().unwrap().starts_with("bc1q"));

    // One layout by name, and more accounts.
    let bci = addresses(h, s, json!({ "Chains": ["bitcoin"], "Layouts": ["blockchain-info"], "Count": 3, "Accounts": 2 }));
    assert_eq!(bci.len(), 6);
    assert!(bci.iter().all(|a| a["Layout"] == "blockchain-info" && a["Path"].as_str().unwrap().matches('/').count() == 4), "{bci:?}");
    find(&bci, "bitcoin:p2pkh:m/44'/0'/1'/2");
    let accounts = addresses(h, s, json!({ "Chains": ["bitcoin"], "Count": 1, "Accounts": 3 }));
    find(&accounts, "bitcoin:p2wpkh:m/84'/0'/2'/1/0");
    assert_eq!(accounts.len(), 3 * 2 * 3, "3 layouts × receive/change × 3 accounts");

    assert!(err(h, "Recovery:addresses", json!({ "Session": s, "Layouts": ["electrum"] })).contains("unknown layout"));
    assert!(err(h, "Recovery:addresses", json!({ "Session": s, "Accounts": 0 })).contains("Accounts"));
    assert!(err(h, "Recovery:addresses", json!({ "Session": s, "Accounts": 21 })).contains("Accounts"));
    // A private key has no layouts to choose.
    let k = ok(h, "Recovery:open", json!({ "Type": "privateKey", "Key": "0000000000000000000000000000000000000000000000000000000000000001" }));
    assert!(k.get("Layouts").is_none());
    LibwalletDestroy(h);
}

#[test]
fn a_mistyped_phrase_is_refused() {
    let h = new_env();
    let bad = MNEMONIC.replace("about", "abandon");
    assert!(err(h, "Recovery:open", json!({ "Type": "mnemonic", "Mnemonic": bad })).contains("valid recovery phrase"));
    // Spacing and case don't matter.
    open(h, json!({ "Type": "mnemonic", "Mnemonic": format!("  {}  ", MNEMONIC.to_uppercase().replace(' ', "   ")) }));
    assert!(err(h, "Recovery:open", json!({ "Type": "seed" })).contains("unknown recovery Type"));
    LibwalletDestroy(h);
}

#[test]
fn private_keys_in_every_format() {
    let h = new_env();
    // Key 1: the most published key there is.
    let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let s = open(h, json!({ "Type": "privateKey", "Key": hex }));
    let list = addresses(h, &s, json!({}));
    assert_eq!(find(&list, "bitcoin:p2pkh:key")["Address"], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    assert_eq!(find(&list, "bitcoin:p2pukh:key")["Address"], "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
    assert_eq!(find(&list, "ethereum:evm:key")["Address"].as_str().unwrap().to_lowercase(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    find(&list, "bitcoin:p2wpkh:key");
    find(&list, "tron:tron:key");
    // 32 bytes of hex may also be a Solana seed.
    find(&list, "solana:solana:key");
    // One key, one index: asking past it finds nothing.
    assert!(addresses(h, &s, json!({ "Start": 1 })).is_empty());

    // A WIF says whether its addresses use the compressed key.
    let compressed = open(h, json!({ "Type": "privateKey", "Key": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn" }));
    let c = addresses(h, &compressed, json!({ "Chains": ["bitcoin"] }));
    assert!(c.iter().all(|a| a["Kind"] != "p2pukh"), "{c:?}");
    let uncompressed = open(h, json!({ "Type": "privateKey", "Key": "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf" }));
    let u = addresses(h, &uncompressed, json!({ "Chains": ["bitcoin"] }));
    assert_eq!(u.len(), 1);
    assert_eq!(u[0]["Address"], "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
    assert!(err(h, "Recovery:addresses", json!({ "Session": uncompressed, "Chains": ["solana"] })).contains("nothing on solana"));

    // A Solana keypair (Phantom's export: base58 of seed ‖ public key).
    let exported = ok(h, "Recovery:export", json!({ "Session": s, "Address": "solana:solana:key" }));
    let pair = exported["PrivateKey"].as_str().unwrap();
    let sol = open(h, json!({ "Type": "privateKey", "Key": pair }));
    let sl = addresses(h, &sol, json!({}));
    assert_eq!(sl.len(), 1, "a Solana keypair holds nothing elsewhere: {sl:?}");
    assert_eq!(sl[0]["Address"], find(&list, "solana:solana:key")["Address"]);

    assert!(err(h, "Recovery:open", json!({ "Type": "privateKey", "Key": "not a key" })).contains("recognises"));
    LibwalletDestroy(h);
}

#[test]
fn ethereum_keystore() {
    let h = new_env();
    assert!(err(h, "Recovery:open", json!({ "Type": "keystore", "Keystore": KEYSTORE, "Password": "wrong" })).contains("wrong password"));
    let s = open(h, json!({ "Type": "keystore", "Keystore": KEYSTORE, "Password": "testpassword" }));
    let list = addresses(h, &s, json!({}));
    assert_eq!(find(&list, "ethereum:evm:key")["Address"].as_str().unwrap().to_lowercase(), "0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b");
    let keys = ok(h, "Recovery:export", json!({ "Session": s, "Address": "ethereum:evm:key" }));
    assert_eq!(keys["PrivateKey"], "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d");
    // The same key's other chains are listed too.
    find(&list, "tron:tron:key");
    find(&list, "bitcoin:p2wpkh:key");
    LibwalletDestroy(h);
}

#[test]
fn bitfi_matches_its_own_derivation() {
    let h = new_env();
    let s = open(h, json!({ "Type": "bitfi", "Salt": "test-salt-0001", "Secret": "correct horse battery staple is thirty+ chars" }));
    let list = addresses(h, &s, json!({ "Count": 2 }));
    // The same vectors as tests/bitfi_derive.rs.
    assert_eq!(find(&list, "bitcoin:p2pukh:bitfi:1")["Address"], "17T2SFMtkaX1joxyntCU9vjnhAgSvjKNmQ");
    assert_eq!(find(&list, "bitcoin:p2wpkh:bitfi:1")["Address"], "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4");
    assert_eq!(find(&list, "ethereum:evm:bitfi:0")["Address"].as_str().unwrap().to_lowercase(), "0x37ea7fda970f84b8f34f746a3254c186e23a5a52");
    assert_eq!(
        find(&list, "monero:monero:bitfi:0")["Address"],
        "4AqBdb3UydfBxBEMQvYrubgTQTh6HKWo2hKeMhd6iF1k9sjXDhdfwqCDUASuQWfF5o3pnJn51ZDx43PRHzgSzuApM1mmiw3"
    );
    let wif = ok(h, "Recovery:export", json!({ "Session": s, "Address": "bitcoin:p2pukh:bitfi:1" }));
    assert_eq!(wif["Wif"], "5K7wHZsMFaeiCjr6tKC4HpU8w9ZwbMYNtxAS1oohiTJikKJXjeX");
    let segwit = ok(h, "Recovery:export", json!({ "Session": s, "Address": "bitcoin:p2wpkh:bitfi:1" }));
    assert_eq!(segwit["Wif"], "L2ycc85EPMXSrp7iyVHoXEWn1zpPxdfVeJUdQZb8hy7DFtdNgB6d");
    let xmr = ok(h, "Recovery:export", json!({ "Session": s, "Address": "monero:monero:bitfi:0" }));
    assert!(xmr["SpendKey"].is_string() && xmr["ViewKey"].is_string());
    // No Solana or Tron on a Bitfi.
    assert!(list.iter().all(|a| a["Chain"] != "solana" && a["Chain"] != "tron"));
    LibwalletDestroy(h);
}

#[test]
fn ids_are_checked_against_the_source() {
    let h = new_env();
    let s = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    for bad in ["bitcoin:p2wpkh:bitfi:1", "bitcoin:evm:m/44'/0'/0'/0/0", "monero:monero:m/44'/128'/0'/0/0", "bitcoin:p2wpkh:key", "nope", "bitcoin:p2sh:p2pkh:m/49'/0'/0'/0/0"] {
        let e = err(h, "Recovery:export", json!({ "Session": s, "Address": bad }));
        assert!(e.contains("unknown address") || e.contains("isn't one this source"), "{bad}: {e}");
    }
    // Any path is accepted, not only the listed ones: a wallet may have used one.
    let k = ok(h, "Recovery:export", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/84'/0'/5'/0/77" }));
    assert!(k["Address"].as_str().unwrap().starts_with("bc1q"));
    LibwalletDestroy(h);
}

#[test]
fn closing_forgets_the_session() {
    let h = new_env();
    let s = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    assert_eq!(ok(h, "Recovery:close", json!({ "Session": s }))["Closed"], true);
    let r = request(h, "Recovery:addresses", json!({ "Session": s }));
    assert_eq!(r["code"], 404, "{r}");
    assert_eq!(ok(h, "Recovery:close", json!({ "Session": s }))["Closed"], false);
    LibwalletDestroy(h);
}

/// Two unspent outputs of `sats` each (and one spent, which must not count).
fn utxos(sats: f64) -> Value {
    json!({ "assets": [{ "asset": "NATIVE", "balance": sats * 2.0 / 1e8, "decimals": 8, "type": "spendable_outputs", "txo": [
        { "txo": format!("{}:0", "ab".repeat(32)), "amt": sats / 1e8, "height": 100 },
        { "txo": format!("{}:1", "cd".repeat(32)), "amt": sats / 1e8, "height": 101 },
        { "txo": format!("{}:0", "ef".repeat(32)), "amt": 1.0, "height": 102, "spent": { "tx": "x" } },
    ]}]})
}

#[test]
fn scan_reports_failures_rather_than_empty() {
    let h = new_env();
    let s = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    // Funds on the BIP-49 receive 0 address; the node fails for native SegWit.
    let (url, _) = mock_node(|method, params| match method {
        "modchain_assets" if params[0].as_str().unwrap().starts_with("bc1") => None,
        "modchain_assets" if params[0].as_str().unwrap().starts_with('3') && params[0] != Value::Null => Some(utxos(5000.0)),
        "modchain_assets" => Some(json!({ "assets": [] })),
        _ => None,
    });
    let rows = ok(h, "Recovery:scan", json!({ "Session": s, "Chains": ["bitcoin"], "Count": 1, "RPC": url }))["Addresses"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 6);
    for row in &rows {
        let kind = row["Kind"].as_str().unwrap();
        match kind {
            "p2wpkh" => assert!(row["Error"].is_string() && row.get("Assets").is_none(), "{row}"),
            "p2sh:p2wpkh" => {
                let assets = row["Assets"].as_array().unwrap();
                assert_eq!(assets.len(), 1, "{row}");
                assert_eq!(assets[0]["Balance"], "10000");
                assert_eq!(assets[0]["Symbol"], "BTC");
            }
            _ => assert_eq!(row["Assets"], json!([]), "{row}"),
        }
    }
    LibwalletDestroy(h);
}

/// Check every input signature of a signed Bitcoin transaction against `key`
/// (hex), spending outputs of `scheme` worth `amount` each.
fn verify_bitcoin(raw: &str, key: &str, scheme: &str, amount: u64) {
    use outscript::btctx::BtcTx;
    use outscript::crypto::secp256k1::SecpPrivateKey;
    let bytes: Vec<u8> = (0..raw.len()).step_by(2).map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap()).collect();
    let tx = BtcTx::from_bytes(&bytes).unwrap();
    let key: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&key[i..i + 2], 16).unwrap()).collect();
    let key: [u8; 32] = key.try_into().unwrap();
    let signer = SecpPrivateKey::from_bytes(&key).unwrap();
    let public = signer.public_key();
    let prev = outscript::script::Script::new(public.clone()).out(scheme).unwrap().bytes().to_vec();
    for (n, input) in tx.inputs.iter().enumerate() {
        // A P2SH-wrapped SegWit input signs like native SegWit: read its witness.
        let script = if scheme == "p2sh:p2wpkh" { &[][..] } else { &input.script[..] };
        let sigs = outscript::btctxparse::extract_btc_input_sig(script, &input.witnesses).unwrap();
        assert_eq!(sigs.len(), 1, "{scheme} input {n}");
        let sig = &sigs[0];
        let digest = tx.input_sighash(n, sig, &prev, outscript::BtcAmount(amount)).unwrap();
        let signing = outscript::crypto::secp256k1::SecpPublicKey::from_sec1(&sig.pubkey).unwrap();
        let (r, s): ([u8; 32], [u8; 32]) = (sig.r.clone().try_into().unwrap(), sig.s.clone().try_into().unwrap());
        assert!(signing.verify(&digest, &r, &s), "{scheme} input {n} signature");
    }
}

#[test]
fn bitcoin_sweeps_sign_every_script_type() {
    let h = new_env();
    let s = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    let (url, log) = mock_node(|method, _| match method {
        "modchain_assets" => Some(utxos(100_000_000.0)),
        "estimatesmartfee" => Some(json!({ "feerate": 0.00010000, "blocks": 6 })),
        "sendrawtransaction" => Some(json!("feedfacefeedface")),
        _ => None,
    });
    let to = "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4";
    for (id, scheme, input) in [
        ("bitcoin:p2wpkh:m/84'/0'/0'/0/0", "p2wpkh", 68),
        ("bitcoin:p2sh:p2wpkh:m/49'/0'/0'/1/3", "p2sh:p2wpkh", 91),
        ("bitcoin:p2pkh:m/44'/0'/0'/0/0", "p2pkh", 148),
        // Non-standard layouts sign the same way.
        ("bitcoin:p2wpkh:m/44'/0'/0'/0/0", "p2wpkh", 68),
        ("bitcoin:p2pkh:m/44'/0'/0'/7", "p2pkh", 148),
        ("bitcoin:p2sh:p2wpkh:m/0'/0'/2'", "p2sh:p2wpkh", 91),
    ] {
        let p = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": to, "RPC": url }));
        let (amount, fee): (u64, u64) = (p["Amount"].as_str().unwrap().parse().unwrap(), p["Fee"].as_str().unwrap().parse().unwrap());
        assert_eq!(amount + fee, 200_000_000, "{id}: the spent output must not count");
        let overhead = if scheme == "p2pkh" { 10 } else { 11 };
        assert_eq!(fee, (overhead + 2 * input + 43) * 10, "{id}");
        assert_eq!((p["Chain"].as_str(), p["To"].as_str(), p["Asset"].as_str()), (Some("bitcoin"), Some(to), Some("NATIVE")));
        let key = ok(h, "Recovery:export", json!({ "Session": s, "Address": id }));
        verify_bitcoin(p["Raw"].as_str().unwrap(), key["PrivateKey"].as_str().unwrap(), scheme, 100_000_000);
    }
    // An uncompressed-key legacy address, from a private key.
    let k = open(h, json!({ "Type": "privateKey", "Key": "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf" }));
    let p = ok(h, "Recovery:prepareSweep", json!({ "Session": k, "Address": "bitcoin:p2pukh:key", "To": to, "RPC": url, "FeeRate": 2 }));
    verify_bitcoin(p["Raw"].as_str().unwrap(), "0000000000000000000000000000000000000000000000000000000000000001", "p2pukh", 100_000_000);
    assert_eq!(p["FeeRate"], 2);

    // An exact amount leaves change at the same address.
    let p = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/84'/0'/0'/0/0", "To": to, "Amount": "150000000", "RPC": url }));
    assert!(p["Change"].as_str().unwrap().parse::<u64>().unwrap() > 0);

    // Another chain's address is refused, and so is sending to itself.
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/84'/0'/0'/0/0", "To": "ltc1q9h8zz9l6c4el0upxs676xursl8fj5w0k85c0g3", "RPC": url }));
    assert!(e.contains("isn't a BTC address"), "{e}");
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/84'/0'/0'/0/0", "To": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "RPC": url }));
    assert!(e.contains("being recovered"), "{e}");
    assert!(!log.lock().unwrap().iter().any(|m| m == "sendrawtransaction"), "prepareSweep must not broadcast");

    let sent = ok(h, "Recovery:broadcast", json!({ "Chain": "bitcoin", "Raw": p["Raw"], "RPC": url }));
    assert_eq!(sent["Txid"], "feedfacefeedface");
    LibwalletDestroy(h);
}

#[test]
fn sweeps_to_an_account_of_the_users_wallet() {
    let h = new_env();
    let w = ok(h, "Wallet", json!({ "Name": "Mine", "Curve": "secp256k1", "Keys": [
        { "Type": "Password", "Key": "passwordone" }, { "Type": "Password", "Key": "passwordtwo" }, { "Type": "Password", "Key": "passwordthree" } ] }));
    let wallet = w["Id"].as_str().unwrap();
    let btc = ok(h, "Account", json!({ "Wallet": wallet, "Type": "bitcoin", "Index": 0 }));
    let eth = ok(h, "Account", json!({ "Wallet": wallet, "Type": "ethereum", "Index": 0 }));

    let s = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    let (url, _) = mock_node(|method, _| match method {
        "modchain_assets" => Some(utxos(100_000_000.0)),
        "estimatesmartfee" => Some(json!({ "feerate": 0.00010000, "blocks": 6 })),
        _ => None,
    });
    let p = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/84'/0'/0'/0/0", "ToAccount": btc["Id"], "RPC": url }));
    // The account's default receive address: what the app shows for it.
    let formats = ok(h, "Account:addressFormats", json!({ "Id": btc["Id"], "Network": "bitcoin.bitcoin" }));
    let default = formats["formats"].as_array().unwrap().iter().find(|f| f["default"] == true).unwrap()["address"].clone();
    assert_eq!(p["To"], default, "{formats}");
    // The same Bitcoin-family account receives on Litecoin at its Litecoin address.
    let p = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "litecoin:p2wpkh:m/84'/2'/0'/0/0", "ToAccount": btc["Id"], "RPC": url }));
    assert!(p["To"].as_str().unwrap().starts_with("ltc1"), "{p}");
    // An account of another chain can't receive.
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/84'/0'/0'/0/0", "ToAccount": eth["Id"], "RPC": url }));
    assert!(e.contains("can't receive bitcoin"), "{e}");
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "bitcoin:p2wpkh:m/84'/0'/0'/0/0", "To": "x", "ToAccount": btc["Id"], "RPC": url }));
    assert!(e.contains("not both"), "{e}");
    LibwalletDestroy(h);
}

#[test]
fn ethereum_sweeps_tokens_and_ether() {
    let h = new_env();
    let s = open(h, json!({ "Type": "keystore", "Keystore": KEYSTORE, "Password": "testpassword" }));
    let (url, log) = mock_node(|method, _| match method {
        "modchain_assets" => Some(json!({ "assets": [
            { "asset": "NATIVE", "balance": "0x56bc75e2d63100000", "decimals": 18, "type": "balance" },
            { "asset": "0x6b175474e89094c44da98b954eedeac495271d0f", "balance": "0x3e8", "decimals": 18, "symbol": "DAI", "type": "erc20" },
        ]})),
        "eth_getTransactionCount" => Some(json!("0x5")),
        "eth_estimateGas" => Some(json!("0xc350")),
        "eth_getBlockByNumber" => Some(json!({ "baseFeePerGas": "0x3b9aca00" })),
        "eth_maxPriorityFeePerGas" => Some(json!("0x3b9aca00")),
        "eth_sendRawTransaction" => Some(json!("0xfeed")),
        _ => None,
    });
    let to = "0x000000000000000000000000000000000000dEaD";
    let scan = ok(h, "Recovery:scan", json!({ "Session": s, "Chains": ["ethereum"], "RPC": url }))["Addresses"][0].clone();
    assert_eq!(scan["Assets"].as_array().unwrap().len(), 2, "{scan}");

    let token = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "ethereum:evm:key", "To": to, "Asset": "0x6b175474e89094c44da98b954eedeac495271d0f", "RPC": url }));
    assert_eq!((token["Amount"].as_str(), token["Symbol"].as_str()), (Some("1000"), Some("DAI")));
    let ether = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "ethereum:evm:key", "To": to, "RPC": url }));
    assert_eq!(ether["Fee"], "63000000000000");
    assert_eq!(ether["Amount"], "99999937000000000000");
    assert!(ether["Raw"].as_str().unwrap().starts_with("0x02"), "EIP-1559");
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "ethereum:evm:key", "To": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "RPC": url }));
    assert!(e.contains("isn't an Ethereum address"), "{e}");
    assert!(!log.lock().unwrap().iter().any(|m| m == "eth_sendRawTransaction"));
    assert_eq!(ok(h, "Recovery:broadcast", json!({ "Chain": "ethereum", "Raw": ether["Raw"], "RPC": url }))["Txid"], "0xfeed");
    LibwalletDestroy(h);
}

/// A Solana wire transaction's `(signature, message)`.
fn solana_parts(raw_b58: &str) -> ([u8; 64], Vec<u8>) {
    let raw = bs58::decode(raw_b58).into_vec().unwrap();
    assert_eq!(raw[0], 1, "one signature");
    (raw[1..65].try_into().unwrap(), raw[65..].to_vec())
}

#[test]
fn solana_sweeps_tokens_and_sol() {
    let h = new_env();
    let s = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let lamports = Arc::new(Mutex::new(5_000_000u64));
    let l = lamports.clone();
    let (url, log) = mock_node(move |method, params| match method {
        "getBalance" => Some(json!({ "value": *l.lock().unwrap() })),
        "getTokenAccountsByOwner" => {
            let filter = &params[1];
            if filter.get("programId").and_then(Value::as_str) == Some("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb") {
                return Some(json!({ "value": [] }));
            }
            Some(json!({ "value": [{ "pubkey": "x", "account": { "data": { "parsed": { "info": {
                "mint": usdc, "tokenAmount": { "amount": "2500000", "decimals": 6 } } } } } }] }))
        }
        "getAccountInfo" => {
            let a = params[0].as_str().unwrap();
            if a == usdc {
                // The mint: SPL Token program owned, 82 bytes, 6 decimals at offset 44.
                let mut data = vec![0u8; 82];
                data[44] = 6;
                data[45] = 1;
                use base64::Engine as _;
                Some(json!({ "value": { "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "data": [base64::engine::general_purpose::STANDARD.encode(&data), "base64"] } }))
            } else {
                Some(json!({ "value": null }))
            }
        }
        "getLatestBlockhash" => Some(json!({ "value": { "blockhash": "11111111111111111111111111111111", "lastValidBlockHeight": 10 } })),
        "getMinimumBalanceForRentExemption" => Some(json!(890880)),
        "sendTransaction" => Some(json!("solsig")),
        _ => None,
    });
    let id = "solana:solana:m/44'/501'/0'/0'";
    let scan = ok(h, "Recovery:scan", json!({ "Session": s, "Chains": ["solana"], "Count": 1, "RPC": url }))["Addresses"].clone();
    let row = scan.as_array().unwrap().iter().find(|r| r["Id"] == id).unwrap().clone();
    let assets = row["Assets"].as_array().unwrap();
    assert_eq!(assets.len(), 2, "{row}");
    assert_eq!((assets[1]["Asset"].as_str(), assets[1]["Symbol"].as_str()), (Some(usdc), Some("USDC")));

    let to = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let public: [u8; 32] = bs58::decode(row["Address"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();
    let token = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": to, "Asset": usdc, "RPC": url }));
    assert_eq!(token["Amount"], "2500000");
    let (sig, msg) = solana_parts(token["Raw"].as_str().unwrap());
    assert!(outscript::crypto::ed25519::verify(&public, &msg, &sig), "token sweep signature");

    // Without SOL for the fee and the recipient's token account, a token can't move.
    *lamports.lock().unwrap() = 1000;
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": to, "Asset": usdc, "RPC": url }));
    assert!(e.contains("needs") && e.contains("SOL"), "{e}");
    *lamports.lock().unwrap() = 5_000_000;

    let sol = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": to, "RPC": url }));
    assert_eq!(sol["Asset"], "NATIVE");
    let (sig, msg) = solana_parts(sol["Raw"].as_str().unwrap());
    assert!(outscript::crypto::ed25519::verify(&public, &msg, &sig), "SOL sweep signature");
    assert_eq!(sol["Txid"], bs58::encode(sig).into_string());
    assert!(!log.lock().unwrap().iter().any(|m| m == "sendTransaction"));
    assert_eq!(ok(h, "Recovery:broadcast", json!({ "Chain": "solana", "Raw": sol["Raw"], "RPC": url }))["Txid"], "solsig");
    LibwalletDestroy(h);
}

#[test]
fn tron_sweeps_trx_and_refuses_tokens_without_energy() {
    let h = new_env();
    let s = open(h, json!({ "Type": "mnemonic", "Mnemonic": MNEMONIC }));
    let trx = Arc::new(Mutex::new(50_000_000u64));
    let t = trx.clone();
    let now = chrono_now_ms();
    let (url, log) = mock_node(move |method, body| match method {
        "getaccount" => {
            if body["address"] == "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH" {
                Some(json!({ "address": "x", "balance": *t.lock().unwrap() }))
            } else {
                Some(json!({}))
            }
        }
        "getaccountresource" => Some(json!({ "freeNetLimit": 600, "freeNetUsed": 0 })),
        "triggerconstantcontract" => Some(json!({ "result": { "result": true }, "constant_result": [format!("{:064x}", 7_000_000u64)] })),
        "getnowblock" => Some(json!({ "blockID": format!("{:016x}{}", 1234u64, "ab".repeat(24)), "block_header": { "raw_data": { "number": 1234, "timestamp": now } } })),
        "broadcasthex" => Some(json!({ "result": true, "txid": "beef" })),
        _ => None,
    });
    let id = "tron:tron:m/44'/195'/0'/0/0";
    let row = ok(h, "Recovery:scan", json!({ "Session": s, "Chains": ["tron"], "Count": 1, "RPC": url }))["Addresses"][0].clone();
    let assets = row["Assets"].as_array().unwrap();
    assert_eq!((assets[0]["Balance"].as_str(), assets[1]["Symbol"].as_str(), assets[1]["Balance"].as_str()), (Some("50000000"), Some("USDT"), Some("7000000")), "{row}");

    let to = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
    let usdt = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf", "Asset": to, "RPC": url }));
    assert_eq!((usdt["Amount"].as_str(), usdt["Symbol"].as_str()), (Some("7000000"), Some("USDT")));
    // A fresh recipient: TRX minus the account-creation fee (bandwidth is free).
    let sweep = ok(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf", "RPC": url }));
    assert_eq!(sweep["Amount"], (50_000_000 - 1_100_000).to_string());
    assert_eq!(sweep["Txid"].as_str().unwrap().len(), 64);

    *trx.lock().unwrap() = 0;
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf", "Asset": to, "RPC": url }));
    assert!(e.contains("burns TRX"), "{e}");
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": id, "To": "0x000000000000000000000000000000000000dEaD", "RPC": url }));
    assert!(e.contains("isn't a Tron address"), "{e}");
    assert!(!log.lock().unwrap().iter().any(|m| m == "broadcasthex"));
    assert_eq!(ok(h, "Recovery:broadcast", json!({ "Chain": "tron", "Raw": sweep["Raw"], "RPC": url }))["Txid"], "beef");
    LibwalletDestroy(h);
}

fn chrono_now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

#[test]
fn monero_is_keys_only() {
    let h = new_env();
    let s = open(h, json!({ "Type": "bitfi", "Salt": "test-salt-0001", "Secret": "correct horse battery staple is thirty+ chars" }));
    let row = ok(h, "Recovery:scan", json!({ "Session": s, "Chains": ["monero"], "Count": 1 }))["Addresses"][0].clone();
    assert!(row["Error"].as_str().unwrap().contains("export the keys"), "{row}");
    let e = err(h, "Recovery:prepareSweep", json!({ "Session": s, "Address": "monero:monero:bitfi:0", "To": "4AqB" }));
    assert!(e.contains("Monero"), "{e}");
    LibwalletDestroy(h);
}
