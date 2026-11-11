//! Air-gapped signer interop end to end over the C-ABI: import a Keystone-style
//! key export, build unsigned requests for each chain, play the "device" with
//! the seed's private keys, feed the device's answer back one QR frame at a
//! time through a decoder context, and check the finalized transactions.
//!
//! The device side is the abandon…about seed, so every address is a public
//! test vector (MetaMask 0x9858…, BIP-84 bc1qcr8…).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use base64::Engine;
use libwallet::airgap::registry::{self, HdKey, KeyPath, MultiAccounts, HARDENED};
use libwallet::airgap::{cbor, ur_parts};
use libwallet::{EventCallback, LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, LibwalletSetEventCallback, ResponseCallback};

extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    tx.send(json).unwrap();
}

fn request(h: usize, body: &str) -> serde_json::Value {
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx)) as usize;
    let req = CString::new(body).unwrap();
    let cb: ResponseCallback = capture;
    LibwalletRequest(h, req.as_ptr(), Some(cb), ud);
    let value = loop {
        let json = rx.recv_timeout(Duration::from_secs(30)).expect("callback fired");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        if v["result"] == "progress" {
            continue;
        }
        break v;
    };
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    value
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-airgap-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0);
    h
}

/// A JSON-RPC mock answering by method name for as many requests as come.
fn mock_rpc_dispatch(routes: Vec<(&'static str, String)>) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { break };
            let mut buf = [0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let reqtxt = String::from_utf8_lossy(&buf[..n]);
            let result = routes.iter().find(|(m, _)| reqtxt.contains(&format!("\"method\":\"{m}\""))).map(|(_, r)| r.clone()).unwrap_or_else(|| "null".into());
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// A plain HTTP mock (java-tron's API): the reply for the first route whose
/// path fragment the request line contains.
fn mock_http(routes: Vec<(&'static str, String)>) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { break };
            let mut buf = [0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let reqtxt = String::from_utf8_lossy(&buf[..n]);
            let line = reqtxt.lines().next().unwrap_or("");
            let body = routes.iter().find(|(m, _)| line.contains(m)).map(|(_, r)| r.clone()).unwrap_or_else(|| "{}".into());
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const XFP: u32 = 0x73c5_da0a;

fn seed() -> Vec<u8> {
    libwallet::bip39::mnemonic_to_seed(M, "").to_vec()
}

/// The device's `crypto-multi-accounts` export: BTC xpub, ETH xpub, SOL leaf.
fn device_export_frames() -> Vec<String> {
    let seed = seed();
    let node = |path: &str| {
        let (_, cc) = libwallet::hdderive::derive_secp_privkey_and_chaincode(&seed, path).unwrap();
        (libwallet::hdderive::derive_pubkey_for_path(&seed, "secp256k1", path).unwrap(), cc)
    };
    let (btc, btc_cc) = node("m/84'/0'/0'");
    let (eth, eth_cc) = node("m/44'/60'/0'");
    let sol = libwallet::hdderive::derive_pubkey_for_path(&seed, "ed25519", "m/44'/501'/0'/0'").unwrap();
    let (tron, tron_cc) = node("m/44'/195'/0'");
    let origin = |p: &str| Some(KeyPath { components: KeyPath::parse(p).unwrap().components, source_fingerprint: Some(XFP), depth: None });
    let m = MultiAccounts {
        master_fingerprint: XFP,
        keys: vec![
            HdKey { key_data: btc, chain_code: Some(btc_cc), origin: origin("m/84'/0'/0'"), ..Default::default() },
            HdKey { key_data: eth, chain_code: Some(eth_cc), origin: origin("m/44'/60'/0'"), note: Some("account.standard".into()), ..Default::default() },
            HdKey { key_data: sol, origin: origin("m/44'/501'/0'/0'"), note: Some("account.standard".into()), ..Default::default() },
            HdKey { key_data: tron, chain_code: Some(tron_cc), origin: origin("m/44'/195'/0'"), ..Default::default() },
        ],
        device: Some("Keystone 3 Pro".into()),
        device_id: Some("TEST-1".into()),
        version: Some("1.0".into()),
    };
    let cbor = cbor::to_bytes(&m.to_cbor()).unwrap();
    // Small fragments so the import itself is a multi-frame animated QR.
    ur_parts(registry::UR_MULTI_ACCOUNTS, &cbor, Some(60), None).unwrap()
}

/// Feed frames through a decoder context like a camera would (reverse order,
/// a duplicate, and skipping the first two so fountain redundancy is used).
fn scan(h: usize, frames: &[String]) -> (String, serde_json::Value) {
    let ctx = request(h, r#"{"path":"Airgap:decoderNew","params":{}}"#);
    let id = ctx["data"]["Id"].as_str().unwrap().to_string();
    let mut last = serde_json::Value::Null;
    let skip = if frames.len() > 4 { 2 } else { 0 };
    // Late frames first (reversed), a duplicate, then — only if the fountain
    // mixes did not already cover them — the skipped early frames.
    let order: Vec<&String> = frames.iter().skip(skip).rev().chain(frames.iter().skip(skip).rev().take(1)).chain(frames.iter().take(skip)).collect();
    for f in order {
        let r = request(h, &serde_json::json!({ "path": "Airgap:decoderFeed", "params": { "Id": id, "Part": f } }).to_string());
        assert_eq!(r["result"], "success", "{r}");
        last = r["data"].clone();
        assert!(last["received"].as_u64().unwrap() <= last["expected"].as_u64().unwrap().max(1), "{last}");
        if last["complete"] == true {
            break;
        }
    }
    assert_eq!(last["complete"], true, "did not complete: {last}");
    assert_eq!(last["percent"], 100);
    (id, last)
}

fn import_device(h: usize) -> serde_json::Value {
    let frames = device_export_frames();
    assert!(frames.len() > 4, "export should be multi-frame: {}", frames.len());
    let (id, prog) = scan(h, &frames);
    assert_eq!(prog["ur_type"], "crypto-multi-accounts");
    assert_eq!(prog["payload"]["decoded"]["device"], "Keystone 3 Pro");

    // Preview, then import from the completed context.
    let preview = request(h, &format!(r#"{{"path":"Airgap:parseKeys","params":{{"DecoderId":"{id}"}}}}"#));
    assert_eq!(preview["result"], "success", "{preview}");
    assert_eq!(preview["data"]["keys"].as_array().unwrap().len(), 4);
    assert_eq!(preview["data"]["keys"][3]["chain"], "tron");
    assert_eq!(preview["data"]["keys"][0]["address"], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(preview["data"]["keys"][1]["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");

    let imported = request(h, &format!(r#"{{"path":"Airgap:importKeys","params":{{"DecoderId":"{id}"}}}}"#));
    assert_eq!(imported["result"], "success", "{imported}");
    assert_eq!(imported["data"]["wallet"]["Protocol"], "airgap");
    assert_eq!(imported["data"]["wallet"]["Name"], "Keystone 3 Pro");
    assert_eq!(imported["data"]["accounts"].as_array().unwrap().len(), 4);
    imported["data"].clone()
}

fn account_of<'a>(imported: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
    imported["accounts"].as_array().unwrap().iter().find(|a| a["Type"] == kind).unwrap()
}

#[test]
fn import_then_sign_ethereum_via_eth_signature() {
    let h = new_env();
    let imported = import_device(h);
    let eth = account_of(&imported, "ethereum");
    assert_eq!(eth["Address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    assert_eq!(eth["Path"], "m/44'/60'/0'/0/0");
    let acct_id = eth["Id"].as_str().unwrap();

    // Offline request: the Transaction is complete, no node involved.
    let req = request(
        h,
        &format!(
            r#"{{"path":"Airgap:signRequest","params":{{"Account":"{acct_id}","Offline":true,"MaxFragmentLen":80,"Transaction":{{"nonce":7,"gas":21000,"gasPrice":"20000000000","to":"0x000000000000000000000000000000000000dEaD","value":"1000000000000000","chainId":1}}}}}}"#
        ),
    );
    assert_eq!(req["result"], "success", "{req}");
    assert_eq!(req["data"]["format"], "eth-sign-request");
    let rid = req["data"]["request_id"].as_str().unwrap().to_string();
    let parts: Vec<String> = req["data"]["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_owned()).collect();
    assert!(parts.iter().all(|p| p.starts_with("UR:ETH-SIGN-REQUEST/")), "{:?}", &parts[0]);

    // Device side: decode the request, check path + fingerprint, sign the preimage.
    let (_, prog) = scan(h, &parts);
    let decoded = &prog["payload"]["decoded"];
    assert_eq!(decoded["derivationPath"], "m/44'/60'/0'/0/0");
    assert_eq!(decoded["masterFingerprint"], "73c5da0a");
    assert_eq!(decoded["dataType"], 1);
    assert_eq!(decoded["chainId"], 1);
    let sign_data = libwallet::airgap::unhex(decoded["signData"].as_str().unwrap()).unwrap();
    assert_eq!(sign_data, libwallet::airgap::unhex(req["data"]["payload"]["signData"].as_str().unwrap()).unwrap());
    let digest = purecrypto::hash::keccak256(&sign_data);
    let priv_key = libwallet::hdderive::derive_privkey_from_seed(&seed(), "secp256k1", "m/44'/60'/0'/0/0").unwrap();
    let sk = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(&priv_key).unwrap();
    let (r, s, recid) = sk.sign_recoverable(&digest);
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&s);
    sig.push(27 + recid); // Keystone-style v
    let answer = registry::EthSignature { request_id: Some(registry::uuid_parse(&rid).unwrap()), signature: sig, origin: Some("Keystone".into()) };
    let answer_frames = ur_parts(registry::UR_ETH_SIGNATURE, &cbor::to_bytes(&answer.to_cbor()).unwrap(), None, None).unwrap();
    assert_eq!(answer_frames.len(), 1);

    // Host side: scan the answer and submit it (no RequestId needed: it is in
    // the eth-signature). Broadcast through a mock node.
    let node = mock_rpc_dispatch(vec![("eth_sendRawTransaction", r#""0xabc""#.into())]);
    let (dec_id, _) = scan(h, &answer_frames);
    let done = request(h, &format!(r#"{{"path":"Airgap:submitSignature","params":{{"DecoderId":"{dec_id}","Broadcast":true,"RPC":"{node}"}}}}"#));
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["chain"], "ethereum");
    assert_eq!(done["data"]["request_id"], rid);
    assert_eq!(done["data"]["broadcast"], "0xabc");
    let raw = libwallet::airgap::unhex(done["data"]["raw"].as_str().unwrap()).unwrap();
    assert_eq!(libwallet::evm::recover_sender(&raw).unwrap().to_lowercase(), "0x9858effd232b4033e47d90003d41ec34ecaeda94");
    // The request is consumed.
    let gone = request(h, &format!(r#"{{"path":"Airgap:pending","params":{{"RequestId":"{rid}"}}}}"#));
    assert_eq!(gone["code"], 404, "{gone}");
    LibwalletDestroy(h);
}

extern "C" fn capture_event(json: *const c_char, user_data: usize) {
    let s = unsafe { CStr::from_ptr(json) }.to_str().unwrap().to_owned();
    LibwalletFree(json as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    let _ = tx.send(s);
}

/// The generic routes work for an air-gapped account: the call emits
/// `airgap:sign` with the request to show, waits, and returns once the host has
/// handed the device's answer to `Airgap:submitSignature`.
#[test]
fn generic_routes_sign_through_the_air_gapped_signer() {
    let h = new_env();
    let (etx, erx) = channel::<String>();
    let eud = Box::into_raw(Box::new(etx)) as usize;
    LibwalletSetEventCallback(h, Some(capture_event as EventCallback), eud);
    let imported = import_device(h);
    let acct_id = account_of(&imported, "ethereum")["Id"].as_str().unwrap().to_owned();
    let wallet_id = imported["wallet"]["Id"].as_str().unwrap().to_owned();
    let node = mock_rpc_dispatch(vec![("eth_sendRawTransaction", r#""0xfeed""#.into())]);

    let wait_request = || loop {
        let ev: serde_json::Value = serde_json::from_str(&erx.recv_timeout(Duration::from_secs(20)).expect("airgap:sign event")).unwrap();
        if ev["event"] == "airgap:sign" {
            break ev["data"].clone();
        }
    };
    let call = |path: &str, extra: &str| {
        let (tx, rx) = channel::<String>();
        let ud = Box::into_raw(Box::new(tx)) as usize;
        let body = format!(
            r#"{{"path":"{path}","params":{{"Id":"{acct_id}"{extra},"Transaction":{{"nonce":7,"gas":21000,"gasPrice":"20000000000","to":"0x000000000000000000000000000000000000dEaD","value":"1000000000000000","chainId":1}}}}}}"#
        );
        let req = CString::new(body).unwrap();
        LibwalletRequest(h, req.as_ptr(), Some(capture as ResponseCallback), ud);
        (rx, ud)
    };
    // The "device": sign the request's preimage with the seed's key.
    let answer = |data: &serde_json::Value| {
        let rid = data["request"]["request_id"].as_str().unwrap().to_owned();
        let sign_data = libwallet::airgap::unhex(data["request"]["payload"]["signData"].as_str().unwrap()).unwrap();
        let priv_key = libwallet::hdderive::derive_privkey_from_seed(&seed(), "secp256k1", "m/44'/60'/0'/0/0").unwrap();
        let sk = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(&priv_key).unwrap();
        let (r, s, recid) = sk.sign_recoverable(&purecrypto::hash::keccak256(&sign_data));
        let mut sig = [r.as_slice(), s.as_slice()].concat();
        sig.push(27 + recid);
        let a = registry::EthSignature { request_id: Some(registry::uuid_parse(&rid).unwrap()), signature: sig, origin: None };
        (rid, ur_parts(registry::UR_ETH_SIGNATURE, &cbor::to_bytes(&a.to_cbor()).unwrap(), None, None).unwrap())
    };
    let finish = |rx: std::sync::mpsc::Receiver<String>, ud: usize| {
        let v: serde_json::Value = serde_json::from_str(&rx.recv_timeout(Duration::from_secs(20)).expect("generic route returned")).unwrap();
        drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
        v
    };

    // signTransaction: signs, does not broadcast.
    let (rx, ud) = call("Account:signTransaction", "");
    let data = wait_request();
    assert_eq!(data["account"], acct_id.as_str());
    assert!(!data["request"]["parts"].as_array().unwrap().is_empty());
    let (_, frames) = answer(&data);
    let submitted = request(h, &format!(r#"{{"path":"Airgap:submitSignature","params":{{"Parts":{}}}}}"#, serde_json::to_string(&frames).unwrap()));
    assert_eq!(submitted["data"]["delivered"], true, "{submitted}");
    let out = finish(rx, ud);
    assert_eq!(out["result"], "success", "{out}");
    let raw = libwallet::airgap::unhex(out["data"]["raw"].as_str().unwrap()).unwrap();
    assert_eq!(libwallet::evm::recover_sender(&raw).unwrap().to_lowercase(), "0x9858effd232b4033e47d90003d41ec34ecaeda94");
    assert!(out["data"].get("broadcast").is_none(), "{out}");

    // signAndSendTransaction: the waiting route broadcasts, the submit does not.
    let (rx, ud) = call("Account:signAndSendTransaction", &format!(r#","RPC":"{node}""#));
    let (_, frames) = answer(&wait_request());
    let submitted = request(h, &format!(r#"{{"path":"Airgap:submitSignature","params":{{"Parts":{},"Broadcast":true,"RPC":"{node}"}}}}"#, serde_json::to_string(&frames).unwrap()));
    assert!(submitted["data"].get("broadcast").is_none(), "{submitted}");
    let out = finish(rx, ud);
    assert_eq!(out["data"]["hash"], "0xfeed", "{out}");

    // Cancelling fails the waiting route with 4001.
    let (rx, ud) = call("Account:signTransaction", "");
    let rid = wait_request()["request"]["request_id"].as_str().unwrap().to_owned();
    let cancelled = request(h, &format!(r#"{{"path":"Airgap:cancelSign","params":{{"RequestId":"{rid}"}}}}"#));
    assert_eq!(cancelled["data"]["cancelled"], true, "{cancelled}");
    assert_eq!(finish(rx, ud)["code"], 4001);

    // Account:signMessage and Account:signTypedData take the same road: the
    // request to show arrives as an event, the answer through submitSignature.
    let typed = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Note":[{"name":"text","type":"string"}]},"primaryType":"Note","domain":{"name":"t"},"message":{"text":"hi"}}"#;
    for (path, field, value, digest) in [
        ("Account:signMessage", "Message", serde_json::json!("aGVsbG8="), libwallet::evm::personal_sign_digest(b"hello")),
        ("Account:signTypedData", "TypedData", serde_json::json!(typed), libwallet::eip712::parse(typed).unwrap().hash().unwrap()),
    ] {
        let (tx, rx) = channel::<String>();
        let ud = Box::into_raw(Box::new(tx)) as usize;
        let body = serde_json::json!({ "path": path, "params": { "Id": acct_id, field: value } }).to_string();
        let req = CString::new(body).unwrap();
        LibwalletRequest(h, req.as_ptr(), Some(capture as ResponseCallback), ud);
        let data = wait_request();
        assert_eq!(data["request"]["format"], "eth-sign-request");
        let rid = data["request"]["request_id"].as_str().unwrap().to_owned();
        let priv_key = libwallet::hdderive::derive_privkey_from_seed(&seed(), "secp256k1", "m/44'/60'/0'/0/0").unwrap();
        let sk = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(&priv_key).unwrap();
        let (r, s, recid) = sk.sign_recoverable(&digest);
        let mut sig = [r.as_slice(), s.as_slice()].concat();
        sig.push(recid); // a bare recovery id is normalized to 27/28
        let a = registry::EthSignature { request_id: Some(registry::uuid_parse(&rid).unwrap()), signature: sig.clone(), origin: None };
        let frames = ur_parts(registry::UR_ETH_SIGNATURE, &cbor::to_bytes(&a.to_cbor()).unwrap(), None, None).unwrap();
        let submitted = request(h, &format!(r#"{{"path":"Airgap:submitSignature","params":{{"Parts":{}}}}}"#, serde_json::to_string(&frames).unwrap()));
        assert_eq!(submitted["data"]["delivered"], true, "{submitted}");
        let out = finish(rx, ud);
        assert_eq!(out["result"], "success", "{path}: {out}");
        sig[64] += 27;
        assert_eq!(out["data"]["signature"], format!("0x{}", libwallet::airgap::hex(&sig)), "{path}");
    }

    // A hardware wallet is left out of backups.
    let all = request(h, r#"{"path":"Wallet:backup","params":{}}"#);
    assert_eq!(all["data"], serde_json::json!([]), "{all}");
    let one = request(h, &format!(r#"{{"path":"Wallet:backup","params":{{"Id":"{wallet_id}"}}}}"#));
    assert_eq!(one["code"], 400, "{one}");

    LibwalletDestroy(h);
    drop(unsafe { Box::from_raw(eud as *mut Sender<String>) });
}

#[test]
fn import_then_sign_solana_via_sol_signature() {
    let h = new_env();
    let imported = import_device(h);
    let sol = account_of(&imported, "solana");
    let acct_id = sol["Id"].as_str().unwrap();
    let sol_pub = libwallet::hdderive::derive_pubkey_for_path(&seed(), "ed25519", "m/44'/501'/0'/0'").unwrap();
    assert_eq!(sol["Address"], bs58::encode(&sol_pub).into_string());

    let bh = bs58::encode([7u8; 32]).into_string();
    let req = request(
        h,
        &format!(
            r#"{{"path":"Airgap:signRequest","params":{{"Account":"{acct_id}","Offline":true,"Transport":"bbqr","MaxPartLen":120,"Transaction":{{"to":"{}","value":"5000","recentBlockhash":"{bh}"}}}}}}"#,
            bs58::encode([9u8; 32]).into_string()
        ),
    );
    assert_eq!(req["result"], "success", "{req}");
    assert_eq!(req["data"]["transport"], "bbqr");
    assert_eq!(req["data"]["format"], "C", "BBQr CBOR file");
    let rid = req["data"]["request_id"].as_str().unwrap().to_string();
    let parts: Vec<String> = req["data"]["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_owned()).collect();
    assert!(parts.len() > 1 && parts.iter().all(|p| p.starts_with("B$")), "{parts:?}");

    // Device: reassemble the BBQr, parse the CBOR as sol-sign-request, sign.
    let (_, prog) = scan(h, &parts);
    assert_eq!(prog["kind"], "bbqr");
    let data = base64::engine::general_purpose::STANDARD.decode(prog["payload"]["data"].as_str().unwrap()).unwrap();
    let sreq = registry::SolSignRequest::from_cbor(&cbor::from_bytes(&data).unwrap()).unwrap();
    assert_eq!(sreq.derivation_path.to_string(), "m/44'/501'/0'/0'");
    assert_eq!(sreq.derivation_path.source_fingerprint, Some(XFP));
    assert_eq!(sreq.address.unwrap().to_vec(), sol_pub);
    let priv_key = libwallet::hdderive::derive_privkey_from_seed(&seed(), "ed25519", "m/44'/501'/0'/0'").unwrap();
    let sig = purecrypto::ec::Ed25519PrivateKey::from_bytes(priv_key).sign(&sreq.sign_data).to_bytes().to_vec();
    let answer = registry::SolSignature { request_id: Some(sreq.request_id), signature: sig.clone() };
    let frames = ur_parts(registry::UR_SOL_SIGNATURE, &cbor::to_bytes(&answer.to_cbor()).unwrap(), None, None).unwrap();

    let done = request(h, &serde_json::json!({ "path": "Airgap:submitSignature", "params": { "Parts": frames } }).to_string());
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["request_id"], rid);
    let raw = bs58::decode(done["data"]["raw"].as_str().unwrap()).into_vec().unwrap();
    // [1 sig][64-byte sig][message]
    assert_eq!(raw[0], 1);
    assert_eq!(&raw[1..65], &sig[..]);
    assert_eq!(&raw[65..], &sreq.sign_data[..]);

    // A wrong signature is refused.
    let bad = registry::SolSignature { request_id: None, signature: vec![1u8; 64] };
    let req2 = request(h, &format!(r#"{{"path":"Airgap:signRequest","params":{{"Account":"{acct_id}","Offline":true,"Transaction":{{"to":"{}","value":"1","recentBlockhash":"{bh}"}}}}}}"#, bs58::encode([9u8; 32]).into_string()));
    let rid2 = req2["data"]["request_id"].as_str().unwrap();
    let frames = ur_parts(registry::UR_SOL_SIGNATURE, &cbor::to_bytes(&bad.to_cbor()).unwrap(), None, None).unwrap();
    let refused = request(h, &serde_json::json!({ "path": "Airgap:submitSignature", "params": { "Parts": frames, "RequestId": rid2 } }).to_string());
    assert_eq!(refused["result"], "error", "{refused}");
    assert!(refused["error"].as_str().unwrap().contains("does not verify"), "{refused}");
    LibwalletDestroy(h);
}

#[test]
fn import_then_sign_bitcoin_via_psbt() {
    use outscript::psbt::Psbt;
    let h = new_env();
    let imported = import_device(h);
    let btc = account_of(&imported, "bitcoin");
    let acct_id = btc["Id"].as_str().unwrap();
    assert_eq!(btc["Path"], "m/84'/0'/0'");

    // The node knows two UTXOs on the account (m/0/0 and m/1/0) and accepts a
    // broadcast.
    let utxos = r#"{"assets":[{"asset":"NATIVE","txo":[
        {"txo":"1111111111111111111111111111111111111111111111111111111111111111:0","amt":"0.00080000","path":"m/0/0","script":"p2wpkh"},
        {"txo":"2222222222222222222222222222222222222222222222222222222222222222:1","amt":"0.00030000","path":"m/1/0","script":"p2wpkh"}]}]}"#;
    let node = mock_rpc_dispatch(vec![("modchain_assets", utxos.into()), ("sendrawtransaction", r#""deadbeef""#.into())]);

    let req = request(
        h,
        &format!(
            r#"{{"path":"Airgap:signRequest","params":{{"Account":"{acct_id}","RPC":"{node}","MaxFragmentLen":100,"Transaction":{{"To":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","Amount":90000,"FeeRate":5}}}}}}"#
        ),
    );
    assert_eq!(req["result"], "success", "{req}");
    assert_eq!(req["data"]["format"], "crypto-psbt");
    let rid = req["data"]["request_id"].as_str().unwrap().to_string();
    let summary = &req["data"]["payload"]["summary"];
    assert_eq!(summary["inputs"], 2, "{summary}");
    assert!(summary["change_sats"].as_u64().unwrap() > 0);
    let parts: Vec<String> = req["data"]["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_owned()).collect();
    assert!(parts.len() > 2);

    // Device: reassemble, inspect bip32 derivations, sign both inputs with the
    // seed's leaf keys, hand back the signed (not finalized) PSBT.
    let (_, prog) = scan(h, &parts);
    assert_eq!(prog["ur_type"], "crypto-psbt");
    let psbt_b64 = prog["payload"]["decoded"]["psbt"].as_str().unwrap();
    assert_eq!(psbt_b64, req["data"]["payload"]["psbt"].as_str().unwrap());
    let unsigned = base64::engine::general_purpose::STANDARD.decode(psbt_b64).unwrap();
    let p = Psbt::parse(&unsigned).unwrap();
    assert_eq!(p.unsigned_tx().input_count(), 2);
    assert_eq!(p.unsigned_tx().output_count(), 2);
    for (n, path) in [(0usize, "m/84'/0'/0'/0/0"), (1, "m/84'/0'/0'/1/0")] {
        let input = p.input(n).unwrap();
        assert!(input.witness_utxo().is_some(), "input {n} has witness_utxo");
        // bip32_derivation (key type 6): value = fingerprint || path (LE u32s).
        let rec = input.map().records_of(6).next().expect("bip32_derivation");
        let val = p.input(n).unwrap().map().get(&{
            let mut k = vec![6u8];
            k.extend_from_slice(rec.key_data());
            k
        }).unwrap();
        assert_eq!(&val[..4], &XFP.to_be_bytes());
        let want = KeyPath::parse(path).unwrap().components;
        let got: Vec<u32> = val[4..].chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        assert_eq!(got, want);
        assert!(got[0] & HARDENED != 0);
    }
    let mut signed = unsigned.clone();
    let mut total = 0;
    for path in ["m/84'/0'/0'/0/0", "m/84'/0'/0'/1/0"] {
        let k = libwallet::hdderive::derive_privkey_from_seed(&seed(), "secp256k1", path).unwrap();
        let sk = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(&k).unwrap();
        let (out, count) = Psbt::parse(&signed).unwrap().sign_to_vec(&sk).unwrap();
        signed = out;
        total += count;
    }
    assert_eq!(total, 2, "both inputs signed by the device");

    // Host: the device shows the signed PSBT as crypto-psbt; combine, finalize,
    // extract, broadcast. Signed PSBTs carry no request id → pass RequestId.
    let frames = ur_parts(registry::UR_PSBT, &registry::psbt_to_cbor(&signed), Some(100), None).unwrap();
    let (dec_id, _) = scan(h, &frames);
    let done = request(h, &format!(r#"{{"path":"Airgap:submitSignature","params":{{"DecoderId":"{dec_id}","RequestId":"{rid}","Broadcast":true,"RPC":"{node}"}}}}"#));
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["chain"], "bitcoin");
    assert_eq!(done["data"]["broadcast"], "deadbeef");
    let raw = libwallet::airgap::unhex(done["data"]["raw"].as_str().unwrap()).unwrap();
    let tx = outscript::btctx::BtcTx::from_bytes(&raw).unwrap();
    assert_eq!(tx.inputs.len(), 2);
    assert!(tx.inputs.iter().all(|i| i.witnesses.len() == 2), "p2wpkh witness [sig, pubkey] on every input");
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(done["data"]["id"].as_str().unwrap().len(), 64);
    let fin = base64::engine::general_purpose::STANDARD.decode(done["data"]["psbt"].as_str().unwrap()).unwrap();
    assert!(Psbt::parse(&fin).unwrap().is_finalized());
    LibwalletDestroy(h);
}

#[test]
fn coldcard_json_over_bbqr_and_generic_encode() {
    let h = new_env();
    // A Coldcard-style export arrives as a BBQr `J` file; encode it the way
    // the device would (Airgap:encode is the generic framer).
    let json = r#"{"chain":"BTC","xfp":"73C5DA0A","bip84":{"name":"p2wpkh","deriv":"m/84'/0'/0'","xpub":"xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"}}"#;
    let enc = request(
        h,
        &serde_json::json!({ "path": "Airgap:encode", "params": { "Transport": "bbqr", "FileType": "J", "Bytes": base64::engine::general_purpose::STANDARD.encode(json), "MaxPartLen": 100 } }).to_string(),
    );
    assert_eq!(enc["result"], "success", "{enc}");
    let parts: Vec<String> = enc["data"]["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_owned()).collect();
    assert!(parts.len() > 1);
    assert!(parts[0].starts_with("B$ZJ") || parts[0].starts_with("B$2J"));

    let one_shot = request(h, &serde_json::json!({ "path": "Airgap:decode", "params": { "Parts": parts } }).to_string());
    assert_eq!(one_shot["data"]["complete"], true, "{one_shot}");
    assert_eq!(one_shot["data"]["file_type"], "J");

    let imported = request(h, &serde_json::json!({ "path": "Airgap:importKeys", "params": { "Parts": parts, "Name": "Coldcard Q" } }).to_string());
    assert_eq!(imported["result"], "success", "{imported}");
    assert_eq!(imported["data"]["export"]["format"], "json");
    assert_eq!(imported["data"]["accounts"][0]["Address"], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(imported["data"]["wallet"]["Name"], "Coldcard Q");

    // A bare zpub pasted as text works too, and the account balance endpoint
    // treats the result like any xpub-backed account.
    let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    let imported2 = request(h, &format!(r#"{{"path":"Airgap:importKeys","params":{{"Payload":"{zpub}"}}}}"#));
    assert_eq!(imported2["result"], "success", "{imported2}");
    assert_eq!(imported2["data"]["accounts"][0]["Address"], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(imported2["data"]["accounts"][0]["Path"], "m/84'/0'/0'");
    LibwalletDestroy(h);
}

// ── Messages, typed data and Tron ────────────────────────────────────────────

fn secp(path: &str) -> outscript::crypto::secp256k1::SecpPrivateKey {
    outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(&libwallet::hdderive::derive_privkey_from_seed(&seed(), "secp256k1", path).unwrap()).unwrap()
}

/// r ‖ s ‖ (27 + recid) over `digest`, as a device answers.
fn rsv(path: &str, digest: &[u8; 32]) -> Vec<u8> {
    let (r, s, recid) = secp(path).sign_recoverable(digest);
    let mut sig = [r.as_slice(), s.as_slice()].concat();
    sig.push(27 + recid);
    sig
}

fn sign_request(h: usize, account: &str, what: serde_json::Value) -> serde_json::Value {
    let mut params = serde_json::json!({ "Account": account, "Offline": true });
    for (k, v) in what.as_object().unwrap() {
        params[k] = v.clone();
    }
    let r = request(h, &serde_json::json!({ "path": "Airgap:signRequest", "params": params }).to_string());
    assert_eq!(r["result"], "success", "{r}");
    r["data"].clone()
}

fn submit(h: usize, ur_type: &str, body: Vec<u8>, extra: serde_json::Value) -> serde_json::Value {
    let frames = ur_parts(ur_type, &body, None, None).unwrap();
    let mut params = serde_json::json!({ "Parts": frames });
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    request(h, &serde_json::json!({ "path": "Airgap:submitSignature", "params": params }).to_string())
}

/// The decoded request a device would see, from the request's own frames.
fn decoded(h: usize, req: &serde_json::Value) -> serde_json::Value {
    let parts: Vec<String> = req["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_owned()).collect();
    scan(h, &parts).1["payload"]["decoded"].clone()
}

#[test]
fn messages_and_typed_data_are_signed_by_the_air_gapped_signer() {
    let h = new_env();
    let imported = import_device(h);
    let b64 = |m: &[u8]| base64::engine::general_purpose::STANDARD.encode(m);
    let rid_of = |req: &serde_json::Value| registry::uuid_parse(req["request_id"].as_str().unwrap()).unwrap();

    // Ethereum personal_sign: eth-sign-request, data type 3, the bare message.
    let eth = account_of(&imported, "ethereum")["Id"].as_str().unwrap().to_owned();
    let req = sign_request(h, &eth, serde_json::json!({ "Message": b64(b"hello keystone") }));
    assert_eq!(req["format"], "eth-sign-request");
    let d = decoded(h, &req);
    assert_eq!(d["dataType"], 3);
    assert_eq!(d["signData"], format!("0x{}", libwallet::airgap::hex(b"hello keystone")));
    assert_eq!(d["derivationPath"], "m/44'/60'/0'/0/0");
    let sig = rsv("m/44'/60'/0'/0/0", &libwallet::evm::personal_sign_digest(b"hello keystone"));
    // A signature by another key is refused, and the request stays pending.
    let wrong = rsv("m/44'/60'/0'/0/1", &libwallet::evm::personal_sign_digest(b"hello keystone"));
    let bad = submit(h, registry::UR_ETH_SIGNATURE, cbor::to_bytes(&registry::EthSignature { request_id: Some(rid_of(&req)), signature: wrong, origin: None }.to_cbor()).unwrap(), serde_json::json!({}));
    assert_eq!(bad["result"], "error", "{bad}");
    // A message signature has nothing to broadcast: asking is harmless.
    let done = submit(h, registry::UR_ETH_SIGNATURE, cbor::to_bytes(&registry::EthSignature { request_id: Some(rid_of(&req)), signature: sig.clone(), origin: None }.to_cbor()).unwrap(), serde_json::json!({ "Broadcast": true }));
    assert!(done["data"].get("broadcast").is_none(), "{done}");
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["type"], "message");
    assert_eq!(done["data"]["signature"], libwallet::walletcore::sign_evm_personal(M, "", "hello keystone").unwrap());

    // EIP-712 typed data: data type 2, the JSON itself.
    let typed = serde_json::json!({
        "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }, { "name": "chainId", "type": "uint256" }],
            "Mail": [{ "name": "to", "type": "address" }, { "name": "contents", "type": "string" }],
        },
        "primaryType": "Mail",
        "domain": { "name": "Ether Mail", "chainId": 1 },
        "message": { "to": "0x000000000000000000000000000000000000dEaD", "contents": "Hello" },
    });
    let req = sign_request(h, &eth, serde_json::json!({ "TypedData": typed }));
    let d = decoded(h, &req);
    assert_eq!(d["dataType"], 2);
    let shown = libwallet::airgap::unhex(d["signData"].as_str().unwrap()).unwrap();
    let digest = libwallet::eip712::parse(std::str::from_utf8(&shown).unwrap()).unwrap().hash().unwrap();
    let done = submit(h, registry::UR_ETH_SIGNATURE, cbor::to_bytes(&registry::EthSignature { request_id: Some(rid_of(&req)), signature: rsv("m/44'/60'/0'/0/0", &digest), origin: None }.to_cbor()).unwrap(), serde_json::json!({}));
    assert_eq!(done["result"], "success", "{done}");
    let sig = libwallet::airgap::unhex(done["data"]["signature"].as_str().unwrap()).unwrap();
    assert_eq!(libwallet::evm::recover_digest_address(&digest, &sig).unwrap(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    // Message requests are UR requests: there is no BBQr form of them.
    let r = request(h, &serde_json::json!({ "path": "Airgap:signRequest", "params": { "Account": eth, "Message": b64(b"x"), "Transport": "bbqr" } }).to_string());
    assert_eq!(r["result"], "error", "{r}");
    // Typed data is an EVM thing.
    let sol = account_of(&imported, "solana")["Id"].as_str().unwrap().to_owned();
    let r = request(h, &serde_json::json!({ "path": "Airgap:signRequest", "params": { "Account": sol, "TypedData": typed } }).to_string());
    assert_eq!(r["result"], "error", "{r}");

    // Solana message: sol-sign-request, sign type 2.
    let req = sign_request(h, &sol, serde_json::json!({ "Message": b64(b"gm solana") }));
    assert_eq!(req["format"], "sol-sign-request");
    assert_eq!(decoded(h, &req)["type"], 2);
    let ed = purecrypto::ec::ed25519::Ed25519PrivateKey::from_bytes(libwallet::hdderive::derive_privkey_from_seed(&seed(), "ed25519", "m/44'/501'/0'/0'").unwrap());
    let sig = ed.sign(b"gm solana").to_bytes().to_vec();
    let done = submit(h, registry::UR_SOL_SIGNATURE, cbor::to_bytes(&registry::SolSignature { request_id: Some(rid_of(&req)), signature: sig.clone() }.to_cbor()).unwrap(), serde_json::json!({}));
    assert_eq!(done["data"]["signature"], bs58::encode(&sig).into_string(), "{done}");

    // Bitcoin message: btc-sign-request for the first receive address; the
    // answer is the 65-byte compact signature (also accepted as base64 text).
    let btc = account_of(&imported, "bitcoin")["Id"].as_str().unwrap().to_owned();
    let req = sign_request(h, &btc, serde_json::json!({ "Message": b64(b"hello bitcoin") }));
    assert_eq!(req["format"], "btc-sign-request");
    let d = decoded(h, &req);
    assert_eq!(d["derivationPath"], "m/84'/0'/0'/0/0");
    assert_eq!(d["addresses"][0], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    let digest = {
        let mut full = b"\x18Bitcoin Signed Message:\n".to_vec();
        full.push(13);
        full.extend_from_slice(b"hello bitcoin");
        outscript::hash::dsha256(&full)
    };
    let (r, s, recid) = secp("m/84'/0'/0'/0/0").sign_recoverable(&digest);
    let compact = [&[39 + recid][..], r.as_slice(), s.as_slice()].concat(); // 39: p2wpkh header
    let done = request(h, &serde_json::json!({ "path": "Airgap:submitSignature", "params": { "Payload": b64(&compact), "RequestId": req["request_id"] } }).to_string());
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["signature"], b64(&compact));
    let req = sign_request(h, &btc, serde_json::json!({ "Message": b64(b"hello bitcoin") }));
    let done = submit(h, registry::UR_BTC_SIGNATURE, cbor::to_bytes(&registry::BtcSignature { request_id: Some(rid_of(&req)), signature: compact.clone(), public_key: None }.to_cbor()).unwrap(), serde_json::json!({}));
    assert_eq!(done["data"]["signature"], b64(&compact), "{done}");
    // A message answer cannot stand in for a transaction request and vice versa.
    let req = sign_request(h, &btc, serde_json::json!({ "Message": b64(b"hello bitcoin") }));
    let done = request(h, &serde_json::json!({ "path": "Airgap:submitSignature", "params": { "Payload": b64(b"psbt\xff\x00"), "RequestId": req["request_id"] } }).to_string());
    assert_eq!(done["result"], "error", "{done}");

    LibwalletDestroy(h);
}

#[test]
fn tron_transfers_and_messages_via_tron_signature() {
    let h = new_env();
    let imported = import_device(h);
    let tron = account_of(&imported, "tron");
    assert_eq!(tron["Path"], "m/44'/195'/0'/0/0");
    let address = tron["Address"].as_str().unwrap().to_owned();
    assert!(address.starts_with('T'), "{address}");
    let id = tron["Id"].as_str().unwrap().to_owned();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let block = serde_json::json!({ "blockID": format!("{:016x}{}", 70_000_000u64, "ab".repeat(24)), "block_header": { "raw_data": { "number": 70_000_000u64, "timestamp": now } } });
    let transfer = serde_json::json!({ "to": "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy", "value": "1500000" });

    // Offline: the reference block comes with the request.
    let mut tx = transfer.clone();
    tx["refBlock"] = block.clone();
    let req = sign_request(h, &id, serde_json::json!({ "Transaction": tx }));
    assert_eq!(req["format"], "tron-sign-request");
    let d = decoded(h, &req);
    assert_eq!(d["dataType"], 1);
    assert_eq!(d["derivationPath"], "m/44'/195'/0'/0/0");
    let raw_data = libwallet::airgap::unhex(d["signData"].as_str().unwrap()).unwrap();
    let rid = registry::uuid_parse(req["request_id"].as_str().unwrap()).unwrap();
    let digest: [u8; 32] = purecrypto::hash::sha256(&raw_data);
    let answer = |sig: Vec<u8>| cbor::to_bytes(&registry::TronSignature { request_id: Some(rid), signature: sig, origin: None }.to_cbor()).unwrap();
    // Another key's signature is refused.
    let bad = submit(h, registry::UR_TRON_SIGNATURE, answer(rsv("m/44'/195'/0'/0/1", &digest)), serde_json::json!({}));
    assert_eq!(bad["result"], "error", "{bad}");
    // The right one is attached and broadcast through the node's HTTP API.
    let node = mock_http(vec![("broadcasthex", r#"{"result":true,"txid":"feedbeef"}"#.into())]);
    let done = submit(h, registry::UR_TRON_SIGNATURE, answer(rsv("m/44'/195'/0'/0/0", &digest)), serde_json::json!({ "Broadcast": true, "RPC": node }));
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(done["data"]["chain"], "tron");
    assert_eq!(done["data"]["id"], libwallet::airgap::hex(&digest));
    assert_eq!(done["data"]["broadcast"], "feedbeef");
    let signed = libwallet::airgap::unhex(done["data"]["raw"].as_str().unwrap()).unwrap();
    assert!(signed.windows(raw_data.len()).any(|w| w == raw_data.as_slice()), "the signed transaction carries the raw data");

    // Without a reference block (and no node) there is nothing to anchor on.
    let r = request(h, &serde_json::json!({ "path": "Airgap:signRequest", "params": { "Account": id, "Offline": true, "Transaction": transfer } }).to_string());
    assert_eq!(r["result"], "error", "{r}");

    // A Tron message: data type 2, signed as TronWeb's signMessageV2.
    let req = sign_request(h, &id, serde_json::json!({ "Message": base64::engine::general_purpose::STANDARD.encode(b"hello tron") }));
    assert_eq!(decoded(h, &req)["dataType"], 2);
    let digest = libwallet::tron::message_digest(b"hello tron");
    let rid = registry::uuid_parse(req["request_id"].as_str().unwrap()).unwrap();
    let sig = rsv("m/44'/195'/0'/0/0", &digest);
    let done = submit(h, registry::UR_TRON_SIGNATURE, cbor::to_bytes(&registry::TronSignature { request_id: Some(rid), signature: sig.clone(), origin: None }.to_cbor()).unwrap(), serde_json::json!({}));
    assert_eq!(done["data"]["type"], "message", "{done}");
    assert_eq!(done["data"]["signature"], format!("0x{}", libwallet::airgap::hex(&sig)));

    LibwalletDestroy(h);
}

/// The software path's explicit `{UTXOs, Outputs}` shape: every input is
/// spent, the outputs are exactly the ones listed, the rest is the fee.
#[test]
fn bitcoin_explicit_inputs_and_outputs() {
    let h = new_env();
    let imported = import_device(h);
    let btc = account_of(&imported, "bitcoin")["Id"].as_str().unwrap().to_owned();
    let utxos = serde_json::json!([
        { "txid": "11".repeat(32), "vout": 1, "amount": 60_000, "path": "m/0/0" },
        { "txo": format!("{}:0", "22".repeat(32)), "amount_sats": 50_000, "path": "m/0/3" },
    ]);
    let change = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"; // m/84'/0'/0'/1/0
    let outputs = serde_json::json!([
        { "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "amount": 70_000 },
        { "address": change, "amount": 38_500, "path": "m/1/0" },
    ]);
    let req = sign_request(h, &btc, serde_json::json!({ "Transaction": { "UTXOs": utxos, "Outputs": outputs } }));
    let summary = &req["payload"]["summary"];
    assert_eq!(summary["inputs"], 2, "{summary}");
    assert_eq!(summary["outputs"], 2);
    assert_eq!(summary["fee_sats"], 1_500);
    let psbt = base64::engine::general_purpose::STANDARD.decode(req["payload"]["psbt"].as_str().unwrap()).unwrap();
    let p = outscript::psbt::Psbt::parse(&psbt).unwrap();
    assert_eq!(p.unsigned_tx().input_count(), 2);
    // The change output names its key, so the signer can tell it is ours.
    let needle = [&XFP.to_be_bytes()[..], &(84u32 | HARDENED).to_le_bytes(), &HARDENED.to_le_bytes(), &HARDENED.to_le_bytes(), &1u32.to_le_bytes(), &0u32.to_le_bytes()].concat();
    assert!(psbt.windows(needle.len()).any(|w| w == needle.as_slice()), "change derivation missing");

    // An output claimed as the account's that is not, and outputs that exceed
    // the inputs, are refused.
    let bad = |outputs: serde_json::Value| {
        request(h, &serde_json::json!({ "path": "Airgap:signRequest", "params": { "Account": btc, "Offline": true, "Transaction": { "UTXOs": utxos, "Outputs": outputs } } }).to_string())
    };
    let r = bad(serde_json::json!([{ "address": change, "amount": 1_000, "path": "m/1/1" }]));
    assert_eq!(r["result"], "error", "{r}");
    let r = bad(serde_json::json!([{ "address": change, "amount": 200_000 }]));
    assert_eq!(r["result"], "error", "{r}");
    LibwalletDestroy(h);
}
