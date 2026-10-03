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
use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};

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
    let origin = |p: &str| Some(KeyPath { components: KeyPath::parse(p).unwrap().components, source_fingerprint: Some(XFP), depth: None });
    let m = MultiAccounts {
        master_fingerprint: XFP,
        keys: vec![
            HdKey { key_data: btc, chain_code: Some(btc_cc), origin: origin("m/84'/0'/0'"), ..Default::default() },
            HdKey { key_data: eth, chain_code: Some(eth_cc), origin: origin("m/44'/60'/0'"), note: Some("account.standard".into()), ..Default::default() },
            HdKey { key_data: sol, origin: origin("m/44'/501'/0'/0'"), note: Some("account.standard".into()), ..Default::default() },
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
    assert_eq!(preview["data"]["keys"].as_array().unwrap().len(), 3);
    assert_eq!(preview["data"]["keys"][0]["address"], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(preview["data"]["keys"][1]["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");

    let imported = request(h, &format!(r#"{{"path":"Airgap:importKeys","params":{{"DecoderId":"{id}"}}}}"#));
    assert_eq!(imported["result"], "success", "{imported}");
    assert_eq!(imported["data"]["wallet"]["Protocol"], "airgap");
    assert_eq!(imported["data"]["wallet"]["Name"], "Keystone 3 Pro");
    assert_eq!(imported["data"]["accounts"].as_array().unwrap().len(), 3);
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

    // Signing through the TSS endpoints is refused for an airgap account.
    let refused = request(h, &format!(r#"{{"path":"Account:signMessage","params":{{"Id":"{acct_id}","Message":"aGVsbG8=","Keys":[]}}}}"#));
    assert_eq!(refused["result"], "error", "{refused}");

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
