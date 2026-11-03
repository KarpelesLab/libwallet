//! `Account:signTransaction` on a complete serialized Solana transaction
//! (legacy or v0), the shape swap aggregators, dApps and the browser app hand
//! over: the account's signature is spliced into its own slot, the message and
//! every other signer's slot are left untouched. Driven through the C-ABI
//! against FROST (MPC) accounts, root and derived, and the 1-of-1 mnemonic and
//! private-key imports.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use base64::Engine as _;
use libwallet::solana::{build_transfer_message, tx_message};
use libwallet::tss::ed25519_verify;
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
    let dir = std::env::temp_dir().join(format!("libwallet-solana-raw-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0);
    h
}

/// A 2-of-3 FROST wallet and its Solana account at `index`; returns (account
/// id, 32-byte pubkey, two of the three unlock Keys).
fn frost_account(h: usize, index: u32) -> (String, [u8; 32], Value) {
    let w = request(
        h,
        &json!({"path":"Wallet","verb":"POST","params":{"Name":"W","Curve":"ed25519","Keys":[
            {"Type":"Password","Key":"passwordone"},
            {"Type":"Password","Key":"passwordtwo"},
            {"Type":"Password","Key":"passwordthree"}]}}),
    );
    let wallet_id = w["data"]["Id"].as_str().expect("wallet created").to_string();
    let keys = json!([
        {"Type":"Password","Id":w["data"]["Keys"][0]["Id"],"Key":"passwordone"},
        {"Type":"Password","Id":w["data"]["Keys"][2]["Id"],"Key":"passwordthree"},
    ]);
    let a = request(
        h,
        &json!({"path":"Account","verb":"POST","params":{"Wallet":wallet_id,"Type":"solana","Index":index}}),
    );
    let pk: [u8; 32] = bs58::decode(a["data"]["Address"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();
    (a["data"]["Id"].as_str().unwrap().to_string(), pk, keys)
}

fn sign(h: usize, id: &str, keys: &Value, tx: Value) -> Value {
    request(h, &json!({"path":"Account:signTransaction","verb":"POST","params":{"Id":id,"Keys":keys,"Transaction":tx}}))
}

/// A v0 message with two required signers — `fee_payer` (slot 0) and `signer`
/// (slot 1) — one program instruction and one address-lookup-table entry.
fn v0_message(fee_payer: &[u8; 32], signer: &[u8; 32]) -> Vec<u8> {
    let mut m = vec![0x80, 2, 0, 1, 3];
    m.extend_from_slice(fee_payer);
    m.extend_from_slice(signer);
    m.extend_from_slice(&[0x42; 32]); // program
    m.extend_from_slice(&[0x09; 32]); // recent blockhash
    m.extend_from_slice(&[1, 2, 2, 0, 1, 3, 0xde, 0xad, 0xbe]); // 1 ix: prog 2, accts [0,1], 3 data bytes
    m.push(1); // 1 lookup table
    m.extend_from_slice(&[0x77; 32]);
    m.extend_from_slice(&[1, 0, 0]); // writable [0], readonly []
    m
}

/// `[shortvec(n)][n zeroed signatures][message]`, optionally pre-filling slot 0.
fn unsigned_tx(n: u8, msg: &[u8], slot0: Option<[u8; 64]>) -> Vec<u8> {
    let mut tx = vec![n];
    tx.extend(std::iter::repeat_n(0u8, n as usize * 64));
    if let Some(s) = slot0 {
        tx[1..65].copy_from_slice(&s);
    }
    tx.extend_from_slice(msg);
    tx
}

#[test]
fn v0_cosigns_its_own_slot_derived_account() {
    let h = new_env();
    let (id, pk, keys) = frost_account(h, 1);
    let fee_payer = [0x55u8; 32];
    let msg = v0_message(&fee_payer, &pk);
    let payer_sig = [0xabu8; 64];
    let tx = unsigned_tx(2, &msg, Some(payer_sig));

    // Dart form: `Transaction` is the bare base64 string.
    let r = sign(h, &id, &keys, json!(base64::engine::general_purpose::STANDARD.encode(&tx)));
    assert_eq!(r["result"], "success", "{r}");
    let signed = base64::engine::general_purpose::STANDARD.decode(r["data"]["transaction"].as_str().unwrap()).unwrap();
    assert_eq!(bs58::decode(r["data"]["raw"].as_str().unwrap()).into_vec().unwrap(), signed);

    assert_eq!(signed.len(), tx.len());
    assert_eq!(tx_message(&signed).unwrap(), msg.as_slice(), "message must be signed untouched");
    assert_eq!(&signed[1..65], &payer_sig, "fee payer's slot must be left as is");
    let sig: [u8; 64] = signed[65..129].try_into().unwrap();
    assert!(ed25519_verify(&pk, &msg, &sig));
    assert_eq!(r["data"]["signature"].as_str().unwrap(), bs58::encode(sig).into_string());
    LibwalletDestroy(h);
}

#[test]
fn legacy_tx_object_form_base58() {
    let h = new_env();
    let (id, pk, keys) = frost_account(h, 0);
    let msg = build_transfer_message(&pk, &[7u8; 32], 1_000, &[9u8; 32]);
    let tx = unsigned_tx(1, &msg, None);

    // dApp form: `{transaction: "..."}`, here base58.
    let r = sign(h, &id, &keys, json!({ "transaction": bs58::encode(&tx).into_string() }));
    assert_eq!(r["result"], "success", "{r}");
    let signed = bs58::decode(r["data"]["raw"].as_str().unwrap()).into_vec().unwrap();
    let sig: [u8; 64] = signed[1..65].try_into().unwrap();
    assert!(ed25519_verify(&pk, &msg, &sig));
    LibwalletDestroy(h);
}

#[test]
fn refuses_tx_not_signed_by_account() {
    let h = new_env();
    let (id, pk, keys) = frost_account(h, 0);
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

    // The account is only a recipient.
    let msg = build_transfer_message(&[3u8; 32], &pk, 1_000, &[9u8; 32]);
    let r = sign(h, &id, &keys, json!(b64(&unsigned_tx(1, &msg, None))));
    assert_eq!(r["result"], "error", "{r}");

    // Signature array shorter than the header's numRequiredSignatures.
    let msg = v0_message(&[0x55u8; 32], &pk);
    let r = sign(h, &id, &keys, json!(b64(&unsigned_tx(1, &msg, None))));
    assert_eq!(r["result"], "error", "{r}");

    // Not a transaction at all.
    let r = sign(h, &id, &keys, json!("hello world"));
    assert_eq!(r["result"], "error", "{r}");
    LibwalletDestroy(h);
}

#[test]
fn native_transfer_form_still_builds() {
    let h = new_env();
    let (id, pk, keys) = frost_account(h, 0);
    let r = sign(
        h,
        &id,
        &keys,
        json!({"to":"11111111111111111111111111111112","value":"1000","recentBlockhash":"11111111111111111111111111111111"}),
    );
    assert_eq!(r["result"], "success", "{r}");
    let signed = bs58::decode(r["data"]["raw"].as_str().unwrap()).into_vec().unwrap();
    let sig: [u8; 64] = signed[1..65].try_into().unwrap();
    assert!(ed25519_verify(&pk, tx_message(&signed).unwrap(), &sig));
    LibwalletDestroy(h);
}

/// The field names integrators reach for all sign the same transaction.
#[test]
fn serialized_field_aliases() {
    let h = new_env();
    let (id, pk, keys) = frost_account(h, 0);
    let msg = build_transfer_message(&pk, &[7u8; 32], 1_000, &[9u8; 32]);
    let b64 = base64::engine::general_purpose::STANDARD.encode(unsigned_tx(1, &msg, None));
    for field in ["transaction", "serializedTransaction", "raw"] {
        let r = sign(h, &id, &keys, json!({ field: b64 }));
        assert_eq!(r["result"], "success", "{field}: {r}");
        let signed = bs58::decode(r["data"]["raw"].as_str().unwrap()).into_vec().unwrap();
        assert_eq!(tx_message(&signed).unwrap(), msg.as_slice(), "{field}");
    }
    LibwalletDestroy(h);
}

/// Signing `{to, value, mint}` as a plain transfer would move `value` lamports of
/// SOL instead of the token. Nothing the signer doesn't understand gets ignored.
#[test]
fn refuses_transaction_it_would_misread() {
    let h = new_env();
    let (id, pk, keys) = frost_account(h, 0);
    let transfer = json!({"to":"11111111111111111111111111111112","value":"1000","recentBlockhash":"11111111111111111111111111111111"});
    let b64 = base64::engine::general_purpose::STANDARD
        .encode(unsigned_tx(1, &build_transfer_message(&pk, &[7u8; 32], 1_000, &[9u8; 32]), None));

    for field in ["mint", "token", "instructions", "programId"] {
        let mut tx = transfer.clone();
        tx[field] = json!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let r = sign(h, &id, &keys, tx);
        assert_eq!(r["result"], "error", "{field}: {r}");
        assert!(r["error"].as_str().unwrap().contains(field), "{field}: {r}");
    }
    for tx in [
        json!({ "transaction": b64, "to": "11111111111111111111111111111112" }), // which one is it?
        json!({ "transaction": b64, "raw": b64 }),
        json!({ "raw": 42 }),
        json!(42),
    ] {
        let r = sign(h, &id, &keys, tx.clone());
        assert_eq!(r["result"], "error", "{tx}: {r}");
    }
    LibwalletDestroy(h);
}

/// The same refusal on the broadcast path, before anything reaches the node.
#[test]
fn sign_and_send_refuses_token_fields() {
    let h = new_env();
    let (id, _, keys) = frost_account(h, 0);
    let r = request(
        h,
        &json!({"path":"Account:signAndSendTransaction","verb":"POST","params":{
            "Id":id,"Keys":keys,"RPC":"http://127.0.0.1:9/",
            "Transaction":{"to":"11111111111111111111111111111112","value":"1000","mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}}}),
    );
    assert_eq!(r["result"], "error", "{r}");
    assert!(r["error"].as_str().unwrap().contains("mint"), "{r}");
    LibwalletDestroy(h);
}

/// Seed-phrase and imported-key accounts sign serialized transactions as well,
/// legacy and v0, without their message changing.
#[test]
fn mnemonic_and_imported_accounts_sign() {
    let h = new_env();
    let key = "seal-password";
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    for (path, secret) in [
        ("Wallet:importMnemonic", json!({ "Mnemonic": mnemonic })),
        ("Wallet:importPrivateKey", json!({ "PrivateKey": "11".repeat(32) })),
    ] {
        let mut params = json!({"Name":"I","Curve":"ed25519","Keys":[{"Type":"Password","Key":key}]});
        params.as_object_mut().unwrap().extend(secret.as_object().unwrap().clone());
        let w = request(h, &json!({"path":path,"verb":"POST","params":params}));
        assert_eq!(w["result"], "success", "{path}: {w}");
        let keys = json!([{"Type":"Password","Id":w["data"]["Keys"][0]["Id"],"Key":key}]);
        let a = request(
            h,
            &json!({"path":"Account","verb":"POST","params":{"Wallet":w["data"]["Id"],"Type":"solana","Index":0,"Keys":keys}}),
        );
        assert_eq!(a["result"], "success", "{path}: {a}");
        let id = a["data"]["Id"].as_str().unwrap();
        let pk: [u8; 32] = bs58::decode(a["data"]["Address"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();

        let legacy = build_transfer_message(&pk, &[7u8; 32], 1_000, &[9u8; 32]);
        for (msg, n, slot) in [(legacy, 1u8, 0usize), (v0_message(&[0x55u8; 32], &pk), 2, 1)] {
            let r = sign(h, id, &keys, json!(base64::engine::general_purpose::STANDARD.encode(unsigned_tx(n, &msg, None))));
            assert_eq!(r["result"], "success", "{path}: {r}");
            let signed = bs58::decode(r["data"]["raw"].as_str().unwrap()).into_vec().unwrap();
            assert_eq!(tx_message(&signed).unwrap(), msg.as_slice(), "{path}");
            let sig: [u8; 64] = signed[1 + slot * 64..1 + (slot + 1) * 64].try_into().unwrap();
            assert!(ed25519_verify(&pk, &msg, &sig), "{path}");
        }
    }
    LibwalletDestroy(h);
}

/// The mnemonic-only browser signer has the same rule: it builds SOL transfers,
/// so a token field must not be dropped on the way to one.
#[test]
fn walletcore_transfer_refuses_unknown_fields() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let transfer = json!({"to":"11111111111111111111111111111112","lamports":1000,"recentBlockhash":"11111111111111111111111111111111"});
    assert!(libwallet::walletcore::sign_solana_transfer(mnemonic, "", &transfer.to_string()).is_ok());

    let mut with_mint = transfer.clone();
    with_mint["mint"] = json!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    assert!(libwallet::walletcore::sign_solana_transfer(mnemonic, "", &with_mint.to_string()).is_err());
}
