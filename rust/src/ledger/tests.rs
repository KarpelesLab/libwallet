//! The device operations against a simulated device: a `Transport` that
//! answers the Ethereum / Solana / Bitcoin app APDUs from a test mnemonic,
//! signing for real. (The Bitcoin app's PSBT protocol is not simulated.)

use std::cell::RefCell;

use outscript::crypto::secp256k1::SecpPrivateKey;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use serde_json::{json, Value};

use super::*;
use crate::airgap::import::{import, ImportOptions};
use crate::{bip39, hdderive};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// A device running one app, holding `mnemonic`'s keys.
struct FakeLedger {
    app: &'static str,
    seed: Vec<u8>,
    /// Refuse every signing request, as a user pressing "reject" would.
    refuse: bool,
    sent: RefCell<Vec<Vec<u8>>>,
}

impl FakeLedger {
    fn new(app: &'static str, mnemonic: &str) -> Self {
        FakeLedger { app, seed: bip39::mnemonic_to_seed(mnemonic, "").to_vec(), refuse: false, sent: RefCell::new(Vec::new()) }
    }

    /// `count(1) ‖ u32be…` → ("m/44'/…", bytes consumed).
    fn path(data: &[u8]) -> (String, usize) {
        let n = data[0] as usize;
        let mut s = String::from("m");
        for i in 0..n {
            let c = u32::from_be_bytes(data[1 + 4 * i..5 + 4 * i].try_into().unwrap());
            s.push_str(&if c & HARDENED != 0 { format!("/{}'", c & !HARDENED) } else { format!("/{c}") });
        }
        (s, 1 + 4 * n)
    }

    fn secp(&self, path: &str) -> SecpPrivateKey {
        SecpPrivateKey::from_bytes(&hdderive::derive_privkey_from_seed(&self.seed, "secp256k1", path).unwrap()).unwrap()
    }

    fn ed(&self, path: &str) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(hdderive::derive_privkey_from_seed(&self.seed, "ed25519", path).unwrap())
    }

    fn ok(mut data: Vec<u8>) -> Vec<u8> {
        data.extend([0x90, 0x00]);
        data
    }

    fn handle(&self, apdu: &[u8]) -> Vec<u8> {
        let (cla, ins, p1) = (apdu[0], apdu[1], apdu[2]);
        let data = if apdu.len() > 5 { &apdu[5..] } else { &[][..] };
        match (cla, ins) {
            // GET_APP_AND_VERSION
            (0xb0, 0x01) => {
                let mut d = vec![1, self.app.len() as u8];
                d.extend(self.app.as_bytes());
                d.extend([5, b'1', b'.', b'2', b'.', b'3']);
                Self::ok(d)
            }
            _ if self.app == "Ethereum" && cla == 0xe0 => self.eth(ins, data),
            _ if self.app == "Solana" && cla == 0xe0 => self.sol(ins, data),
            _ if self.app == "Bitcoin" && cla == 0xe1 => self.btc(ins, p1, data),
            _ => vec![0x6e, 0x00],
        }
    }

    fn eth(&self, ins: u8, data: &[u8]) -> Vec<u8> {
        let (path, n) = Self::path(data);
        let key = self.secp(&path);
        match ins {
            // GET_PUBLIC_KEY: LV(uncompressed key) ‖ LV(ascii address)
            0x02 => {
                let compressed = hdderive::derive_pubkey_for_path(&self.seed, "secp256k1", &path).unwrap();
                let address = hdderive::evm_address(&compressed).unwrap();
                let pk = outscript::crypto::secp256k1::SecpPublicKey::from_sec1(&compressed).unwrap().serialize_uncompressed();
                let mut d = vec![65];
                d.extend_from_slice(&pk);
                let ascii = address.trim_start_matches("0x").to_lowercase();
                d.push(ascii.len() as u8);
                d.extend(ascii.as_bytes());
                Self::ok(d)
            }
            _ if self.refuse => vec![0x69, 0x85],
            // SIGN (transaction): v(1) ‖ r ‖ s over keccak(unsigned)
            0x04 => {
                let unsigned = &data[n..];
                let (r, s, recid) = key.sign_recoverable(&purecrypto::hash::keccak256(unsigned));
                // Typed: the parity. Legacy: chain_id*2+35+parity, one byte.
                let v = if unsigned[0] < 0x80 {
                    recid
                } else {
                    // Unsigned EIP-155 RLP: […6 fields, chain_id, 0, 0].
                    let (item, _) = outscript::rlp::decode_one(unsigned).unwrap();
                    let chain_id = outscript::rlp::decode_uint64_checked(item.as_list().unwrap()[6].as_bytes().unwrap()).unwrap();
                    ((chain_id * 2 + 35 + recid as u64) % 256) as u8
                };
                let mut d = vec![v];
                d.extend_from_slice(&r);
                d.extend_from_slice(&s);
                Self::ok(d)
            }
            // SIGN_PERSONAL_MESSAGE: path ‖ len(4) ‖ message
            0x08 => {
                let message = &data[n + 4..];
                let (r, s, recid) = key.sign_recoverable(&crate::evm::personal_sign_digest(message));
                let mut d = vec![27 + recid];
                d.extend_from_slice(&r);
                d.extend_from_slice(&s);
                Self::ok(d)
            }
            _ => vec![0x6d, 0x00],
        }
    }

    fn sol(&self, ins: u8, data: &[u8]) -> Vec<u8> {
        match ins {
            // GET_PUBKEY
            0x05 => {
                let (path, _) = Self::path(data);
                Self::ok(self.ed(&path).public_key().to_bytes().to_vec())
            }
            _ if self.refuse => vec![0x69, 0x85],
            // SIGN: signer count(1) ‖ path ‖ message
            0x06 => {
                let (path, n) = Self::path(&data[1..]);
                Self::ok(self.ed(&path).sign(&data[1 + n..]).to_bytes().to_vec())
            }
            _ => vec![0x6d, 0x00],
        }
    }

    fn btc(&self, ins: u8, _p1: u8, data: &[u8]) -> Vec<u8> {
        match ins {
            // GET_MASTER_FINGERPRINT
            0x05 => Self::ok(vec![0x73, 0xc5, 0xda, 0x0a]),
            // GET_EXTENDED_PUBKEY: display(1) ‖ path
            0x00 => {
                let (path, _) = Self::path(&data[1..]);
                let pk: [u8; 33] = hdderive::derive_pubkey_for_path(&self.seed, "secp256k1", &path).unwrap().try_into().unwrap();
                Self::ok(crate::bitcoin::build_xpub(&pk, &[7u8; 32]).into_bytes())
            }
            _ => vec![0x6d, 0x00],
        }
    }
}

impl Transport for FakeLedger {
    async fn exchange(&self, apdu: &[u8]) -> lsdk::Result<Vec<u8>> {
        self.sent.borrow_mut().push(apdu.to_vec());
        Ok(self.handle(apdu))
    }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    crate::models::wallet::init(&env).unwrap();
    crate::models::account::init(&env).unwrap();
    crate::models::network::init(&env).unwrap();
    env
}

fn run<F: std::future::Future>(f: F) -> F::Output {
    crate::rt::block_on(f)
}

fn query() -> KeyQuery {
    KeyQuery::from_params(&json!({})).unwrap()
}

/// Read the open app's keys and import them as (or into) a Ledger wallet.
fn import_app(env: &Env, app: &'static str, wallet: Option<&str>) -> crate::airgap::import::Imported {
    let device = Device::new(FakeLedger::new(app, MNEMONIC));
    let export = run(keys(env, &device, &query())).unwrap();
    import(env, &export, &ImportOptions { protocol: Some("ledger".into()), wallet: wallet.map(str::to_owned), ..Default::default() }).unwrap()
}

#[test]
fn keys_match_the_mnemonic_and_import_into_one_wallet() {
    let env = env();
    let want = crate::walletcore::derive_addresses(MNEMONIC, "").unwrap();

    let eth = import_app(&env, "Ethereum", None);
    assert_eq!(eth.wallet.protocol, "ledger");
    assert_eq!(eth.wallet.name, "Ledger");
    assert_eq!(eth.accounts.len(), 1);
    assert_eq!(eth.accounts[0].kind, "ethereum");
    assert_eq!(eth.accounts[0].address, want.evm);
    assert_eq!(eth.accounts[0].path, "m/44'/60'/0'/0/0");

    // The other apps' keys join the same wallet; nothing is duplicated.
    let sol = import_app(&env, "Solana", Some(&eth.wallet.id));
    assert_eq!(sol.wallet.id, eth.wallet.id);
    assert_eq!(sol.accounts[0].address, want.solana);
    let btc = import_app(&env, "Bitcoin", Some(&eth.wallet.id));
    assert_eq!(btc.accounts[0].kind, "bitcoin");
    assert_eq!(btc.accounts[0].path, "m/84'/0'/0'");
    assert!(btc.accounts[0].address.starts_with("bc1q"), "{}", btc.accounts[0].address);
    let (_, info) = load_account(&env, &btc.accounts[0].id).unwrap();
    assert_eq!(info.master_fingerprint.as_deref(), Some("73c5da0a"));
    assert_eq!(info.script, "p2wpkh");
    assert!(import_app(&env, "Ethereum", Some(&eth.wallet.id)).accounts.is_empty(), "the same key was imported twice");

    let all: Vec<_> = crate::models::account::list(&env).unwrap().into_iter().filter(|a| a.wallet == eth.wallet.id).collect();
    assert_eq!(all.len(), 3);
}

#[test]
fn keys_need_a_supported_app_and_sane_parameters() {
    let env = env();
    let err = run(keys(&env, &Device::new(FakeLedger::new("BOLOS", MNEMONIC)), &query())).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);
    assert!(KeyQuery::from_params(&json!({ "Count": 0 })).is_err());
    assert!(KeyQuery::from_params(&json!({ "Count": 21 })).is_err());
    assert!(KeyQuery::from_params(&json!({ "Account": 0x8000_0000u32 })).is_err());

    let q = KeyQuery::from_params(&json!({ "Account": 1, "Count": 2 })).unwrap();
    let export = run(keys(&env, &Device::new(FakeLedger::new("Ethereum", MNEMONIC)), &q)).unwrap();
    assert_eq!(export.keys.iter().map(|k| k.path.as_str()).collect::<Vec<_>>(), ["m/44'/60'/1'/0/0", "m/44'/60'/2'/0/0"]);
}

#[test]
fn only_ledger_wallet_accounts_are_signed_for() {
    let env = env();
    let eth = import_app(&env, "Ethereum", None);
    assert!(load_account(&env, &eth.accounts[0].id).is_ok());
    assert_eq!(load_account(&env, "acct-nope").unwrap_err().code, 404);
    // The software signing paths refuse a Ledger account, naming the route.
    let err = crate::evm::personal_sign(&env, &eth.accounts[0].id, &[], b"hi").unwrap_err().to_string();
    assert!(err.contains("Ledger"), "{err}");
}

fn evm_tx() -> Value {
    json!({
        "to": "0x000000000000000000000000000000000000dEaD", "value": "1000000000000000",
        "nonce": 7, "gas": 21000, "chainId": 1,
        "maxFeePerGas": "30000000000", "maxPriorityFeePerGas": "1000000000",
    })
}

#[test]
fn evm_transaction_is_signed_and_bound_to_the_account() {
    let env = env();
    let account = import_app(&env, "Ethereum", None).accounts.remove(0);
    let (account, info) = load_account(&env, &account.id).unwrap();

    for tx in [evm_tx(), json!({ "to": "0x000000000000000000000000000000000000dEaD", "value": "5", "nonce": 0, "gas": 21000, "chainId": 137, "gasPrice": "1000000000" })] {
        let device = Device::new(FakeLedger::new("Ethereum", MNEMONIC));
        let out = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": tx, "Offline": true }))).unwrap();
        let raw = unhex(out["raw"].as_str().unwrap()).unwrap();
        assert!(crate::evm::recover_sender(&raw).unwrap().eq_ignore_ascii_case(&account.address), "{out}");
        let signed = outscript::evmtx::EvmTx::from_bytes(&raw).unwrap();
        assert_eq!(signed.chain_id, tx["chainId"].as_u64().unwrap());
        assert_eq!(signed.nonce, tx["nonce"].as_u64().unwrap());
        // Exactly one signing APDU carried the preimage of the returned tx.
        assert_eq!(device.transport().sent.borrow().iter().filter(|a| a[0] == 0xe0 && a[1] == 0x04).count(), 1);
    }

    // A device holding other keys signs fine — but not as this account.
    let wrong = Device::new(FakeLedger::new("Ethereum", OTHER));
    let err = run(sign_transaction(&env, &wrong, &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);

    // The wrong app, a refusal on the device, and an incomplete offline tx.
    let err = run(sign_transaction(&env, &Device::new(FakeLedger::new("Solana", MNEMONIC)), &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);
    assert!(err.message.contains("Ethereum app"), "{}", err.message);
    let mut refusing = FakeLedger::new("Ethereum", MNEMONIC);
    refusing.refuse = true;
    let err = run(sign_transaction(&env, &Device::new(refusing), &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 4001, "{}", err.message);
    let mut incomplete = evm_tx();
    incomplete.as_object_mut().unwrap().remove("chainId");
    let untouched = Device::new(FakeLedger::new("Ethereum", MNEMONIC));
    let err = run(sign_transaction(&env, &untouched, &account, &info, &json!({ "Transaction": incomplete, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
    assert!(untouched.transport().sent.borrow().is_empty(), "the device was asked to sign an incomplete transaction");
    // Broadcasting needs a node.
    let err = run(sign_transaction(&env, &Device::new(FakeLedger::new("Ethereum", MNEMONIC)), &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true, "Broadcast": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
}

#[test]
fn evm_message_signature_and_address_display() {
    let env = env();
    let account = import_app(&env, "Ethereum", None).accounts.remove(0);
    let (account, info) = load_account(&env, &account.id).unwrap();

    let device = Device::new(FakeLedger::new("Ethereum", MNEMONIC));
    let out = run(sign_message(&device, &account, &info, b"hello ledger")).unwrap();
    assert_eq!(out["signature"].as_str().unwrap(), crate::walletcore::sign_evm_personal(MNEMONIC, "", "hello ledger").unwrap());
    assert_eq!(run(show_address(&device, &account, &info)).unwrap()["address"], account.address.as_str());

    let wrong = Device::new(FakeLedger::new("Ethereum", OTHER));
    assert_eq!(run(sign_message(&wrong, &account, &info, b"hello ledger")).unwrap_err().code, 409);
    assert_eq!(run(show_address(&wrong, &account, &info)).unwrap_err().code, 409);
}

#[test]
fn solana_message_is_signed_and_bound_to_the_account() {
    let env = env();
    let account = import_app(&env, "Solana", None).accounts.remove(0);
    let (account, info) = load_account(&env, &account.id).unwrap();
    let from = crate::solana::pubkey_from_b64url(&account.pubkey).unwrap();
    let message = crate::solana::build_transfer_message(&from, &[9u8; 32], 1_000, &[3u8; 32]);
    let params = json!({ "Transaction": { "message": bs58::encode(&message).into_string() }, "Offline": true });

    let device = Device::new(FakeLedger::new("Solana", MNEMONIC));
    let out = run(sign_transaction(&env, &device, &account, &info, &params)).unwrap();
    let raw = bs58::decode(out["raw"].as_str().unwrap()).into_vec().unwrap();
    assert_eq!(crate::solana::tx_message(&raw).unwrap(), &message[..]);
    let sig: [u8; 64] = bs58::decode(out["id"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();
    assert!(crate::tss::ed25519_verify(&from, &message, &sig));

    // Another device's signature is refused, and so is a message that does
    // not name this account as a signer (before the device is asked).
    let wrong = Device::new(FakeLedger::new("Solana", OTHER));
    assert_eq!(run(sign_transaction(&env, &wrong, &account, &info, &params)).unwrap_err().code, 409);
    let foreign = crate::solana::build_transfer_message(&[5u8; 32], &[9u8; 32], 1_000, &[3u8; 32]);
    let untouched = Device::new(FakeLedger::new("Solana", MNEMONIC));
    let err = run(sign_transaction(&env, &untouched, &account, &info, &json!({ "Transaction": { "message": bs58::encode(&foreign).into_string() }, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
    assert!(untouched.transport().sent.borrow().is_empty());
}

#[test]
fn bitcoin_spend_reaches_the_device_and_leaves_nothing_pending_on_failure() {
    let env = env();
    let account = import_app(&env, "Bitcoin", None).accounts.remove(0);
    let (account, info) = load_account(&env, &account.id).unwrap();
    let tx = json!({
        "To": account.address, "Amount": 10_000, "FeeRate": 2,
        "UTXOs": [{ "txo": format!("{}:0", "11".repeat(32)), "amount_sats": 100_000, "path": "m/0/0", "script": "p2wpkh" }],
        // Not the transaction that txid names: must be ignored, not embedded.
        "PrevTxs": { "11".repeat(32): "00" },
    });
    // The simulated app does not speak the PSBT protocol: the spend is built,
    // the device is asked (SIGN_PSBT), and its refusal is reported.
    let device = Device::new(FakeLedger::new("Bitcoin", MNEMONIC));
    let err = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": tx, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 502, "{}", err.message);
    assert!(device.transport().sent.borrow().iter().any(|a| a[0] == 0xe1 && a[1] == 0x04), "the device was not asked to sign");

    // Other chains are not the Bitcoin app's business; no UTXOs and no node is an error.
    let mut ltc = tx.clone();
    ltc["ChainId"] = json!("litecoin");
    assert_eq!(run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": ltc, "Offline": true }))).unwrap_err().code, 400);
    let err = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": { "To": account.address, "Amount": 1 }, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
}

#[test]
fn bridge_relays_apdus_through_the_host() {
    use std::sync::{Arc, Mutex};
    let env = Arc::new(env());
    // The "host": answers each ledger:apdu event from a simulated device, on
    // another thread, through the same resolver Ledger:apduResponse uses.
    let seen = Arc::new(Mutex::new(0usize));
    let counter = seen.clone();
    env.set_event_sink(Some(Box::new(move |ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        if ev["event"] != "ledger:apdu" {
            return;
        }
        *counter.lock().unwrap() += 1;
        let id = ev["data"]["id"].as_str().unwrap().to_owned();
        let apdu = unhex(ev["data"]["apdu"].as_str().unwrap()).unwrap();
        std::thread::spawn(move || {
            let reply = FakeLedger::new("Ethereum", MNEMONIC).handle(&apdu);
            assert!(transport::bridge_resolve(&id, Ok(reply)));
        });
    })));

    let out = run(crate::handlers::ledger::route(&env, "info", &json!({ "Transport": "bridge" }))).unwrap();
    assert_eq!(out["app"]["name"], "Ethereum");
    let keys = run(crate::handlers::ledger::route(&env, "getKeys", &json!({ "Transport": "bridge" }))).unwrap();
    assert_eq!(keys["keys"][0]["address"], crate::walletcore::derive_addresses(MNEMONIC, "").unwrap().evm);
    assert!(*seen.lock().unwrap() >= 3);

    // Ledger:import persists them; the answer route rejects unknown exchanges.
    let imported = run(crate::handlers::ledger::route(&env, "import", &json!({ "Keys": keys["keys"], "Name": "My Nano" }))).unwrap();
    assert_eq!(imported["wallet"]["Name"], "My Nano");
    assert_eq!(imported["wallet"]["Protocol"], "ledger");
    let err = run(crate::handlers::ledger::route(&env, "apduResponse", &json!({ "Id": "apdu-nope", "Data": "9000" }))).unwrap_err();
    assert_eq!(err.code, 404);
    env.set_event_sink(None);
}
