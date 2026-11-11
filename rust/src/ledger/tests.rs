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
    /// The Tron app's `path ‖ raw_data`, as the chunks of a SIGN arrive.
    tron_tx: RefCell<Vec<u8>>,
}

impl FakeLedger {
    fn new(app: &'static str, mnemonic: &str) -> Self {
        FakeLedger { app, seed: bip39::mnemonic_to_seed(mnemonic, "").to_vec(), refuse: false, sent: RefCell::new(Vec::new()), tron_tx: RefCell::new(Vec::new()) }
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
            _ if self.app == "Tron" && cla == 0xe0 => self.tron(ins, p1, data),
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
            // SIGN_EIP712_HASHED: path ‖ domain separator ‖ message hash
            0x0c => {
                let mut preimage = vec![0x19, 0x01];
                preimage.extend_from_slice(&data[n..n + 64]);
                let (r, s, recid) = key.sign_recoverable(&purecrypto::hash::keccak256(&preimage));
                let mut d = vec![27 + recid];
                d.extend_from_slice(&r);
                d.extend_from_slice(&s);
                Self::ok(d)
            }
            _ => vec![0x6d, 0x00],
        }
    }

    /// The Tron app: r ‖ s ‖ v answers, the transaction arriving in chunks.
    fn tron(&self, ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
        let rsv = |key: &SecpPrivateKey, digest: &[u8; 32]| {
            let (r, s, recid) = key.sign_recoverable(digest);
            let mut d = r.to_vec();
            d.extend_from_slice(&s);
            d.push(recid);
            Self::ok(d)
        };
        match ins {
            // GET ADDRESS: LV(uncompressed key) ‖ LV(ascii address)
            0x02 => {
                let (path, _) = Self::path(data);
                let compressed = hdderive::derive_pubkey_for_path(&self.seed, "secp256k1", &path).unwrap();
                let pk = outscript::crypto::secp256k1::SecpPublicKey::from_sec1(&compressed).unwrap().serialize_uncompressed();
                let address = hdderive::tron_address(&compressed).unwrap();
                let mut d = vec![65];
                d.extend_from_slice(&pk);
                d.push(address.len() as u8);
                d.extend(address.as_bytes());
                Self::ok(d)
            }
            _ if self.refuse => vec![0x69, 0x85],
            // SIGN: 0x10 the whole transaction; 0x00 first, 0x80 more, 0x90 last.
            0x04 => {
                let mut buf = self.tron_tx.borrow_mut();
                if p1 == 0x10 || p1 == 0x00 {
                    buf.clear();
                }
                buf.extend_from_slice(data);
                if p1 == 0x00 || p1 == 0x80 {
                    return Self::ok(Vec::new());
                }
                let (path, n) = Self::path(&buf);
                rsv(&self.secp(&path), &purecrypto::hash::sha256(&buf[n..]))
            }
            // SIGN PERSONAL MESSAGE: path ‖ len(4) ‖ message
            0x08 => {
                let (path, n) = Self::path(data);
                rsv(&self.secp(&path), &crate::tron::message_digest(&data[n + 4..]))
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
            // SIGN / SIGN OFFCHAIN: signer count(1) ‖ path ‖ message
            0x06 | 0x07 => {
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

/// The generic routes sign for a Ledger account on the device, and persist a
/// Transaction row for `Transaction:signAndSend`.
#[test]
fn generic_routes_sign_on_the_device() {
    use std::sync::Arc;
    let env = Arc::new(env());
    crate::models::transaction::init(&env).unwrap();
    env.set_event_sink(Some(Box::new(|ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        if ev["event"] != "ledger:apdu" {
            return;
        }
        let id = ev["data"]["id"].as_str().unwrap().to_owned();
        let apdu = unhex(ev["data"]["apdu"].as_str().unwrap()).unwrap();
        std::thread::spawn(move || {
            transport::bridge_resolve(&id, Ok(FakeLedger::new("Ethereum", MNEMONIC).handle(&apdu)));
        });
    })));
    let account = import_app(&env, "Ethereum", None).accounts.remove(0);

    // Account:signTransaction — no Keys, the device signs.
    let out = crate::handlers::account::sign_transaction(&env, &json!({ "Id": account.id, "Transaction": evm_tx(), "Transport": "bridge" })).unwrap();
    let raw = unhex(out["raw"].as_str().unwrap()).unwrap();
    assert!(crate::evm::recover_sender(&raw).unwrap().eq_ignore_ascii_case(&account.address), "{out}");
    assert_eq!(out["hash"], out["id"]);

    // Account:signMessage.
    use base64::Engine;
    let msg = base64::engine::general_purpose::STANDARD.encode("hello ledger");
    let out = crate::handlers::account::sign_message(&env, &json!({ "Id": account.id, "Message": msg, "Transport": "bridge" })).unwrap();
    assert_eq!(out["signature"].as_str().unwrap(), crate::walletcore::sign_evm_personal(MNEMONIC, "", "hello ledger").unwrap());

    // A swap's transaction: complete, signed on the device, sent by nobody here.
    let req = crate::evm::EvmTxRequest { nonce: 3, gas: 150_000, max_fee: "20000000000".into(), max_priority: "0".into(), to: "0x000000000000000000000000000000000000dEaD".into(), value: "5".into(), data: vec![0xa9, 0x05, 0x9c, 0xbb], chain_id: 137, eip1559: false };
    let raw = run(crate::handlers::signer::sign_evm_request(&env, &account, "ledger", &json!({ "Transport": "bridge", "Keys": [] }), &req)).unwrap();
    assert!(crate::evm::recover_sender(&raw).unwrap().eq_ignore_ascii_case(&account.address));
    let unsigned = crate::evm::build_unsigned(&req).unwrap();
    assert!(raw.windows(4).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb]) && raw.len() > unsigned.sign_bytes().unwrap().len());

    // Account:signTypedData — the device is given the two hashes.
    let typed = json!({
        "types": { "EIP712Domain": [{ "name": "name", "type": "string" }], "Note": [{ "name": "text", "type": "string" }] },
        "primaryType": "Note", "domain": { "name": "t" }, "message": { "text": "hi" },
    });
    let out = crate::handlers::account::sign_typed_data(&env, &json!({ "Id": account.id, "TypedData": typed, "Transport": "bridge" })).unwrap();
    let digest = crate::eip712::parse(&typed.to_string()).unwrap().hash().unwrap();
    let sig = unhex(out["signature"].as_str().unwrap()).unwrap();
    assert!(crate::evm::recover_digest_address(&digest, &sig).unwrap().eq_ignore_ascii_case(&account.address), "{out}");
    assert!(sig[64] == 27 || sig[64] == 28);
    env.set_event_sink(None);
}

/// A device for the generic routes: every bridged APDU goes to `app`.
fn bridge_to(env: &Env, app: &'static str) {
    let device = std::sync::Arc::new(std::sync::Mutex::new(SendLedger(FakeLedger::new(app, MNEMONIC))));
    env.set_event_sink(Some(Box::new(move |ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        if ev["event"] != "ledger:apdu" {
            return;
        }
        let id = ev["data"]["id"].as_str().unwrap().to_owned();
        let apdu = unhex(ev["data"]["apdu"].as_str().unwrap()).unwrap();
        let device = device.clone();
        std::thread::spawn(move || {
            let reply = device.lock().unwrap().0.handle(&apdu);
            transport::bridge_resolve(&id, Ok(reply));
        });
    })));
}

/// The fake keeps its state in `RefCell`s; behind the mutex one thread at a
/// time touches it.
struct SendLedger(FakeLedger);
unsafe impl Send for SendLedger {}

fn tron_block() -> Value {
    let now = chrono::Utc::now().timestamp_millis() as u64;
    json!({ "blockID": format!("{:016x}{}", 70_000_000u64, "ab".repeat(24)), "block_header": { "raw_data": { "number": 70_000_000u64, "timestamp": now } } })
}

#[test]
fn tron_app_keys_transfers_and_messages() {
    let env = env();
    let account = import_app(&env, "Tron", None).accounts.remove(0);
    assert_eq!(account.kind, "tron");
    assert_eq!(account.path, "m/44'/195'/0'/0/0");
    let pk = hdderive::derive_pubkey_for_path(&bip39::mnemonic_to_seed(MNEMONIC, ""), "secp256k1", "m/44'/195'/0'/0/0").unwrap();
    assert_eq!(account.address, hdderive::tron_address(&pk).unwrap());
    let (account, info) = load_account(&env, &account.id).unwrap();

    // The address is shown and checked.
    let device = Device::new(FakeLedger::new("Tron", MNEMONIC));
    assert_eq!(run(show_address(&device, &account, &info)).unwrap()["address"], account.address.as_str());

    // A TRX transfer and a TRC-20 transfer, anchored on the block given.
    for tx in [
        json!({ "to": "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy", "value": "1500000", "refBlock": tron_block() }),
        json!({ "to": "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy", "value": "2500000", "token": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "refBlock": tron_block() }),
    ] {
        let out = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": tx, "Offline": true }))).unwrap();
        let signed = unhex(out["raw"].as_str().unwrap()).unwrap();
        let raw_data = crate::tron::unsigned_raw_data(&account, &tx).unwrap();
        assert_eq!(out["id"], hex(&purecrypto::hash::sha256(&raw_data)));
        assert!(signed.windows(raw_data.len()).any(|w| w == raw_data.as_slice()));
        // What reached the device is the path and exactly that raw data.
        let sent = device.transport().sent.borrow();
        let apdu = sent.last().unwrap();
        assert_eq!((apdu[1], apdu[2]), (0x04, 0x10), "one SIGN chunk");
        assert_eq!(&apdu[5 + 21..], raw_data.as_slice());
    }

    // Raw data that is not this account's is refused before the device sees it.
    let other = Account { address: "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy".into(), ..account.clone() };
    let foreign = crate::tron::unsigned_raw_data(&other, &json!({ "to": account.address, "value": "1", "refBlock": tron_block() })).unwrap();
    let err = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": { "rawDataHex": hex(&foreign) }, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);

    // A device holding other keys signs — and is not believed.
    let stranger = Device::new(FakeLedger::new("Tron", OTHER));
    let tx = json!({ "to": "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy", "value": "1", "refBlock": tron_block() });
    assert_eq!(run(sign_transaction(&env, &stranger, &account, &info, &json!({ "Transaction": tx, "Offline": true }))).unwrap_err().code, 409);
    assert_eq!(run(sign_message(&stranger, &account, &info, b"hello tron")).unwrap_err().code, 409);

    // A message, as TronWeb's signMessageV2.
    let out = run(sign_message(&device, &account, &info, b"hello tron")).unwrap();
    let sig = unhex(out["signature"].as_str().unwrap()).unwrap();
    assert_eq!(crate::tron::message_signature(&account, b"hello tron", &sig).unwrap().to_vec(), sig);

    // The wrong app is named.
    let eth = Device::new(FakeLedger::new("Ethereum", MNEMONIC));
    let err = run(sign_message(&eth, &account, &info, b"x")).unwrap_err();
    assert!(err.code == 409 && err.message.contains("Tron"), "{}", err.message);
}

/// A long transaction goes out in several APDUs, cut between protobuf fields.
#[test]
fn tron_transactions_are_chunked_between_fields() {
    let path: DerivationPath = "m/44'/195'/0'/0/0".parse().unwrap();
    // Fields of 100 bytes each (tag 0x0a, length 98, payload).
    let field = |b: u8| [vec![0x0a, 98], vec![b; 98]].concat();
    let raw: Vec<u8> = (1..=5u8).flat_map(field).collect();
    let chunks = tron::sign_chunks(&path, &raw).unwrap();
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].len(), 21 + 200);
    assert!(chunks.iter().all(|c| c.len() <= 250));
    assert_eq!(chunks.iter().flatten().copied().skip(21).collect::<Vec<u8>>(), raw);
    // Every later chunk starts on a field.
    assert!(chunks[1..].iter().all(|c| c[0] == 0x0a && c[1] == 98));
    // A truncated field, or one too long for an APDU, is refused.
    assert!(tron::sign_chunks(&path, &[0x0a, 98, 1, 2]).is_err());
    assert!(tron::sign_chunks(&path, &[vec![0x0a, 0xfb, 0x01], vec![0; 251]].concat()).is_err());

    // The device reassembles them and signs the whole.
    let device = Device::new(FakeLedger::new("Tron", MNEMONIC));
    let sig = run(tron::TronApp::new(&device).sign_transaction(&path, &raw)).unwrap();
    let p1s: Vec<u8> = device.transport().sent.borrow().iter().map(|a| a[2]).collect();
    assert_eq!(p1s, vec![0x00, 0x80, 0x90]);
    let key = device.transport().secp("m/44'/195'/0'/0/0");
    let (r, s, _) = key.sign_recoverable(&purecrypto::hash::sha256(&raw));
    assert_eq!(&sig[..64], [r.as_slice(), s.as_slice()].concat().as_slice());
}

#[test]
fn typed_data_and_solana_messages() {
    let env = env();
    // EIP-712: the device gets the domain separator and the message hash.
    let account = import_app(&env, "Ethereum", None).accounts.remove(0);
    let (account, info) = load_account(&env, &account.id).unwrap();
    let typed = json!({
        "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }, { "name": "chainId", "type": "uint256" }],
            "Mail": [{ "name": "to", "type": "address" }, { "name": "contents", "type": "string" }],
        },
        "primaryType": "Mail",
        "domain": { "name": "Ether Mail", "chainId": 1 },
        "message": { "to": "0x000000000000000000000000000000000000dEaD", "contents": "Hello" },
    })
    .to_string();
    let device = Device::new(FakeLedger::new("Ethereum", MNEMONIC));
    let out = run(sign_typed_data(&device, &account, &info, &typed)).unwrap();
    let td = crate::eip712::parse(&typed).unwrap();
    let sig = unhex(out["signature"].as_str().unwrap()).unwrap();
    assert!(crate::evm::recover_digest_address(&td.hash().unwrap(), &sig).unwrap().eq_ignore_ascii_case(&account.address));
    let (domain, message) = td.hashes().unwrap();
    let sent = device.transport().sent.borrow();
    let apdu = sent.last().unwrap();
    assert_eq!(apdu[1], 0x0c);
    assert_eq!(&apdu[apdu.len() - 64..], [domain, message].concat().as_slice());
    drop(sent);
    assert_eq!(run(sign_typed_data(&Device::new(FakeLedger::new("Ethereum", OTHER)), &account, &info, &typed)).unwrap_err().code, 409);
    assert_eq!(run(sign_typed_data(&device, &account, &info, "{not json")).unwrap_err().code, 400);

    // Solana: the text goes out wrapped as an off-chain message, and that is
    // what the signature is over.
    let sol = import_app(&env, "Solana", Some(&account.wallet)).accounts.remove(0);
    let (sol, info) = load_account(&env, &sol.id).unwrap();
    let device = Device::new(FakeLedger::new("Solana", MNEMONIC));
    let out = run(sign_message(&device, &sol, &info, b"gm solana")).unwrap();
    use base64::Engine;
    let wrapped = base64::engine::general_purpose::STANDARD.decode(out["signedMessage"].as_str().unwrap()).unwrap();
    let pk = crate::solana::pubkey_from_b64url(&sol.pubkey).unwrap();
    assert_eq!(&wrapped[..16], b"\xffsolana offchain");
    assert_eq!(wrapped[16], 0, "header version");
    assert_eq!(&wrapped[17..49], &[0u8; 32], "no application domain");
    assert_eq!((wrapped[49], wrapped[50]), (0, 1), "ASCII, one signer");
    assert_eq!(&wrapped[51..83], &pk);
    assert_eq!(&wrapped[83..85], &9u16.to_le_bytes());
    assert_eq!(&wrapped[85..], b"gm solana");
    let sig: [u8; 64] = bs58::decode(out["signature"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();
    assert!(crate::tss::ed25519_verify(&pk, &wrapped, &sig));
    assert_eq!(out["format"], "offchain");
    // Other UTF-8 is format 1; bytes that are not text are refused.
    assert_eq!(solana_offchain_message(&pk, "héllo".as_bytes()).unwrap()[49], 1);
    assert_eq!(run(sign_message(&device, &sol, &info, &[0xff, 0xfe])).unwrap_err().code, 400);
}

/// Tron and Solana through the generic routes, and a Solana transaction that
/// another party has to sign too.
#[test]
fn generic_routes_cover_tron_and_shared_solana_transactions() {
    use base64::Engine;
    let env = std::sync::Arc::new(env());
    bridge_to(&env, "Tron");
    let tron = import_app(&env, "Tron", None).accounts.remove(0);
    let tx = json!({ "to": "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy", "value": "1500000", "refBlock": tron_block() });
    let out = crate::handlers::account::sign_transaction(&env, &json!({ "Id": tron.id, "Transaction": tx, "Transport": "bridge" })).unwrap();
    assert_eq!(out["txid"], out["id"], "{out}");
    assert_eq!(out["txid"], hex(&purecrypto::hash::sha256(&crate::tron::unsigned_raw_data(&tron, &tx).unwrap())));
    let msg = base64::engine::general_purpose::STANDARD.encode("hello tron");
    let out = crate::handlers::account::sign_message(&env, &json!({ "Id": tron.id, "Message": msg, "Transport": "bridge" })).unwrap();
    assert!(out["signature"].as_str().unwrap().starts_with("0x"), "{out}");

    // A two-signer Solana transaction: this account's slot is filled, the
    // other is left as it was, and nothing is sent while one is missing.
    bridge_to(&env, "Solana");
    let sol = import_app(&env, "Solana", Some(&tron.wallet)).accounts.remove(0);
    let me = crate::solana::pubkey_from_b64url(&sol.pubkey).unwrap();
    let other = [7u8; 32];
    // Header (2 signers, 0 read-only signed, 1 read-only unsigned), three
    // account keys, a blockhash, no instructions.
    let mut message = vec![2, 0, 1, 3];
    message.extend_from_slice(&other);
    message.extend_from_slice(&me);
    message.extend_from_slice(&[0u8; 32]);
    message.extend_from_slice(&[9u8; 32]);
    message.push(0);
    let mut raw = vec![2];
    raw.extend_from_slice(&[0u8; 128]);
    raw.extend_from_slice(&message);
    let serialized = base64::engine::general_purpose::STANDARD.encode(&raw);
    let out = crate::handlers::account::sign_transaction(&env, &json!({ "Id": sol.id, "Transaction": { "transaction": serialized }, "Transport": "bridge" })).unwrap();
    assert_eq!(out["missingSignatures"], 1, "{out}");
    let signed = bs58::decode(out["raw"].as_str().unwrap()).into_vec().unwrap();
    assert_eq!(&signed[1..65], &[0u8; 64], "the other signer's slot is untouched");
    let sig: [u8; 64] = signed[65..129].try_into().unwrap();
    assert!(crate::tss::ed25519_verify(&me, &message, &sig));
    assert_eq!(&signed[129..], message.as_slice());
    let err = run(crate::handlers::signer::sign_transaction(&env, &sol, "ledger", &json!({ "Transaction": { "transaction": serialized }, "Transport": "bridge", "RPC": "http://127.0.0.1:1" }), true)).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);

    // Account:signMessage for Solana returns the off-chain message it signed.
    let msg = base64::engine::general_purpose::STANDARD.encode("gm");
    let out = crate::handlers::account::sign_message(&env, &json!({ "Id": sol.id, "Message": msg, "Transport": "bridge" })).unwrap();
    assert!(out["signedMessage"].is_string(), "{out}");

    // What the CatCard firmware has no request for is said so, not attempted.
    for (kind, what) in [("tron", "Tron"), ("solana", "Solana")] {
        let a: Account = serde_json::from_value(json!({ "Id": "acct-x", "Wallet": tron.wallet, "Type": kind })).unwrap();
        let err = run(crate::handlers::signer::sign_message(&env, &a, "catcard", &json!({}), crate::handlers::signer::Message::Plain(b"x"))).unwrap_err();
        assert!(err.code == 501 && err.message.contains(what), "{}", err.message);
    }
    let a: Account = serde_json::from_value(json!({ "Id": "acct-x", "Wallet": tron.wallet, "Type": "tron" })).unwrap();
    assert_eq!(run(crate::handlers::signer::sign_transaction(&env, &a, "catcard", &json!({ "Transaction": {} }), false)).unwrap_err().code, 501);
    let a: Account = serde_json::from_value(json!({ "Id": "acct-x", "Wallet": tron.wallet, "Type": "ethereum" })).unwrap();
    assert_eq!(run(crate::handlers::signer::sign_message(&env, &a, "catcard", &json!({}), crate::handlers::signer::Message::TypedData("{}"))).unwrap_err().code, 501);
    env.set_event_sink(None);
}
