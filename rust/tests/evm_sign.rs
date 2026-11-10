//! Gold-standard EVM signing proof: a DKLs-signed legacy transaction, built for
//! a derived ethereum account, must recover (ecrecover) to that account's own
//! address. This verifies the whole chain — BIP32 tweak derivation, DKLs
//! sign_with_tweak, low-s normalization, EIP-155 v, and RLP assembly.

use libwallet::evm::{recover_sender, sign_tx, EvmTxRequest};
use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::Env;

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

#[test]
fn evm_tx_signature_recovers_to_account() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();

    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();

    // All three unlocked: extras beyond threshold+1 are accepted.
    let unlock: Vec<(String, String)> = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
        (w.keys[2].id.clone(), "passwordthree".to_string()),
    ];
    let legacy = EvmTxRequest {
        nonce: 0,
        gas: 21000,
        max_fee: "20000000000".to_string(),
        max_priority: "0".to_string(),
        to: "0x000000000000000000000000000000000000dEaD".to_string(),
        value: "1000000000000000000".to_string(),
        data: vec![],
        chain_id: 1,
        eip1559: false,
    };
    let raw = sign_tx(&env, &a.id, &unlock, &legacy).unwrap();
    assert_eq!(
        recover_sender(&raw).unwrap().to_lowercase(),
        a.address.to_lowercase(),
        "legacy tx must recover to the account address"
    );

    // EIP-1559 (type-2) transaction also recovers correctly.
    let eip1559 = EvmTxRequest {
        nonce: 1,
        gas: 21000,
        max_fee: "30000000000".to_string(),
        max_priority: "2000000000".to_string(),
        to: "0x000000000000000000000000000000000000bEEF".to_string(),
        value: "500000000000000000".to_string(),
        data: vec![],
        chain_id: 1,
        eip1559: true,
    };
    let raw2 = sign_tx(&env, &a.id, &unlock, &eip1559).unwrap();
    assert_eq!(
        recover_sender(&raw2).unwrap().to_lowercase(),
        a.address.to_lowercase(),
        "eip-1559 tx must recover to the account address"
    );
}

#[test]
fn personal_sign_recovers_to_account() {
    use libwallet::evm::{personal_sign, personal_sign_digest};
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let unlock: Vec<(String, String)> = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
        (w.keys[2].id.clone(), "passwordthree".to_string()),
    ];

    let msg = b"Hello from libwallet personal_sign";
    let sig = personal_sign(&env, &a.id, &unlock, msg).unwrap();
    assert_eq!(sig.len(), 65, "R || S || V");
    let v = sig[64];
    assert!(v == 27 || v == 28, "EIP-191 V is 27/28, got {v}");

    // ecrecover: recover the pubkey from (r, s, recid, digest) and derive the
    // EVM address — it must equal the signing account's address.
    let r: [u8; 32] = sig[0..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..64].try_into().unwrap();
    let digest = personal_sign_digest(msg);
    let pk = outscript::crypto::secp256k1::recover_public_key(&r, &s, v - 27, &digest).unwrap();
    let addr = libwallet::hdderive::evm_address(&pk.serialize_compressed()).unwrap();
    assert_eq!(
        addr.to_lowercase(),
        a.address.to_lowercase(),
        "personal_sign must recover to the account address"
    );

    // The digest uses the exact EIP-191 prefix.
    let mut expect = format!("\u{0019}Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    expect.extend_from_slice(msg);
    assert_eq!(digest, purecrypto::hash::keccak256(&expect));
}

/// Audit H1: chain id 0 would make a legacy signature pre-EIP-155 — valid on
/// every chain — so no transaction is built (let alone signed) with it.
#[test]
fn chain_id_zero_is_refused() {
    use libwallet::evm::{attach_signature, build_unsigned};
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let unlock: Vec<(String, String)> =
        vec![(w.keys[0].id.clone(), "passwordone".to_string()), (w.keys[1].id.clone(), "passwordtwo".to_string())];
    let req = |chain_id: u64, eip1559: bool| EvmTxRequest {
        nonce: 0,
        gas: 21000,
        max_fee: "20000000000".to_string(),
        max_priority: "0".to_string(),
        to: "0x000000000000000000000000000000000000dead".to_string(),
        value: "1".to_string(),
        data: vec![],
        chain_id,
        eip1559,
    };
    for eip1559 in [false, true] {
        assert!(build_unsigned(&req(0, eip1559)).is_err());
        let err = sign_tx(&env, &a.id, &unlock, &req(0, eip1559)).unwrap_err().to_string();
        assert!(err.contains("chain id"), "{err}");
        // Too large for the legacy v = chain_id*2 + 35 + parity to fit.
        assert!(build_unsigned(&req(u64::MAX, eip1559)).is_err());
    }
    // A tx whose chain id was zeroed after building can't be given a signature.
    let mut tx = build_unsigned(&req(1, false)).unwrap();
    tx.chain_id = 0;
    assert!(attach_signature(tx, &[1u8; 32], &[1u8; 32], 0).is_err());
    assert!(build_unsigned(&req(1, false)).is_ok());
}

/// Audit L7: only an ethereum account signs an EVM transaction, and only to a
/// well-formed recipient — 20 bytes, with a valid EIP-55 checksum when written
/// in mixed case.
#[test]
fn sign_tx_checks_account_kind_and_recipient() {
    use libwallet::evm::validate_to;
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    let eth = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let tron = account::create(&env, &w.id, "", "tron", 0).unwrap();
    let unlock: Vec<(String, String)> =
        vec![(w.keys[0].id.clone(), "passwordone".to_string()), (w.keys[1].id.clone(), "passwordtwo".to_string())];
    let req = |to: &str, data: Vec<u8>| EvmTxRequest {
        nonce: 0,
        gas: 21000,
        max_fee: "20000000000".to_string(),
        max_priority: "0".to_string(),
        to: to.to_string(),
        value: "1".to_string(),
        data,
        chain_id: 1,
        eip1559: false,
    };
    let good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"; // EIP-55 spec vector

    let err = sign_tx(&env, &tron.id, &unlock, &req(good, vec![])).unwrap_err().to_string();
    assert!(err.contains("ethereum-account-only"), "{err}");

    for to in [good.to_string(), good.to_lowercase(), format!("0x{}", good[2..].to_uppercase())] {
        let raw = sign_tx(&env, &eth.id, &unlock, &req(&to, vec![])).unwrap_or_else(|e| panic!("{to}: {e}"));
        assert_eq!(recover_sender(&raw).unwrap().to_lowercase(), eth.address.to_lowercase());
    }
    for to in [
        "",                                              // missing
        "0x",                                            // creation without init code
        "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",      // no prefix
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",     // 19.5 bytes
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed00",  // 21 bytes
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg",    // not hex
        "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",    // one letter's case flipped
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Be\u{e9}d", // non-ASCII
    ] {
        assert!(validate_to(to, &[]).is_err(), "{to:?} accepted");
        assert!(sign_tx(&env, &eth.id, &unlock, &req(to, vec![])).is_err(), "{to:?} signed");
    }
    // Contract creation: an empty recipient with init code.
    assert!(validate_to("0x", &[0x60, 0x00]).is_ok());
    sign_tx(&env, &eth.id, &unlock, &req("0x", vec![0x60, 0x00])).unwrap();
}

/// A 2-of-3 wallet signs with ANY two shares — whichever pair the caller holds,
/// in any order — and recovers to the account; a single share is refused.
#[test]
fn two_of_three_signs_with_any_pair() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let pws = ["passwordone", "passwordtwo", "passwordthree"];
    let kds: Vec<_> = pws.iter().map(|p| pw(p)).collect();
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    assert_eq!(w.threshold, 1, "3 shares → 2-of-3");
    let accts = [
        account::create(&env, &w.id, "", "ethereum", 0).unwrap(),
        account::create(&env, &w.id, "", "ethereum", 1).unwrap(),
    ];
    let cred = |i: usize| (w.keys[i].id.clone(), pws[i].to_string());
    let req = EvmTxRequest {
        nonce: 7,
        gas: 21000,
        max_fee: "30000000000".to_string(),
        max_priority: "2000000000".to_string(),
        to: "0x000000000000000000000000000000000000bEEF".to_string(),
        value: "1".to_string(),
        data: vec![],
        chain_id: 1,
        eip1559: true,
    };
    for a in &accts {
        for pair in [[0, 1], [0, 2], [1, 2], [2, 0], [2, 1]] {
            let unlock = vec![cred(pair[0]), cred(pair[1])];
            let raw = sign_tx(&env, &a.id, &unlock, &req).unwrap_or_else(|e| panic!("pair {pair:?}: {e}"));
            assert_eq!(
                recover_sender(&raw).unwrap().to_lowercase(),
                a.address.to_lowercase(),
                "pair {pair:?} on {} must recover to the account",
                a.path
            );
        }
        // The same share named twice is still one share.
        for unlock in [vec![cred(1)], vec![cred(1), cred(1)]] {
            let err = sign_tx(&env, &a.id, &unlock, &req).unwrap_err().to_string();
            assert!(err.contains("needs 2 of the wallet's 3 shares"), "{err}");
        }
    }
}
