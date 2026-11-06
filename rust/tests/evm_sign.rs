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
