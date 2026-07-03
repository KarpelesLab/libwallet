//! Solana transfer signing: build a transfer message, sign it with the FROST
//! wallet, and verify the signature under the account's Ed25519 key.

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::solana::{assemble_tx, build_transfer_message, pubkey_from_b64url};
use libwallet::tss::ed25519_verify;
use libwallet::Env;

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

#[test]
fn solana_transfer_signs_and_verifies() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();

    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "SOL", "ed25519", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "solana", 0).unwrap();

    let from = pubkey_from_b64url(&a.pubkey).expect("account pubkey");
    let to = [7u8; 32];
    let blockhash = [9u8; 32];
    let msg = build_transfer_message(&from, &to, 1_000_000, &blockhash);

    // Sign the message with two of the three FROST shares.
    let unlock = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
    ];
    let sig = wallet::sign_frost_local(&env, &w.id, &unlock, &msg).unwrap();
    assert_eq!(sig.len(), 64);

    // The signature must verify under the account (= wallet group) key.
    let sig64: [u8; 64] = sig.clone().try_into().unwrap();
    assert!(ed25519_verify(&from, &msg, &sig64), "solana tx must verify under the account key");

    // Wire tx = shortvec(1) + sig + message.
    let tx = assemble_tx(&msg, &sig);
    assert_eq!(tx[0], 1);
    assert_eq!(tx.len(), 1 + 64 + msg.len());
}
