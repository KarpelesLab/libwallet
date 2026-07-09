//! Wallet:create write path — generate an all-local ed25519/FROST wallet and
//! persist it. The signing crypto is proven separately (tss / wallet_lifecycle
//! tests); here we verify create produces a well-formed, persisted wallet.

use libwallet::models::wallet;
use libwallet::sign::KeyDescription;
use libwallet::Env;

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    env
}

#[test]
fn create_local_frost_wallet_persists() {
    let env = env();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "My Wallet", "ed25519", &kds).unwrap();

    assert!(w.id.starts_with("wlt-"));
    assert_eq!(w.name, "My Wallet");
    assert_eq!(w.curve, "ed25519");
    assert_eq!(w.protocol, "frost");
    assert_eq!(w.threshold, 1);
    assert_eq!(w.keys.len(), 3);
    // Pubkey is base64url (no pad) of the 32-byte compressed group key = 43 chars.
    assert_eq!(w.pubkey.len(), 43);
    // Chaincode is base64url of 32 random bytes = 43 chars.
    assert_eq!(w.chaincode.len(), 43);
    for k in &w.keys {
        assert_eq!(k.schema, "frost");
        assert_eq!(k.kind, "Password");
        assert!(k.id.starts_with("wkey-"));
        assert!(!k.data.is_empty(), "encrypted share stored");
        assert!(!k.key.is_empty(), "recipient PKIX stored");
    }

    // Persisted and re-readable, with the shares attached.
    let got = wallet::fetch(&env, &w.id).unwrap().expect("found");
    assert_eq!(got.pubkey, w.pubkey);
    assert_eq!(got.threshold, 1);
    assert_eq!(got.keys.len(), 3);
    assert!(got.keys.iter().all(|k| !k.data.is_empty()));
    assert_eq!(wallet::list(&env).unwrap().len(), 1);

    // The serialized wallet (for the host) never leaks the encrypted share.
    let j = serde_json::to_value(&got).unwrap();
    assert!(j["Keys"][0].get("Data").is_none());
    assert_eq!(j["Pubkey"], w.pubkey);
}

#[test]
fn create_then_sign_roundtrip() {
    // The full loop: create an on-device wallet, then sign with two of its
    // password-protected shares. sign_frost_local self-verifies the signature
    // against the wallet's stored group key.
    let env = env();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "Signer", "ed25519", &kds).unwrap();

    // Unlock two shares (threshold+1) with their passwords.
    let unlock = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
    ];
    let sig = wallet::sign_frost_local(&env, &w.id, &unlock, b"hello chain").unwrap();
    assert_eq!(sig.len(), 64);

    // A different committee (shares 0 and 2) also signs.
    let unlock2 = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[2].id.clone(), "passwordthree".to_string()),
    ];
    assert_eq!(wallet::sign_frost_local(&env, &w.id, &unlock2, b"hello chain").unwrap().len(), 64);

    // Wrong password can't unlock a share.
    let bad = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "WRONG".to_string()),
    ];
    assert!(wallet::sign_frost_local(&env, &w.id, &bad, b"hello chain").is_err());
}

#[test]
fn create_and_sign_storekey_wallet() {
    use libwallet::keystore;
    use libwallet::sign::KeyDescription;
    let env = env();

    // A StoreKey is a 64-byte base64url device key; its derived Ed25519 PKIX
    // public key is the descriptor (Go storeKeyToEd25519, PBKDF2 of the halves).
    let store_key_b64 = keystore::seed_to_b64url_64(&[5u8; 64]);
    let device = keystore::store_key_to_ed25519(&store_key_b64).unwrap();
    let pkix = keystore::public_key_to_pkix_b64(&device.public()).unwrap();

    let sk = |p: &str| KeyDescription { kind: "StoreKey".into(), key: p.into(), id: String::new() };
    let kds = vec![sk(&pkix), sk(&pkix), sk(&pkix)];
    let w = wallet::create(&env, "SK", "ed25519", &kds).unwrap();
    assert!(w.keys.iter().all(|k| k.kind == "StoreKey"));

    // Unlock two shares with the device store key and sign.
    let unlock = vec![
        (w.keys[0].id.clone(), store_key_b64.clone()),
        (w.keys[1].id.clone(), store_key_b64.clone()),
    ];
    let sig = wallet::sign_frost_local(&env, &w.id, &unlock, b"msg").unwrap();
    assert_eq!(sig.len(), 64);

    // The wrong store key can't unlock.
    let bad = vec![
        (w.keys[0].id.clone(), keystore::seed_to_b64url_64(&[9u8; 64])),
        (w.keys[1].id.clone(), store_key_b64.clone()),
    ];
    assert!(wallet::sign_frost_local(&env, &w.id, &bad, b"msg").is_err());
}

#[test]
fn create_rejects_too_few_keys() {
    let env = env();
    assert!(wallet::create(&env, "x", "ed25519", &[pw("aaaaaa"), pw("bbbbbb")]).is_err());
}

#[test]
fn create_secp256k1_dkls_wallet_persists() {
    let env = env();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "EVM Wallet", "secp256k1", &kds).unwrap();

    assert_eq!(w.curve, "secp256k1");
    assert_eq!(w.protocol, "dkls23");
    assert_eq!(w.threshold, 1);
    assert_eq!(w.keys.len(), 3);
    // 33-byte SEC1-compressed secp256k1 pubkey -> 44 base64url chars.
    assert_eq!(w.pubkey.len(), 44);
    for k in &w.keys {
        assert_eq!(k.schema, "dkls23");
        assert!(!k.data.is_empty());
    }

    let got = wallet::fetch(&env, &w.id).unwrap().expect("found");
    assert_eq!(got.pubkey, w.pubkey);
    assert_eq!(got.protocol, "dkls23");
    assert_eq!(got.keys.len(), 3);
}

#[test]
fn create_and_sign_legacy_eddsa_wallet() {
    // Legacy eddsatss (pre-FROST ed25519) round-trip: create a 2-of-3 legacy
    // wallet, then sign via the standard sign path (which dispatches to the
    // eddsa_legacy branch on Protocol="eddsa"). Proves Rust can open + sign
    // Go-created legacy ed25519 wallets (unblocked by tsslib 0.2.4).
    let env = env();
    let kds = [pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create_eddsa_legacy(&env, "Legacy", 1, &kds).unwrap();
    assert_eq!(w.protocol, "eddsa");
    assert_eq!(w.curve, "ed25519");
    assert!(w.keys.iter().all(|k| k.schema.is_empty()), "legacy shares carry Schema=\"\"");

    // Sign with a 2-of-3 subset — self-verifies against the group pubkey inside.
    let unlock = vec![(w.keys[0].id.clone(), "passwordone".to_string()), (w.keys[1].id.clone(), "passwordtwo".to_string())];
    let sig = wallet::sign_frost_local(&env, &w.id, &unlock, b"legacy message").unwrap();
    assert_eq!(sig.len(), 64);

    // External verify under the stored group pubkey.
    use base64::Engine;
    let pk: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&w.pubkey).unwrap().try_into().unwrap();
    let sig64: [u8; 64] = sig.try_into().unwrap();
    assert!(libwallet::tss::ed25519_verify(&pk, b"legacy message", &sig64), "legacy eddsa sig must verify");

    // A different subset also signs + verifies.
    let unlock2 = vec![(w.keys[1].id.clone(), "passwordtwo".to_string()), (w.keys[2].id.clone(), "passwordthree".to_string())];
    let s2 = wallet::sign_frost_local(&env, &w.id, &unlock2, b"legacy message").unwrap();
    assert!(libwallet::tss::ed25519_verify(&pk, b"legacy message", &s2.try_into().unwrap()));

    // Wrong password fails.
    let bad = vec![(w.keys[0].id.clone(), "nope".to_string()), (w.keys[1].id.clone(), "passwordtwo".to_string())];
    assert!(wallet::sign_frost_local(&env, &w.id, &bad, b"legacy message").is_err());
}
