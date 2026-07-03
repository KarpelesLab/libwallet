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
fn create_rejects_too_few_keys() {
    let env = env();
    assert!(wallet::create(&env, "x", "ed25519", &[pw("aaaaaa"), pw("bbbbbb")]).is_err());
}

#[test]
fn secp256k1_create_not_yet_supported() {
    let env = env();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    assert!(wallet::create(&env, "x", "secp256k1", &kds).is_err());
}
