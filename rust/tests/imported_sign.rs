//! A private key imported as a 1-of-1 wallet (threshold 0) signs directly —
//! FROST refuses threshold 0, so the single share signs as plain Ed25519.

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::tss::ed25519_verify;
use libwallet::Env;

const PW: &str = "seal-password";

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

#[test]
fn imported_ed25519_key_signs_for_its_accounts() {
    let env = env();
    let kd = KeyDescription { kind: "Password".into(), key: PW.into(), id: String::new() };
    let w = wallet::import_private_key(&env, "sol", "ed25519", &[0x42u8; 32], &kd).unwrap();
    assert_eq!(w.threshold, 0);
    let unlock = vec![(w.keys[0].id.clone(), PW.to_string())];

    for idx in [0, 1] {
        let a = account::create(&env, &w.id, "", "solana", idx).unwrap();
        let pk: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &a.pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        for msg in [&b"hello"[..], &[0u8; 300][..]] {
            let sig = wallet::sign_ed25519_for_account(&env, &a, &unlock, msg).unwrap();
            assert!(ed25519_verify(&pk, msg, &sig.try_into().unwrap()), "index {idx}");
        }
    }

    // The wallet-level (group key) path signs too.
    let sig = wallet::sign_frost_local(&env, &w.id, &unlock, b"x").unwrap();
    let pk: [u8; 32] =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &w.pubkey).unwrap().try_into().unwrap();
    assert!(ed25519_verify(&pk, b"x", &sig.try_into().unwrap()));
}

#[test]
fn imported_secp256k1_key_signs_for_its_accounts() {
    let env = env();
    let kd = KeyDescription { kind: "Password".into(), key: PW.into(), id: String::new() };
    let w = wallet::import_private_key(&env, "eth", "secp256k1", &[0x43u8; 32], &kd).unwrap();
    let unlock = vec![(w.keys[0].id.clone(), PW.to_string())];
    for idx in [0, 1] {
        let a = account::create(&env, &w.id, "", "ethereum", idx).unwrap();
        let sig = libwallet::evm::personal_sign(&env, &a.id, &unlock, b"hello").unwrap();
        assert_eq!(sig.len(), 65, "index {idx}");
    }
}

/// Promoting an imported ed25519 key splits it into a FROST committee: same
/// group key (same addresses), and any T+1 of the new shares sign.
#[test]
fn imported_ed25519_key_promotes_and_keeps_its_addresses() {
    let env = env();
    let kd = KeyDescription { kind: "Password".into(), key: PW.into(), id: String::new() };
    let w = wallet::import_private_key(&env, "sol", "ed25519", &[0x44u8; 32], &kd).unwrap();
    let a0 = account::create(&env, &w.id, "", "solana", 0).unwrap();
    let a1 = account::create(&env, &w.id, "", "solana", 1).unwrap();

    let new: Vec<KeyDescription> = ["pw-one-xx", "pw-two-xx", "pw-three-x"]
        .iter()
        .map(|p| KeyDescription { kind: "Password".into(), key: (*p).into(), id: String::new() })
        .collect();
    // A wrong unlock leaves the wallet untouched.
    assert!(wallet::promote(&env, &w.id, &[(w.keys[0].id.clone(), "wrong-password".into())], &new, 1).is_err());
    assert_eq!(wallet::fetch(&env, &w.id).unwrap().unwrap().keys.len(), 1);

    let p = wallet::promote(&env, &w.id, &[(w.keys[0].id.clone(), PW.into())], &new, 1).unwrap();
    assert_eq!(p.pubkey, w.pubkey);
    assert_eq!((p.protocol.as_str(), p.threshold, p.keys.len()), ("frost", 1, 3));

    // Any two of the three new shares sign, for the group key and a derived
    // account. (Promoted keys keep the order of `new`.)
    for (i, j) in [(0, 1), (1, 2)] {
        let ul = vec![(p.keys[i].id.clone(), new[i].key.clone()), (p.keys[j].id.clone(), new[j].key.clone())];
        for a in [&a0, &a1] {
            let a = account::fetch(&env, &a.id).unwrap().unwrap();
            let sig = wallet::sign_ed25519_for_account(&env, &a, &ul, b"after promote").unwrap();
            let pk: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &a.pubkey)
                .unwrap()
                .try_into()
                .unwrap();
            assert!(ed25519_verify(&pk, b"after promote", &sig.try_into().unwrap()));
        }
    }
}

