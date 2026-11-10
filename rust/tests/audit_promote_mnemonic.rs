//! Audit KC-01: `Wallet:promote` on a secp256k1 mnemonic-keep wallet keeps only
//! the BIP-32 master key and drops the sealed seed. Accounts derived from the
//! seed at hardened paths would then sign for the wrong address, so promote must
//! refuse while any exists (promoteMnemonic migrates them instead); accounts
//! that are the master key or a non-hardened tweak of it stay valid.

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::Env;

const PW: &str = "seal-password";
const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

fn committee() -> Vec<KeyDescription> {
    vec![pw("pw-one-xx"), pw("pw-two-xx"), pw("pw-three-x")]
}

#[test]
fn promote_refuses_a_mnemonic_wallet_with_seed_derived_accounts() {
    let env = env();
    let w = wallet::import_mnemonic(&env, "seed", "secp256k1", M, "", &pw(PW)).unwrap();
    let unlock = vec![(w.keys[0].id.clone(), PW.to_string())];
    // The MetaMask account m/44'/60'/0'/0/0 — derived from the seed.
    let a = account::create_with_unlock(&env, &w.id, "", "ethereum", 0, &unlock).unwrap();
    assert_eq!(a.path, "m/44'/60'/0'/0/0");

    let err = wallet::promote(&env, &w.id, &unlock, &committee(), 1).unwrap_err().to_string();
    assert!(err.contains("promoteMnemonic"), "{err}");

    // Nothing changed: still the 1-of-1 mnemonic wallet, and the account still
    // signs for its own address.
    let after = wallet::fetch(&env, &w.id).unwrap().unwrap();
    assert_eq!(after.protocol, "mnemonic");
    assert_eq!(after.keys.len(), 1);
    assert_eq!(after.keys[0].id, w.keys[0].id);
    assert_eq!(after.keys[0].schema, "mnemonic");
    let sig = libwallet::evm::personal_sign(&env, &a.id, &unlock, b"hello").unwrap();
    let who = libwallet::evm::personal_ec_recover(b"hello", &sig).unwrap();
    assert_eq!(who.to_lowercase(), a.address.to_lowercase());
}

#[test]
fn promote_still_converts_a_mnemonic_wallet_whose_accounts_follow_the_master_key() {
    let env = env();
    let w = wallet::import_mnemonic(&env, "seed", "secp256k1", M, "", &pw(PW)).unwrap();
    let unlock = vec![(w.keys[0].id.clone(), PW.to_string())];
    // Group-key style accounts: the master key itself (null path) and a
    // non-hardened child carrying its IL tweak.
    let a0 = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let a1 = account::create(&env, &w.id, "", "ethereum", 1).unwrap();
    assert!(a0.path.is_empty() && !a1.path.is_empty() && !a1.il.is_null());

    let new = committee();
    let p = wallet::promote(&env, &w.id, &unlock, &new, 1).unwrap();
    assert_eq!(p.pubkey, w.pubkey);
    assert_eq!((p.protocol.as_str(), p.threshold, p.keys.len()), ("dkls23", 1, 3));

    let ul = vec![(p.keys[0].id.clone(), new[0].key.clone()), (p.keys[2].id.clone(), new[2].key.clone())];
    for a in [&a0, &a1] {
        let sig = libwallet::evm::personal_sign(&env, &a.id, &ul, b"after promote").unwrap();
        let who = libwallet::evm::personal_ec_recover(b"after promote", &sig).unwrap();
        assert_eq!(who.to_lowercase(), a.address.to_lowercase());
    }
}
