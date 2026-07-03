//! Account:create — derive a Solana account from an ed25519/FROST wallet.

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::Env;

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

fn wallet_env() -> (Env, String, String) {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "W", "ed25519", &kds).unwrap();
    let pubkey = w.pubkey.clone();
    (env, w.id, pubkey)
}

#[test]
fn create_solana_account_from_ed25519_wallet() {
    let (env, wallet_id, pubkey) = wallet_env();
    let a = account::create(&env, &wallet_id, "", "solana", 0).unwrap();

    assert!(a.id.starts_with("acct-"));
    assert_eq!(a.wallet, wallet_id);
    assert_eq!(a.name, "Account 1"); // default name for index 0
    assert_eq!(a.kind, "solana");
    assert_eq!(a.curve, "ed25519");
    assert_eq!(a.path, "m");
    assert_eq!(a.pubkey, pubkey);
    assert_eq!(a.uri, format!("solana:{}", a.address));
    // base58 address: non-empty and uses the base58 alphabet (no 0 O I l).
    assert!(!a.address.is_empty());
    assert!(!a.address.contains(['0', 'O', 'I', 'l']));

    // Persisted, and set as current.
    let got = account::fetch(&env, &a.id).unwrap().expect("found");
    assert_eq!(got.address, a.address);
    assert_eq!(env.get_current("account").unwrap().as_deref(), Some(a.id.as_str()));
    assert_eq!(account::for_wallet(&env, &wallet_id).unwrap().len(), 1);
}

#[test]
fn solana_requires_ed25519_and_rejects_secp() {
    let (env, wallet_id, _) = wallet_env();
    // ethereum on an ed25519 wallet is unsupported; secp derivation not ported.
    assert!(account::create(&env, &wallet_id, "", "ethereum", 0).is_err());
    assert!(account::create(&env, "wlt-missing", "", "solana", 0).is_err());
}
