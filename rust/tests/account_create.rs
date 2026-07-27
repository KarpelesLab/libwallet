//! Account:create — derive a Solana account from an ed25519/FROST wallet.

use base64::Engine;
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
fn create_ethereum_account_from_secp256k1_wallet() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();

    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    assert_eq!(a.kind, "ethereum");
    assert_eq!(a.curve, "secp256k1");
    // Null derivation: the account IS the group key, so no HD path and Null IL.
    assert_eq!(a.path, "");
    assert!(a.il.is_null());
    assert_eq!(a.pubkey, w.pubkey, "null-derivation pubkey is the group pubkey");
    // Address is the secp group key's own EVM address (NOT m/44/60/0/0).
    let group_pub = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&w.pubkey).unwrap();
    assert_eq!(a.address, libwallet::hdderive::evm_address(&group_pub).unwrap());
    assert_eq!(a.uri, format!("ethereum:{}", a.address));
    // EIP-55 checksummed 0x-address, 42 chars.
    assert!(a.address.starts_with("0x"));
    assert_eq!(a.address.len(), 42);
    assert!(a.address[2..].chars().all(|c| c.is_ascii_hexdigit()));

    // With null derivation the index no longer drives a path, so a second index
    // yields the SAME direct-key address (identity/UX only).
    let a1 = account::create(&env, &w.id, "", "ethereum", 1).unwrap();
    assert_eq!(a1.address, a.address);
    assert_eq!(a1.path, "");

    // Persisted.
    assert_eq!(account::for_wallet(&env, &w.id).unwrap().len(), 2);

    // Explicit (legacy) derivation still derives the old m/44/60/0/0 child.
    let d = account::create_derived(&env, &w.id, "", "ethereum", 0, "m/44/60/0/0").unwrap();
    assert_eq!(d.path, "m/44/60/0/0");
    assert!(d.il.is_string(), "explicit derivation stores the tweak IL");
    assert_ne!(d.address, a.address, "derived child != direct group key");
    let cc = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&w.chaincode).unwrap();
    let (child, _tw) = libwallet::hdderive::derive_pub_tweak(&group_pub, &cc, &[44, 60, 0, 0]).unwrap();
    assert_eq!(d.address, libwallet::hdderive::evm_address(&child).unwrap());
}

#[test]
fn create_bitcoin_account_p2pkh() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();

    let a = account::create(&env, &w.id, "", "bitcoin", 0).unwrap();
    assert_eq!(a.kind, "bitcoin");
    assert_eq!(a.curve, "secp256k1");
    // Null derivation: direct group key, no HD path, Null IL.
    assert_eq!(a.path, "");
    assert!(a.il.is_null());
    assert_eq!(a.pubkey, w.pubkey, "null-derivation pubkey is the group pubkey");
    // Address is the group key's own P2PKH (no bitcoin network selected here).
    let group_pub = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&w.pubkey).unwrap();
    let expect = outscript::address::encode_base58_addr(0x00, &outscript::hash::hash160(&group_pub));
    assert_eq!(a.address, expect);
    // Mainnet P2PKH addresses start with '1' and are base58.
    assert!(a.address.starts_with('1'), "P2PKH address: {}", a.address);
    assert!(!a.address.contains(['0', 'O', 'I', 'l']));
    assert_eq!(a.uri, format!("bitcoin:{}", a.address));
}

#[test]
fn create_derived_solana_signs_under_child_key() {
    // Explicit (legacy) ed25519 derivation: the account address is the DERIVED
    // child key, and a FROST-tweaked signature verifies under it. This is a
    // create+sign smoke — the derivation primitive itself is proven by
    // tss::frost_hd_derivation_roundtrip.
    use libwallet::tss::{ed25519_verify, frost_sign_local_tweaked};

    let (env, wallet_id, group_b64) = wallet_env();
    let group: [u8; 32] =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&group_b64).unwrap().try_into().unwrap();

    let path = "m/44/501/0/0/7";
    let d = account::create_derived(&env, &wallet_id, "", "solana", 0, path).unwrap();
    assert_eq!(d.path, path);
    assert!(d.il.is_string(), "explicit derivation stores the tweak IL");

    // The stored address is base58 of the derived child pubkey.
    let indices = libwallet::hdderive::parse_bip32_path(path).unwrap();
    let (tweak, child) = libwallet::hdderive::ed25519_derive_pub_tweak(&group, &indices).unwrap();
    assert_eq!(d.address, bs58::encode(&child).into_string());
    assert_ne!(d.address, bs58::encode(&group).into_string(), "child != group key");

    // Reconstruct a 2-of-3 committee for the wallet and sign tweaked; the
    // signature must verify under the DERIVED child pubkey (not the group key).
    let w = wallet::fetch(&env, &wallet_id).unwrap().unwrap();
    let unlock = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
    ];
    let committee = wallet::frost_committee(&w, &unlock).unwrap();
    let msg = b"explicit ed25519 derivation smoke";
    let sig = frost_sign_local_tweaked(&committee, 1, msg, &tweak).unwrap();
    let sig64: [u8; 64] = sig.try_into().unwrap();
    assert!(ed25519_verify(&child, msg, &sig64), "must verify under the derived child key");
    assert!(!ed25519_verify(&group, msg, &sig64), "must NOT verify under the group key");
}

#[test]
fn solana_requires_ed25519_and_rejects_secp() {
    let (env, wallet_id, _) = wallet_env();
    // ethereum on an ed25519 wallet is unsupported; secp derivation not ported.
    assert!(account::create(&env, &wallet_id, "", "ethereum", 0).is_err());
    assert!(account::create(&env, "wlt-missing", "", "solana", 0).is_err());
}
