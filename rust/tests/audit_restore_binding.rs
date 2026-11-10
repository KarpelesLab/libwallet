//! Audit KC-04: a backup / device-transfer blob is untrusted. Restoring wallet
//! X must not write WalletKey rows into another wallet, must not store an entry
//! without shares, and must not turn an undecodable share into an empty one.

use base64::Engine;
use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::Env;

const PW: &str = "seal-password";

fn pw() -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: PW.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

fn backup_json(env: &Env, wallet_id: &str) -> serde_json::Value {
    let w = wallet::fetch(env, wallet_id).unwrap().unwrap();
    let data = wallet::backup_entry(env, &w).unwrap()["data"].as_str().unwrap().to_owned();
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data).unwrap()).unwrap()
}

fn encode(wj: &serde_json::Value) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(wj).unwrap())
}

#[test]
fn restored_keys_are_bound_to_the_restored_wallet() {
    // The victim wallet lives on the device the crafted backup is restored to.
    let dst = env();
    let victim = wallet::import_private_key(&dst, "victim", "secp256k1", &[0x61u8; 32], &pw()).unwrap();

    let src = env();
    let x = wallet::import_private_key(&src, "x", "secp256k1", &[0x62u8; 32], &pw()).unwrap();
    let mut wj = backup_json(&src, &x.id);
    // Point the backed-up share at the victim.
    wj["Keys"][0]["Wallet"] = serde_json::json!(victim.id);

    assert_eq!(wallet::restore_entry(&dst, &encode(&wj)).unwrap(), x.id);
    let v = wallet::fetch(&dst, &victim.id).unwrap().unwrap();
    assert_eq!(v.keys, victim.keys, "the victim's shares are untouched");
    let restored = wallet::fetch(&dst, &x.id).unwrap().unwrap();
    assert_eq!(restored.keys.len(), 1);
    assert_eq!(restored.keys[0].wallet, x.id);
    assert_eq!(restored.keys[0].data, x.keys[0].data);
}

#[test]
fn a_backup_cannot_reuse_a_key_id_already_on_the_device() {
    let dst = env();
    let victim = wallet::import_private_key(&dst, "victim", "secp256k1", &[0x63u8; 32], &pw()).unwrap();
    let src = env();
    let x = wallet::import_private_key(&src, "x", "secp256k1", &[0x64u8; 32], &pw()).unwrap();

    let mut wj = backup_json(&src, &x.id);
    wj["Keys"][0]["Id"] = serde_json::json!(victim.keys[0].id);
    let err = wallet::restore_entry(&dst, &encode(&wj)).unwrap_err().to_string();
    assert!(err.contains("already exists"), "{err}");
    assert!(wallet::fetch(&dst, &x.id).unwrap().is_none(), "nothing was written");
    assert_eq!(wallet::fetch(&dst, &victim.id).unwrap().unwrap().keys, victim.keys);

    // The same key listed twice is refused too.
    let mut wj = backup_json(&src, &x.id);
    let dup = wj["Keys"][0].clone();
    wj["Keys"].as_array_mut().unwrap().push(dup);
    assert!(wallet::restore_entry(&dst, &encode(&wj)).is_err());
    assert!(wallet::fetch(&dst, &x.id).unwrap().is_none());
}

#[test]
fn a_backup_without_usable_shares_is_refused() {
    let src = env();
    let x = wallet::import_private_key(&src, "x", "secp256k1", &[0x65u8; 32], &pw()).unwrap();
    let dst = env();

    for keys in [serde_json::json!([]), serde_json::Value::Null] {
        let mut wj = backup_json(&src, &x.id);
        wj["Keys"] = keys;
        let err = wallet::restore_entry(&dst, &encode(&wj)).unwrap_err().to_string();
        assert!(err.contains("no wallet keys"), "{err}");
    }

    let mut wj = backup_json(&src, &x.id);
    wj["Keys"][0]["Data"] = serde_json::json!("***not base64***");
    let err = wallet::restore_entry(&dst, &encode(&wj)).unwrap_err().to_string();
    assert!(err.contains("undecodable Data"), "{err}");

    let mut wj = backup_json(&src, &x.id);
    wj["Keys"][0]["Id"] = serde_json::json!("");
    assert!(wallet::restore_entry(&dst, &encode(&wj)).is_err());

    assert!(wallet::fetch(&dst, &x.id).unwrap().is_none(), "no partial wallet was stored");

    // The untampered backup still restores, share intact.
    assert_eq!(wallet::restore_entry(&dst, &encode(&backup_json(&src, &x.id))).unwrap(), x.id);
    assert_eq!(wallet::fetch(&dst, &x.id).unwrap().unwrap().keys, x.keys);
}
