//! Wallet backups carry the wallet's accounts, so restoring on a fresh install
//! brings back every derived account (type, index, path, address) — not only
//! the index-0 account the host recreates by hand.

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::Env;

const PW: &str = "seal-password";
const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn pw() -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: PW.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

fn summary(env: &Env, wallet_id: &str) -> Vec<(String, String, i64, String, String, String)> {
    let mut v: Vec<_> = account::for_wallet(env, wallet_id)
        .unwrap()
        .into_iter()
        .map(|a| (a.id, a.kind, a.index, a.path, a.address, a.name))
        .collect();
    v.sort();
    v
}

fn backup_data(env: &Env, wallet_id: &str) -> String {
    let w = wallet::fetch(env, wallet_id).unwrap().unwrap();
    wallet::backup_entry(env, &w).unwrap()["data"].as_str().unwrap().to_owned()
}

#[test]
fn restore_recreates_every_backed_up_account() {
    let src = env();
    let key = [0x11u8; 32];
    let wk = wallet::import_private_key(&src, "k", "secp256k1", &key, &pw()).unwrap();
    for (typ, idx) in [("ethereum", 0), ("ethereum", 1), ("ethereum", 2), ("bitcoin", 0), ("bitcoin", 1)] {
        account::create(&src, &wk.id, "", typ, idx).unwrap();
    }
    account::update(&src, &account::at_index(&src, &wk.id, "ethereum", 2).unwrap().unwrap().id, Some("Savings")).unwrap();

    let wm = wallet::import_mnemonic(&src, "seed", "secp256k1", M, "", &pw()).unwrap();
    let unlock = vec![(wm.keys[0].id.clone(), PW.to_string())];
    for idx in 0..3 {
        account::create_with_unlock(&src, &wm.id, "", "ethereum", idx, &unlock).unwrap();
    }

    let (dk, dm) = (backup_data(&src, &wk.id), backup_data(&src, &wm.id));
    let dst = env();
    assert_eq!(wallet::restore_entry(&dst, &dk).unwrap(), wk.id);
    assert_eq!(wallet::restore_entry(&dst, &dm).unwrap(), wm.id);
    assert_eq!(summary(&dst, &wk.id), summary(&src, &wk.id));
    assert_eq!(summary(&dst, &wm.id), summary(&src, &wm.id));

    // Restoring again (or over a wallet that is already here) is idempotent,
    // and fills in only what is missing.
    let eth1 = account::at_index(&dst, &wk.id, "ethereum", 1).unwrap().unwrap();
    account::delete(&dst, &eth1.id).unwrap();
    wallet::restore_entry(&dst, &dk).unwrap();
    assert_eq!(summary(&dst, &wk.id), summary(&src, &wk.id));
}

#[test]
fn restore_rejects_an_account_that_does_not_match_its_wallet() {
    let src = env();
    let w = wallet::import_private_key(&src, "k", "secp256k1", &[0x22u8; 32], &pw()).unwrap();
    account::create(&src, &w.id, "", "ethereum", 1).unwrap();

    // Tamper with the backed-up account's key: a group-key wallet re-derives
    // and refuses the mismatch.
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut wj: serde_json::Value = serde_json::from_slice(&b64.decode(backup_data(&src, &w.id)).unwrap()).unwrap();
    wj["Accounts"][0]["Pubkey"] = serde_json::json!(w.pubkey);
    let err = wallet::restore_entry(&env(), &b64.encode(serde_json::to_vec(&wj).unwrap())).unwrap_err();
    assert!(err.to_string().contains("does not match"), "{err}");

    // A backup made before Accounts existed still restores the wallet alone.
    wj.as_object_mut().unwrap().remove("Accounts");
    let dst = env();
    wallet::restore_entry(&dst, &b64.encode(serde_json::to_vec(&wj).unwrap())).unwrap();
    assert!(account::for_wallet(&dst, &w.id).unwrap().is_empty());
}
