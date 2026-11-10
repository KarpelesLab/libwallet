//! Audit KC-03: replacing a wallet's key shares must never pass through a state
//! where the wallet has none. New rows are written before the old ones go, and
//! a single-share recrypt rewrites its row in place.

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::{Env, SqlValue};

const PW: &str = "seal-password";

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

fn key_rows(env: &Env, wallet_id: &str) -> Vec<String> {
    let rows = env
        .query(r#"SELECT "Id" FROM "WalletKey" WHERE "Wallet" = ?1"#, vec![SqlValue::Text(wallet_id.into())])
        .unwrap();
    let mut ids: Vec<String> = rows.iter().map(|r| r[0].as_text().unwrap().to_owned()).collect();
    ids.sort();
    ids
}

#[test]
fn promote_swaps_the_committee_and_leaves_other_wallets_alone() {
    let env = env();
    let other = wallet::import_private_key(&env, "other", "secp256k1", &[0x51u8; 32], &pw(PW)).unwrap();
    let w = wallet::import_private_key(&env, "k", "secp256k1", &[0x52u8; 32], &pw(PW)).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();

    let new = vec![pw("pw-one-xx"), pw("pw-two-xx"), pw("pw-three-x")];
    let p = wallet::promote(&env, &w.id, &[(w.keys[0].id.clone(), PW.into())], &new, 1).unwrap();

    // Exactly the new committee, in the order of `new`; the old share is gone.
    let mut want: Vec<String> = p.keys.iter().map(|k| k.id.clone()).collect();
    assert_eq!(p.keys.len(), 3);
    assert!(!want.contains(&w.keys[0].id));
    assert_eq!(p.generation, w.generation + 1);
    want.sort();
    assert_eq!(key_rows(&env, &w.id), want);
    assert_eq!(key_rows(&env, &other.id), vec![other.keys[0].id.clone()]);

    for (i, kd) in new.iter().enumerate() {
        assert_eq!(p.keys[i].kind, "Password");
        let key = wallet::fetch_key(&env, &p.keys[i].id).unwrap().unwrap();
        let xid: xuid::Xuid = key.id.parse().unwrap();
        let sk = wallet::resolve_unlock_key("Password", &kd.key, xid.uuid().as_bytes()).unwrap();
        libwallet::keystore::open(&key.data, [sk]).expect("share i opens with descriptor i");
    }
    let ul = vec![(p.keys[0].id.clone(), new[0].key.clone()), (p.keys[1].id.clone(), new[1].key.clone())];
    let sig = libwallet::evm::personal_sign(&env, &a.id, &ul, b"hi").unwrap();
    assert_eq!(libwallet::evm::personal_ec_recover(b"hi", &sig).unwrap().to_lowercase(), a.address.to_lowercase());
}

#[test]
fn recrypt_rewrites_the_share_row_in_place() {
    let env = env();
    let w = wallet::import_private_key(&env, "k", "secp256k1", &[0x53u8; 32], &pw(PW)).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let before = wallet::fetch_key(&env, &w.keys[0].id).unwrap().unwrap();

    // A failing recrypt (wrong old password) changes nothing.
    assert!(wallet::recrypt_key(&env, &before.id, &pw("not-the-password"), &pw("new-password")).is_err());
    assert_eq!(wallet::fetch_key(&env, &before.id).unwrap().unwrap(), before);

    let wk = wallet::recrypt_key(&env, &before.id, &pw(PW), &pw("new-password")).unwrap();
    let after = wallet::fetch_key(&env, &before.id).unwrap().unwrap();
    assert_eq!(after, wk);
    assert_eq!(key_rows(&env, &w.id), vec![before.id.clone()]);
    assert_eq!((&after.wallet, &after.schema, after.generation), (&before.wallet, &before.schema, before.generation));
    assert_ne!(after.key, before.key);
    assert_ne!(after.data, before.data);

    // The new password signs; the old one no longer opens the share.
    let sig = libwallet::evm::personal_sign(&env, &a.id, &[(before.id.clone(), "new-password".into())], b"hi").unwrap();
    assert_eq!(libwallet::evm::personal_ec_recover(b"hi", &sig).unwrap().to_lowercase(), a.address.to_lowercase());
    assert!(libwallet::evm::personal_sign(&env, &a.id, &[(before.id.clone(), PW.into())], b"hi").is_err());

    // To Plain and back: Type/Key follow the descriptor.
    let plain = KeyDescription { kind: "Plain".into(), key: String::new(), id: String::new() };
    let wk = wallet::recrypt_key(&env, &before.id, &pw("new-password"), &plain).unwrap();
    assert_eq!((wk.kind.as_str(), wk.key.as_str()), ("Plain", ""));
    assert_eq!(wallet::fetch_key(&env, &before.id).unwrap().unwrap(), wk);

    assert!(wallet::recrypt_key(&env, "wkey-aaaaaa-aaaa-aaaa-aaaa-aaaaaaaa", &pw(PW), &plain).is_err());
}
