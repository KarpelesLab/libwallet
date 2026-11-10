//! Audit KC-10: signing for an account of a mnemonic wallet that has no key
//! rows must return an error, not panic on an out-of-bounds index.

use libwallet::models::{account, wallet};
use libwallet::{Env, SqlValue};

#[test]
fn ed25519_mnemonic_sign_on_a_wallet_without_keys_errors() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();

    let wallet_id = xuid::Xuid::new("wlt").to_string();
    env.exec(
        r#"INSERT INTO "Wallet" ("Id","Name","Curve","Protocol","Threshold","Gen","Pubkey","Chaincode","Created","Modified") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
        vec![
            SqlValue::Text(wallet_id.clone()), SqlValue::Text("keyless".into()), SqlValue::Text("ed25519".into()),
            SqlValue::Text("mnemonic".into()), SqlValue::Int(0), SqlValue::Int(0),
            SqlValue::Text(String::new()), SqlValue::Text(String::new()),
            SqlValue::Text(libwallet::now_rfc3339()), SqlValue::Text(libwallet::now_rfc3339()),
        ],
    )
    .unwrap();
    let w = wallet::fetch(&env, &wallet_id).unwrap().unwrap();
    assert!(w.keys.is_empty() && w.is_mnemonic());

    let acct: account::Account = serde_json::from_value(serde_json::json!({
        "Id": xuid::Xuid::new("acct").to_string(), "Wallet": wallet_id, "Type": "solana",
        "Curve": "ed25519", "Path": "m/44'/501'/0'/0'",
    }))
    .unwrap();
    let unlock = vec![("wkey-does-not-exist".to_string(), "password".to_string())];
    let err = wallet::sign_ed25519_for_account(&env, &acct, &unlock, b"msg").unwrap_err().to_string();
    assert!(err.contains("no keys"), "{err}");
    assert!(wallet::sign_frost_local(&env, &wallet_id, &unlock, b"msg").is_err());
}
