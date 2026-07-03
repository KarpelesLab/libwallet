use libwallet::models::account;
use libwallet::{Env, SqlValue};

fn seed() -> Env {
    let env = Env::init_memory().unwrap();
    account::init(&env).unwrap();
    env.exec(
        r#"INSERT INTO "Account" ("Id","Wallet","Name","Index","Type","Curve","Path","Address","URI","Pubkey","Chaincode","IL","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)"#,
        vec![
            SqlValue::Text("acct-1".into()),
            SqlValue::Text("wlt-abc".into()),
            SqlValue::Text("Acct 0".into()),
            SqlValue::Int(0),
            SqlValue::Text("ethereum".into()),
            SqlValue::Text("secp256k1".into()),
            SqlValue::Text("m/44/60/0/0/0".into()),
            SqlValue::Text("0xabc".into()),
            SqlValue::Text("ethereum:0xabc".into()),
            SqlValue::Text("PUB".into()),
            SqlValue::Text("CC".into()),
            SqlValue::Text("\"12345\"".into()), // IL stored as JSON string
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();
    env
}

#[test]
fn fetch_and_list() {
    let env = seed();
    let a = account::fetch(&env, "acct-1").unwrap().expect("found");
    assert_eq!(a.wallet, "wlt-abc");
    assert_eq!(a.index, 0);
    assert_eq!(a.address, "0xabc");
    assert_eq!(a.il, serde_json::json!("12345"));

    assert_eq!(account::list(&env).unwrap().len(), 1);
    assert_eq!(account::for_wallet(&env, "wlt-abc").unwrap().len(), 1);
    assert!(account::for_wallet(&env, "wlt-other").unwrap().is_empty());
    assert!(account::fetch(&env, "acct-none").unwrap().is_none());
}

#[test]
fn json_shape_matches_dart_keys() {
    let env = seed();
    let a = account::fetch(&env, "acct-1").unwrap().unwrap();
    let j = serde_json::to_value(&a).unwrap();
    for key in ["Id", "Wallet", "Name", "Index", "Type", "Path", "Address", "URI", "Pubkey", "Chaincode", "Created", "Updated"] {
        assert!(j.get(key).is_some(), "missing key {key}");
    }
}
