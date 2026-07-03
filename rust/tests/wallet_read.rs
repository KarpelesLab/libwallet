use libwallet::{Env, SqlValue};

fn seed() -> Env {
    let env = Env::init_memory().unwrap();
    libwallet::models::wallet::init(&env).unwrap();

    env.exec(
        r#"INSERT INTO "Wallet" ("Id","Name","Curve","Protocol","Threshold","Gen","Pubkey","Chaincode","Created","Modified") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
        vec![
            SqlValue::Text("wlt-abc".into()),
            SqlValue::Text("Main".into()),
            SqlValue::Text("secp256k1".into()),
            SqlValue::Text("dkls23".into()),
            SqlValue::Int(2),
            SqlValue::Int(0),
            SqlValue::Text("BASE64PUB".into()),
            SqlValue::Text("BASE64CC".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
            SqlValue::Text("2026-01-02T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();

    for i in 0..3 {
        env.exec(
            r#"INSERT INTO "WalletKey" ("Id","Wallet","Type","Schema","Key","Data","Gen") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            vec![
                SqlValue::Text(format!("wkey-{i}")),
                SqlValue::Text("wlt-abc".into()),
                SqlValue::Text("StoreKey".into()),
                SqlValue::Text("dkls23".into()),
                SqlValue::Text("pubkey-material".into()),
                SqlValue::Blob(vec![0xDE, 0xAD, 0xBE, 0xEF]), // encrypted share
                SqlValue::Int(0),
            ],
        )
        .unwrap();
    }
    env
}

#[test]
fn fetch_embeds_keys() {
    let env = seed();
    let w = libwallet::models::wallet::fetch(&env, "wlt-abc").unwrap().expect("found");
    assert_eq!(w.name, "Main");
    assert_eq!(w.curve, "secp256k1");
    assert_eq!(w.protocol, "dkls23");
    assert_eq!(w.threshold, 2);
    assert_eq!(w.keys.len(), 3);
    // Data is loaded internally...
    assert_eq!(w.keys[0].data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn data_is_never_serialized() {
    let env = seed();
    let w = libwallet::models::wallet::fetch(&env, "wlt-abc").unwrap().unwrap();
    let j = serde_json::to_value(&w).unwrap();
    assert_eq!(j["Keys"].as_array().unwrap().len(), 3);
    let k0 = &j["Keys"][0];
    assert_eq!(k0["Id"], "wkey-0");
    assert_eq!(k0["Type"], "StoreKey");
    assert_eq!(k0["Key"], "pubkey-material");
    // The encrypted share must not appear anywhere in the JSON.
    assert!(k0.get("Data").is_none(), "Data must be protected");
    assert!(!serde_json::to_string(&w).unwrap().to_lowercase().contains("dead"));
}

#[test]
fn list_returns_wallet_with_keys() {
    let env = seed();
    let all = libwallet::models::wallet::list(&env).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].keys.len(), 3);
}

#[test]
fn missing_wallet_is_none() {
    let env = seed();
    assert!(libwallet::models::wallet::fetch(&env, "wlt-nope").unwrap().is_none());
}
