use libwallet::models::transaction as tx;
use libwallet::{Env, SqlValue};

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    tx::init(&env).unwrap();
    env
}

#[test]
fn fetch_with_amounts_and_raw_base64() {
    let env = env();
    env.exec(
        r#"INSERT INTO "Transaction" ("Id","Type","Asset","From","To","Gas","GasPrice","MaxFeePerGas","MaxPriorityFeePerGas","Fee","Nonce","Format","Raw","Hash","URL","Network","Amount","Value","Data","Created") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)"#,
        vec![
            SqlValue::Text("tx-1".into()),
            SqlValue::Text("transfer".into()),
            SqlValue::Text("evm.1.NATIVE".into()),
            SqlValue::Text("acct-1".into()),
            SqlValue::Text("0xdead".into()),
            SqlValue::Int(21000),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text(r#"{"v":"210000000000000","e":18,"f":0.00021}"#.into()),
            SqlValue::Int(7),
            SqlValue::Text("eip1559".into()),
            SqlValue::Blob(vec![0x02, 0xf8, 0x6c]), // raw tx bytes
            SqlValue::Text("0xhash".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("net-1".into()),
            SqlValue::Text(r#"{"v":"1000000000000000000","e":18,"f":1.0}"#.into()),
            SqlValue::Null,
            SqlValue::Text("".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();

    let t = tx::fetch(&env, "tx-1").unwrap().expect("found");
    assert_eq!(t.kind, "transfer");
    assert_eq!(t.gas, 21000);
    assert_eq!(t.nonce, 7);
    assert_eq!(t.amount.as_ref().unwrap().to_display_string(), "1.000000000000000000");
    assert_eq!(t.fee.as_ref().unwrap().exp(), 18);
    assert!(t.value.is_none());
    assert_eq!(t.raw, "Avhs"); // base64 of [0x02,0xf8,0x6c]

    let j = serde_json::to_value(&t).unwrap();
    assert_eq!(j["type"], "transfer"); // lowercase keys
    assert_eq!(j["raw"], "Avhs");
    assert_eq!(j["amount"]["v"], "1000000000000000000");
    // omitempty: empty from-less fields dropped; value (None) dropped
    assert!(j.get("value").is_none());
    assert!(j.get("url").is_none());
    assert!(j.get("data").is_none());
}

#[test]
fn list_and_missing() {
    let env = env();
    assert!(tx::list(&env).unwrap().is_empty());
    assert!(tx::fetch(&env, "tx-none").unwrap().is_none());
}
