use libwallet::models::asset;
use libwallet::{Env, SqlValue};

fn seed() -> Env {
    let env = Env::init_memory().unwrap();
    asset::init(&env).unwrap();
    // 1 ETH: significand 1e18, exp 18.
    env.exec(
        r#"INSERT INTO "Asset" ("Id","Key","Name","Symbol","Amount","Type","Network","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"#,
        vec![
            SqlValue::Text("as-1".into()),
            SqlValue::Text("evm.1.NATIVE".into()),
            SqlValue::Text("Ethereum".into()),
            SqlValue::Text("ETH".into()),
            SqlValue::Text(r#"{"v":"1000000000000000000","e":18,"f":1.0}"#.into()),
            SqlValue::Text("evm".into()),
            SqlValue::Text("net-1".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();
    env
}

#[test]
fn amount_roundtrips_through_db() {
    let env = seed();
    let a = asset::fetch(&env, "as-1").unwrap().expect("found");
    assert_eq!(a.key, "evm.1.NATIVE");
    assert_eq!(a.symbol, "ETH");
    assert_eq!(a.amount.to_display_string(), "1.000000000000000000");
    assert_eq!(a.amount.exp(), 18);
}

#[test]
fn json_uses_lowercase_keys_and_amount_object() {
    let env = seed();
    let a = asset::fetch(&env, "as-1").unwrap().unwrap();
    let j = serde_json::to_value(&a).unwrap();
    // lowercase field keys (Go json tags), except Created/Updated
    assert_eq!(j["key"], "evm.1.NATIVE");
    assert_eq!(j["symbol"], "ETH");
    assert_eq!(j["type"], "evm");
    assert!(j.get("Created").is_some());
    // amount is the {v,e,f} object
    assert_eq!(j["amount"]["v"], "1000000000000000000");
    assert_eq!(j["amount"]["e"], 18);
}

#[test]
fn list_and_missing() {
    let env = seed();
    assert_eq!(asset::list(&env).unwrap().len(), 1);
    assert!(asset::fetch(&env, "as-none").unwrap().is_none());
}

#[test]
fn convert_to_fiat_from_cached_quotes() {
    use std::time::Duration;
    let env = seed();
    // Pre-warm the quote cache so convert_to needs no network: ETH = $3200.50.
    let quotes = r#"[{"id":1027,"name":"Ethereum","symbol":"ETH","quote":{"USD":{"price":3200.5}}}]"#;
    env.cache_store(libwallet::quote::CACHE_KEY, quotes.as_bytes(), Duration::from_secs(300))
        .unwrap();

    let mut a = asset::fetch(&env, "as-1").unwrap().unwrap();
    assert!(a.convert_to(&env, "USD").unwrap(), "conversion applied");
    assert_eq!(a.fiat_currency, "USD");
    // 1 ETH * $3200.50 = $3200.50 (8-decimal amount).
    assert_eq!(a.fiat_amount.as_ref().unwrap().to_display_string(), "3200.50000000");
    assert_eq!(a.fiat_quote.as_ref().unwrap().price, 3200.5);

    // JSON exposes the computed fiat fields under Go's snake_case tags.
    let j = serde_json::to_value(&a).unwrap();
    assert_eq!(j["fiat_currency"], "USD");
    assert_eq!(j["fiat_quote"]["price"], 3200.5);

    // A currency with no entry leaves the fields unset (no error).
    let mut b = asset::fetch(&env, "as-1").unwrap().unwrap();
    assert!(!b.convert_to(&env, "JPY").unwrap());
    assert!(b.fiat_amount.is_none());
}
