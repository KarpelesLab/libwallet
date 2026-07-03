use libwallet::models::{nft, token};
use libwallet::{Env, SqlValue};

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    token::init(&env).unwrap();
    nft::init(&env).unwrap();
    env
}

#[test]
fn token_fetch_list() {
    let env = env();
    env.exec(
        r#"INSERT INTO "Token" ("Id","Name","Symbol","Address","Decimals","Type","Network","Logo","Memo","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
        vec![
            SqlValue::Text("tok-1".into()),
            SqlValue::Text("USD Coin".into()),
            SqlValue::Text("USDC".into()),
            SqlValue::Text("0xA0b8...".into()),
            SqlValue::Int(6),
            SqlValue::Text("erc20".into()),
            SqlValue::Text("net-1".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();
    let t = token::fetch(&env, "tok-1").unwrap().expect("found");
    assert_eq!(t.symbol, "USDC");
    assert_eq!(t.decimals, 6);
    let j = serde_json::to_value(&t).unwrap();
    assert_eq!(j["Symbol"], "USDC"); // PascalCase keys
    assert_eq!(token::list(&env).unwrap().len(), 1);
}

#[test]
fn nft_attributes_roundtrip_and_json_keys() {
    let env = env();
    env.exec(
        r#"INSERT INTO "Nft" ("Id","Key","ContractAddress","ContractName","TokenId","Name","Description","Image","ImageUrl","AnimationUrl","BackgroundColor","YoutubeUrl","ExternalUrl","Decimals","Attributes","Network","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)"#,
        vec![
            SqlValue::Text("nft-1".into()),
            SqlValue::Text("1.0xC.42".into()),
            SqlValue::Text("0xC".into()),
            SqlValue::Text("Cool Cats".into()),
            SqlValue::Text("42".into()),
            SqlValue::Text("Cool Cat #42".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("https://img".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text("".into()),
            SqlValue::Text(r#"[{"trait_type":"Color","value":"Blue"},{"display_type":"number","trait_type":"Level","value":7}]"#.into()),
            SqlValue::Text("net-1".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();

    let n = nft::fetch(&env, "nft-1").unwrap().expect("found");
    assert_eq!(n.contract_name, "Cool Cats");
    assert_eq!(n.token_id, "42");
    assert_eq!(n.attributes.len(), 2);
    assert_eq!(n.attributes[0].trait_type, "Color");
    assert_eq!(n.attributes[0].value, serde_json::json!("Blue"));
    assert_eq!(n.attributes[1].value, serde_json::json!(7));

    let j = serde_json::to_value(&n).unwrap();
    assert_eq!(j["contract_address"], "0xC"); // lowercase json keys
    assert_eq!(j["token_id"], "42");
    assert_eq!(j["attributes"][0]["trait_type"], "Color");
    // empty optional fields are omitted
    assert!(j.get("description").is_none());
    assert!(j.get("Created").is_some()); // Created stays PascalCase

    assert_eq!(nft::list(&env).unwrap().len(), 1);
    assert!(nft::fetch(&env, "nope").unwrap().is_none());
}
