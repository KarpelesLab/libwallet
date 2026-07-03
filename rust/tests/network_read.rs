use libwallet::models::network;
use libwallet::{Env, SqlValue};

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    env
}

#[test]
fn ephemeral_evm_uses_chain_registry() {
    let env = env();
    let n = network::fetch(&env, "evm.1").unwrap().expect("ephemeral");
    let j = n.to_json();
    assert_eq!(j["Type"], "evm");
    assert_eq!(j["ChainId"], "1");
    assert_eq!(j["TxHistoryProvider"], "modchain");
    assert_eq!(j["ResolvedBlockExplorer"], "https://etherscan.io");
    // EVM_Info comes from the ethrpc-rs chain registry.
    assert_eq!(j["EVM_Info"]["name"], "Ethereum Mainnet");
    assert_eq!(j["EVM_Info"]["nativeCurrency"]["symbol"], "ETH");
    // Custom MarshalJSON omits CurrencyDecimals / Priority.
    assert!(j.get("CurrencyDecimals").is_none());
    assert!(j.get("Priority").is_none());
}

#[test]
fn native_symbol_by_type_and_chain() {
    let env = env();
    // EVM from the chain registry.
    assert_eq!(network::fetch(&env, "evm.1").unwrap().unwrap().native_symbol().unwrap(), "ETH");
    assert_eq!(network::fetch(&env, "evm.137").unwrap().unwrap().native_symbol().unwrap(), "POL");
    // Bitcoin family by chain id.
    assert_eq!(
        network::fetch(&env, "bitcoin.bitcoin").unwrap().unwrap().native_symbol().unwrap(),
        "BTC"
    );
    assert_eq!(
        network::fetch(&env, "bitcoin.litecoin").unwrap().unwrap().native_symbol().unwrap(),
        "LTC"
    );
    // Solana.
    assert_eq!(
        network::fetch(&env, "solana.mainnet").unwrap().unwrap().native_symbol().unwrap(),
        "SOL"
    );
    // Unknown bitcoin chain errors.
    assert!(network::fetch(&env, "bitcoin.nope").unwrap().unwrap().native_symbol().is_err());
}

#[test]
fn ephemeral_solana_and_bitcoin() {
    let env = env();
    let sol = network::fetch(&env, "solana.mainnet").unwrap().unwrap().to_json();
    assert_eq!(sol["ResolvedBlockExplorer"], "https://explorer.solana.com");
    assert_eq!(sol["TxHistoryProvider"], "signatures");
    assert!(sol.get("EVM_Info").is_none());

    let btc = network::fetch(&env, "bitcoin.bitcoin").unwrap().unwrap().to_json();
    assert_eq!(btc["TxHistoryProvider"], "");
    assert_eq!(btc["ResolvedBlockExplorer"], "");
}

#[test]
fn stored_network_fetch_and_list() {
    let env = env();
    env.exec(
        r#"INSERT INTO "Network" ("Id","Type","ChainId","Name","RPC","CurrencySymbol","CurrencyDecimals","BlockExplorer","TestNet","Priority","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
        vec![
            SqlValue::Text("net-1".into()),
            SqlValue::Text("evm".into()),
            SqlValue::Text("137".into()),
            SqlValue::Text("Polygon".into()),
            SqlValue::Text("https://polygon-rpc.com".into()),
            SqlValue::Text("POL".into()),
            SqlValue::Int(18),
            SqlValue::Text("auto".into()),
            SqlValue::Int(0),
            SqlValue::Int(50),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();

    let n = network::fetch(&env, "net-1").unwrap().expect("found");
    assert_eq!(n.name, "Polygon");
    assert_eq!(n.chain_id, "137");
    // BlockExplorer "auto" resolves via the registry.
    let j = n.to_json();
    assert!(j["ResolvedBlockExplorer"].as_str().unwrap().contains("polygonscan"));

    assert_eq!(network::list(&env).unwrap().len(), 1);
    assert!(network::fetch(&env, "net-missing").unwrap().is_none());
}
