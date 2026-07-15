//! Network create / update / delete parity with the Go `wltnet` object, plus
//! the RPC-URL SSRF guard shared by create/update/testRPC.

use libwallet::models::network::{self, Network};
use libwallet::Env;

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    env
}

fn base(kind: &str, chain: &str) -> Network {
    Network { kind: kind.into(), chain_id: chain.into(), ..Default::default() }
}

#[test]
fn create_evm_fills_registry_defaults() {
    let env = env();
    let created = network::create(&env, base("evm", "1")).unwrap();
    // Deterministic id from type.chainId, and check() filled the blanks.
    assert_eq!(created.id, network::network_id_for("evm", "1"));
    assert_eq!(created.name, "Ethereum Mainnet");
    assert_eq!(created.currency_symbol, "ETH");
    assert_eq!(created.rpc, "auto");
    assert_eq!(created.block_explorer, "auto");
    assert!(!created.created.is_empty());

    // Persisted and re-fetchable by id.
    let got = network::fetch(&env, &created.id).unwrap().expect("stored");
    assert_eq!(got.name, "Ethereum Mainnet");
    assert_eq!(network::list(&env).unwrap().len(), 1);
}

#[test]
fn create_polygon_matic_rewritten_to_pol() {
    let env = env();
    let mut n = base("evm", "137");
    n.currency_symbol = "MATIC".into();
    let created = network::create(&env, n).unwrap();
    assert_eq!(created.currency_symbol, "POL");
}

#[test]
fn create_bitcoin_and_solana_defaults() {
    let env = env();
    let ltc = network::create(&env, base("bitcoin", "litecoin")).unwrap();
    assert_eq!(ltc.name, "Litecoin");
    assert_eq!(ltc.currency_symbol, "LTC");

    let dev = network::create(&env, base("solana", "devnet")).unwrap();
    assert_eq!(dev.name, "Solana Devnet");
    assert_eq!(dev.currency_symbol, "SOL");
    assert_eq!(dev.currency_decimals, 9);
    assert!(dev.testnet, "devnet is a testnet");
    assert_eq!(dev.rpc, "auto");
}

#[test]
fn create_rejects_invalid_type_and_chain() {
    let env = env();
    assert!(network::create(&env, base("dogecoin", "x")).is_err());
    assert!(network::create(&env, base("bitcoin", "nope")).is_err());
    assert!(network::create(&env, base("solana", "nope")).is_err());
}

#[test]
fn create_rejects_internal_rpc() {
    let env = env();
    let mut n = base("evm", "1");
    n.rpc = "http://10.0.0.5/rpc".into();
    assert!(network::create(&env, n).is_err(), "internal RPC must be refused");
    assert_eq!(network::list(&env).unwrap().len(), 0, "nothing persisted");
}

#[test]
fn update_applies_mutable_fields() {
    let env = env();
    let created = network::create(&env, base("evm", "1")).unwrap();
    let updated = network::update(
        &env,
        &created.id,
        &serde_json::json!({ "Name": "My ETH", "Priority": 42, "TestNet": true }),
    )
    .unwrap();
    assert_eq!(updated.name, "My ETH");
    assert_eq!(updated.priority, 42);
    assert!(updated.testnet);
    // Persisted.
    let got = network::fetch(&env, &created.id).unwrap().unwrap();
    assert_eq!(got.name, "My ETH");
    assert_eq!(got.priority, 42);
}

#[test]
fn update_rejects_internal_rpc_and_keeps_row() {
    let env = env();
    let created = network::create(&env, base("evm", "1")).unwrap();
    // A genuinely internal (link-local) RPC must fail the update via check().
    let err = network::update(
        &env,
        &created.id,
        &serde_json::json!({ "RPC": "http://169.254.1.1/rpc", "Name": "hacked" }),
    );
    assert!(err.is_err(), "link-local RPC must be refused");
    // The stored row keeps its original name (update was not persisted).
    let got = network::fetch(&env, &created.id).unwrap().unwrap();
    assert_eq!(got.name, "Ethereum Mainnet");
}

#[test]
fn update_noop_returns_row_unchanged() {
    let env = env();
    let created = network::create(&env, base("evm", "1")).unwrap();
    let same = network::update(&env, &created.id, &serde_json::json!({})).unwrap();
    assert_eq!(same.name, created.name);
}

#[test]
fn delete_removes_row() {
    let env = env();
    let created = network::create(&env, base("evm", "1")).unwrap();
    network::delete(&env, &created.id).unwrap();
    assert!(network::fetch(&env, &created.id).unwrap().is_none());
    assert_eq!(network::list(&env).unwrap().len(), 0);
}

#[test]
fn rpc_url_guard_policy() {
    // Public host must be https.
    assert!(network::validate_rpc_url("https://mainnet.example/rpc").is_ok());
    assert!(network::validate_rpc_url("http://mainnet.example/rpc").is_err());
    // localhost / loopback dev escape hatch (http allowed).
    assert!(network::validate_rpc_url("http://localhost:8545").is_ok());
    assert!(network::validate_rpc_url("http://127.0.0.1:8545").is_ok());
    assert!(network::validate_rpc_url("http://[::1]:8545").is_ok());
    // Internal / private / mDNS targets rejected even over https.
    assert!(network::validate_rpc_url("https://10.0.0.1/rpc").is_err());
    assert!(network::validate_rpc_url("https://192.168.1.1/rpc").is_err());
    assert!(network::validate_rpc_url("https://node.local/rpc").is_err());
    // Bad scheme.
    assert!(network::validate_rpc_url("ftp://example.com").is_err());
    // "" / "auto" sentinels pass the network-level guard.
    assert!(network::validate_network_rpc("").is_ok());
    assert!(network::validate_network_rpc("auto").is_ok());
}
