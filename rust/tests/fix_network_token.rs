//! Regression coverage for the two failing Dart FFI integration tests:
//!   * "Network list returns built-in networks" — a fresh env must seed the
//!     built-in networks (port of Go `MakeDefaultNetworks`).
//!   * "Wallet Account Token CRUD lifecycle" — once a network exists, the token
//!     create/list/get/update/delete cycle works end-to-end.

use libwallet::models::{network, token};
use libwallet::models::token::Token;
use libwallet::Env;

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    token::init(&env).unwrap();
    env
}

#[test]
fn fresh_env_seeds_builtin_networks() {
    let env = env();
    let list = network::list(&env).unwrap();

    // Exactly the Go MakeDefaultNetworks set: 5 EVM + 4 bitcoin-family + 1 solana.
    assert_eq!(list.len(), 10, "expected 10 seeded networks");

    // Ordered by Priority DESC, so the first entry is Ethereum mainnet (prio 100)
    // and it must carry a resolved name + currency symbol (Dart asserts both).
    let first = &list[0];
    assert_eq!(first.kind, "evm");
    assert_eq!(first.chain_id, "1");
    assert!(!first.name.is_empty(), "first network name must be non-empty");
    assert!(!first.currency_symbol.is_empty(), "first network symbol must be non-empty");

    // The expected (type, chainId) set is present with deterministic ids.
    let expected = [
        ("evm", "1"),
        ("evm", "137"),
        ("evm", "56"),
        ("evm", "11155111"),
        ("evm", "80002"),
        ("bitcoin", "bitcoin"),
        ("bitcoin", "bitcoin-cash"),
        ("bitcoin", "litecoin"),
        ("bitcoin", "dogecoin"),
        ("solana", "mainnet"),
    ];
    for (kind, chain) in expected {
        let id = network::network_id_for(kind, chain);
        let got = network::fetch(&env, &id).unwrap();
        assert!(got.is_some(), "seeded network missing: {kind}.{chain}");
    }

    // At least one EVM non-testnet network exists (Dart's firstWhere target).
    assert!(list.iter().any(|n| n.kind == "evm" && !n.testnet));
}

#[test]
fn seed_is_idempotent() {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    let first = network::list(&env).unwrap().len();
    // Re-running init must not duplicate rows.
    network::init(&env).unwrap();
    network::make_default_networks(&env).unwrap();
    assert_eq!(network::list(&env).unwrap().len(), first);
    assert_eq!(first, 10);
}

#[test]
fn token_lifecycle_on_seeded_network() {
    let env = env();

    // Mirror the Dart test: pick a non-testnet EVM network from the seeded list.
    let networks = network::list(&env).unwrap();
    let evm = networks
        .iter()
        .find(|n| n.kind == "evm" && !n.testnet)
        .expect("a seeded EVM network");

    // Create (USDT mainnet contract, as in the Dart test).
    let created = token::create(
        &env,
        Token {
            id: String::new(),
            name: "Test Token".into(),
            symbol: "TST".into(),
            address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".into(),
            decimals: 6,
            kind: "erc20".into(),
            network: evm.id.clone(),
            logo: String::new(),
            memo: String::new(),
            created: String::new(),
            updated: String::new(),
        },
    )
    .unwrap();
    assert_eq!(created.name, "Test Token");
    assert_eq!(created.symbol, "TST");
    assert_eq!(created.decimals, 6);
    assert!(created.id.starts_with("tok-"));

    // List → one token.
    assert_eq!(token::list(&env).unwrap().len(), 1);

    // Get.
    let fetched = token::fetch(&env, &created.id).unwrap().expect("stored");
    assert_eq!(fetched.symbol, "TST");

    // Update.
    let updated =
        token::update(&env, &created.id, &serde_json::json!({ "Name": "Updated Token" })).unwrap();
    assert_eq!(updated.name, "Updated Token");

    // Delete.
    token::delete(&env, &created.id).unwrap();
    assert!(token::list(&env).unwrap().is_empty());
}
