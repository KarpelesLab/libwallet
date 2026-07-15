//! Token create / update / delete parity with the Go `wlttoken` object:
//! address normalization, type defaults, metadata sanitisation, decimals
//! bounds.

use libwallet::models::{network, token};
use libwallet::models::network::Network;
use libwallet::models::token::Token;
use libwallet::Env;

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    token::init(&env).unwrap();
    env
}

/// Create and persist a network of the given type/chain, returning its id.
fn make_network(env: &Env, kind: &str, chain: &str) -> String {
    let n = Network { kind: kind.into(), chain_id: chain.into(), ..Default::default() };
    network::create(env, n).unwrap().id
}

fn tok(network: &str, address: &str) -> Token {
    Token {
        network: network.to_owned(),
        address: address.to_owned(),
        ..blank()
    }
}

fn blank() -> Token {
    Token {
        id: String::new(),
        name: String::new(),
        symbol: String::new(),
        address: String::new(),
        decimals: 0,
        kind: String::new(),
        network: String::new(),
        logo: String::new(),
        memo: String::new(),
        created: String::new(),
        updated: String::new(),
    }
}

#[test]
fn create_erc20_checksums_address_and_defaults_type() {
    let env = env();
    let net = make_network(&env, "evm", "1");
    let mut t = tok(&net, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    t.symbol = "TT".into();
    t.decimals = 18;
    let created = token::create(&env, t).unwrap();

    // EIP-55 checksum applied (canonical vector) and type defaulted.
    assert_eq!(created.address, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    assert_eq!(created.kind, "erc20");
    assert!(created.id.starts_with("tok-"), "id: {}", created.id);
    assert!(!created.created.is_empty());

    let got = token::fetch(&env, &created.id).unwrap().expect("stored");
    assert_eq!(got.address, created.address);
    assert_eq!(token::list(&env).unwrap().len(), 1);
}

#[test]
fn create_spl_roundtrips_mint_and_defaults_type() {
    let env = env();
    let net = make_network(&env, "solana", "mainnet");
    // Wrapped-SOL mint — a valid 32-byte base58 pubkey.
    let t = tok(&net, "So11111111111111111111111111111111111111112");
    let created = token::create(&env, t).unwrap();
    assert_eq!(created.address, "So11111111111111111111111111111111111111112");
    assert_eq!(created.kind, "spl-token");
}

#[test]
fn create_sanitizes_display_metadata() {
    let env = env();
    let net = make_network(&env, "evm", "1");
    let mut t = tok(&net, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    // U+202E RIGHT-TO-LEFT OVERRIDE + surrounding whitespace must be stripped.
    t.name = "  Good\u{202E}Token  ".into();
    t.symbol = "AB\u{200B}C".into();
    let created = token::create(&env, t).unwrap();
    assert_eq!(created.name, "GoodToken");
    assert_eq!(created.symbol, "ABC");
}

#[test]
fn create_rejects_bad_address_and_unsupported_network() {
    let env = env();
    let evm = make_network(&env, "evm", "1");
    assert!(token::create(&env, tok(&evm, "0x1234")).is_err(), "short EVM addr");

    let sol = make_network(&env, "solana", "mainnet");
    assert!(token::create(&env, tok(&sol, "not-base58-!!!")).is_err(), "bad base58");

    let btc = make_network(&env, "bitcoin", "bitcoin");
    assert!(
        token::create(&env, tok(&btc, "bc1qexample")).is_err(),
        "tokens unsupported on bitcoin"
    );
}

#[test]
fn create_rejects_missing_fields() {
    let env = env();
    let net = make_network(&env, "evm", "1");
    assert!(token::create(&env, tok("", "0xabc")).is_err(), "network required");
    assert!(token::create(&env, tok(&net, "")).is_err(), "address required");
}

#[test]
fn update_applies_and_sanitizes_fields() {
    let env = env();
    let net = make_network(&env, "evm", "1");
    let created =
        token::create(&env, tok(&net, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")).unwrap();

    let updated = token::update(
        &env,
        &created.id,
        &serde_json::json!({ "Symbol": "US\u{202E}DC", "Decimals": 6, "Memo": "note" }),
    )
    .unwrap();
    assert_eq!(updated.symbol, "USDC");
    assert_eq!(updated.decimals, 6);
    assert_eq!(updated.memo, "note");

    let got = token::fetch(&env, &created.id).unwrap().unwrap();
    assert_eq!(got.decimals, 6);
    assert_eq!(got.memo, "note");
}

#[test]
fn update_rejects_out_of_range_decimals() {
    let env = env();
    let net = make_network(&env, "evm", "1");
    let created =
        token::create(&env, tok(&net, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")).unwrap();
    assert!(token::update(&env, &created.id, &serde_json::json!({ "Decimals": 99 })).is_err());
    assert!(token::update(&env, &created.id, &serde_json::json!({ "Decimals": -1 })).is_err());
}

#[test]
fn delete_removes_row() {
    let env = env();
    let net = make_network(&env, "evm", "1");
    let created =
        token::create(&env, tok(&net, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")).unwrap();
    token::delete(&env, &created.id).unwrap();
    assert!(token::fetch(&env, &created.id).unwrap().is_none());
    assert_eq!(token::list(&env).unwrap().len(), 0);
}
