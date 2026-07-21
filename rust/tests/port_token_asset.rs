//! Ports of the two Go commits:
//!   * wlttoken: accept "<type>.<chainId>" network refs in Token:create /
//!     discoverToken (Go wlttoken/network_ref_test.go).
//!   * wltbase: registered ERC-20 tokens appear in Asset:list with live
//!     balances (Go wlttest/erc20_assets_test.go).
//!
//! The balance leg uses a mock JSON-RPC server (the TcpListener pattern from
//! src/handlers/token.rs #[cfg(test)]) rather than a live public RPC, so the
//! test is hermetic.

use std::io::{Read, Write};
use std::net::TcpListener;

use libwallet::models::network::Network;
use libwallet::models::{account, asset, network, token};
use libwallet::models::token::Token;
use libwallet::Env;

/// Serve `results` in order: each incoming HTTP POST gets a JSON-RPC envelope
/// wrapping the next canned `result`. Returns the listener URL.
fn mock_rpc(results: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for result in results {
            let (mut stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// A uint256 as an eth_call would return it, quoted for the JSON-RPC `result`.
fn abi_uint(n: u128) -> String {
    format!("\"0x{n:064x}\"")
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    token::init(&env).unwrap();
    asset::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

// --- Commit 1: "<type>.<chainId>" network ref -----------------------------

#[test]
fn resolve_network_ref_accepts_both_forms() {
    // Canonical "<type>.<chainId>" — the form the Dart Token API / Asset.network
    // send, which used to fail as "invalid UUID length: 7" (e.g. "evm.137").
    for (reference, typ, chain) in [
        ("evm.137", "evm", "137"),      // Polygon — the reported case
        ("evm.1", "evm", "1"),          // Ethereum
        ("solana.mainnet", "solana", "mainnet"),
    ] {
        let got = token::resolve_network_ref(reference).expect("resolve");
        assert_eq!(got, network::network_id_for(typ, chain), "ref {reference}");
    }

    // A network xuid passes through unchanged.
    let id = network::network_id_for("evm", "1");
    assert!(id.starts_with("net-"), "id shape: {id}");
    assert_eq!(token::resolve_network_ref(&id).unwrap(), id);

    // Empty and bare-name refs must error clearly (not "invalid UUID length").
    assert!(token::resolve_network_ref("").is_err());
    assert!(token::resolve_network_ref("polygon").is_err());
}

#[test]
fn token_create_accepts_type_chainid_and_stores_resolved_id() {
    let env = env();
    // "evm.137" (Polygon) — the reported failing case — must now create.
    let created = token::create(
        &env,
        Token {
            symbol: "USDC".into(),
            address: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359".into(),
            decimals: 6,
            network: "evm.137".into(),
            ..blank()
        },
    )
    .expect("create with evm.137");
    // The stored Network is the resolved deterministic id, not "evm.137" — so
    // tokens_by_network (and thus Asset:list) can find it.
    assert_eq!(created.network, network::network_id_for("evm", "137"));
    assert_eq!(created.kind, "erc20"); // defaulted for EVM

    let scoped = token::tokens_by_network(&env, &network::network_id_for("evm", "137")).unwrap();
    assert_eq!(scoped.len(), 1);
    // Scoped to the network: nothing leaks onto Ethereum mainnet.
    assert!(token::tokens_by_network(&env, &network::network_id_for("evm", "1")).unwrap().is_empty());
}

// --- Commit 2: ERC-20 tokens in Asset:list --------------------------------

/// Set up an env whose current network is EVM Ethereum with `rpc` as its
/// endpoint, and whose current account is a watch-only ethereum view account.
fn evm_env_with_current(rpc: &str, owner: &str) -> Env {
    let env = env();
    // Overwrite the seeded evm.1 (rpc "auto") with the mock endpoint. Same id,
    // so network::create replaces the row rather than colliding.
    let net = network::create(
        &env,
        Network { kind: "evm".into(), chain_id: "1".into(), rpc: rpc.into(), ..Default::default() },
    )
    .unwrap();
    env.set_current("network", &net.id).unwrap();
    // A watch-only ethereum account (sets itself current).
    account::create_view(&env, "acct", "ethereum", owner).unwrap();
    env
}

#[test]
fn asset_list_includes_registered_erc20_with_live_balance() {
    let owner = "0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf";
    // One eth_call balanceOf → 1_000_000 base units (1 USDC at 6 decimals).
    let rpc = mock_rpc(vec![abi_uint(1_000_000)]);
    let env = evm_env_with_current(&rpc, owner);

    let created = token::create(
        &env,
        Token {
            name: "USD Coin".into(),
            symbol: "USDC".into(),
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into(),
            decimals: 6,
            network: "evm.1".into(),
            ..blank()
        },
    )
    .unwrap();

    let assets = asset::list(&env).unwrap();
    let want_key = format!("evm.1.{}", created.address);
    let erc20 = assets
        .iter()
        .find(|a| a.key == want_key)
        .unwrap_or_else(|| panic!("ERC-20 asset {want_key} not in {:?}", assets.iter().map(|a| &a.key).collect::<Vec<_>>()));
    assert_eq!(erc20.symbol, "USDC");
    assert_eq!(erc20.name, "USD Coin");
    assert_eq!(erc20.kind, "fungible");
    assert_eq!(erc20.network, network::network_id_for("evm", "1"));
    // Amount: 1_000_000 raw base units at 6 decimals.
    let amt = serde_json::to_value(&erc20.amount).unwrap();
    assert_eq!(amt["v"], "1000000");
    assert_eq!(amt["e"], 6);
}

#[test]
fn asset_list_includes_zero_balance_token() {
    // A token the user explicitly registered shows as "0" rather than vanishing.
    let owner = "0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf";
    let rpc = mock_rpc(vec![abi_uint(0)]);
    let env = evm_env_with_current(&rpc, owner);

    let created = token::create(
        &env,
        Token {
            symbol: "ZERO".into(),
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into(),
            decimals: 18,
            network: "evm.1".into(),
            ..blank()
        },
    )
    .unwrap();

    let assets = asset::list(&env).unwrap();
    let want_key = format!("evm.1.{}", created.address);
    let erc20 = assets.iter().find(|a| a.key == want_key).expect("zero-balance token present");
    let amt = serde_json::to_value(&erc20.amount).unwrap();
    assert_eq!(amt["v"], "0");
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
