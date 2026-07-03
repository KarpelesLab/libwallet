//! Swap quote logic + an end-to-end quote against a mock OKX proxy (no live
//! credentials). The mock ignores the request signature, so the whole quote
//! path — chain-index/token mapping, REST call, response parse, min-receive —
//! is exercised deterministically.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::rest::ApiKey;
use libwallet::swap::{self, TokenRef};

#[test]
fn okx_chain_index_maps_networks() {
    assert_eq!(swap::okx_chain_index("evm", "1").unwrap(), "1");
    assert_eq!(swap::okx_chain_index("evm", "137").unwrap(), "137");
    assert!(swap::okx_chain_index("evm", "").is_err());
    assert_eq!(swap::okx_chain_index("solana", "mainnet").unwrap(), "501");
    assert_eq!(swap::okx_chain_index("solana", "").unwrap(), "501");
    assert_eq!(swap::okx_chain_index("solana", "devnet").unwrap(), "103");
    assert!(swap::okx_chain_index("solana", "testnet").is_err());
    assert!(swap::okx_chain_index("bitcoin", "bitcoin").is_err());
}

#[test]
fn okx_token_addr_and_slippage() {
    // Native -> chain sentinel; strips a "type.chain." prefix.
    assert_eq!(swap::okx_token_addr("evm", "NATIVE"), "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    assert_eq!(swap::okx_token_addr("solana", "NATIVE"), "So11111111111111111111111111111111111111112");
    assert_eq!(swap::okx_token_addr("evm", "evm.1.0xABC"), "0xABC");
    assert_eq!(swap::okx_token_addr("evm", "0xdef"), "0xdef");
    // Slippage clamping.
    assert_eq!(swap::normalize_slippage(0), 50);
    assert_eq!(swap::normalize_slippage(100), 100);
    assert_eq!(swap::normalize_slippage(9999), 5000);
}

/// One-shot mock serving a KLB envelope wrapping `data_json`.
fn mock(data_json: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(r#"{{"result":"success","data":{data_json}}}"#);
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn token(addr: &str, sym: &str, dec: i64) -> TokenRef {
    TokenRef { address: addr.into(), symbol: sym.into(), decimals: dec }
}

#[test]
fn get_quote_builds_from_okx_entry() {
    // OKX: 1.0 tokenIn (6 dec) -> 2_000_000 tokenOut base units, 0.25% impact.
    let base = mock(
        r#"{"fromTokenAmount":"1000000","toTokenAmount":"2000000","priceImpactPercent":"0.25","estimateGasFee":"21000"}"#,
    );
    let key = ApiKey::from_seed("test", [3u8; 32]);
    let q = swap::get_quote(
        &key,
        &base,
        "evm",
        "1",
        token("0xIN", "IN", 6),
        token("0xOUT", "OUT", 6),
        "1000000",
        50, // 0.5% slippage
    )
    .unwrap();

    assert_eq!(q.provider, "okx_evm");
    assert_eq!(q.amount_out.to_display_string(), "2.000000");
    // min = 2_000_000 * 9950/10000 = 1_990_000 -> 1.990000
    assert_eq!(q.min_amount_out.to_display_string(), "1.990000");
    assert_eq!(q.slippage_bps, 50);
    assert_eq!(q.fee_bps, 50);
    assert!((q.price_impact - 0.0025).abs() < 1e-9);
    // networkFee = 21000 wei @ 18 dec.
    assert_eq!(q.network_fee.as_ref().unwrap().exp(), 18);
}

#[test]
fn get_quote_no_route_errors() {
    // toTokenAmount 0 -> no liquidity.
    let base = mock(r#"{"fromTokenAmount":"1000000","toTokenAmount":"0"}"#);
    let key = ApiKey::from_seed("test", [3u8; 32]);
    let err = swap::get_quote(
        &key,
        &base,
        "evm",
        "1",
        token("0xIN", "IN", 6),
        token("0xOUT", "OUT", 6),
        "1000000",
        0,
    );
    assert!(err.is_err(), "no route must error");
}
