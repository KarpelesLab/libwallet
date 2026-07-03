//! Bitcoin native-balance parsing (BtcAmount) and modchain_assets summation,
//! against a local mock — no external network.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::bitcoin::{native_balance_satoshi, parse_btc_amount};
use serde_json::json;

#[test]
fn btc_amount_parses_like_go() {
    // Decimal BTC -> satoshi, padded to 8 places.
    assert_eq!(parse_btc_amount(&json!("0.00000000")).unwrap(), 0);
    assert_eq!(parse_btc_amount(&json!("0.00012345")).unwrap(), 12_345);
    assert_eq!(parse_btc_amount(&json!("1.5")).unwrap(), 150_000_000);
    assert_eq!(parse_btc_amount(&json!("1.23456789")).unwrap(), 123_456_789);
    // Bare number literal keeps precision (no float rounding).
    assert_eq!(parse_btc_amount(&json!(0.00012345)).unwrap(), 12_345);
    // Integer (no dot) is whole BTC -> *1e8.
    assert_eq!(parse_btc_amount(&json!("2")).unwrap(), 200_000_000);
    assert_eq!(parse_btc_amount(&json!(3)).unwrap(), 300_000_000);
    // Hex is raw satoshi.
    assert_eq!(parse_btc_amount(&json!("0x5f5e100")).unwrap(), 100_000_000);
    // More than 8 decimals is rejected.
    assert!(parse_btc_amount(&json!("0.000000001")).is_err());
}

/// One-shot mock replying with a single JSON-RPC result.
fn mock(result_json: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
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
    format!("http://{addr}/")
}

#[test]
fn native_balance_sums_only_native_assets() {
    // A NATIVE entry plus an unrelated token — only NATIVE is summed.
    let url = mock(
        r#"{"assets":[
            {"asset":"NATIVE","decimals":8,"balance":"0.00500000"},
            {"asset":"NATIVE","decimals":8,"balance":"0.00000123"},
            {"asset":"SOMETOKEN","decimals":8,"balance":"9.99999999"}
        ]}"#,
    );
    let sats = native_balance_satoshi(&url, "bc1qexampleaddr").unwrap();
    assert_eq!(sats, 500_000 + 123);
}

#[test]
fn native_balance_empty_is_zero() {
    let url = mock(r#"{"assets":[]}"#);
    assert_eq!(native_balance_satoshi(&url, "addr").unwrap(), 0);
}
