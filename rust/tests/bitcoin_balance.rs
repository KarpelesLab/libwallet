//! Bitcoin native-balance parsing (BtcAmount) and modchain_assets summation,
//! against a local mock — no external network.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::bitcoin::{hd_address, native_balance_satoshi, next_address, parse_btc_amount};
use serde_json::json;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

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

#[test]
fn hd_address_encodes_p2wpkh_and_p2pkh() {
    // BIP-32 vector-1 master pubkey — a valid compressed secp256k1 key.
    let pk: [u8; 33] = unhex("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
        .try_into()
        .unwrap();
    // bitcoin -> native segwit (bech32).
    let btc = hd_address(&pk, "bitcoin").unwrap();
    assert!(btc.starts_with("bc1q"), "got {btc}");
    // litecoin segwit.
    assert!(hd_address(&pk, "litecoin").unwrap().starts_with("ltc1q"));
    // dogecoin -> P2PKH base58 (D...).
    assert!(hd_address(&pk, "dogecoin").unwrap().starts_with('D'));
    // unknown chain errors.
    assert!(hd_address(&pk, "ethereum").is_err());
}

#[test]
fn next_address_uses_lookup_index_and_derives() {
    // modchain_lookupTxoBIP32 says index 4 is the highest used -> next is 5.
    let url = mock(r#"{"lastI":4}"#);
    let account_pubkey: [u8; 33] =
        unhex("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
            .try_into()
            .unwrap();
    let account_chaincode: [u8; 32] =
        unhex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
            .try_into()
            .unwrap();
    let (addr, index, path) =
        next_address(&url, "xpub-ignored-by-mock", &account_pubkey, &account_chaincode, "bitcoin", false)
            .unwrap();
    assert_eq!(index, 5);
    assert_eq!(path, "m/0/5");
    assert!(addr.starts_with("bc1q"), "got {addr}");

    // Change chain uses m/1.
    let url2 = mock(r#"{"lastI":-1}"#);
    let (_, idx2, path2) =
        next_address(&url2, "xpub", &account_pubkey, &account_chaincode, "bitcoin", true).unwrap();
    assert_eq!(idx2, 0); // unused chain (lastI=-1) -> first index
    assert_eq!(path2, "m/1/0");
}
