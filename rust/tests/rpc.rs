//! JSON-RPC client tests against a local mock server — no external network.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use serde_json::json;

/// Spin up a one-shot mock HTTP server that replies to a single request with
/// `response_json`, and return its URL.
fn mock(response_json: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = response_json.to_string();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf); // drain the request
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}/")
}

#[test]
fn call_returns_result() {
    let url = mock(r#"{"jsonrpc":"2.0","id":1,"result":"1"}"#);
    let got = libwallet::rpc::call(&url, "net_version", json!([])).unwrap();
    assert_eq!(got, json!("1"));
}

#[test]
fn get_balance_decodes_hex_wei() {
    // 0xde0b6b3a7640000 == 1e18 wei (1 ETH).
    let url = mock(r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#);
    let bal = libwallet::rpc::eth_get_balance(&url, "0xabc").unwrap();
    assert_eq!(bal, "1000000000000000000");
}

#[test]
fn send_raw_transaction_returns_hash() {
    let url = mock(r#"{"jsonrpc":"2.0","id":1,"result":"0xdeadbeefcafe"}"#);
    let h = libwallet::rpc::eth_send_raw_transaction(&url, "0x02f86c").unwrap();
    assert_eq!(h, "0xdeadbeefcafe");
}

#[test]
fn rpc_error_is_surfaced() {
    let url = mock(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#);
    let err = libwallet::rpc::call(&url, "eth_sendRawTransaction", json!(["0x.."])).unwrap_err();
    assert!(err.to_string().contains("nonce too low"), "{err}");
}
