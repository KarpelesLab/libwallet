//! Counterparty `create_send` compose call (the mpurse_sendAsset compose step).
//! Drives `counterparty::create_send` against a local mock JSON-RPC node,
//! asserting the request carries the expected method + params and that the
//! unsigned tx hex is parsed back out.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use libwallet::counterparty::create_send;

/// Mock JSON-RPC node: captures the request body (sent back over `tx`) and
/// replies with `{"result": <result_json>}`.
fn mock_node(result_json: &'static str) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Some(stream) = listener.incoming().next() {
            let mut s = stream.unwrap();
            let mut acc = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        acc.extend_from_slice(&buf[..n]);
                        // Stop once the JSON body (with the method) has arrived.
                        if String::from_utf8_lossy(&acc).contains("create_send") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let req = String::from_utf8_lossy(&acc).to_string();
            let _ = tx.send(req);
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });
    (format!("http://{addr}/"), rx)
}

#[test]
fn create_send_composes_and_parses_string_result() {
    let (url, rx) = mock_node(r#""0100deadbeef""#);
    let hex = create_send(
        &url,
        "MSourceAddrxxxxxxxxxxxxxxxxxxxxxxxx",
        "MDestAddrxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "XMP",
        123_456,
        None,
        false,
    )
    .expect("create_send ok");
    assert_eq!(hex, "0100deadbeef");

    let req = rx.recv().unwrap();
    // Body must be a JSON-RPC create_send carrying the send fields.
    let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(body).expect("request body is JSON");
    assert_eq!(v["method"], "create_send");
    assert_eq!(v["params"]["source"], "MSourceAddrxxxxxxxxxxxxxxxxxxxxxxxx");
    assert_eq!(
        v["params"]["destination"],
        "MDestAddrxxxxxxxxxxxxxxxxxxxxxxxxxx"
    );
    assert_eq!(v["params"]["asset"], "XMP");
    assert_eq!(v["params"]["quantity"], 123_456);
    assert_eq!(v["params"]["allow_unconfirmed_inputs"], true);
    // No memo → the memo fields are omitted.
    assert!(v["params"].get("memo").is_none());
}

#[test]
fn create_send_includes_hex_memo_and_parses_object_result() {
    let (url, rx) = mock_node(r#"{"tx_hex":"abc123"}"#);
    let hex = create_send(&url, "src", "dst", "XMP", 7, Some("deadbeef"), true).expect("ok");
    assert_eq!(hex, "abc123");

    let req = rx.recv().unwrap();
    let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["params"]["memo"], "deadbeef");
    assert_eq!(v["params"]["memo_is_hex"], true);
}
