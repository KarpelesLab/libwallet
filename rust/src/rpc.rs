//! Minimal blocking JSON-RPC client for blockchain nodes (port of the wltnet
//! DoRPC path). ethrpc-rs's own client is async; the FFI runs each request on a
//! worker thread, so a blocking transport fits without pulling in a runtime.
//! Built on rsurl (the project's HTTP client). Used for EVM/Bitcoin/Solana node
//! calls (eth_getBalance, eth_sendRawTransaction, net_version, modchain_*, ...).

use serde_json::{json, Value};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use crate::{Error, Result};

/// Encode a JSON-RPC 2.0 request body for `method`/`params`.
fn encode_body(method: &str, params: &Value) -> Result<Vec<u8>> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    serde_json::to_vec(&body).map_err(|e| Error::Env(format!("rpc {method} encode failed: {e}")))
}

/// Extract `result` from a decoded JSON-RPC response, surfacing a JSON-RPC
/// `error` as an [`Error`]. Shared by the blocking and async transports.
fn parse_response(method: &str, resp: Value) -> Result<Value> {
    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            return Err(Error::Env(format!("rpc {method} error: {err}")));
        }
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| Error::Env(format!("rpc {method} response missing result")))
}

/// POST a single JSON-RPC 2.0 call and return its `result` (or an error if the
/// node returned a JSON-RPC error). Blocking transport — native only; the FFI
/// worker thread makes this fine, and the browser uses [`call_async`] instead.
#[cfg(not(target_arch = "wasm32"))]
pub fn call(url: &str, method: &str, params: Value) -> Result<Value> {
    let resp: Value = rsurl::Request::new("POST", url)
        .map_err(|e| Error::Env(format!("rpc {method} request build failed: {e}")))?
        .header("Content-Type", "application/json")
        .read_timeout(Some(Duration::from_secs(20)))
        .body(encode_body(method, &params)?)
        .send()
        .map_err(|e| Error::Env(format!("rpc {method} request failed: {e}")))?
        .json()
        .map_err(|e| Error::Env(format!("rpc {method} decode failed: {e}")))?;
    parse_response(method, resp)
}

/// Async twin of [`call`], built on rsurl's async `aio` client. Identical logic
/// on native and wasm: on wasm it routes through the browser Fetch API, on
/// native through rsurl's Tokio runtime. This is the transport the browser
/// handlers use for chain RPC, so endpoint resolution stays in Rust and the JS
/// never names a node URL. Native code can use it too (see the test below).
pub async fn call_async(url: &str, method: &str, params: Value) -> Result<Value> {
    let req = rsurl::aio::Request::new("POST", url)
        .header("Content-Type", "application/json")
        .body(encode_body(method, &params)?);
    let resp = aio_send(&req)
        .await
        .map_err(|e| Error::Env(format!("rpc {method} request failed: {e}")))?;
    let resp: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Env(format!("rpc {method} decode failed: {e}")))?;
    parse_response(method, resp)
}

/// Send an `aio` request, supplying rsurl's Tokio runtime on native; on wasm the
/// browser event loop *is* the runtime, so `request` takes no argument. This
/// tiny shim is the ONLY target-specific line — [`call_async`] above is shared.
#[cfg(not(target_arch = "wasm32"))]
async fn aio_send(req: &rsurl::aio::Request) -> std::result::Result<rsurl::aio::Response, rsurl::Error> {
    rsurl::aio::request(&rsurl::aio::TokioRuntime, req).await
}
#[cfg(target_arch = "wasm32")]
async fn aio_send(req: &rsurl::aio::Request) -> std::result::Result<rsurl::aio::Response, rsurl::Error> {
    rsurl::aio::request(req).await
}

/// Native balance (in wei) of `address` at the latest block, as a decimal
/// string. Convenience over eth_getBalance.
#[cfg(not(target_arch = "wasm32"))]
pub fn eth_get_balance(url: &str, address: &str) -> Result<String> {
    let hex = call(url, "eth_getBalance", json!([address, "latest"]))?;
    let hex = hex.as_str().ok_or_else(|| Error::Env("balance not a string".into()))?;
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let n = num_bigint::BigInt::parse_bytes(stripped.as_bytes(), 16)
        .ok_or_else(|| Error::Env(format!("bad balance hex {hex}")))?;
    Ok(n.to_string())
}

/// Broadcast a raw signed transaction, returning its hash.
#[cfg(not(target_arch = "wasm32"))]
pub fn eth_send_raw_transaction(url: &str, raw_hex: &str) -> Result<String> {
    let res = call(url, "eth_sendRawTransaction", json!([raw_hex]))?;
    res.as_str().map(str::to_owned).ok_or_else(|| Error::Env("tx hash not a string".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// One-shot mock JSON-RPC server: accepts one connection, reads the request,
    /// and replies with `result_json` wrapped in a JSON-RPC envelope. Returns the
    /// `http://addr` to POST to.
    fn mock_rpc(result_json: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    // Proves the async rsurl::aio transport works on native (driven by rsurl's
    // Tokio runtime) — the same code path the browser runs over Fetch.
    #[tokio::test]
    async fn call_async_roundtrips() {
        let url = mock_rpc(r#""0x2a""#);
        let got = call_async(&url, "eth_getBalance", json!(["0xabc", "latest"])).await.unwrap();
        assert_eq!(got, json!("0x2a"));
    }

    // A JSON-RPC error envelope surfaces as an Err, not a missing-result.
    #[tokio::test]
    async fn call_async_surfaces_rpc_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let err = call_async(&format!("http://{addr}"), "eth_call", json!([])).await.unwrap_err();
        assert!(format!("{err}").contains("boom"), "got: {err}");
    }
}
