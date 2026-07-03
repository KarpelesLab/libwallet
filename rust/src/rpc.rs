//! Minimal blocking JSON-RPC client for blockchain nodes (port of the wltnet
//! DoRPC path). ethrpc-rs's own client is async; the FFI runs each request on a
//! worker thread, so a blocking transport fits without pulling in a runtime.
//! Used for EVM/Bitcoin/Solana node calls (eth_getBalance, eth_sendRawTransaction,
//! net_version, modchain_*, ...).

use serde_json::{json, Value};
use std::time::Duration;

use crate::{Error, Result};

/// POST a single JSON-RPC 2.0 call and return its `result` (or an error if the
/// node returned a JSON-RPC error).
pub fn call(url: &str, method: &str, params: Value) -> Result<Value> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp: Value = ureq::post(url)
        .timeout(Duration::from_secs(20))
        .send_json(body)
        .map_err(|e| Error::Env(format!("rpc {method} request failed: {e}")))?
        .into_json()
        .map_err(|e| Error::Env(format!("rpc {method} decode failed: {e}")))?;

    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            return Err(Error::Env(format!("rpc {method} error: {err}")));
        }
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| Error::Env(format!("rpc {method} response missing result")))
}

/// Native balance (in wei) of `address` at the latest block, as a decimal
/// string. Convenience over eth_getBalance.
pub fn eth_get_balance(url: &str, address: &str) -> Result<String> {
    let hex = call(url, "eth_getBalance", json!([address, "latest"]))?;
    let hex = hex.as_str().ok_or_else(|| Error::Env("balance not a string".into()))?;
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let n = num_bigint::BigInt::parse_bytes(stripped.as_bytes(), 16)
        .ok_or_else(|| Error::Env(format!("bad balance hex {hex}")))?;
    Ok(n.to_string())
}

/// Broadcast a raw signed transaction, returning its hash.
pub fn eth_send_raw_transaction(url: &str, raw_hex: &str) -> Result<String> {
    let res = call(url, "eth_sendRawTransaction", json!([raw_hex]))?;
    res.as_str().map(str::to_owned).ok_or_else(|| Error::Env("tx hash not a string".into()))
}
