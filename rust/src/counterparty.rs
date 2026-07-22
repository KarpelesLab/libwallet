//! Counterparty asset-transfer composition for the Mpurse (Monacoin) web3
//! provider — the compose step behind `mpurse_sendAsset`.
//!
//! DIVERGENCE FROM GO: the Go build deliberately returns "mpurse_sendAsset is
//! not implemented" (`wltbase/web3.go`) because composing a Counterparty send
//! requires an external Counterparty server. This module adds that step by
//! calling the canonical counterparty-lib JSON-RPC `create_send` method, which
//! returns an unsigned transaction hex the caller then signs (the
//! `mpurse_signRawTransaction` bitcoin path) and broadcasts.
//!
//! CAVEAT: the endpoint and its exact request/response contract are NOT
//! exercised against a live Counterparty node anywhere in this repo. `create_send`
//! targets the standard counterparty-lib API shape and MUST be validated against
//! the target server (endpoint, auth, quantity/divisibility semantics) before
//! production use. The endpoint is configurable per call.

use serde_json::{json, Value};

use crate::{Error, Result};

/// Default Monacoin Counterparty (Monaparty) compose endpoint used when the
/// caller does not pass an explicit `CounterpartyRPC` override. Documented, not
/// verified — see the module caveat.
pub const DEFAULT_MONACOIN_COUNTERPARTY_URL: &str = "https://wallet.monaparty.me/_api";

/// Compose an unsigned Counterparty `send` transaction, returning its raw hex.
///
/// `quantity` is the asset's integer base units — Counterparty quantities are
/// integers, and divisible assets carry 8 implied decimals, so the caller is
/// responsible for scaling a human amount before calling. `memo` is optional;
/// `memo_is_hex` selects hex vs. text interpretation of the memo.
pub fn create_send(
    api_url: &str,
    source: &str,
    destination: &str,
    asset: &str,
    quantity: u64,
    memo: Option<&str>,
    memo_is_hex: bool,
) -> Result<String> {
    let mut params = json!({
        "source": source,
        "destination": destination,
        "asset": asset,
        "quantity": quantity,
        // Spend unconfirmed change so a rapid second send from the same address
        // doesn't fail for lack of confirmed inputs (Counterparty default off).
        "allow_unconfirmed_inputs": true,
    });
    if let Some(m) = memo.filter(|s| !s.is_empty()) {
        params["memo"] = Value::String(m.to_owned());
        params["memo_is_hex"] = Value::Bool(memo_is_hex);
    }

    let result = crate::rpc::call(api_url, "create_send", params)?;
    extract_tx_hex(&result)
}

/// Pull the unsigned tx hex out of a `create_send` result. counterparty-lib
/// returns the hex string directly; some deployments wrap it in an object under
/// `tx_hex` / `rawtransaction` / `raw_transaction`.
fn extract_tx_hex(result: &Value) -> Result<String> {
    match result {
        Value::String(s) if !s.is_empty() => Ok(s.clone()),
        Value::Object(_) => result
            .get("tx_hex")
            .or_else(|| result.get("rawtransaction"))
            .or_else(|| result.get("raw_transaction"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| Error::Env(format!("create_send: no tx hex in result {result}"))),
        _ => Err(Error::Env(format!(
            "create_send: unexpected result {result}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hex_from_string() {
        assert_eq!(extract_tx_hex(&json!("0100abcd")).unwrap(), "0100abcd");
    }

    #[test]
    fn extract_hex_from_object_variants() {
        assert_eq!(extract_tx_hex(&json!({ "tx_hex": "aa" })).unwrap(), "aa");
        assert_eq!(
            extract_tx_hex(&json!({ "rawtransaction": "bb" })).unwrap(),
            "bb"
        );
        assert_eq!(
            extract_tx_hex(&json!({ "raw_transaction": "cc" })).unwrap(),
            "cc"
        );
    }

    #[test]
    fn extract_hex_rejects_empty_and_missing() {
        assert!(extract_tx_hex(&json!("")).is_err());
        assert!(extract_tx_hex(&json!({ "nope": 1 })).is_err());
        assert!(extract_tx_hex(&json!(42)).is_err());
    }
}
