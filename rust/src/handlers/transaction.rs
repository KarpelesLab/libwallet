//! Transaction object endpoints — read surface (fetch/list). Building/signing/
//! broadcast is deferred to the tx pass, so POST returns 501.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    // Optional best-effort fiat conversion when Currency is supplied.
    let currency = params.get("Currency").and_then(Value::as_str);
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::transaction::fetch(env, id).map_err(ApiError::internal)? {
                Some(mut t) => {
                    if let Some(cur) = currency {
                        let _ = t.convert_to(env, cur);
                    }
                    Ok(serde_json::to_value(t).unwrap())
                }
                None => Err(ApiError::new(404, "transaction not found")),
            },
            None => {
                let mut list =
                    crate::models::transaction::list(env).map_err(ApiError::internal)?;
                if let Some(cur) = currency {
                    for t in &mut list {
                        let _ = t.convert_to(env, cur);
                    }
                }
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => Err(ApiError::new(501, "transaction build/sign not yet ported")),
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Transaction"))),
    }
}

/// `Transaction:validate` — the structural validation of a Transaction (Go
/// `Transaction.Validate`, the type/required-field checks). A positive amount is
/// required for value transfers; erc20/bitcoin also need a recipient; erc20 also
/// an asset. Nonce/gas population needs a live node and is left to signAndSend.
pub fn validate(_env: &Env, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").unwrap_or(params);
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("");
    // Amount is an {v,e,f} object or a decimal string; positive when v != "0".
    let amount_positive = || {
        tx.get("amount")
            .map(|a| match a {
                Value::Object(m) => m.get("v").and_then(|v| v.as_str()).map(|s| s != "0" && !s.is_empty()).unwrap_or(false),
                Value::String(s) => s != "0" && !s.is_empty(),
                _ => false,
            })
            .unwrap_or(false)
    };
    let s = |k: &str| tx.get(k).and_then(Value::as_str).unwrap_or("");
    match typ {
        "transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
            if s("asset").is_empty() {
                return Err(ApiError::new(400, "asset is required"));
            }
        }
        "solana_transfer" | "solana_spl_transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
        }
        "evm" => {} // raw evm tx — no structural requirement
        "erc20_transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
            if s("asset").is_empty() {
                return Err(ApiError::new(400, "asset is required for erc20_transfer"));
            }
            if s("to").is_empty() {
                return Err(ApiError::new(400, "recipient (To) is required for erc20_transfer"));
            }
        }
        "bitcoin_transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
            if s("to").is_empty() {
                return Err(ApiError::new(400, "recipient (To) is required for bitcoin_transfer"));
            }
        }
        other => return Err(ApiError::new(400, format!("unsupported transaction type {other}"))),
    }
    Ok(serde_json::json!({ "valid": true, "type": typ }))
}
