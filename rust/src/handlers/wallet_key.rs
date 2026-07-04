//! `Wallet/Key` object endpoints (port of wltwallet/wkapi.go). The Dart client
//! addresses these object-scoped: `Wallet/Key/<id>` (fetch), `Wallet/Key`
//! (list), and `Wallet/Key/<id>:recrypt` (change the wrapping key).

use serde_json::Value;

use crate::sign::KeyDescription;
use crate::Env;

use super::{ApiError, ApiResult};

/// Route an object-scoped `Wallet/Key/<id>[:action]` request. `action` is empty
/// for the bare object (fetch).
pub fn route(env: &Env, verb: &str, id: &str, action: &str, params: &Value) -> ApiResult {
    match action {
        "" => match verb {
            "GET" => fetch(env, id),
            other => Err(ApiError::new(405, format!("unsupported verb {other} for Wallet/Key"))),
        },
        "recrypt" => recrypt(env, id, params),
        other => Err(ApiError::new(404, format!("unknown Wallet/Key action: {other}"))),
    }
}

/// `Wallet/Key` (no id) — list every wallet key (Go apiListWalletKey). The
/// encrypted `Data` is never serialized (WalletKey's `#[serde(skip)]`).
pub fn list(env: &Env) -> ApiResult {
    let wallets = crate::models::wallet::list(env).map_err(ApiError::internal)?;
    let mut keys = Vec::new();
    for w in &wallets {
        for k in &w.keys {
            keys.push(serde_json::to_value(k).unwrap());
        }
    }
    Ok(Value::Array(keys))
}

/// `Wallet/Key/<id>` GET — fetch a single wallet key.
pub fn fetch(env: &Env, id: &str) -> ApiResult {
    match crate::models::wallet::fetch_key(env, id).map_err(ApiError::internal)? {
        Some(k) => Ok(serde_json::to_value(k).unwrap()),
        None => Err(ApiError::new(404, "wallet key not found")),
    }
}

/// `Wallet/Key/<id>:recrypt` {Old, New} — decrypt the share with `Old` and
/// re-encrypt it under `New`, returning the updated key.
pub fn recrypt(env: &Env, id: &str, params: &Value) -> ApiResult {
    let old: KeyDescription = params
        .get("Old")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| ApiError::new(400, "Old key descriptor required"))?;
    let new: KeyDescription = params
        .get("New")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| ApiError::new(400, "New key descriptor required"))?;
    let wk = crate::models::wallet::recrypt_key(env, id, &old, &new)
        .map_err(|e| ApiError::new(400, e.to_string()))?;
    Ok(serde_json::to_value(wk).unwrap())
}
