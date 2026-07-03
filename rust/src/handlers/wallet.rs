//! Wallet object endpoints — read surface (fetch/list). Creation is TSS key
//! generation and is deferred to Phase 3, so POST returns 501 for now.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::wallet::fetch(env, id).map_err(ApiError::internal)? {
                Some(w) => Ok(serde_json::to_value(w).unwrap()),
                None => Err(ApiError::new(404, "wallet not found")),
            },
            None => {
                let list = crate::models::wallet::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => Err(ApiError::new(501, "wallet creation (TSS keygen) not yet ported")),
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Wallet"))),
    }
}
