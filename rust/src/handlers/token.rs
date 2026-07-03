//! Token object endpoints — Fetch/List. Creation discovers metadata via RPC
//! and is deferred (POST 501).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::token::fetch(env, id).map_err(ApiError::internal)? {
                Some(t) => Ok(serde_json::to_value(t).unwrap()),
                None => Err(ApiError::new(404, "token not found")),
            },
            None => Ok(serde_json::to_value(
                crate::models::token::list(env).map_err(ApiError::internal)?,
            )
            .unwrap()),
        },
        "POST" => Err(ApiError::new(501, "token creation (metadata discovery) not yet ported")),
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Token"))),
    }
}

/// `Token:listCurated` {Network} — the embedded curated token list for a
/// canonical "<type>.<chainId>" chain key (Go apiListCurated). Always a JSON
/// array; the dynamic ChiefStaker (Solana mainnet) feed is not included.
pub fn list_curated(_env: &Env, params: &Value) -> ApiResult {
    let network = params
        .get("Network")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Network required (canonical \"<type>.<chainId>\")"))?;
    Ok(Value::Array(crate::curated::for_chain(network)))
}
