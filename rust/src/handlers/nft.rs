//! Nft object endpoints — Fetch/List only (NFTs are discovered, not created).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::nft::fetch(env, id).map_err(ApiError::internal)? {
                Some(n) => Ok(serde_json::to_value(n).unwrap()),
                None => Err(ApiError::new(404, "nft not found")),
            },
            None => Ok(serde_json::to_value(
                crate::models::nft::list(env).map_err(ApiError::internal)?,
            )
            .unwrap()),
        },
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Nft"))),
    }
}
