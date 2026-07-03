//! Asset object endpoints — Fetch/List only (balances are discovered, not
//! created via the API).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::asset::fetch(env, id).map_err(ApiError::internal)? {
                Some(a) => Ok(serde_json::to_value(a).unwrap()),
                None => Err(ApiError::new(404, "asset not found")),
            },
            None => {
                let list = crate::models::asset::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Asset"))),
    }
}
