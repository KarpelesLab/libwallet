//! Crash object endpoints — Fetch/List only (crashes are logged internally).

use serde_json::Value;

use wltbase::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match wltcrash::fetch(env, id).map_err(ApiError::internal)? {
                Some(c) => Ok(serde_json::to_value(c).unwrap()),
                None => Err(ApiError::new(404, "crash not found")),
            },
            None => {
                let list = wltcrash::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Crash"))),
    }
}
