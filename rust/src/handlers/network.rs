//! Network object endpoints — read surface (fetch/list). Creation runs check()
//! + RPC probing and is deferred, so POST returns 501.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::network::fetch(env, id).map_err(ApiError::internal)? {
                Some(n) => Ok(n.to_json()),
                None => Err(ApiError::new(404, "network not found")),
            },
            None => {
                let list = crate::models::network::list(env).map_err(ApiError::internal)?;
                Ok(Value::Array(list.iter().map(|n| n.to_json()).collect()))
            }
        },
        "POST" => Err(ApiError::new(501, "network creation (check + RPC) not yet ported")),
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Network"))),
    }
}
