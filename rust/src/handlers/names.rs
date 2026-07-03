//! Name resolution endpoint (ENS). `Name:resolve` {Name, RPC} -> {address}.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn resolve(_env: &Env, params: &Value) -> ApiResult {
    let name = params
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Name required"))?;
    let rpc = params
        .get("RPC")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "RPC endpoint required"))?;
    let address = if name.trim().to_lowercase().ends_with(".sol") {
        crate::names::resolve_sns(rpc, name)
    } else {
        crate::names::resolve_ens(rpc, name)
    }
    .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "name": name, "address": address }))
}
