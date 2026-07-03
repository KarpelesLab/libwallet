//! Contract label lookup endpoint. `Contract:lookup` {chainKey, Address} ->
//! the curated contract (or null).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn lookup(_env: &Env, params: &Value) -> ApiResult {
    let chain_key = params
        .get("chainKey")
        .or_else(|| params.get("Network"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "chainKey required"))?;
    let address = params
        .get("Address")
        .or_else(|| params.get("address"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Address required"))?;
    match crate::contract::lookup(chain_key, address) {
        Some(c) => Ok(serde_json::to_value(c).unwrap()),
        None => Ok(Value::Null),
    }
}
