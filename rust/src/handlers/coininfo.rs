//! Coin metadata endpoint (wltasset CoinInfo). `Coin:info` {Symbol|Address,
//! Backend?} returns display metadata (name, logo, links) for a token, cached
//! for 7 days. Absent records return 404.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn info(env: &Env, params: &Value) -> ApiResult {
    let base = params
        .get("Backend")
        .and_then(Value::as_str)
        .unwrap_or(crate::rest::DEFAULT_HOST);

    let found = if let Some(sym) = params.get("Symbol").and_then(Value::as_str) {
        crate::coininfo::by_key(env, base, "symbol", sym)
    } else if let Some(addr) = params.get("Address").and_then(Value::as_str) {
        crate::coininfo::by_key(env, base, "address", addr)
    } else {
        return Err(ApiError::new(400, "Symbol or Address required"));
    }
    .map_err(ApiError::internal)?;

    match found {
        Some(info) => Ok(serde_json::to_value(info).unwrap()),
        None => Err(ApiError::new(404, "no coin info")),
    }
}
