//! Asset object endpoints — Fetch/List only (balances are discovered, not
//! created via the API).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    // Optional fiat conversion: when Currency is supplied, populate each asset's
    // fiat_* fields from the quote table (best-effort — a missing quote leaves
    // them unset rather than failing the read).
    let currency = params.get("Currency").and_then(Value::as_str);
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::asset::fetch(env, id).map_err(ApiError::internal)? {
                Some(mut a) => {
                    if let Some(cur) = currency {
                        let _ = a.convert_to(env, cur);
                    }
                    Ok(serde_json::to_value(a).unwrap())
                }
                None => Err(ApiError::new(404, "asset not found")),
            },
            None => {
                let mut list = crate::models::asset::list(env).map_err(ApiError::internal)?;
                if let Some(cur) = currency {
                    for a in &mut list {
                        let _ = a.convert_to(env, cur);
                    }
                }
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Asset"))),
    }
}
