//! Transaction object endpoints — read surface (fetch/list). Building/signing/
//! broadcast is deferred to the tx pass, so POST returns 501.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    // Optional best-effort fiat conversion when Currency is supplied.
    let currency = params.get("Currency").and_then(Value::as_str);
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::transaction::fetch(env, id).map_err(ApiError::internal)? {
                Some(mut t) => {
                    if let Some(cur) = currency {
                        let _ = t.convert_to(env, cur);
                    }
                    Ok(serde_json::to_value(t).unwrap())
                }
                None => Err(ApiError::new(404, "transaction not found")),
            },
            None => {
                let mut list =
                    crate::models::transaction::list(env).map_err(ApiError::internal)?;
                if let Some(cur) = currency {
                    for t in &mut list {
                        let _ = t.convert_to(env, cur);
                    }
                }
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => Err(ApiError::new(501, "transaction build/sign not yet ported")),
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Transaction"))),
    }
}
