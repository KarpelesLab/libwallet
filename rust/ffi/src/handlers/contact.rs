//! Contact object endpoints — the object-CRUD dispatch pattern.
//!
//! `GET Contact` with an `Id` param fetches one; without, it lists. `POST
//! Contact` creates. This shape (verb + optional Id) is what every registered
//! object type in the Go `pobj` registry follows, and later models plug in the
//! same way.

use serde_json::Value;

use wltbase::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match wltcontact::fetch(env, id).map_err(ApiError::internal)? {
                Some(c) => Ok(serde_json::to_value(c).unwrap()),
                None => Err(ApiError::new(404, "contact not found")),
            },
            None => {
                let list = wltcontact::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => {
            let c: wltcontact::Contact =
                serde_json::from_value(params.clone()).map_err(|e| ApiError::new(400, e.to_string()))?;
            let created = wltcontact::create(env, c).map_err(ApiError::internal)?;
            Ok(serde_json::to_value(created).unwrap())
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Contact"))),
    }
}
