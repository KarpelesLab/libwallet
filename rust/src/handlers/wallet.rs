//! Wallet object endpoints — fetch/list and create (ed25519/FROST local path).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::wallet::fetch(env, id).map_err(ApiError::internal)? {
                Some(w) => Ok(serde_json::to_value(w).unwrap()),
                None => Err(ApiError::new(404, "wallet not found")),
            },
            None => {
                let list = crate::models::wallet::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => {
            #[derive(serde::Deserialize)]
            struct CreateReq {
                #[serde(rename = "Name", default)]
                name: String,
                #[serde(rename = "Curve", default)]
                curve: String,
                #[serde(rename = "Keys", default)]
                keys: Vec<crate::sign::KeyDescription>,
            }
            let req: CreateReq =
                serde_json::from_value(params.clone()).map_err(|e| ApiError::new(400, e.to_string()))?;
            let w = crate::models::wallet::create(env, &req.name, &req.curve, &req.keys)
                .map_err(ApiError::internal)?;
            Ok(serde_json::to_value(w).unwrap())
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Wallet"))),
    }
}
