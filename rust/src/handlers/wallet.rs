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
            // Notify the host (balance poller / UI) that a wallet appeared.
            env.broadcast(&crate::response::event(
                "wallet:created",
                serde_json::json!({ "id": w.id, "curve": w.curve }),
            ));
            Ok(serde_json::to_value(w).unwrap())
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Wallet"))),
    }
}

/// `Wallet:importPrivateKey` {PrivateKey, Curve, Name, Keys(1)} — wrap a raw
/// 32-byte hex private key as a 1-of-1 wallet (Go apiImportPrivateKey).
pub fn import_private_key(env: &Env, params: &Value) -> ApiResult {
    let curve = params.get("Curve").and_then(Value::as_str).unwrap_or("");
    if curve != "secp256k1" && curve != "ed25519" {
        return Err(ApiError::new(400, format!("unsupported curve {curve:?}")));
    }
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("").to_owned();
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    if keys.len() != 1 {
        return Err(ApiError::new(400, format!("import requires exactly 1 KeyDescription (got {})", keys.len())));
    }
    // 32-byte hex private key (0x optional).
    let pk_s = params
        .get("PrivateKey")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "PrivateKey required"))?
        .trim();
    let hexs = pk_s.strip_prefix("0x").or_else(|| pk_s.strip_prefix("0X")).unwrap_or(pk_s);
    if hexs.len() != 64 {
        return Err(ApiError::new(400, format!("hex private key must be 64 chars, got {}", hexs.len())));
    }
    let priv_bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| ApiError::new(400, format!("decode hex: {e}")))?;

    let w = crate::models::wallet::import_private_key(env, &name, curve, &priv_bytes, &keys[0])
        .map_err(ApiError::internal)?;
    env.broadcast(&crate::response::event(
        "wallet:created",
        serde_json::json!({ "id": w.id, "curve": w.curve, "imported": true }),
    ));
    Ok(serde_json::to_value(w).unwrap())
}
