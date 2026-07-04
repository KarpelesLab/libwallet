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

/// `Wallet:multiCreate` {Name, Keys} — create both a secp256k1 (dkls23) and an
/// ed25519 (frost) wallet with the same key set (Go apiMultiCreateWallet).
/// Returns both wallets.
pub fn multi_create(env: &Env, params: &Value) -> ApiResult {
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("").to_owned();
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let secp = crate::models::wallet::create(env, &name, "secp256k1", &keys).map_err(ApiError::internal)?;
    let ed = crate::models::wallet::create(env, &name, "ed25519", &keys).map_err(ApiError::internal)?;
    for w in [&secp, &ed] {
        env.broadcast(&crate::response::event(
            "wallet:created",
            serde_json::json!({ "id": w.id, "curve": w.curve }),
        ));
    }
    Ok(serde_json::json!({
        "secp256k1": serde_json::to_value(&secp).unwrap(),
        "ed25519": serde_json::to_value(&ed).unwrap(),
    }))
}

/// `Wallet:backup` {Id?} — export the wallet(s) as backup entries (including the
/// encrypted key shares). One wallet when `Id` is given, else all (Go
/// apiWalletBackup).
pub fn backup(env: &Env, params: &Value) -> ApiResult {
    let entries = match params.get("Id").and_then(Value::as_str) {
        Some(id) => {
            let w = crate::models::wallet::fetch(env, id)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(404, "wallet not found"))?;
            vec![crate::models::wallet::backup_entry(&w).map_err(ApiError::internal)?]
        }
        None => crate::models::wallet::list(env)
            .map_err(ApiError::internal)?
            .iter()
            .map(crate::models::wallet::backup_entry)
            .collect::<crate::Result<Vec<_>>>()
            .map_err(ApiError::internal)?,
    };
    Ok(Value::Array(entries))
}

/// `Wallet:restore` {Files: [{Data}]} — restore wallets from backup entries (Go
/// apiWalletRestore). Returns the restored wallet ids.
pub fn restore(env: &Env, params: &Value) -> ApiResult {
    let files = params
        .get("Files")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::new(400, "Files (backup entries) required"))?;
    let mut restored = Vec::new();
    for f in files {
        let data = f
            .get("Data")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::new(400, "backup entry missing Data"))?;
        restored.push(crate::models::wallet::restore_entry(env, data).map_err(ApiError::internal)?);
    }
    Ok(serde_json::json!({ "restored": restored }))
}

/// `Wallet:importMnemonic` {Mnemonic, Passphrase?, Curve, Name, Keys(1)} — import
/// a BIP-39 mnemonic as a 1-of-1 wallet (Go apiImportMnemonic).
pub fn import_mnemonic(env: &Env, params: &Value) -> ApiResult {
    let curve = params.get("Curve").and_then(Value::as_str).unwrap_or("");
    if curve != "secp256k1" && curve != "ed25519" {
        return Err(ApiError::new(400, format!("unsupported curve {curve:?}")));
    }
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("").to_owned();
    let mnemonic = params
        .get("Mnemonic")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Mnemonic required"))?;
    let passphrase = params.get("Passphrase").and_then(Value::as_str).unwrap_or("");
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    if keys.len() != 1 {
        return Err(ApiError::new(400, format!("import requires exactly 1 KeyDescription (got {})", keys.len())));
    }
    let w = crate::models::wallet::import_mnemonic(env, &name, curve, mnemonic, passphrase, &keys[0])
        .map_err(ApiError::internal)?;
    env.broadcast(&crate::response::event(
        "wallet:created",
        serde_json::json!({ "id": w.id, "curve": w.curve, "imported": true }),
    ));
    Ok(serde_json::to_value(w).unwrap())
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
