//! Account object endpoints — fetch/list and create (ed25519/Solana path).

use base64::Engine;
use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

/// `Account:signMessage` — sign raw bytes with the account's wallet. For a
/// Solana (ed25519) account this is a raw EdDSA signature over the message,
/// returned base58-encoded (matching Go accountSignMessage). `Keys` carries the
/// unlock material (Password shares here).
pub fn sign_message(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let message_b64 = params
        .get("Message")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Message required"))?;
    let msg = base64::engine::general_purpose::STANDARD
        .decode(message_b64)
        .map_err(|e| ApiError::new(400, format!("bad Message base64: {e}")))?;

    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let unlock: Vec<(String, String)> = keys
        .iter()
        .filter(|k| k.kind == "Password")
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();

    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;

    let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &msg)
        .map_err(ApiError::internal)?;

    // Solana signatures are base58 in their canonical chain encoding.
    Ok(serde_json::json!({ "signature": bs58::encode(&sig).into_string() }))
}

/// `Account:signTransaction` — build and threshold-sign an EVM transaction for
/// the account, returning the signed raw tx as `0x`-hex. Broadcast
/// (signAndSend) layers eth_sendRawTransaction on top once RPC is wired.
pub fn sign_transaction(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let tx = params
        .get("Transaction")
        .ok_or_else(|| ApiError::new(400, "Transaction required"))?;

    let req = crate::evm::LegacyTxRequest {
        nonce: tx.get("nonce").and_then(Value::as_u64).unwrap_or(0),
        gas: tx.get("gas").and_then(Value::as_u64).unwrap_or(21000),
        gas_price: tx.get("gasPrice").and_then(Value::as_str).unwrap_or("0").to_string(),
        to: tx.get("to").and_then(Value::as_str).unwrap_or("").to_string(),
        value: tx.get("value").and_then(Value::as_str).unwrap_or("0").to_string(),
        data: match tx.get("data").and_then(Value::as_str) {
            Some(h) => decode_hex(h)?,
            None => Vec::new(),
        },
        chain_id: tx.get("chainId").and_then(Value::as_u64).unwrap_or(1),
    };

    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let unlock: Vec<(String, String)> = keys
        .iter()
        .filter(|k| k.kind == "Password")
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();

    let raw = crate::evm::sign_legacy_tx(env, account_id, &unlock, &req).map_err(ApiError::internal)?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(serde_json::json!({ "raw": format!("0x{hex}") }))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(ApiError::new(400, "odd-length hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| ApiError::new(400, e.to_string())))
        .collect()
}

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::account::fetch(env, id).map_err(ApiError::internal)? {
                Some(a) => Ok(serde_json::to_value(a).unwrap()),
                None => Err(ApiError::new(404, "account not found")),
            },
            None => {
                let list = crate::models::account::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => {
            #[derive(serde::Deserialize)]
            struct CreateReq {
                #[serde(rename = "Wallet", default)]
                wallet: String,
                #[serde(rename = "Name", default)]
                name: String,
                #[serde(rename = "Type", default)]
                kind: String,
                #[serde(rename = "Index", default)]
                index: i64,
            }
            let req: CreateReq =
                serde_json::from_value(params.clone()).map_err(|e| ApiError::new(400, e.to_string()))?;
            let a = crate::models::account::create(env, &req.wallet, &req.name, &req.kind, req.index)
                .map_err(ApiError::internal)?;
            Ok(serde_json::to_value(a).unwrap())
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Account"))),
    }
}
