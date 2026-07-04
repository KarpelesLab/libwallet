//! StoreKey endpoints (wltwallet/storekey.go). `StoreKey:derivePassword` derives
//! the Ed25519 public key a Password-scheme WalletKey resolves to, so a host can
//! pre-register it as a recipient without unlocking anything.

use serde_json::{json, Value};
use xuid::Xuid;

use crate::Env;

use super::{ApiError, ApiResult};

/// `StoreKey:create` -> {private, public}: generate a fresh 64-byte store key
/// (base64url) and the Ed25519 PKIX public key it derives to (Go
/// `storekeyCreate`). The host persists `private` on the device.
pub fn create(_env: &Env, _params: &Value) -> ApiResult {
    let (private, public) = crate::keystore::create_store_key().map_err(ApiError::internal)?;
    Ok(json!({ "private": private, "public": public }))
}

/// `StoreKey:derivePassword` {Password, WalletKeyId} -> {Public_Key}: PBKDF2
/// (salt = the WalletKey UUID) to an Ed25519 key, returned as its base64url
/// PKIX public key (Go `storekeyDerivePassword`).
pub fn derive_password(_env: &Env, params: &Value) -> ApiResult {
    let password = params
        .get("Password")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Password required"))?;
    let wkey_id = params
        .get("WalletKeyId")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "WalletKeyId required"))?;
    let xid = Xuid::parse_prefix(wkey_id, "wkey")
        .map_err(|_| ApiError::new(400, "bad WalletKeyId (expected wkey prefix)"))?;

    let pk = crate::keystore::password_to_ed25519(password, xid.uuid().as_bytes())
        .map_err(|e| ApiError::new(400, e.to_string()))?;
    let pub_b64 = crate::keystore::public_key_to_pkix_b64(&pk.public()).map_err(ApiError::internal)?;
    Ok(json!({ "Public_Key": pub_b64 }))
}
