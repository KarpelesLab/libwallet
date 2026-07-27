//! `RemoteKey:new/reshare/validate` — thin authed-REST wrappers over the
//! `Crypto/WalletSign:*` backend (port of wltwallet/remote.go). Each is a POST
//! whose only libwallet-side auth is the `Sec-ClientId` header (from
//! Info:setWalletInfo); the WalletSign backend runs the 2FA / session logic and
//! owns the response shape, which we pass through verbatim (`res.Data`).
//!
//! `Backend` overrides the REST host for tests (mirrors Go `rest.BackendURL`).

use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

// The `Backend` host override is HTTP-only; over Spot there is no host, so it is
// native-only. The clientId is used on BOTH paths (native: `Sec-ClientId`
// header; browser: merged into the Spot request params) — it selects the
// WalletSign 2FA email/SMS branding.
#[cfg(not(target_arch = "wasm32"))]
fn base<'a>(params: &'a Value) -> &'a str {
    params.get("Backend").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(crate::rest::DEFAULT_HOST)
}

fn client_id(env: &Env) -> Option<String> {
    env.config_get("walletinfo:clientId").ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}

/// `RemoteKey:new` {number|email} — start a 2FA session. The backend routes
/// SMS vs email on whether the value contains `@` (Go `remotekeyNew`).
#[cfg(not(target_arch = "wasm32"))]
pub fn new(env: &Env, params: &Value) -> ApiResult {
    let number = params.get("number").and_then(Value::as_str).unwrap_or("");
    let target = if number.is_empty() { params.get("email").and_then(Value::as_str).unwrap_or("") } else { number };
    if target.is_empty() {
        return Err(ApiError::new(400, "number or email is required"));
    }
    let mut body = json!({ "number": target });
    if let Some(v) = params.get("verify").and_then(Value::as_str) {
        body["verify"] = json!(v);
    }
    crate::rest::do_post(base(params), "Crypto/WalletSign:new", &body, client_id(env).as_deref())
        .map_err(|e| ApiError::new(502, e.to_string()))
}

/// wasm twin of [`new`]: routes the POST over the authenticated Spot connection
/// (`spot_do` → `@/p_api`) — no HTTP host, no CORS, no clientId. Param
/// validation runs FIRST so the pre-network 400 is returned before any Spot call.
#[cfg(target_arch = "wasm32")]
pub async fn new_async(env: &Env, params: &Value) -> ApiResult {
    let number = params.get("number").and_then(Value::as_str).unwrap_or("");
    let target = if number.is_empty() { params.get("email").and_then(Value::as_str).unwrap_or("") } else { number };
    if target.is_empty() {
        return Err(ApiError::new(400, "number or email is required"));
    }
    // `verify` selects the 2FA method: 'code' (default) or 'passkey' (closed by
    // the passkeyAuthBegin/Finish pair instead of a one-time code).
    let mut body = json!({ "number": target });
    if let Some(v) = params.get("verify").and_then(Value::as_str) {
        body["verify"] = json!(v);
    }
    let client = env.spot_start().map_err(ApiError::internal)?;
    client.wait_online(std::time::Duration::from_secs(15)).await.map_err(|e| ApiError::new(502, e.to_string()))?;
    crate::rest::spot_do(&client, "Crypto/WalletSign:new", "POST", &body, client_id(env).as_deref())
        .await
        .map_err(|e| ApiError::new(502, e.to_string()))
}

/// Thin passthrough to a `Crypto/WalletSign:<method>` endpoint over the Spot
/// connection — used by the browser passkey enroll/auth dance
/// (`passkeyRegisterBegin`/`Finish`, `passkeyAuthBegin`/`Finish`), which is
/// orchestrated in JS (WebAuthn is a browser API). The whole `params` object is
/// forwarded verbatim; the clientId is merged in by `spot_do`. Restricted to the
/// WalletSign object.
#[cfg(target_arch = "wasm32")]
pub async fn wallet_sign_proxy(env: &Env, method: &str, params: &Value) -> ApiResult {
    let client = env.spot_start().map_err(ApiError::internal)?;
    client.wait_online(std::time::Duration::from_secs(15)).await.map_err(|e| ApiError::new(502, e.to_string()))?;
    crate::rest::spot_do(&client, &format!("Crypto/WalletSign:{method}"), "POST", params, client_id(env).as_deref())
        .await
        .map_err(|e| ApiError::new(502, e.to_string()))
}

/// `RemoteKey:reshare` {key} — kick a reshare cycle for an existing RemoteKey.
/// threshold/count are fixed (1/3); the curve is recorded server-side at issue
/// time and must NOT be passed back (Go `remotekeyReshare`).
#[cfg(not(target_arch = "wasm32"))]
pub fn reshare(env: &Env, params: &Value) -> ApiResult {
    let key = params.get("key").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "key is required"))?;
    crate::rest::do_post(
        base(params),
        "Crypto/WalletSign:reshare",
        &json!({ "key": key, "threshold": 1, "count": 3 }),
        client_id(env).as_deref(),
    )
    .map_err(|e| ApiError::new(502, e.to_string()))
}

/// wasm twin of [`reshare`]: routes the POST over the authenticated Spot
/// connection. The key 400 check runs FIRST (before any Spot call).
#[cfg(target_arch = "wasm32")]
pub async fn reshare_async(env: &Env, params: &Value) -> ApiResult {
    let key = params.get("key").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "key is required"))?;
    let client = env.spot_start().map_err(ApiError::internal)?;
    client.wait_online(std::time::Duration::from_secs(15)).await.map_err(|e| ApiError::new(502, e.to_string()))?;
    crate::rest::spot_do(&client, "Crypto/WalletSign:reshare", "POST", &json!({ "key": key, "threshold": 1, "count": 3 }), client_id(env).as_deref())
        .await
        .map_err(|e| ApiError::new(502, e.to_string()))
}

/// `RemoteKey:validate` {session, code} — verify the 2FA code; returns
/// `{RemoteKey: "<crws-id>:<crwsv-id>"}` on success (Go `remotekeyValidate`).
#[cfg(not(target_arch = "wasm32"))]
pub fn validate(env: &Env, params: &Value) -> ApiResult {
    let session = params.get("session").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "session is required"))?;
    let code = params.get("code").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "code is required"))?;
    crate::rest::do_post(
        base(params),
        "Crypto/WalletSign:verify",
        &json!({ "session": session, "code": code }),
        client_id(env).as_deref(),
    )
    .map_err(|e| ApiError::new(502, e.to_string()))
}

/// wasm twin of [`validate`]: routes the POST over the authenticated Spot
/// connection. The session/code 400 checks run FIRST (before any Spot call).
#[cfg(target_arch = "wasm32")]
pub async fn validate_async(env: &Env, params: &Value) -> ApiResult {
    let session = params.get("session").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "session is required"))?;
    let code = params.get("code").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "code is required"))?;
    let client = env.spot_start().map_err(ApiError::internal)?;
    client.wait_online(std::time::Duration::from_secs(15)).await.map_err(|e| ApiError::new(502, e.to_string()))?;
    crate::rest::spot_do(&client, "Crypto/WalletSign:verify", "POST", &json!({ "session": session, "code": code }), client_id(env).as_deref())
        .await
        .map_err(|e| ApiError::new(502, e.to_string()))
}
