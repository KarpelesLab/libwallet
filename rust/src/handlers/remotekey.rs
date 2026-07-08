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

fn base<'a>(params: &'a Value) -> &'a str {
    params.get("Backend").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(crate::rest::DEFAULT_HOST)
}

fn client_id(env: &Env) -> Option<String> {
    env.config_get("walletinfo:clientId").ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}

/// `RemoteKey:new` {number|email} — start a 2FA session. The backend routes
/// SMS vs email on whether the value contains `@` (Go `remotekeyNew`).
pub fn new(env: &Env, params: &Value) -> ApiResult {
    let number = params.get("number").and_then(Value::as_str).unwrap_or("");
    let target = if number.is_empty() { params.get("email").and_then(Value::as_str).unwrap_or("") } else { number };
    if target.is_empty() {
        return Err(ApiError::new(400, "number or email is required"));
    }
    crate::rest::do_post(base(params), "Crypto/WalletSign:new", &json!({ "number": target }), client_id(env).as_deref())
        .map_err(|e| ApiError::new(502, e.to_string()))
}

/// `RemoteKey:reshare` {key} — kick a reshare cycle for an existing RemoteKey.
/// threshold/count are fixed (1/3); the curve is recorded server-side at issue
/// time and must NOT be passed back (Go `remotekeyReshare`).
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

/// `RemoteKey:validate` {session, code} — verify the 2FA code; returns
/// `{RemoteKey: "<crws-id>:<crwsv-id>"}` on success (Go `remotekeyValidate`).
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
