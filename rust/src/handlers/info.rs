//! Info endpoints — ports of `wltbase/info.go`.
//!
//! Build-time version metadata is injected via environment variables at
//! compile time (the Rust analogue of the Go `-ldflags -X` in the Makefile).
//! Empty strings — the default for dev builds — signal a non-release binary,
//! exactly like the Go side.

use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

const VERSION: &str = match option_env!("LIBWALLET_VERSION") {
    Some(v) => v,
    None => "",
};
const GIT_TAG: &str = match option_env!("LIBWALLET_GIT_TAG") {
    Some(v) => v,
    None => "",
};
const DATE_TAG: &str = match option_env!("LIBWALLET_DATE_TAG") {
    Some(v) => v,
    None => "",
};

/// `Info:ping` — liveness check. Returns the string "pong".
pub fn ping() -> ApiResult {
    Ok(json!("pong"))
}

/// `Info:version` — release version + commit SHA + commit date. Consumed by
/// `InfoApi.version()` / `versionInfo()` on the Dart side.
pub fn version() -> ApiResult {
    Ok(version_value())
}

fn version_value() -> Value {
    json!({
        "version": VERSION,
        "gitTag": GIT_TAG,
        "dateTag": DATE_TAG,
    })
}

/// `Info:paths` — filesystem locations the host may need. Port of
/// `wltbase/info.go` `infoPaths` (subset: DataDir/TempDir/UserHomeDir; per-OS
/// cache/config dirs land with the `dirs` crate in a later pass).
pub fn paths(env: &Env) -> ApiResult {
    let mut m = serde_json::Map::new();
    m.insert("DataDir".into(), json!(env.data_dir.to_string_lossy()));
    m.insert("TempDir".into(), json!(std::env::temp_dir().to_string_lossy()));
    if let Some(home) = std::env::var_os("HOME") {
        m.insert("UserHomeDir".into(), json!(home.to_string_lossy()));
    }
    Ok(Value::Object(m))
}

/// `Info:onboarding` — whether the wallet has any account / wallet yet, so the
/// host can decide between the create-flow and the main UI (Go `infoOnboarding`).
pub fn onboarding(env: &Env) -> ApiResult {
    let has_wallet = !crate::models::wallet::list(env).map_err(ApiError::internal)?.is_empty();
    let has_account = !crate::models::account::list(env).map_err(ApiError::internal)?.is_empty();
    Ok(json!({ "has_account": has_account, "has_wallet": has_wallet }))
}

/// `Info:setWalletInfo` — register the host wallet's identity (ClientId, Name,
/// Version, LogLevel) in config; returns the stored record (Go
/// `infoSetWalletInfo`).
pub fn set_wallet_info(env: &Env, params: &Value) -> ApiResult {
    for (param, field) in
        [("ClientId", "clientId"), ("Name", "name"), ("Version", "version"), ("LogLevel", "logLevel")]
    {
        if let Some(v) = params.get(param).and_then(Value::as_str) {
            env.config_set(&format!("walletinfo:{field}"), v.as_bytes()).map_err(ApiError::internal)?;
        }
    }
    Ok(wallet_info_value(env))
}

/// `Info:getWalletInfo` — the configured wallet-identity record.
pub fn get_wallet_info(env: &Env) -> ApiResult {
    Ok(wallet_info_value(env))
}

fn wallet_info_value(env: &Env) -> Value {
    let g = |field: &str| {
        env.config_get(&format!("walletinfo:{field}"))
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default()
    };
    let log_level = g("logLevel");
    let effective = if log_level.is_empty() { "info".to_owned() } else { log_level.clone() };
    json!({
        "clientId": g("clientId"),
        "name": g("name"),
        "version": g("version"),
        "logLevel": log_level,
        "effectiveLogLevel": effective,
    })
}

/// `Info:first_run` — the first-launch TimeId. Port of `infoFirstRun`: decode
/// the 16-byte config blob into `{type, unix, nano, idx}` (the JSON shape of
/// `wltobj.TimeId`).
pub fn first_run(env: &Env) -> ApiResult {
    let raw = env
        .config_get("first_run")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(500, "first_run not set"))?;
    if raw.len() != 16 {
        return Err(ApiError::new(500, format!("bad first_run length: {}", raw.len())));
    }
    let unix = u64::from_be_bytes(raw[0..8].try_into().unwrap());
    let nano = u32::from_be_bytes(raw[8..12].try_into().unwrap());
    let idx = u32::from_be_bytes(raw[12..16].try_into().unwrap());
    Ok(json!({ "type": "", "unix": unix, "nano": nano, "idx": idx }))
}
