//! `Vault:*` — secrets libwallet keeps for the host (see [`crate::vault`]).
//!
//! | endpoint | params | returns |
//! |---|---|---|
//! | `Vault:capabilities` | – | `{Secure, Hardware, Biometry, Provider, Reason?}` |
//! | `Vault:create` | `{Label, Kind, Backend, Policy?, Password?}` | entry |
//! | `Vault:import` | `{…create, Secret, Encoding?}` | entry |
//! | `Vault` (GET) | – | `[entry]` |
//! | `Vault/<id>` (GET / DELETE) | – | entry / `{Deleted}` |
//! | `Vault:unlock` | `{Id, Password?, Reason?}` | `{Unlocked, Expires}` |
//! | `Vault:lock` | `{Id?}` | `{Locked}` |
//! | `Vault:export` | `{Id, Password?, Reason?}` | `{Secret}` (Exportable only) |
//! | `Vault:blob` | `{Id}` | `{Blob}` (password entries) |
//! | `Vault:load` | `{Blob}` | entry |
//! | `Vault:changePassword` | `{Id, Password, NewPassword}` | entry |
//!
//! Entries are used elsewhere as `{"Type":"Vault","Key":"<id>"}` wherever a
//! request takes `Keys`.

use serde_json::{json, Value};

use crate::vault::{self, blob::Kdf, session, Kind, NewEntry, Policy};
use crate::Env;

use super::{ApiError, ApiResult};

fn str_param<'a>(params: &'a Value, k: &str) -> Option<&'a str> {
    params.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn bad(e: crate::Error) -> ApiError {
    ApiError::new(400, e.to_string())
}

fn entry(env: &Env, params: &Value) -> Result<vault::Entry, ApiError> {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id required"))?;
    vault::fetch(env, id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, format!("vault entry {id} not found")))
}

fn reason(params: &Value) -> &str {
    str_param(params, "Reason").unwrap_or(session::DEFAULT_REASON)
}

pub fn route(env: &Env, verb: &str, action: &str, params: &Value) -> ApiResult {
    match (action, verb) {
        ("", "GET") if params.get("Id").is_some() => Ok(entry(env, params)?.to_json()),
        ("", "GET") => Ok(Value::Array(vault::list(env).map_err(ApiError::internal)?.iter().map(vault::Entry::to_json).collect())),
        ("", "DELETE") | ("delete", _) => {
            let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id required"))?;
            Ok(json!({ "Deleted": vault::delete(env, id).map_err(bad)? }))
        }
        ("capabilities", _) => Ok(serde_json::to_value(vault::platform::capabilities()).unwrap()),
        ("create", _) => create(env, params, false),
        ("import", _) => create(env, params, true),
        ("unlock", _) => {
            let e = entry(env, params)?;
            let expires = session::unlock(&e, env.vault_scope(), str_param(params, "Password"), reason(params)).map_err(bad)?;
            Ok(json!({ "Unlocked": true, "Expires": expires }))
        }
        ("lock", _) => {
            match str_param(params, "Id") {
                Some(id) => session::forget(env.vault_scope(), id),
                None => session::lock_scope(env.vault_scope()),
            }
            // A prompt still waiting for the user is dismissed either way.
            if let Some(b) = vault::platform::backend() {
                b.cancel_prompts();
            }
            Ok(json!({ "Locked": true }))
        }
        ("status", _) => {
            let e = entry(env, params)?;
            Ok(json!({ "Id": e.id, "Unlocked": session::is_unlocked(env.vault_scope(), &e.id) }))
        }
        ("export", _) => {
            let e = entry(env, params)?;
            if !e.policy.exportable {
                return Err(ApiError::new(403, "this vault entry is not exportable"));
            }
            let secret = session::secret(&e, env.vault_scope(), str_param(params, "Password"), reason(params)).map_err(bad)?;
            let encoded = vault::encode_secret(e.kind, &secret);
            Ok(json!({ "Id": e.id, "Kind": e.kind.as_str(), "Secret": encoded.as_str() }))
        }
        ("blob", _) => {
            let e = entry(env, params)?;
            if e.backend != "password" {
                return Err(ApiError::new(400, "only password entries have a portable blob; secure entries are bound to this device"));
            }
            use base64::Engine;
            Ok(json!({ "Id": e.id, "Blob": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e.data) }))
        }
        ("load", _) => {
            use base64::Engine;
            let b = str_param(params, "Blob").ok_or_else(|| ApiError::new(400, "Blob required"))?;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b.trim_end_matches('='))
                .map_err(|_| ApiError::new(400, "Blob is not base64url"))?;
            Ok(vault::load_blob(env, &bytes).map_err(bad)?.to_json())
        }
        ("changePassword", _) => {
            let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id required"))?;
            let old = str_param(params, "Password").ok_or_else(|| ApiError::new(400, "Password required"))?;
            let new = str_param(params, "NewPassword").ok_or_else(|| ApiError::new(400, "NewPassword required"))?;
            let e = vault::change_password(env, id, old, new, kdf(params)).map_err(bad)?;
            session::forget_everywhere(&e.id);
            Ok(e.to_json())
        }
        (other, _) => Err(ApiError::new(404, format!("unknown Vault action {other:?}"))),
    }
}

/// Argon2id cost. Hosts can lower it for weak devices with `Kdf:{MemoryKiB,
/// Iterations}` but not below OWASP's floor (19 MiB × 2); tests in this crate
/// call the model directly with a cheaper one.
fn kdf(params: &Value) -> Kdf {
    let d = Kdf::default();
    let Some(k) = params.get("Kdf") else { return d };
    let m = k.get("MemoryKiB").and_then(Value::as_u64).map_or(d.m_kib, |v| v.clamp(19 * 1024, 1024 * 1024) as u32);
    let t = k.get("Iterations").and_then(Value::as_u64).map_or(d.t, |v| v.clamp(2, 16) as u32);
    Kdf { m_kib: m, t, p: 1 }
}

fn create(env: &Env, params: &Value, import: bool) -> ApiResult {
    let kind = Kind::parse(str_param(params, "Kind").unwrap_or("storekey")).map_err(bad)?;
    let backend = str_param(params, "Backend").unwrap_or("secure");
    let policy: Policy = match params.get("Policy") {
        None | Some(Value::Null) => Policy::default(),
        Some(p) => serde_json::from_value(p.clone()).map_err(|e| ApiError::new(400, format!("bad Policy: {e}")))?,
    };
    let secret = if import {
        let s = str_param(params, "Secret").ok_or_else(|| ApiError::new(400, "Secret required"))?;
        Some(vault::decode_secret(kind, s, str_param(params, "Encoding")).map_err(bad)?)
    } else {
        None
    };
    let e = vault::create(
        env,
        NewEntry {
            label: str_param(params, "Label").unwrap_or(""),
            kind,
            backend,
            policy,
            password: str_param(params, "Password"),
            secret,
            kdf: kdf(params),
        },
    )
    .map_err(bad)?;
    let mut out = e.to_json();
    if e.backend == "password" {
        use base64::Engine;
        out["Blob"] = json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e.data));
    }
    Ok(out)
}
