//! Minimal blocking client for the KarpelesLab REST backend (port of the Go
//! `rest.Do` path). Calls land at `https://www.atonline.com/_special/rest/<path>`
//! and return the KLB envelope `{ "result": "success"|"error", "data": ... }`;
//! `do_get` returns the inner `data` (or an error carrying the envelope message).
//!
//! Only the unauthenticated GET path is ported — that covers the public data
//! endpoints the wallet reads (quotes, contract/token registries). Token auth
//! and renewal land with the cross-device work.

use serde_json::Value;
use std::time::Duration;

use crate::{Error, Result};

/// Default backend host, matching Go `rest.Host` (`www.atonline.com`, https).
pub const DEFAULT_HOST: &str = "https://www.atonline.com";

/// GET `<base>/_special/rest/<path>` and return the envelope's `data` field.
/// `base` is the scheme+host (no trailing slash); tests pass a mock server URL.
pub fn do_get(base: &str, path: &str) -> Result<Value> {
    let url = format!("{base}/_special/rest/{path}");
    let resp: Value = ureq::get(&url)
        .set("Sec-Rest-Http", "false")
        .timeout(Duration::from_secs(20))
        .call()
        .map_err(|e| Error::Env(format!("rest {path} request failed: {e}")))?
        .into_json()
        .map_err(|e| Error::Env(format!("rest {path} decode failed: {e}")))?;

    match resp.get("result").and_then(Value::as_str) {
        Some("success") => resp
            .get("data")
            .cloned()
            .ok_or_else(|| Error::Env(format!("rest {path} envelope missing data"))),
        _ => {
            let msg = resp
                .get("error")
                .and_then(Value::as_str)
                .or_else(|| resp.get("message").and_then(Value::as_str))
                .unwrap_or("unknown error");
            Err(Error::Env(format!("rest {path} error: {msg}")))
        }
    }
}
