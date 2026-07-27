//! Minimal blocking client for the KarpelesLab REST backend (port of the Go
//! `rest.Do` path). Calls land at `https://www.atonline.com/_special/rest/<path>`
//! and return the KLB envelope `{ "result": "success"|"error", "data": ... }`;
//! `do_get` returns the inner `data` (or an error carrying the envelope message).
//!
//! Auth is the app's clientId in the `Sec-ClientId` header only (Go
//! `withClientID`) — there is no request signature. `do_get`/`do_get_params`
//! (GET, params in the `_` query arg) and `do_post` (POST, JSON body) all take
//! an optional `client_id`; the OKX swap proxy and WalletSign endpoints use it.

use serde_json::Value;
use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use crate::{Error, Result};

/// Encode query params the way Go `url.Values.Encode` does: keys sorted
/// ascending (BTreeMap iteration order), each `escape(k)=escape(v)` joined by
/// `&`, using Go's query-component escaping.
pub fn encode_query(query: &BTreeMap<String, String>) -> String {
    query
        .iter()
        .map(|(k, v)| format!("{}={}", go_query_escape(k), go_query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Port of Go `url.QueryEscape`: unreserved `A-Za-z0-9-_.~` pass through, space
/// becomes `+`, every other byte becomes `%XX` (uppercase hex).
fn go_query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Default backend host, matching Go `rest.Host` (`www.atonline.com`, https).
pub const DEFAULT_HOST: &str = "https://www.atonline.com";

/// GET `<base>/_special/rest/<path>` and return the envelope's `data` field.
/// `base` is the scheme+host (no trailing slash); tests pass a mock server URL.
#[cfg(not(target_arch = "wasm32"))]
pub fn do_get(base: &str, path: &str) -> Result<Value> {
    do_get_with_client_id(base, path, None)
}

/// Like [`do_get`] but stamps the `Sec-ClientId` header (Go `withClientID`) —
/// used by the WalletSign helpers (`Crypto/WalletSign:keys`).
#[cfg(not(target_arch = "wasm32"))]
pub fn do_get_with_client_id(base: &str, path: &str, client_id: Option<&str>) -> Result<Value> {
    let url = format!("{base}/_special/rest/{path}");
    let mut req = rsurl::Request::new("GET", &url)
        .map_err(|e| Error::Env(format!("rest {path} request build failed: {e}")))?
        .header("Sec-Rest-Http", "false")
        .read_timeout(Some(Duration::from_secs(20)));
    if let Some(id) = client_id.filter(|s| !s.is_empty()) {
        req = req.header("Sec-ClientId", id);
    }
    let resp: Value = req
        .send()
        .map_err(|e| Error::Env(format!("rest {path} request failed: {e}")))?
        .json()
        .map_err(|e| Error::Env(format!("rest {path} decode failed: {e}")))?;
    unwrap_envelope(path, resp)
}

/// POST `<base>/_special/rest/<path>` with a JSON body and return the
/// envelope's `data`. Mirrors the Go `rest.Do(ctx, path, "POST", param)` used by
/// the RemoteKey / WalletSign helpers. `client_id`, when set, is stamped as the
/// `Sec-ClientId` header (Go `withClientID`). Auth beyond that header is the
/// backend's concern — these endpoints gate 2FA on ClientID + rate limits.
#[cfg(not(target_arch = "wasm32"))]
pub fn do_post(base: &str, path: &str, params: &Value, client_id: Option<&str>) -> Result<Value> {
    let url = format!("{base}/_special/rest/{path}");
    let body = serde_json::to_vec(params)
        .map_err(|e| Error::Env(format!("rest {path} encode failed: {e}")))?;
    let mut req = rsurl::Request::new("POST", &url)
        .map_err(|e| Error::Env(format!("rest {path} request build failed: {e}")))?
        .header("Sec-Rest-Http", "false")
        .header("Content-Type", "application/json")
        .read_timeout(Some(Duration::from_secs(20)))
        .body(body);
    if let Some(id) = client_id.filter(|s| !s.is_empty()) {
        req = req.header("Sec-ClientId", id);
    }
    let resp: Value = req
        .send()
        .map_err(|e| Error::Env(format!("rest {path} request failed: {e}")))?
        .json()
        .map_err(|e| Error::Env(format!("rest {path} decode failed: {e}")))?;
    unwrap_envelope(path, resp)
}

/// GET `<base>/_special/rest/<path>` with `params` JSON-encoded into the `_`
/// query param (the KLB argument convention) and the app's `client_id` stamped
/// as the `Sec-ClientId` header (Go `withClientID`). That header is the only
/// auth these endpoints require — e.g. the `Crypto/Okx:*` swap proxy — there is
/// no request signature. Returns the envelope's `data`.
#[cfg(not(target_arch = "wasm32"))]
pub fn do_get_params(base: &str, path: &str, params: &Value, client_id: Option<&str>) -> Result<Value> {
    let json = serde_json::to_string(params).unwrap_or_else(|_| "null".into());
    let url = format!("{base}/_special/rest/{path}?_={}", go_query_escape(&json));
    let mut req = rsurl::Request::new("GET", &url)
        .map_err(|e| Error::Env(format!("rest {path} request build failed: {e}")))?
        .header("Sec-Rest-Http", "false")
        .read_timeout(Some(Duration::from_secs(30)));
    if let Some(id) = client_id.filter(|s| !s.is_empty()) {
        req = req.header("Sec-ClientId", id);
    }
    let resp: Value = req
        .send()
        .map_err(|e| Error::Env(format!("rest {path} request failed: {e}")))?
        .json()
        .map_err(|e| Error::Env(format!("rest {path} decode failed: {e}")))?;
    unwrap_envelope(path, resp)
}

// Browser (wasm32) REST goes over the Spot network, not HTTP Fetch: klbfw's
// `spot` feature ships `{path,verb,params}` over the authenticated spotlib
// connection to `@/p_api` and parses the same `{result,data,error}` envelope.
// This removes the browser's CORS requirement (no HTTP host / origin). The
// clientId is still meaningful — it selects the WalletSign email/SMS branding —
// but over Spot there is no `Sec-ClientId` header, so it travels as a
// `client_id` field merged into the request params instead.

/// Adapter: drive klbfw's REST-over-Spot through our spotlib client.
#[cfg(target_arch = "wasm32")]
struct SpotRest<'a>(&'a spotlib::Client);

#[cfg(target_arch = "wasm32")]
impl klbfw::SpotClient for SpotRest<'_> {
    async fn query(&self, target: &str, body: &[u8]) -> std::result::Result<Vec<u8>, String> {
        self.0
            .query(target, body, std::time::Duration::from_secs(30))
            .await
            .map_err(|e| e.to_string())
    }
}

/// Execute a KLB REST call over the Spot connection (klbfw `spot` feature →
/// `@/p_api`) and return the envelope's `data`. The browser path: no HTTP host,
/// no CORS. `client` must already be online (call `wait_online` first).
///
/// `client_id`, when set, is merged into the request params as `client_id` (the
/// HTTP path sent it as the `Sec-ClientId` header; `@/p_api` has no headers, so
/// it rides the params) — the backend uses it e.g. to brand WalletSign 2FA
/// email/SMS. Requires `params` to be a JSON object or null.
#[cfg(target_arch = "wasm32")]
pub async fn spot_do(client: &spotlib::Client, path: &str, verb: &str, params: &Value, client_id: Option<&str>) -> Result<Value> {
    let merged;
    let param_ref = match client_id.filter(|s| !s.is_empty()) {
        Some(id) => {
            let mut obj = match params {
                Value::Object(m) => m.clone(),
                Value::Null => serde_json::Map::new(),
                _ => return Err(Error::Env(format!("rest {path} (spot): cannot attach client_id to non-object params"))),
            };
            obj.insert("client_id".to_string(), Value::String(id.to_string()));
            merged = Value::Object(obj);
            &merged
        }
        None => params,
    };
    let resp = klbfw::spot_do_request(&SpotRest(client), path, verb, param_ref)
        .await
        .map_err(|e| Error::Env(format!("rest {path} (spot): {e}")))?;
    match resp.result.as_str() {
        "success" => Ok(resp.data.unwrap_or(Value::Null)),
        _ => Err(Error::Env(format!(
            "rest {path} (spot) error: {}",
            resp.error.unwrap_or_else(|| "unknown error".into())
        ))),
    }
}

/// Unwrap a KLB envelope `{result, data}` — returns `data` on success, else an
/// error carrying the envelope's message.
fn unwrap_envelope(path: &str, resp: Value) -> Result<Value> {
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
