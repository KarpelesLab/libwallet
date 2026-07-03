//! Minimal blocking client for the KarpelesLab REST backend (port of the Go
//! `rest.Do` path). Calls land at `https://www.atonline.com/_special/rest/<path>`
//! and return the KLB envelope `{ "result": "success"|"error", "data": ... }`;
//! `do_get` returns the inner `data` (or an error carrying the envelope message).
//!
//! Only the unauthenticated GET path is ported — that covers the public data
//! endpoints the wallet reads (quotes, contract/token registries). Token auth
//! and renewal land with the cross-device work.

use base64::Engine as _;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

use crate::{Error, Result};

/// A KarpelesLab REST API key: a key id + the 32-byte Ed25519 seed used to sign
/// requests (Go `rest.ApiKey`). Authenticated endpoints (`rest.Apply`, e.g. the
/// `Crypto/Okx:*` swap proxy) require a signed query.
pub struct ApiKey {
    pub key_id: String,
    seed: [u8; 32],
}

impl ApiKey {
    /// From a key id and the raw 32-byte Ed25519 seed.
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        ApiKey { key_id: key_id.into(), seed }
    }

    /// From a key id and a base64url secret (the server issues a 64-byte
    /// Ed25519 private key = seed ‖ pubkey; a bare 32-byte seed also works).
    pub fn from_secret_b64(key_id: impl Into<String>, secret_b64url: &str) -> Result<Self> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(secret_b64url)
            .map_err(|e| Error::Env(format!("bad api secret: {e}")))?;
        if raw.len() < 32 {
            return Err(Error::Env("api secret must be at least 32 bytes".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw[..32]);
        Ok(ApiKey { key_id: key_id.into(), seed })
    }

    /// The base64url (no-pad) Ed25519 signature over the canonical signing
    /// string `method \0 path \0 <encoded query> \0 sha256(body)` (Go
    /// `ApiKey.generateSignature`). `query` excludes `_sign`.
    pub fn sign_query(
        &self,
        method: &str,
        path: &str,
        query: &BTreeMap<String, String>,
        body: &[u8],
    ) -> String {
        let encoded = encode_query(query);
        let body_hash = purecrypto::hash::sha256(body);
        let mut s = Vec::new();
        s.extend_from_slice(method.as_bytes());
        s.push(0);
        s.extend_from_slice(path.as_bytes());
        s.push(0);
        s.extend_from_slice(encoded.as_bytes());
        s.push(0);
        s.extend_from_slice(&body_hash);

        let key = purecrypto::ec::Ed25519PrivateKey::from_bytes(self.seed);
        let sig = key.sign(&s);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

impl ApiKey {
    /// Authenticated GET of a KLB REST endpoint (Go `rest.Apply`, GET path):
    /// params are JSON-encoded into the `_` query param, `_key`/`_time`/`_nonce`
    /// are added, the request is Ed25519-signed into `_sign`, and the envelope's
    /// `data` is returned. `time`/`nonce` are injected for deterministic tests;
    /// callers use [`apply_get`](Self::apply_get) to generate them.
    pub fn apply_get_at(
        &self,
        base: &str,
        path: &str,
        params: &Value,
        time: i64,
        nonce: &str,
    ) -> Result<Value> {
        let mut query: BTreeMap<String, String> = BTreeMap::new();
        query.insert("_".to_string(), serde_json::to_string(params).unwrap_or_else(|_| "null".into()));
        query.insert("_key".to_string(), self.key_id.clone());
        query.insert("_time".to_string(), time.to_string());
        query.insert("_nonce".to_string(), nonce.to_string());
        let sign = self.sign_query("GET", path, &query, b"");
        query.insert("_sign".to_string(), sign);

        let url = format!("{base}/_special/rest/{path}?{}", encode_query(&query));
        let resp: Value = ureq::get(&url)
            .set("Sec-Rest-Http", "false")
            .timeout(Duration::from_secs(20))
            .call()
            .map_err(|e| Error::Env(format!("rest {path} request failed: {e}")))?
            .into_json()
            .map_err(|e| Error::Env(format!("rest {path} decode failed: {e}")))?;
        unwrap_envelope(path, resp)
    }

    /// Like [`apply_get_at`](Self::apply_get_at) but generates the timestamp and
    /// nonce. `nonce` is derived from a v4 UUID.
    pub fn apply_get(&self, base: &str, path: &str, params: &Value) -> Result<Value> {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let nonce = uuid::Uuid::new_v4().to_string();
        self.apply_get_at(base, path, params, time, &nonce)
    }
}

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
pub fn do_get(base: &str, path: &str) -> Result<Value> {
    let url = format!("{base}/_special/rest/{path}");
    let resp: Value = ureq::get(&url)
        .set("Sec-Rest-Http", "false")
        .timeout(Duration::from_secs(20))
        .call()
        .map_err(|e| Error::Env(format!("rest {path} request failed: {e}")))?
        .into_json()
        .map_err(|e| Error::Env(format!("rest {path} decode failed: {e}")))?;
    unwrap_envelope(path, resp)
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
