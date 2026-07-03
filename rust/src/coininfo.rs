//! Coin metadata lookup — port of Go `wltasset.CoinInfoBySymbol` /
//! `CoinInfoByAddress`. Fetches display metadata (name, logo, links) for a
//! token from the KLB REST endpoint `Crypto/DataCache:ccInfo`, cached in the
//! wallet DB for 7 days.
//!
//! This is enrichment only (populates `Asset.Info`); a lookup failure is never
//! fatal to a balance/asset read.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::{Env, Error, Result};

const TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Coin metadata (mirrors Go `wltasset.CoinInfo`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoinInfo {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub logo: String,
    #[serde(default)]
    pub subreddit: String,
    #[serde(default)]
    pub notice: String,
    #[serde(default)]
    pub urls: HashMap<String, Vec<String>>,
    #[serde(default, rename = "twitter_username")]
    pub twitter: String,
}

/// Look up coin metadata by ticker symbol. `Ok(None)` when the backend has no
/// record. Uses the default REST backend.
pub fn by_symbol(env: &Env, symbol: &str) -> Result<Option<CoinInfo>> {
    by_key(env, crate::rest::DEFAULT_HOST, "symbol", symbol)
}

/// Look up coin metadata by on-chain contract/mint address.
pub fn by_address(env: &Env, address: &str) -> Result<Option<CoinInfo>> {
    by_key(env, crate::rest::DEFAULT_HOST, "address", address)
}

/// Backend-overridable variant (tests point `base` at a mock server).
pub fn by_key(env: &Env, base: &str, key_type: &str, key: &str) -> Result<Option<CoinInfo>> {
    let cache_key = format!("rest:ccInfo:{key_type}:{key}");
    if let Some(bytes) = env.cache_load(&cache_key)? {
        // An empty cache entry records a known-absent record (negative cache).
        if bytes.is_empty() {
            return Ok(None);
        }
        return Ok(serde_json::from_slice(&bytes).ok());
    }

    let path = format!(
        "Crypto/DataCache:ccInfo?key_type={}&key={}",
        urlencode(key_type),
        urlencode(key)
    );
    let data = crate::rest::do_get(base, &path)?;
    if data.is_null() {
        env.cache_store(&cache_key, &[], TTL)?;
        return Ok(None);
    }
    let info: CoinInfo =
        serde_json::from_value(data).map_err(|e| Error::Env(format!("ccInfo parse: {e}")))?;
    let bytes =
        serde_json::to_vec(&info).map_err(|e| Error::Env(format!("ccInfo encode: {e}")))?;
    env.cache_store(&cache_key, &bytes, TTL)?;
    Ok(Some(info))
}

/// Percent-encode a query value (RFC 3986 unreserved chars pass through).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
