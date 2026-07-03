//! Market-quote lookup — port of Go `wltquote`. Fetches the CoinMarketCap-shaped
//! quote table from the KLB REST endpoint `Crypto/DataCache:quotes`, cached in
//! the wallet DB under `rest:Crypto/DataCache:quotes` with a 5-minute TTL, and
//! looks up a token by symbol.
//!
//! The Go cache holds the raw envelope `data` (a JSON array) so a stale hit
//! reparses without a network round-trip. We keep that exact cache key and value
//! for byte-compatibility with an existing sql.db.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::{Env, Error, Result};

/// The REST cache key, identical to Go `quoteCacheKey`.
pub const CACHE_KEY: &str = "rest:Crypto/DataCache:quotes";
const TTL: Duration = Duration::from_secs(5 * 60);

/// One token's quote record (mirrors Go `CMCQuoteData`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CmcQuoteData {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default, rename = "date_added")]
    pub added: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub circulating_supply: f64,
    #[serde(default)]
    pub total_supply: f64,
    #[serde(default)]
    pub last_updated: String,
    #[serde(default)]
    pub quote: HashMap<String, CmcQuoteEntry>,
}

/// A per-currency price entry (mirrors Go `CMCQuoteEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CmcQuoteEntry {
    #[serde(default)]
    pub price: f64,
    #[serde(default)]
    pub volume_24h: f64,
    #[serde(default)]
    pub volume_change_24h: f64,
    #[serde(default)]
    pub percent_change_1h: f64,
    #[serde(default)]
    pub percent_change_24h: f64,
    #[serde(default)]
    pub market_cap: f64,
    #[serde(default)]
    pub last_updated: String,
}

/// Fetch (or reuse the cached) quote table and return the entry for `symbol`.
/// Uses the default REST backend. Returns `Ok(None)` when the symbol is absent.
pub fn get_quotes_for_token(env: &Env, symbol: &str) -> Result<Option<CmcQuoteData>> {
    get_quotes_for_token_from(env, crate::rest::DEFAULT_HOST, symbol)
}

/// Backend-overridable variant (tests point `base` at a mock server).
pub fn get_quotes_for_token_from(
    env: &Env,
    base: &str,
    symbol: &str,
) -> Result<Option<CmcQuoteData>> {
    let all = get_quotes_data(env, base)?;
    Ok(all.into_iter().find(|q| q.symbol == symbol))
}

/// The full quote table, DB-cached under [`CACHE_KEY`] with a 5-minute TTL.
pub fn get_quotes_data(env: &Env, base: &str) -> Result<Vec<CmcQuoteData>> {
    let raw = get_quotes_raw(env, base)?;
    serde_json::from_slice(&raw).map_err(|e| Error::Env(format!("quote parse failed: {e}")))
}

/// The raw JSON array bytes, from cache when fresh, else fetched and re-cached.
fn get_quotes_raw(env: &Env, base: &str) -> Result<Vec<u8>> {
    if let Some(cached) = env.cache_load(CACHE_KEY)? {
        return Ok(cached);
    }
    let data = crate::rest::do_get(base, "Crypto/DataCache:quotes")?;
    let bytes =
        serde_json::to_vec(&data).map_err(|e| Error::Env(format!("quote encode failed: {e}")))?;
    env.cache_store(CACHE_KEY, &bytes, TTL)?;
    Ok(bytes)
}
