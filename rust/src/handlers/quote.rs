//! Market-quote endpoint (wltquote). `Quote:get` {Symbol, Currency?} returns the
//! CMC-shaped price record for a token, plus the price in the requested fiat
//! currency (default USD). The full table is DB-cached for 5 minutes.

use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

pub fn get(env: &Env, params: &Value) -> ApiResult {
    let symbol = params
        .get("Symbol")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Symbol required"))?;
    let currency = params
        .get("Currency")
        .and_then(Value::as_str)
        .unwrap_or("USD");
    // Optional backend override (mirrors Go rest.BackendURL); defaults to the
    // production host. Lets the host/tests point at an alternate REST endpoint.
    let base = params
        .get("Backend")
        .and_then(Value::as_str)
        .unwrap_or(crate::rest::DEFAULT_HOST);

    let quote = crate::quote::get_quotes_for_token_from(env, base, symbol)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, format!("no quote for {symbol}")))?;

    let entry = quote.quote.get(currency);
    Ok(json!({
        "symbol": quote.symbol,
        "name": quote.name,
        "currency": currency,
        "price": entry.map(|e| e.price),
        "quote": entry,
        "data": quote,
    }))
}
