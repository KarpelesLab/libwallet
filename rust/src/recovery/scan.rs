//! What a recovered address holds.
//!
//! A balance that couldn't be checked is reported as an `Error` on that
//! address, never as an empty list: a server problem must not look like an
//! empty wallet, or the user might give up on funds that are still there.

use num_bigint::BigInt;
use serde_json::{json, Value};

use super::{Chain, Family, Slot};

/// SPL Token and Token-2022 program ids.
pub const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const SPL_TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// TRC-20 tokens checked on every Tron address (Tron nodes can't list an
/// address's tokens): `(contract, symbol, decimals)`.
pub const TRC20: &[(&str, &str, u32)] = &[("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "USDT", 6)];

/// One holding: `{Asset, Symbol, Decimals, Balance}`, `Asset` being `NATIVE`
/// or the token's contract / mint, `Balance` base units as a decimal string.
pub fn asset(asset: &str, symbol: &str, decimals: u32, balance: &BigInt) -> Value {
    json!({ "Asset": asset, "Symbol": symbol, "Decimals": decimals, "Balance": balance.to_string() })
}

/// The node to use for a chain: `rpc` when the request overrides it (tests,
/// self-hosted nodes), otherwise libwallet's own.
pub fn rpc_for(c: &Chain, rpc: Option<&str>) -> Result<String, String> {
    if let Some(url) = rpc.filter(|u| !u.is_empty()) {
        return Ok(url.to_owned());
    }
    Ok(match c.family {
        Family::Bitcoin { .. } | Family::Ethereum | Family::Solana => crate::models::network::modchain_rpc(c.name),
        Family::Tron => crate::models::network::modchain_tron_rest(),
        Family::Monero => return Err("Monero balances and sends aren't available: export the keys into a Monero wallet instead.".into()),
    })
}

/// Parse a `modchain_assets` reply for a Bitcoin-family address: its unspent
/// balance in satoshi.
pub fn bitcoin_assets(c: &Chain, raw: &Value) -> Result<Vec<Value>, String> {
    let balance = crate::bitcoin::parse_native_balance(raw).map_err(|e| e.to_string())?;
    Ok(if balance > 0 { vec![asset("NATIVE", c.symbol, c.decimals, &BigInt::from(balance))] } else { Vec::new() })
}

/// Parse a `modchain_assets` reply for an Ethereum address: ETH and every
/// ERC-20 the indexer knows the address holds, leaving out empty entries.
pub fn ethereum_assets(raw: &Value) -> Result<Vec<Value>, String> {
    let entries = raw.get("assets").and_then(Value::as_array).ok_or("modchain_assets: no assets array")?;
    let mut out = Vec::new();
    for entry in entries {
        let hex = entry.get("balance").and_then(Value::as_str).unwrap_or("0x0");
        let balance = BigInt::parse_bytes(hex.trim_start_matches("0x").as_bytes(), 16).ok_or_else(|| format!("bad balance {hex:?}"))?;
        if balance == BigInt::from(0) {
            continue;
        }
        let name = entry.get("asset").and_then(Value::as_str).unwrap_or_default();
        let symbol = entry.get("symbol").and_then(Value::as_str).unwrap_or(if name == "NATIVE" { "ETH" } else { "" });
        let decimals = entry.get("decimals").and_then(Value::as_u64).unwrap_or(18) as u32;
        out.push(asset(name, symbol, decimals, &balance));
    }
    Ok(out)
}

/// The curated symbol for a Solana mint, if it's a known token.
fn spl_symbol(mint: &str) -> Option<String> {
    use std::sync::OnceLock;
    static LIST: OnceLock<Vec<Value>> = OnceLock::new();
    LIST.get_or_init(|| crate::curated::for_chain("solana.mainnet"))
        .iter()
        .find(|t| t.get("address").and_then(Value::as_str) == Some(mint))
        .and_then(|t| t.get("symbol").and_then(Value::as_str))
        .map(str::to_owned)
}

async fn solana_assets(c: &Chain, url: &str, address: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let reply = crate::rpc::call_async(url, "getBalance", json!([address])).await.map_err(|e| e.to_string())?;
    let lamports = reply.get("value").and_then(Value::as_u64).ok_or("getBalance: no value")?;
    if lamports > 0 {
        out.push(asset("NATIVE", c.symbol, c.decimals, &BigInt::from(lamports)));
    }
    let mut tokens: Vec<(String, BigInt, u32)> = Vec::new();
    for program in [SPL_TOKEN, SPL_TOKEN_2022] {
        let reply = crate::rpc::call_async(url, "getTokenAccountsByOwner", json!([address, { "programId": program }, { "encoding": "jsonParsed" }]))
            .await
            .map_err(|e| e.to_string())?;
        for account in reply.get("value").and_then(Value::as_array).into_iter().flatten() {
            let info = account.pointer("/account/data/parsed/info");
            let mint = info.and_then(|i| i.get("mint")).and_then(Value::as_str).unwrap_or_default();
            let amount = info
                .and_then(|i| i.pointer("/tokenAmount/amount"))
                .and_then(Value::as_str)
                .and_then(|s| BigInt::parse_bytes(s.as_bytes(), 10))
                .unwrap_or_default();
            let decimals = info.and_then(|i| i.pointer("/tokenAmount/decimals")).and_then(Value::as_u64).unwrap_or(0) as u32;
            if mint.is_empty() || amount == BigInt::from(0) {
                continue;
            }
            match tokens.iter_mut().find(|t| t.0 == mint) {
                Some(t) => t.1 += amount,
                None => tokens.push((mint.to_owned(), amount, decimals)),
            }
        }
    }
    for (mint, amount, decimals) in tokens {
        let symbol = spl_symbol(&mint).unwrap_or_default();
        out.push(asset(&mint, &symbol, decimals, &amount));
    }
    Ok(out)
}

/// TRX and the known TRC-20 tokens. A token that couldn't be checked makes
/// the whole address an error: a partial list could hide funds.
async fn tron_assets(c: &Chain, base: &str, address: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let account = crate::tron::post_async(base, "getaccount", &crate::tron::account_body(address)).await.map_err(|e| e.to_string())?;
    let sun = crate::tron::parse_balance(&account);
    if sun > 0 {
        out.push(asset("NATIVE", c.symbol, c.decimals, &BigInt::from(sun)));
    }
    for (contract, symbol, decimals) in TRC20 {
        let param = crate::tron::balance_of_param(address).map_err(|e| e.to_string())?;
        let body = crate::tron::constant_call_body(address, contract, "balanceOf(address)", &param);
        let reply = crate::tron::post_async(base, "triggerconstantcontract", &body).await.map_err(|e| e.to_string())?;
        let word = crate::tron::parse_constant_result(&reply).map_err(|e| format!("{symbol} balance: {e}"))?;
        let balance = crate::tron::parse_uint(&word);
        if balance > BigInt::from(0) {
            out.push(asset(contract, symbol, *decimals, &balance));
        }
    }
    Ok(out)
}

/// What a slot's address holds.
pub async fn assets(s: &Slot, rpc: Option<&str>) -> Result<Vec<Value>, String> {
    let url = rpc_for(s.chain, rpc)?;
    match s.chain.family {
        Family::Bitcoin { .. } => {
            let raw = crate::rpc::call_async(&url, "modchain_assets", json!([s.address])).await.map_err(|e| e.to_string())?;
            bitcoin_assets(s.chain, &raw)
        }
        Family::Ethereum => {
            let raw = crate::rpc::call_async(&url, "modchain_assets", json!([s.address])).await.map_err(|e| e.to_string())?;
            ethereum_assets(&raw)
        }
        Family::Solana => solana_assets(s.chain, &url, &s.address).await,
        Family::Tron => tron_assets(s.chain, &url, &s.address).await,
        Family::Monero => Err("unreachable".into()),
    }
}

/// `slot.to_json()` plus `Assets`, or `Error` when they couldn't be checked.
pub async fn scan_one(s: &Slot, rpc: Option<&str>) -> Value {
    let mut row = s.to_json();
    match assets(s, rpc).await {
        Ok(found) => row["Assets"] = json!(found),
        Err(e) => row["Error"] = json!(e),
    }
    row
}

/// How many addresses are checked at once.
pub const CONCURRENCY: usize = 8;

/// Scan every slot, at most [`CONCURRENCY`] at a time, keeping their order.
pub async fn scan_all(slots: &[Slot], rpc: Option<&str>) -> Vec<Value> {
    join_bounded(slots.iter().map(|s| scan_one(s, rpc)).collect(), CONCURRENCY).await
}

/// Run futures with at most `limit` in flight, returning their outputs in order.
/// (No executor is assumed: this works under the native runtime and in the
/// browser alike.)
pub async fn join_bounded<F: std::future::Future>(futures: Vec<F>, limit: usize) -> Vec<F::Output> {
    use std::pin::Pin;
    use std::task::Poll;
    let n = futures.len();
    let mut pending: Vec<Option<Pin<Box<F>>>> = futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut results: Vec<Option<F::Output>> = (0..n).map(|_| None).collect();
    let limit = limit.max(1);
    let mut started = 0usize;
    let mut done = 0usize;
    std::future::poll_fn(|cx| {
        // Poll the started, unfinished ones; start more as slots free up.
        loop {
            let in_flight = started - done;
            if in_flight < limit && started < n {
                started += 1;
                continue;
            }
            break;
        }
        let mut progressed = false;
        for i in 0..started {
            if let Some(f) = pending[i].as_mut() {
                if let Poll::Ready(out) = f.as_mut().poll(cx) {
                    results[i] = Some(out);
                    pending[i] = None;
                    done += 1;
                    progressed = true;
                }
            }
        }
        if done == n {
            Poll::Ready(())
        } else if progressed && started < n {
            // Freed slots: start the next futures on this same wake.
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Pending
        }
    })
    .await;
    results.into_iter().map(|r| r.expect("every future finished")).collect()
}
