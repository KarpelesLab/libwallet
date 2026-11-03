//! `Bitfi:*` — recover funds from a Bitfi salt and secret phrase.
//!
//! The salt and secret are only used to derive the master key, and aren't kept.
//! That key lives in this process's memory under a random session id and is never
//! written to the database, so closing the session, or the window, ends it.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use num_bigint::BigInt;
use serde_json::{json, Value};

use super::{ApiError, ApiResult};
use crate::bitfi::{self, Amount, Coin, Family, Node, PrivateKey};

/// The most positions one request can ask about.
const MAX_POSITIONS: usize = 64;

fn sessions() -> &'static Mutex<HashMap<String, Node>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Node>>> = OnceLock::new();
    SESSIONS.get_or_init(Default::default)
}

/// Run `f` with a session's master key.
fn with_session<T>(params: &Value, f: impl FnOnce(&Node) -> Result<T, ApiError>) -> Result<T, ApiError> {
    let id = text(params, "Session")?;
    let sessions = sessions().lock().map_err(|_| ApiError::new(500, "session store unavailable"))?;
    f(sessions.get(id).ok_or_else(|| ApiError::new(404, "session not found"))?)
}

fn text<'a>(params: &'a Value, name: &str) -> Result<&'a str, ApiError> {
    params.get(name).and_then(Value::as_str).ok_or_else(|| ApiError::new(400, format!("{name} required")))
}

fn coin_param(params: &Value) -> Result<&'static Coin, ApiError> {
    let symbol = text(params, "Coin")?;
    bitfi::coin(symbol).ok_or_else(|| ApiError::new(400, format!("unsupported coin {symbol:?}")))
}

fn position(value: &Value) -> Result<u32, ApiError> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n < 0x8000_0000)
        .ok_or_else(|| ApiError::new(400, "Position must be a non-negative integer below 2^31"))
}

/// `Bitfi:open` {Salt, Secret} — derive the master key, returning `{Session,
/// Coins}`. Whitespace and case count: the input is used exactly as given.
pub fn open(params: &Value) -> ApiResult {
    let node = bitfi::master(text(params, "Salt")?, text(params, "Secret")?).map_err(|e| ApiError::new(400, e))?;
    let id = uuid::Uuid::new_v4().to_string();
    sessions().lock().map_err(|_| ApiError::new(500, "session store unavailable"))?.insert(id.clone(), node);
    let coins: Vec<&str> = bitfi::COINS.iter().map(|c| c.symbol).collect();
    Ok(json!({ "Session": id, "Coins": coins }))
}

/// `Bitfi:addresses` {Session, Coin, Positions} — each position's addresses.
pub fn addresses(params: &Value) -> ApiResult {
    let coin = coin_param(params)?;
    let positions = params.get("Positions").and_then(Value::as_array).ok_or_else(|| ApiError::new(400, "Positions required"))?;
    if positions.len() > MAX_POSITIONS {
        return Err(ApiError::new(400, format!("at most {MAX_POSITIONS} positions per request")));
    }
    with_session(params, |node| {
        let mut found = Vec::with_capacity(positions.len());
        for value in positions {
            let position = position(value)?;
            let key = node.derive(coin.symbol, position).map_err(ApiError::internal)?;
            let addresses = bitfi::addresses(coin, &key).map_err(ApiError::internal)?;
            found.push(json!({ "Position": position, "Addresses": addresses }));
        }
        Ok(json!({ "Coin": coin.symbol, "Positions": found }))
    })
}

/// `Bitfi:export` {Session, Coin, Position} — the private keys, for importing
/// into another wallet. Only ever returned on this explicit request.
pub fn export(params: &Value) -> ApiResult {
    let coin = coin_param(params)?;
    let position = position(params.get("Position").unwrap_or(&Value::Null))?;
    with_session(params, |node| {
        let key = node.derive(coin.symbol, position).map_err(ApiError::internal)?;
        Ok(match coin.family {
            Family::Bitcoin { wif, segwit, .. } => json!({
                "PrivateKey": key.to_hex(),
                "Legacy": key.to_wif(wif, false),
                "Segwit": segwit.then(|| key.to_wif(wif, true)),
            }),
            Family::Ethereum => json!({ "PrivateKey": key.to_hex() }),
            Family::Monero => {
                let keys = key.monero();
                let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                json!({ "Address": keys.address(), "SpendKey": hex(&keys.spend), "ViewKey": hex(&keys.view) })
            }
        })
    })
}

/// `Bitfi:close` {Session} — forget the master key.
pub fn close(params: &Value) -> ApiResult {
    let id = text(params, "Session")?;
    sessions().lock().map_err(|_| ApiError::new(500, "session store unavailable"))?.remove(id);
    Ok(json!({ "closed": true }))
}

/// The node to ask about a coin. `RPC` overrides our server, for tests.
fn rpc_url(coin: &Coin, params: &Value) -> Result<String, ApiError> {
    if matches!(coin.family, Family::Monero) {
        return Err(ApiError::new(501, "Monero balances and sends aren't available yet; export the keys instead"));
    }
    Ok(match params.get("RPC").and_then(Value::as_str) {
        Some(url) => url.to_owned(),
        None => crate::models::network::modchain_rpc(coin.chain),
    })
}

/// A `modchain_assets` reply as `[{Asset, Symbol, Decimals, Balance}]`, with the
/// balance in base units as a decimal string, leaving out empty entries.
fn parse_assets(coin: &Coin, raw: &Value) -> Result<Vec<Value>, ApiError> {
    if !matches!(coin.family, Family::Ethereum) {
        let balance = crate::bitcoin::parse_native_balance(raw).map_err(ApiError::internal)?;
        let mut assets = Vec::new();
        if balance > 0 {
            let symbol = coin.symbol.to_uppercase();
            assets.push(json!({ "Asset": "NATIVE", "Symbol": symbol, "Decimals": 8, "Balance": balance.to_string() }));
        }
        return Ok(assets);
    }
    let entries = raw.get("assets").and_then(Value::as_array).ok_or_else(|| ApiError::new(502, "modchain_assets: no assets array"))?;
    let mut assets = Vec::new();
    for entry in entries {
        let hex = entry.get("balance").and_then(Value::as_str).unwrap_or("0x0");
        let balance = BigInt::parse_bytes(hex.trim_start_matches("0x").as_bytes(), 16)
            .ok_or_else(|| ApiError::new(502, format!("bad balance {hex:?}")))?;
        if balance == BigInt::from(0) {
            continue;
        }
        let asset = entry.get("asset").and_then(Value::as_str).unwrap_or_default();
        let symbol = entry.get("symbol").and_then(Value::as_str).unwrap_or(if asset == "NATIVE" { "ETH" } else { "" });
        assets.push(json!({ "Asset": asset, "Symbol": symbol, "Decimals": entry.get("decimals"), "Balance": balance.to_string() }));
    }
    Ok(assets)
}

/// `Bitfi:balances` {Session, Coin, Positions} — what each address holds. An
/// address that couldn't be checked carries `Error` rather than an empty list, so
/// a server problem is never reported as an empty wallet.
pub async fn balances(params: &Value) -> ApiResult {
    let coin = coin_param(params)?;
    let url = rpc_url(coin, params)?;
    let derived = addresses(params)?;
    let mut found = Vec::new();
    for entry in derived["Positions"].as_array().into_iter().flatten() {
        for address in entry["Addresses"].as_array().into_iter().flatten() {
            let text = address["address"].as_str().unwrap_or_default();
            let mut row = json!({ "Position": entry["Position"], "Kind": address["kind"], "Address": text });
            let reply = crate::rpc::call_async(&url, "modchain_assets", json!([text])).await.map_err(|e| e.to_string());
            match reply.and_then(|raw| parse_assets(coin, &raw).map_err(|e| e.message)) {
                Ok(assets) => row["Assets"] = json!(assets),
                Err(error) => row["Error"] = json!(error),
            }
            found.push(row);
        }
    }
    Ok(json!({ "Coin": coin.symbol, "Addresses": found }))
}

/// Derive the key a send signs with.
fn derive_key(params: &Value, coin: &Coin) -> Result<PrivateKey, ApiError> {
    let position = position(params.get("Position").unwrap_or(&Value::Null))?;
    with_session(params, |node| node.derive(coin.symbol, position).map_err(ApiError::internal))
}

fn amount_param(params: &Value) -> Result<Amount, ApiError> {
    match text(params, "Amount")? {
        "max" => Ok(Amount::Max),
        n => n.parse().map(Amount::Exact).map_err(|_| ApiError::new(400, "Amount must be \"max\" or a whole number of base units")),
    }
}

/// An Ethereum `Amount`, which can exceed 64 bits: 2^64 wei is only 18.4 ETH.
/// `None` means everything.
fn wei_param(params: &Value) -> Result<Option<BigInt>, ApiError> {
    match text(params, "Amount")? {
        "max" => Ok(None),
        n if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => Ok(BigInt::parse_bytes(n.as_bytes(), 10)),
        _ => Err(ApiError::new(400, "Amount must be \"max\" or a whole number of base units")),
    }
}

/// The network's fee rate in satoshi per virtual byte. Bitcoin Cash nodes only
/// have the older `estimatefee`, which takes no target.
async fn fee_rate(url: &str, params: &Value) -> Result<u64, ApiError> {
    if let Some(rate) = params.get("FeeRate") {
        return rate.as_u64().filter(|r| *r > 0).ok_or_else(|| ApiError::new(400, "FeeRate must be a positive whole number"));
    }
    let per_kb = match crate::rpc::call_async(url, "estimatesmartfee", json!([6])).await {
        Ok(reply) => reply.get("feerate").cloned().unwrap_or(Value::Null),
        Err(_) => crate::rpc::call_async(url, "estimatefee", json!([])).await.map_err(ApiError::internal)?,
    };
    let per_kb = crate::bitcoin::parse_btc_amount(&per_kb).ok().filter(|r| *r > 0);
    let per_kb = per_kb.ok_or_else(|| ApiError::new(502, "the node has no fee estimate; pass FeeRate"))?;
    Ok(bitfi::fee_rate_from_per_kb(per_kb))
}

/// `Bitfi:prepareSend` {Session, Coin, Position, Kind?, To, Amount, Token?,
/// FeeRate?} — build and sign a transaction without broadcasting it, so its
/// `{From, To, Amount, Fee, Raw}` can be reviewed. `Amount` is base units or
/// `"max"`. `Kind` picks `legacy` or `segwit` where a coin has both, and `Token`
/// an ERC-20 contract on Ethereum.
pub async fn prepare_send(params: &Value) -> ApiResult {
    let coin = coin_param(params)?;
    let url = rpc_url(coin, params)?;
    let to = text(params, "To")?;
    let key = derive_key(params, coin)?;
    if matches!(coin.family, Family::Ethereum) {
        return prepare_ethereum(coin, &key, &url, to, wei_param(params)?, params).await;
    }
    let amount = amount_param(params)?;
    let kind = text(params, "Kind")?;
    let from = bitfi::addresses(coin, &key)
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|a| a.kind == kind)
        .ok_or_else(|| ApiError::new(400, format!("{} has no {kind} address", coin.symbol)))?
        .address;
    let raw = crate::rpc::call_async(&url, "modchain_assets", json!([from])).await.map_err(ApiError::internal)?;
    let utxos = crate::bitcoin::parse_native_utxos(&raw).map_err(ApiError::internal)?;
    let rate = fee_rate(&url, params).await?;
    let spend = bitfi::spend_bitcoin(coin, &key, kind, &utxos, to, amount, rate).map_err(|e| ApiError::new(400, e))?;
    let hex: String = spend.raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(json!({
        "From": from, "To": to.trim(), "Amount": spend.amount.to_string(), "Fee": spend.fee.to_string(),
        "Change": spend.change.to_string(), "FeeRate": rate, "Raw": hex,
    }))
}

async fn prepare_ethereum(coin: &Coin, key: &PrivateKey, url: &str, to: &str, amount: Option<BigInt>, params: &Value) -> ApiResult {
    let to = to.trim();
    outscript::decode_evm_address(to).map_err(|_| ApiError::new(400, "That isn't an Ethereum address. Sending to another network's address would lose the funds."))?;
    let from = bitfi::addresses(coin, key).map_err(ApiError::internal)?.remove(0).address;
    let token = params.get("Token").and_then(Value::as_str);
    if let Some(token) = token {
        outscript::decode_evm_address(token).map_err(|_| ApiError::new(400, format!("{token} is not a token contract")))?;
    }
    let assets = crate::rpc::call_async(url, "modchain_assets", json!([from])).await.map_err(ApiError::internal)?;
    let assets = parse_assets(coin, &assets)?;
    let held = |asset: &str| -> BigInt {
        assets
            .iter()
            .find(|a| a["Asset"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(asset)))
            .and_then(|a| a["Balance"].as_str())
            .and_then(|b| BigInt::parse_bytes(b.as_bytes(), 10))
            .unwrap_or_default()
    };
    let native = held("NATIVE");
    let requested = |available: &BigInt| amount.clone().unwrap_or_else(|| available.clone());

    // A token moves through its contract: the transaction pays it no ETH.
    let (call_to, value, data, sent) = match token {
        Some(token) => {
            let sent = requested(&held(token));
            if sent == BigInt::from(0) || sent > held(token) {
                let decimals = assets
                    .iter()
                    .find(|a| a["Asset"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(token)))
                    .and_then(|a| a["Decimals"].as_u64())
                    .unwrap_or(18) as usize;
                return Err(ApiError::new(400, format!("This address holds {} of that token.", bitfi::format_units(&held(token).to_string(), decimals))));
            }
            (token.to_owned(), BigInt::from(0), erc20_transfer(to, &sent), sent)
        }
        None => (to.to_owned(), BigInt::from(0), String::new(), BigInt::from(0)),
    };

    // Gas for a token transfer is estimated with its call data, plus a margin.
    let mut tx = json!({ "to": call_to, "value": value.to_string(), "chainId": 1 });
    if !data.is_empty() {
        tx["data"] = json!(data);
        let call = json!([{ "from": from, "to": call_to, "data": data }]);
        let estimate = crate::rpc::call_async(url, "eth_estimateGas", call).await.map_err(ApiError::internal)?;
        let gas = u64::from_str_radix(estimate.as_str().unwrap_or("0").trim_start_matches("0x"), 16).unwrap_or(0);
        if gas == 0 {
            return Err(ApiError::new(502, "the node gave no gas estimate"));
        }
        tx["gas"] = json!(gas + gas / 5);
    } else {
        tx["gas"] = json!(21000);
    }
    let mut filled = super::account::evm_fill(&from, url, &json!({ "Transaction": tx })).await?;
    let fields = &filled["Transaction"];
    let price = fields.get("maxFeePerGas").or_else(|| fields.get("gasPrice")).and_then(Value::as_str).unwrap_or("0");
    let price = BigInt::parse_bytes(price.as_bytes(), 10).unwrap_or_default();
    let fee = price * fields["gas"].as_u64().unwrap_or(0);

    // The native amount needs the worst-case fee known, so it's filled in last.
    let sent = if token.is_some() {
        if native < fee {
            return Err(ApiError::new(400, format!("Moving a token needs up to {} ETH for the network fee, and this address holds {} ETH.", eth(&fee), eth(&native))));
        }
        sent
    } else {
        let sent = amount.clone().unwrap_or_else(|| &native - &fee);
        if sent <= BigInt::from(0) || &sent + &fee > native {
            return Err(ApiError::new(400, format!("This address holds {} ETH, and the network fee can be up to {} ETH.", eth(&native), eth(&fee))));
        }
        filled["Transaction"]["value"] = json!(sent.to_string());
        sent
    };
    let request = super::account::evm_request_from_tx(&filled["Transaction"])?;
    let raw = bitfi::sign_ethereum(key, &request).map_err(ApiError::internal)?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(json!({
        "From": from, "To": to, "Token": token, "Amount": sent.to_string(), "Fee": fee.to_string(), "Raw": format!("0x{hex}"),
    }))
}

fn eth(wei: &BigInt) -> String {
    bitfi::format_units(&wei.to_string(), 18)
}

/// ABI-encoded `transfer(to, amount)`.
fn erc20_transfer(to: &str, amount: &BigInt) -> String {
    format!("0xa9059cbb{:0>64}{:0>64}", to.trim_start_matches("0x").to_lowercase(), amount.to_str_radix(16))
}

/// `Bitfi:broadcast` {Coin, Raw} — send a transaction from `Bitfi:prepareSend`.
pub async fn broadcast(params: &Value) -> ApiResult {
    let coin = coin_param(params)?;
    let url = rpc_url(coin, params)?;
    let raw = text(params, "Raw")?;
    let method = if matches!(coin.family, Family::Ethereum) { "eth_sendRawTransaction" } else { "sendrawtransaction" };
    let txid = crate::rpc::call_async(&url, method, json!([raw])).await.map_err(ApiError::internal)?;
    Ok(json!({ "Txid": txid }))
}
