//! Swap endpoints (wltswap). The wire contract is the Dart `SwapApi`
//! (`dart/lib/src/api/swap_api.dart` + `models/swap_quote.dart`): camelCase
//! params (`tokenIn`, `tokenOut`, `amountIn`, `from`, `slippageBps`, `network`,
//! `provider`, `quoteId`, …) and camelCase results shaped exactly as
//! `SwapQuote` / `QuoteAttempt` / `SwapResult` / `ApprovalPreview` /
//! `SwapOrderStatus` parse them. The PascalCase names of the earlier Rust-only
//! contract (`TokenIn`, `AmountIn`, `Account`, `RPC`, …) are accepted as
//! aliases.
//!
//! Like Go wltswap, Swap:quote / quotes / maxSpendable cache every executable
//! quote (plus the account + network it was issued for) under its `quoteId`
//! for [`QUOTE_TTL`]; Swap:execute and Swap:buildApproval run by that id.
//! Typed failures carry the Go `SwapError` code as a message prefix
//! (`quote_not_found: …`, `no_liquidity: …`) since the response envelope has
//! no separate code field. OKX proxy calls authenticate with the app clientId
//! (Sec-ClientId, from Info:setWalletInfo); `Backend` overrides the REST host
//! for tests.

use std::time::Duration;

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::models::account::Account;
use crate::models::network::Network;
use crate::swap::{self, Quote, TokenRef};
use crate::Env;

use super::{ApiError, ApiResult};

/// How long a quote stays executable (Go `quoteTTL`): aggregator prices move
/// fast, 90 s is enough to read the confirmation sheet.
const QUOTE_TTL: Duration = Duration::from_secs(90);

/// How long an expired quote lingers in the cache so execute can answer
/// `quote_expired` (re-quote) rather than `quote_not_found`.
const QUOTE_CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// What Swap:execute / Swap:buildApproval need from an issued quote.
#[derive(Serialize, Deserialize)]
struct CachedQuote {
    quote: Quote,
    /// Account id the quote was issued to ("" when quoted without one).
    account: String,
    /// The network: its stored id plus the `type.chainId` fallback.
    network: String,
    kind: String,
    chain_id: String,
}

fn cache_key(quote_id: &str) -> String {
    format!("swap:quote:{quote_id}")
}

/// A typed swap failure: the stable Go `SwapError` code prefixes the message.
fn swap_err(status: i64, code: &str, msg: impl std::fmt::Display) -> ApiError {
    ApiError::new(status, format!("{code}: {msg}"))
}

/// The first present param among `names` (camelCase first, then aliases).
fn param<'a>(params: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|n| params.get(*n)).filter(|v| !v.is_null())
}

fn str_param<'a>(params: &'a Value, names: &[&str]) -> Option<&'a str> {
    param(params, names).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

fn token_ref(params: &Value, names: &[&str]) -> Result<TokenRef, ApiError> {
    let v = param(params, names)
        .ok_or_else(|| swap_err(400, "invalid_request", format!("{} is required", names[0])))?;
    let mut t: TokenRef = serde_json::from_value(v.clone())
        .map_err(|e| swap_err(400, "invalid_request", format!("bad {}: {e}", names[0])))?;
    if t.address.is_empty() {
        return Err(swap_err(400, "invalid_request", format!("{}.address is required", names[0])));
    }
    // Asset:list keys ("solana.mainnet.EPjF…") reduce to the bare mint/contract.
    t.address = swap::bare_token_addr(&t.address).to_owned();
    Ok(t)
}

fn slippage(params: &Value) -> u16 {
    let bps = param(params, &["slippageBps", "SlippageBps"]).and_then(Value::as_u64).unwrap_or(0);
    swap::normalize_slippage(bps.min(u16::MAX as u64) as u16)
}

/// The app's clientId, registered via `Info:setWalletInfo` and sent as the
/// `Sec-ClientId` header — the only auth the OKX proxy needs (no request
/// signature, no per-call credential).
fn client_id(env: &Env) -> Option<String> {
    env.config_get("walletinfo:clientId")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.is_empty())
}

fn backend(params: &Value) -> &str {
    params.get("Backend").and_then(Value::as_str).unwrap_or(crate::rest::DEFAULT_HOST)
}

/// The network a request targets: `network` (id or `type.chainId`), else the
/// current one.
fn resolve_network(env: &Env, params: &Value) -> Result<Network, ApiError> {
    let id = str_param(params, &["network", "Network"]).unwrap_or("@");
    crate::models::network::fetch(env, id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| swap_err(400, "invalid_request", format!("network {id} not found")))
}

/// The routed provider for `net`, checking a caller-pinned `provider`.
fn resolve_provider(net: &Network, params: &Value) -> Result<&'static str, ApiError> {
    let routed = swap::provider_for(&net.kind)
        .ok_or_else(|| swap_err(400, "unsupported_chain", format!("swap not supported on {} networks", net.kind)))?;
    match str_param(params, &["provider", "Provider"]) {
        Some(p) if p != routed => Err(swap_err(
            400,
            "invalid_request",
            format!("provider {p:?} is not available on {} networks (use {routed:?})", net.kind),
        )),
        _ => Ok(routed),
    }
}

/// Account type that signs on a network type (evm → ethereum).
fn account_kind(net_kind: &str) -> &str {
    match net_kind {
        "evm" => "ethereum",
        other => other,
    }
}

/// The signing account (Go `resolveAccountAndNetwork`): `from` (account id or
/// address) when given — it must be of the network's chain — else the current
/// account, or, when the current account is of another chain, the matching
/// account of the same wallet (then any matching account). `Ok(None)` only when
/// nothing was requested and no account of that chain exists.
fn resolve_account(env: &Env, params: &Value, net_kind: &str) -> Result<Option<Account>, ApiError> {
    let want = account_kind(net_kind);
    if let Some(from) = str_param(params, &["from", "From", "Account"]) {
        let a = crate::models::account::find(env, from)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(404, format!("account {from} not found")))?;
        if a.kind != want {
            return Err(swap_err(
                400,
                "invalid_request",
                format!("account {from} is a {} account; {net_kind} swaps need a {want} account", a.kind),
            ));
        }
        return Ok(Some(a));
    }
    let Some(cur) = crate::models::account::current(env).map_err(ApiError::internal)? else {
        return Ok(None);
    };
    if cur.kind == want {
        return Ok(Some(cur));
    }
    let sibling = crate::models::account::for_wallet(env, &cur.wallet)
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|a| a.kind == want);
    if sibling.is_some() {
        return Ok(sibling);
    }
    Ok(crate::models::account::list(env).map_err(ApiError::internal)?.into_iter().find(|a| a.kind == want))
}

fn require_account(a: Option<Account>, net_kind: &str) -> Result<Account, ApiError> {
    a.ok_or_else(|| {
        swap_err(400, "invalid_request", format!("no {} account to swap from (pass from)", account_kind(net_kind)))
    })
}

/// Node RPC for `net`: the `RPC` param, else the network's own endpoint, else
/// the chain default ([`super::resolve_rpc_for_kind`]).
fn resolve_rpc(env: &Env, params: &Value, net: &Network) -> Result<String, ApiError> {
    if let Some(url) = str_param(params, &["RPC", "rpc"]) {
        return Ok(url.to_owned());
    }
    match net.resolved_rpc() {
        Ok(url) => Ok(url),
        Err(_) => super::resolve_rpc_for_kind(env, params, &net.kind),
    }
}

/// Map a `swap::get_quote` failure onto its Go `SwapError` code.
fn quote_error(e: crate::Error) -> ApiError {
    let (status, code) = quote_error_code(&e.to_string());
    swap_err(status, code, e)
}

fn quote_error_code(msg: &str) -> (i64, &'static str) {
    if msg.contains("no route") {
        (400, "no_liquidity")
    } else if msg.contains("amountIn is required") || msg.contains("bad amountIn") {
        (400, "invalid_request")
    } else if msg.contains("unsupported network type") || msg.contains("not supported") || msg.contains("missing ChainId") {
        (400, "unsupported_chain")
    } else {
        (502, "provider_unavailable")
    }
}

/// The largest base-unit amount of `token_in` the account can swap (Go
/// `resolveMaxAmountIn`): native = Account:maxSendable (balance − fee − rent),
/// minus on Solana the transient wSOL-wrap / output-ATA rent the swap fronts;
/// tokens (SPL / ERC-20) = the full balance (fees are paid in native).
fn resolve_max_amount_in(
    env: &Env,
    params: &Value,
    account: &Account,
    net: &Network,
    token_in: &TokenRef,
    token_out: &TokenRef,
) -> Result<BigInt, ApiError> {
    let rpc = resolve_rpc(env, params, net)?;
    if swap::is_native_for(&net.kind, &token_in.address) {
        let res = super::account::max_sendable(env, &json!({ "Id": account.id, "RPC": rpc }))?;
        let mut max = res
            .pointer("/max/v")
            .and_then(Value::as_str)
            .and_then(|s| BigInt::parse_bytes(s.as_bytes(), 10))
            .unwrap_or_else(|| BigInt::from(0));
        if net.kind == "solana" {
            let extra = swap::solana_swap_sol_reservation(&rpc, &account.address, &token_in.address, &token_out.address);
            max -= BigInt::from(extra);
        }
        return Ok(max.max(BigInt::from(0)));
    }
    let bal = match net.kind.as_str() {
        "evm" => crate::erc20::balance_of(&rpc, &token_in.address, &account.address),
        "solana" => swap::solana_spl_balance(&rpc, &account.address, &token_in.address),
        other => return Err(swap_err(400, "unsupported_chain", format!("swap not supported on {other} networks"))),
    };
    bal.map_err(|e| swap_err(502, "provider_unavailable", format!("token balance: {e}")))
}

/// Stamp id + expiry on a fresh quote, fill the EVM approval fields, and cache
/// it with the account + network it was issued for (Go `finalizeQuote`).
fn finalize_quote(env: &Env, params: &Value, q: &mut Quote, account: Option<&Account>, net: &Network) -> Result<(), ApiError> {
    if let Some(a) = account {
        let rpc = resolve_rpc(env, params, net).ok();
        swap::apply_evm_approval(q, client_id(env).as_deref(), backend(params), &net.chain_id, rpc.as_deref(), &a.address);
    }
    q.quote_id = swap::new_quote_id();
    let expires = chrono::Utc::now() + chrono::Duration::from_std(QUOTE_TTL).unwrap_or_default();
    q.expires_at = expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let entry = CachedQuote {
        quote: q.clone(),
        account: account.map(|a| a.id.clone()).unwrap_or_default(),
        network: net.id.clone(),
        kind: net.kind.clone(),
        chain_id: net.chain_id.clone(),
    };
    let bytes = serde_json::to_vec(&entry).map_err(ApiError::internal)?;
    env.cache_store(&cache_key(&q.quote_id), &bytes, QUOTE_CACHE_TTL).map_err(ApiError::internal)
}

/// Look up an issued quote: `quote_not_found` when unknown / evicted,
/// `quote_expired` past its `expiresAt`.
fn load_quote(env: &Env, quote_id: &str) -> Result<(CachedQuote, Network), ApiError> {
    let raw = env
        .cache_load(&cache_key(quote_id))
        .map_err(ApiError::internal)?
        .ok_or_else(|| swap_err(404, "quote_not_found", "quote not found or expired; re-quote"))?;
    let entry: CachedQuote = serde_json::from_slice(&raw).map_err(ApiError::internal)?;
    let expired = chrono::DateTime::parse_from_rfc3339(&entry.quote.expires_at)
        .map(|t| chrono::Utc::now() > t)
        .unwrap_or(true);
    if expired {
        return Err(swap_err(410, "quote_expired", "quote expired; re-quote"));
    }
    let net = match crate::models::network::fetch(env, &entry.network).map_err(ApiError::internal)? {
        Some(n) => n,
        None => crate::models::network::fetch(env, &format!("{}.{}", entry.kind, entry.chain_id))
            .map_err(ApiError::internal)?
            .ok_or_else(|| swap_err(400, "invalid_request", "quote network no longer exists"))?,
    };
    Ok((entry, net))
}

/// The quote request shared by Swap:quote / quotes / maxSpendable.
struct QuoteRequest {
    net: Network,
    provider: &'static str,
    account: Option<Account>,
    token_in: TokenRef,
    token_out: TokenRef,
    slippage: u16,
}

fn quote_request(env: &Env, params: &Value) -> Result<QuoteRequest, ApiError> {
    let net = resolve_network(env, params)?;
    let provider = resolve_provider(&net, params)?;
    let token_in = token_ref(params, &["tokenIn", "TokenIn"])?;
    let token_out = token_ref(params, &["tokenOut", "TokenOut"])?;
    let account = resolve_account(env, params, &net.kind)?;
    Ok(QuoteRequest { provider, account, token_in, token_out, slippage: slippage(params), net })
}

/// `amountIn` as base units; `"MAX"` resolves to the account's max spendable.
fn resolve_amount_in(env: &Env, params: &Value, req: &QuoteRequest) -> Result<String, ApiError> {
    let amount = str_param(params, &["amountIn", "AmountIn"]).ok_or_else(|| {
        swap_err(400, "invalid_request", "amountIn is required (use \"MAX\" to swap the full balance)")
    })?;
    if !amount.eq_ignore_ascii_case("MAX") {
        if BigInt::parse_bytes(amount.as_bytes(), 10).is_none_or(|v| v <= BigInt::from(0)) {
            return Err(swap_err(400, "invalid_request", format!("amountIn {amount:?} is not a positive base-unit integer")));
        }
        return Ok(amount.to_owned());
    }
    let account = require_account(req.account.clone(), &req.net.kind)?;
    let max = resolve_max_amount_in(env, params, &account, &req.net, &req.token_in, &req.token_out)?;
    if max <= BigInt::from(0) {
        return Err(swap_err(400, "invalid_request", "balance does not cover network fee + rent"));
    }
    Ok(max.to_string())
}

fn fetch_quote(env: &Env, params: &Value, req: &QuoteRequest, amount_in: &str) -> Result<Quote, crate::Error> {
    swap::get_quote(
        client_id(env).as_deref(),
        backend(params),
        &req.net.kind,
        &req.net.chain_id,
        req.token_in.clone(),
        req.token_out.clone(),
        amount_in,
        req.slippage,
    )
}

/// `Swap:quote` {tokenIn, tokenOut, amountIn, from?, slippageBps?, network?,
/// provider?} — an OKX DEX quote, cached for Swap:execute by its `quoteId`.
pub fn quote(env: &Env, params: &Value) -> ApiResult {
    let req = quote_request(env, params)?;
    let amount_in = resolve_amount_in(env, params, &req)?;
    let mut q = fetch_quote(env, params, &req, &amount_in).map_err(quote_error)?;
    finalize_quote(env, params, &mut q, req.account.as_ref(), &req.net)?;
    Ok(serde_json::to_value(q).unwrap())
}

/// `Swap:quotes` — the multi-provider fan-out form of Swap:quote (Go
/// `swapQuotes`). One routed provider per chain today, so `attempts` has a
/// single entry carrying either the (cached) quote or a typed error.
pub fn quotes(env: &Env, params: &Value) -> ApiResult {
    let req = quote_request(env, params)?;
    let amount_in = resolve_amount_in(env, params, &req)?;
    let mut attempt = json!({ "provider": req.provider, "providerLabel": swap::provider_label(req.provider) });
    // A quote failure becomes an attempt-level error, not an endpoint failure.
    match fetch_quote(env, params, &req, &amount_in) {
        Ok(mut q) => {
            finalize_quote(env, params, &mut q, req.account.as_ref(), &req.net)?;
            attempt["quote"] = serde_json::to_value(q).unwrap();
        }
        Err(e) => {
            let msg = e.to_string();
            attempt["error"] = json!({ "code": quote_error_code(&msg).1, "message": msg });
        }
    }
    Ok(json!({ "attempts": [attempt] }))
}

/// `Swap:maxSpendable` {tokenIn, tokenOut, from?, slippageBps?, network?,
/// provider?} — a quote for the maximum `tokenIn` the account can swap (Go
/// `swapMaxSpendable`). Soft failures come back as advisory quotes with a
/// `status` (`balance_too_small`, `no_route`) instead of errors.
pub fn max_spendable(env: &Env, params: &Value) -> ApiResult {
    let req = quote_request(env, params)?;
    let account = require_account(req.account.clone(), &req.net.kind)?;
    let max = resolve_max_amount_in(env, params, &account, &req.net, &req.token_in, &req.token_out)?;
    let advisory = |amount: BigInt, status: &str, msg: &str| {
        Quote::advisory(&req.net.kind, req.token_in.clone(), req.token_out.clone(), amount, req.slippage, status, msg)
    };
    if max <= BigInt::from(0) {
        let q = advisory(BigInt::from(0), "balance_too_small", "balance does not cover network fee + rent");
        return Ok(serde_json::to_value(q).unwrap());
    }
    match fetch_quote(env, params, &req, &max.to_string()) {
        Ok(mut q) => {
            finalize_quote(env, params, &mut q, Some(&account), &req.net)?;
            Ok(serde_json::to_value(q).unwrap())
        }
        Err(e) if quote_error_code(&e.to_string()).1 == "no_liquidity" => {
            Ok(serde_json::to_value(advisory(max, "no_route", &e.to_string())).unwrap())
        }
        Err(e) => Err(quote_error(e)),
    }
}

/// `Swap:countryAvailability` — whether swaps are offered in a country (Go
/// `swapCountryAvailability`).
pub fn country_availability(_env: &Env, params: &Value) -> ApiResult {
    let country = str_param(params, &["country", "Country"]).ok_or_else(|| ApiError::new(400, "country required"))?;
    Ok(serde_json::to_value(swap::country_availability(country)).unwrap())
}

/// The ERC-20 approve transaction + preview (Go `ApprovalPreview`): calldata,
/// node-fetched nonce / gasPrice / gas, and the Dart `ApprovalPreview` shape.
#[allow(clippy::too_many_arguments)]
fn approval_preview(
    account: &Account,
    net: &Network,
    rpc: &str,
    token: &TokenRef,
    spender: &str,
    spender_label: &str,
    amount: BigInt,
    current_allowance: Option<&crate::Amount>,
) -> ApiResult {
    let data = swap::encode_erc20_approve(spender, &amount).map_err(|e| swap_err(400, "invalid_request", e))?;
    let hex_u64 = |v: &Value| {
        let s = v.as_str().unwrap_or("0x0");
        u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).unwrap_or(0)
    };
    let nonce = crate::rpc::call(rpc, "eth_getTransactionCount", json!([account.address, "pending"]))
        .map_err(ApiError::internal)?;
    let gp = crate::rpc::call(rpc, "eth_gasPrice", json!([])).map_err(ApiError::internal)?;
    let gp = gp.as_str().unwrap_or("0x0");
    let gas_price = BigInt::parse_bytes(gp.strip_prefix("0x").unwrap_or(gp).as_bytes(), 16).unwrap_or_else(|| BigInt::from(0));
    // estimateGas, or a safe default for approve().
    let gas = crate::rpc::call(rpc, "eth_estimateGas", json!([{ "from": account.address, "to": token.address, "data": data }]))
        .ok()
        .map(|v| hex_u64(&v))
        .filter(|g| *g > 0)
        .unwrap_or(60_000);
    let native = net.native_decimals();
    let fee = crate::Amount::new_raw(&gas_price * BigInt::from(gas), native);
    let amt = crate::Amount::new_raw(amount.clone(), token.decimals);
    Ok(json!({
        "token": token,
        "spender": spender,
        "spenderLabel": spender_label,
        "amount": amt,
        "isUnlimited": swap::is_unlimited_approval(&amount),
        "currentAllowance": current_allowance,
        "networkFee": fee,
        "tx": {
            "type": "evm",
            "from": account.address,
            "to": token.address,
            "value": crate::Amount::new_raw(BigInt::from(0), native),
            "amount": amt,
            "data": data,
            "nonce": hex_u64(&nonce),
            "gas": gas,
            "gasPrice": gas_price.to_string(),
            "fee": fee,
            "format": "legacy",
            "network": net.id,
        },
    }))
}

/// `Swap:buildApproval` {quoteId, approvalAmount?, from?} — the ERC-20 approve
/// transaction an EVM token-in swap needs (Go `swapBuildApproval`), returned as
/// a Dart `ApprovalPreview`. `approvalAmount` defaults to the quote's exact
/// amountIn; `"max"` / `"unlimited"` is uint256 max. Without a quoteId the
/// legacy direct form {Account, Token, Spender, Amount|Unlimited} still works.
pub fn build_approval(env: &Env, params: &Value) -> ApiResult {
    let Some(quote_id) = str_param(params, &["quoteId", "QuoteId"]) else {
        return build_approval_direct(env, params);
    };
    let (entry, net) = load_quote(env, quote_id)?;
    let q = &entry.quote;
    if q.chain != "evm" {
        return Err(swap_err(400, "invalid_request", "approvals are only relevant for EVM swaps"));
    }
    if !q.requires_approval || q.approval_spender.is_empty() {
        return Err(swap_err(
            400,
            "invalid_request",
            "quote does not require an approval (native-in swap or existing allowance already covers amountIn)",
        ));
    }
    let amount = match str_param(params, &["approvalAmount", "ApprovalAmount"]) {
        None => q.amount_in.value().cloned().unwrap_or_else(|| BigInt::from(0)),
        Some(s) if s.eq_ignore_ascii_case("max") || s.eq_ignore_ascii_case("unlimited") => swap::max_uint256(),
        Some(s) => BigInt::parse_bytes(s.as_bytes(), 10).filter(|v| *v >= BigInt::from(0)).ok_or_else(|| {
            swap_err(400, "invalid_request", format!("approvalAmount {s:?} is not a non-negative decimal or \"max\""))
        })?,
    };
    let account = execute_account(env, params, &entry, &net)?;
    let rpc = resolve_rpc(env, params, &net)?;
    let label = format!("{} Router", if q.provider_label.is_empty() { &q.provider } else { &q.provider_label });
    approval_preview(&account, &net, &rpc, &q.token_in, &q.approval_spender, &label, amount, q.current_allowance.as_ref())
}

/// Legacy `Swap:buildApproval` {Account, Token, Spender, Amount|Unlimited,
/// Decimals?, RPC?} — the spender/amount supplied directly, no quote.
fn build_approval_direct(env: &Env, params: &Value) -> ApiResult {
    let account_id = str_param(params, &["Account", "from"]).ok_or_else(|| swap_err(400, "invalid_request", "quoteId is required"))?;
    let account = crate::models::account::find(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    if account.kind != "ethereum" {
        return Err(ApiError::new(400, "approvals are EVM-only"));
    }
    let token = str_param(params, &["Token"]).ok_or_else(|| ApiError::new(400, "Token (contract) required"))?;
    let spender = str_param(params, &["Spender"]).ok_or_else(|| ApiError::new(400, "Spender required"))?;
    let amount = if params.get("Unlimited").and_then(Value::as_bool).unwrap_or(false) {
        swap::max_uint256()
    } else {
        let s = str_param(params, &["Amount"]).ok_or_else(|| ApiError::new(400, "Amount required (or Unlimited)"))?;
        BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| ApiError::new(400, "bad Amount"))?
    };
    let decimals = params.get("Decimals").and_then(Value::as_i64).unwrap_or(18);
    let net = resolve_network(env, params)?;
    let rpc = resolve_rpc(env, params, &net)?;
    let token = TokenRef { address: token.to_owned(), symbol: String::new(), decimals };
    approval_preview(&account, &net, &rpc, &token, spender, "", amount, None)
}

/// `Swap:availability` {network?} — whether swaps are available on the current
/// (or given) network, and the eligible providers (Go `swapAvailability`).
pub fn availability(env: &Env, params: &Value) -> ApiResult {
    let net = resolve_network(env, params)?;
    Ok(serde_json::to_value(swap::availability(&net.kind, &net.chain_id)).unwrap())
}

/// The account a cached quote executes with: `from` when given (must match the
/// chain), else the account the quote was issued to, else the current one.
fn execute_account(env: &Env, params: &Value, entry: &CachedQuote, net: &Network) -> Result<Account, ApiError> {
    if str_param(params, &["from", "From", "Account"]).is_none() && !entry.account.is_empty() {
        if let Some(a) = crate::models::account::fetch(env, &entry.account).map_err(ApiError::internal)? {
            return Ok(a);
        }
    }
    require_account(resolve_account(env, params, &net.kind)?, &net.kind)
}

/// The `Keys` unlock secrets (Password / StoreKey / Plain shares).
fn unlock_keys(params: &Value) -> Vec<(String, String)> {
    let keys: Vec<crate::sign::KeyDescription> =
        param(params, &["Keys", "keys"]).and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    keys.iter()
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain"))
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect()
}

/// Map an execute failure onto its Go `SwapError` code.
fn execute_error(e: crate::Error) -> ApiError {
    let msg = e.to_string();
    if msg.contains("minReceiveAmount") {
        swap_err(409, "slippage_exceeded", msg)
    } else {
        swap_err(502, "provider_unavailable", msg)
    }
}

/// `Swap:execute` {quoteId, Keys, from?, mevProtection?} — run a cached quote
/// (Go `swapExecute`): fetch the OKX swap tx, check it against the approved
/// quote, sign locally, broadcast through OKX, and confirm settlement. Returns a
/// Dart `SwapResult` {quoteId, provider, chain, hash, url, orderId, quote}. The
/// quote stays cached until expiry so a failed broadcast can be retried.
pub fn execute(env: &Env, params: &Value) -> ApiResult {
    let Some(quote_id) = str_param(params, &["quoteId", "QuoteId"]).filter(|_| param(params, &["TokenIn"]).is_none()) else {
        return execute_direct(env, params);
    };
    let unlock = unlock_keys(params);
    if unlock.is_empty() {
        return Err(swap_err(400, "invalid_request", "Keys are required for execute"));
    }
    let (entry, net) = load_quote(env, quote_id)?;
    let q = entry.quote.clone();
    if !q.status.is_empty() {
        return Err(swap_err(400, "invalid_request", format!("quote is advisory ({}), not executable", q.status)));
    }
    let account = execute_account(env, params, &entry, &net)?;
    let cid = client_id(env);
    let mev = swap::mev_enabled(param(params, &["mevProtection", "MevProtection"]).and_then(Value::as_bool));
    let amount_in = q.amount_in.value().map(|v| v.to_string()).unwrap_or_default();
    let guard = swap::ExecuteGuard::for_quote(&q);

    let res = match net.kind.as_str() {
        "solana" => swap::execute_solana_guarded(
            env, &account.id, &unlock, cid.as_deref(), backend(params), "", &net.chain_id, &q.token_in, &q.token_out,
            &amount_in, q.slippage_bps, mev, &q.quote_id, &guard,
        ),
        "evm" => {
            let rpc = resolve_rpc(env, params, &net)?;
            swap::execute_evm_guarded(
                env, &account.id, &unlock, cid.as_deref(), backend(params), &rpc, &net.chain_id, &q.token_in,
                &q.token_out, &amount_in, q.slippage_bps, mev, &q.quote_id, &guard,
            )
        }
        other => return Err(swap_err(400, "unsupported_chain", format!("swap not supported on {other} networks"))),
    }
    .map_err(execute_error)?;

    let hash = res.get("hash").and_then(Value::as_str).unwrap_or("").to_owned();
    Ok(json!({
        "quoteId": q.quote_id,
        "provider": q.provider,
        "chain": net.kind,
        "hash": hash,
        "url": net.transaction_url(&hash),
        "orderId": res.get("orderId").cloned().unwrap_or(Value::String(String::new())),
        "quote": q,
    }))
}

/// Legacy `Swap:execute` {Account, TokenIn, TokenOut, AmountIn, SlippageBps?,
/// RPC, Keys, MevProtection?, QuoteId?} — quote-less execution with the pair
/// supplied directly (`QuoteId` is then only OKX's correlation id).
fn execute_direct(env: &Env, params: &Value) -> ApiResult {
    let account_id = str_param(params, &["Account"])
        .ok_or_else(|| swap_err(400, "invalid_request", "quoteId is required"))?;
    let net = resolve_network(env, params)?;
    if net.kind != "evm" && net.kind != "solana" {
        return Err(ApiError::new(400, "Swap:execute supports evm and solana"));
    }
    let token_in = token_ref(params, &["TokenIn", "tokenIn"])?;
    let token_out = token_ref(params, &["TokenOut", "tokenOut"])?;
    let amount_in = str_param(params, &["AmountIn", "amountIn"]).ok_or_else(|| ApiError::new(400, "AmountIn required"))?;
    let rpc = str_param(params, &["RPC"]).ok_or_else(|| ApiError::new(400, "RPC required"))?;
    let cid = client_id(env);
    let unlock = unlock_keys(params);
    let mev = swap::mev_enabled(param(params, &["MevProtection", "mevProtection"]).and_then(Value::as_bool));
    let quote_id = str_param(params, &["QuoteId", "quoteId"]).map(str::to_owned).unwrap_or_else(swap::new_quote_id);
    let slip = slippage(params);
    let res = if net.kind == "solana" {
        swap::execute_solana(env, account_id, &unlock, cid.as_deref(), backend(params), rpc, &net.chain_id, &token_in, &token_out, amount_in, slip, mev, &quote_id)
    } else {
        swap::execute_evm(env, account_id, &unlock, cid.as_deref(), backend(params), rpc, &net.chain_id, &token_in, &token_out, amount_in, slip, mev, &quote_id)
    };
    res.map_err(ApiError::internal)
}

/// `Swap:buildApprovalData` — the ERC-20 `approve(spender, amount)` calldata for
/// an EVM swap. `Unlimited` uses uint256 max; otherwise `Amount` is base units.
pub fn build_approval_data(_env: &Env, params: &Value) -> ApiResult {
    let spender = str_param(params, &["spender", "Spender"]).ok_or_else(|| ApiError::new(400, "Spender required"))?;
    let unlimited = param(params, &["unlimited", "Unlimited"]).and_then(Value::as_bool).unwrap_or(false);
    let amount = if unlimited {
        swap::max_uint256()
    } else {
        let s = str_param(params, &["amount", "Amount"]).ok_or_else(|| ApiError::new(400, "Amount required (or Unlimited)"))?;
        BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| ApiError::new(400, "bad Amount"))?
    };
    let data = swap::encode_erc20_approve(spender, &amount).map_err(ApiError::internal)?;
    Ok(json!({
        "data": data,
        "spender": spender,
        "amount": amount.to_string(),
        "isUnlimited": swap::is_unlimited_approval(&amount),
    }))
}

/// `Swap:orderStatus` {orderId, from?, network?} — poll OKX settlement for a
/// broadcast swap (Go `swapOrderStatus`). Swap:execute reports success the
/// instant OKX ACCEPTS the broadcast (before the tx is validated or landed — OKX
/// returns an orderId for a garbage payload too), so a host that needs
/// certainty the swap actually landed polls here until status is no longer
/// "pending". The order is keyed by the signing account's on-chain address.
pub fn order_status(env: &Env, params: &Value) -> ApiResult {
    let order_id = str_param(params, &["orderId", "OrderId"])
        .ok_or_else(|| swap_err(400, "invalid_request", "orderId is required"))?;
    let net = resolve_network(env, params)?;
    let account = require_account(resolve_account(env, params, &net.kind)?, &net.kind)?;
    let chain_index = swap::okx_chain_index(&net.kind, &net.chain_id).map_err(|e| swap_err(400, "unsupported_chain", e))?;

    let cid = client_id(env);
    let entry = swap::okx_fetch_order_status(cid.as_deref(), backend(params), &chain_index, &account.address, order_id)
        .map_err(|e| swap_err(502, "provider_unavailable", format!("okx: orderStatus: {e}")))?;
    let status = swap::okx_tx_status_label(entry.as_ref());
    let mut res = swap::SwapOrderStatus {
        order_id: order_id.to_owned(),
        chain: net.kind.clone(),
        status: status.to_owned(),
        tx_hash: String::new(),
        fail_reason: String::new(),
    };
    if let Some(e) = entry {
        res.tx_hash = e.tx_hash;
        if status == "failed" {
            res.fail_reason = e.fail_reason.trim().to_owned();
        }
    }
    Ok(serde_json::to_value(res).unwrap())
}
