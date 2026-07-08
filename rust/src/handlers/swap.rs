//! Swap endpoints (wltswap). `Swap:quote` returns an OKX DEX quote for a token
//! pair. The OKX proxy is authenticated, so the caller supplies the platform
//! API credential (KeyId + Secret); Backend overrides the REST host for tests.

use serde_json::Value;

use crate::rest::ApiKey;
use crate::swap::{self, TokenRef};
use crate::Env;

use super::{ApiError, ApiResult};

fn token_ref(v: Option<&Value>) -> Result<TokenRef, ApiError> {
    let v = v.ok_or_else(|| ApiError::new(400, "token reference required"))?;
    serde_json::from_value(v.clone()).map_err(|e| ApiError::new(400, format!("bad token ref: {e}")))
}

pub fn quote(env: &Env, params: &Value) -> ApiResult {
    // Resolve the network (current, or the Network param) for kind + chain id.
    let net_id = params.get("Network").and_then(Value::as_str).unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "network not found"))?;

    let token_in = token_ref(params.get("TokenIn"))?;
    let token_out = token_ref(params.get("TokenOut"))?;
    let amount_in = params
        .get("AmountIn")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "AmountIn required"))?;
    let slippage = params.get("SlippageBps").and_then(Value::as_u64).unwrap_or(0) as u16;

    // Platform credential for the authenticated OKX proxy.
    let key_id = params
        .get("KeyId")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "KeyId required (platform API key)"))?;
    let secret = params
        .get("Secret")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Secret required (platform API secret)"))?;
    let key = ApiKey::from_secret_b64(key_id, secret).map_err(ApiError::internal)?;
    let base = params.get("Backend").and_then(Value::as_str).unwrap_or(crate::rest::DEFAULT_HOST);

    let q = swap::get_quote(&key, base, &net.kind, &net.chain_id, token_in, token_out, amount_in, slippage)
        .map_err(ApiError::internal)?;
    Ok(serde_json::to_value(q).unwrap())
}

/// `Swap:countryAvailability` — whether swaps are offered in a country (Go
/// `swapCountryAvailability`).
pub fn country_availability(_env: &Env, params: &Value) -> ApiResult {
    let country = params
        .get("Country")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Country required"))?;
    Ok(serde_json::to_value(swap::country_availability(country)).unwrap())
}

/// `Swap:buildApproval` — a ready-to-sign ERC-20 approval transaction: the
/// approve calldata plus a fetched nonce / gas / gasPrice, so the host can pass
/// it straight to Account:signAndSendTransaction (Go swapBuildApproval, minus
/// the quote-cache lookup — the spender/amount are supplied directly).
pub fn build_approval(env: &Env, params: &Value) -> ApiResult {
    use num_bigint::BigInt;
    let account_id = params.get("Account").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Account required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    if account.kind != "ethereum" {
        return Err(ApiError::new(400, "approvals are EVM-only"));
    }
    let token = params.get("Token").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Token (contract) required"))?;
    let spender = params.get("Spender").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Spender required"))?;
    let rpc = params.get("RPC").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "RPC required"))?;
    let unlimited = params.get("Unlimited").and_then(Value::as_bool).unwrap_or(false);
    let amount = if unlimited {
        swap::max_uint256()
    } else {
        let s = params.get("Amount").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Amount required (or Unlimited)"))?;
        BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| ApiError::new(400, "bad Amount"))?
    };
    let data = swap::encode_erc20_approve(spender, &amount).map_err(ApiError::internal)?;

    // nonce + gasPrice + gas (estimate, or a safe default for approve()).
    let nonce_hex = crate::rpc::call(rpc, "eth_getTransactionCount", serde_json::json!([account.address, "pending"]))
        .map_err(ApiError::internal)?;
    let nonce_hex = nonce_hex.as_str().unwrap_or("0x0");
    let nonce = u64::from_str_radix(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex), 16).unwrap_or(0);
    let gp = crate::rpc::call(rpc, "eth_gasPrice", serde_json::json!([])).map_err(ApiError::internal)?;
    let gp = gp.as_str().unwrap_or("0x0").to_owned();
    let gas: u64 = crate::rpc::call(rpc, "eth_estimateGas", serde_json::json!([{ "from": account.address, "to": token, "data": data }]))
        .ok()
        .and_then(|v| v.as_str().map(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).unwrap_or(0)))
        .filter(|g| *g > 0)
        .unwrap_or(60_000);

    Ok(serde_json::json!({
        "tx": {
            "type": "evm",
            "from": account.address,
            "to": token,
            "value": "0",
            "data": data,
            "nonce": nonce,
            "gas": gas,
            "gasPrice": BigInt::parse_bytes(gp.strip_prefix("0x").unwrap_or(&gp).as_bytes(), 16).unwrap_or_else(|| BigInt::from(0)).to_string(),
        },
        "spender": spender,
        "amount": amount.to_string(),
        "isUnlimited": swap::is_unlimited_approval(&amount),
    }))
}

/// `Swap:availability` — whether swaps are available on the current (or given)
/// network, and the eligible providers (Go `swapAvailability`).
pub fn availability(env: &Env, params: &Value) -> ApiResult {
    let net_id = params.get("Network").and_then(Value::as_str).unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "network not found"))?;
    Ok(serde_json::to_value(swap::availability(&net.kind, &net.chain_id)).unwrap())
}

/// `Swap:execute` — fetch the OKX swap transaction, sign it locally, and
/// broadcast it (EVM). The caller supplies the OKX credential + node RPC and
/// the wallet's Keys (Password unlock).
pub fn execute(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Account")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Account required"))?;
    let net_id = params.get("Network").and_then(Value::as_str).unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "network not found"))?;
    if net.kind != "evm" && net.kind != "solana" {
        return Err(ApiError::new(400, "Swap:execute supports evm and solana"));
    }
    let token_in = token_ref(params.get("TokenIn"))?;
    let token_out = token_ref(params.get("TokenOut"))?;
    let amount_in = params
        .get("AmountIn")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "AmountIn required"))?;
    let slippage = params.get("SlippageBps").and_then(Value::as_u64).unwrap_or(0) as u16;
    let rpc = params.get("RPC").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "RPC required"))?;

    let key_id = params.get("KeyId").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "KeyId required"))?;
    let secret = params.get("Secret").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Secret required"))?;
    let key = ApiKey::from_secret_b64(key_id, secret).map_err(ApiError::internal)?;
    let base = params.get("Backend").and_then(Value::as_str).unwrap_or(crate::rest::DEFAULT_HOST);

    let keys: Vec<crate::sign::KeyDescription> =
        params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    let unlock: Vec<(String, String)> =
        keys.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain")).map(|k| (k.id.clone(), k.key.clone())).collect();

    let res = if net.kind == "solana" {
        swap::execute_solana(env, account_id, &unlock, &key, base, rpc, &net.chain_id, &token_in, &token_out, amount_in, slippage)
    } else {
        swap::execute_evm(env, account_id, &unlock, &key, base, rpc, &net.chain_id, &token_in, &token_out, amount_in, slippage)
    };
    res.map_err(ApiError::internal)
}

/// `Swap:maxSpendable` — quote the maximum the account can swap (Go
/// `swapMaxSpendable`): compute the max native amountIn (balance minus the fee
/// reserve) and quote it. EVM native-in only for now; a zero max returns an
/// advisory instead of a quote.
pub fn max_spendable(env: &Env, params: &Value) -> ApiResult {
    use num_bigint::BigInt;
    let account_id = params.get("Account").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Account required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let net_id = params.get("Network").and_then(Value::as_str).unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "network not found"))?;
    if net.kind != "evm" {
        return Err(ApiError::new(400, "Swap:maxSpendable is EVM-only here"));
    }
    let token_in = token_ref(params.get("TokenIn"))?;
    let token_out = token_ref(params.get("TokenOut"))?;
    let slippage = params.get("SlippageBps").and_then(Value::as_u64).unwrap_or(0) as u16;
    let rpc = params.get("RPC").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "RPC required"))?;

    // Max native amountIn = balance − (21000 × gasPrice).
    let bal_dec = crate::rpc::eth_get_balance(rpc, &account.address).map_err(ApiError::internal)?;
    let balance = BigInt::parse_bytes(bal_dec.as_bytes(), 10).unwrap_or_else(|| BigInt::from(0));
    let gp = crate::rpc::call(rpc, "eth_gasPrice", serde_json::json!([])).map_err(ApiError::internal)?;
    let gp = gp.as_str().unwrap_or("0x0");
    let gas_price = BigInt::parse_bytes(gp.strip_prefix("0x").unwrap_or(gp).as_bytes(), 16).unwrap_or_else(|| BigInt::from(0));
    let fee = BigInt::from(21000) * gas_price;
    let max = if balance <= fee { BigInt::from(0) } else { balance - fee };
    if max <= BigInt::from(0) {
        return Ok(serde_json::json!({
            "status": "balance_too_small",
            "message": "balance does not cover network fee",
            "amountIn": "0",
        }));
    }

    let key_id = params.get("KeyId").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "KeyId required"))?;
    let secret = params.get("Secret").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Secret required"))?;
    let key = ApiKey::from_secret_b64(key_id, secret).map_err(ApiError::internal)?;
    let base = params.get("Backend").and_then(Value::as_str).unwrap_or(crate::rest::DEFAULT_HOST);

    let q = swap::get_quote(&key, base, &net.kind, &net.chain_id, token_in, token_out, &max.to_string(), slippage)
        .map_err(ApiError::internal)?;
    Ok(serde_json::to_value(q).unwrap())
}

/// `Swap:quotes` — the multi-provider fan-out form of Swap:quote (Go
/// `swapQuotes`). One routed provider per chain today, so `attempts` has a
/// single entry carrying either the quote or a structured error.
pub fn quotes(env: &Env, params: &Value) -> ApiResult {
    let net_id = params.get("Network").and_then(Value::as_str).unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "network not found"))?;
    let provider = match net.kind.as_str() {
        "solana" => "okx_solana",
        "evm" => "okx_evm",
        other => return Err(ApiError::new(400, format!("swap not supported on {other}"))),
    };

    let token_in = token_ref(params.get("TokenIn"))?;
    let token_out = token_ref(params.get("TokenOut"))?;
    let amount_in = params.get("AmountIn").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "AmountIn required"))?;
    let slippage = params.get("SlippageBps").and_then(Value::as_u64).unwrap_or(0) as u16;
    let key_id = params.get("KeyId").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "KeyId required"))?;
    let secret = params.get("Secret").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Secret required"))?;
    let key = ApiKey::from_secret_b64(key_id, secret).map_err(ApiError::internal)?;
    let base = params.get("Backend").and_then(Value::as_str).unwrap_or(crate::rest::DEFAULT_HOST);

    // A quote failure becomes an attempt-level error, not an endpoint failure.
    let attempt = match swap::get_quote(&key, base, &net.kind, &net.chain_id, token_in, token_out, amount_in, slippage) {
        Ok(q) => serde_json::json!({ "provider": provider, "providerLabel": "OKX", "quote": q }),
        Err(e) => serde_json::json!({
            "provider": provider,
            "providerLabel": "OKX",
            "error": { "code": "provider_unavailable", "message": e.to_string() },
        }),
    };
    Ok(serde_json::json!({ "attempts": [attempt] }))
}

/// `Swap:buildApprovalData` — the ERC-20 `approve(spender, amount)` calldata for
/// an EVM swap. `Unlimited` uses uint256 max; otherwise `Amount` is base units.
/// The host wraps this in a Transaction for signAndSend (the stateful
/// quote-cached buildApproval endpoint is the execute-pass concern).
pub fn build_approval_data(_env: &Env, params: &Value) -> ApiResult {
    use num_bigint::BigInt;
    let spender = params
        .get("Spender")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Spender required"))?;
    let unlimited = params.get("Unlimited").and_then(Value::as_bool).unwrap_or(false);
    let amount = if unlimited {
        swap::max_uint256()
    } else {
        let s = params
            .get("Amount")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::new(400, "Amount required (or Unlimited)"))?;
        BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| ApiError::new(400, "bad Amount"))?
    };
    let data = swap::encode_erc20_approve(spender, &amount).map_err(ApiError::internal)?;
    Ok(serde_json::json!({
        "data": data,
        "spender": spender,
        "amount": amount.to_string(),
        "isUnlimited": swap::is_unlimited_approval(&amount),
    }))
}
