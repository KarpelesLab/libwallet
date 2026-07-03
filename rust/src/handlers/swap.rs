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

/// `Swap:availability` — whether swaps are available on the current (or given)
/// network, and the eligible providers (Go `swapAvailability`).
pub fn availability(env: &Env, params: &Value) -> ApiResult {
    let net_id = params.get("Network").and_then(Value::as_str).unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "network not found"))?;
    Ok(serde_json::to_value(swap::availability(&net.kind, &net.chain_id)).unwrap())
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
