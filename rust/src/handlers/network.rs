//! Network object endpoints — read surface (fetch/list). Creation runs check()
//! + RPC probing and is deferred, so POST returns 501.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::network::fetch(env, id).map_err(ApiError::internal)? {
                Some(n) => Ok(n.to_json()),
                None => Err(ApiError::new(404, "network not found")),
            },
            None => {
                let list = crate::models::network::list(env).map_err(ApiError::internal)?;
                Ok(Value::Array(list.iter().map(|n| n.to_json()).collect()))
            }
        },
        "POST" => Err(ApiError::new(501, "network creation (check + RPC) not yet ported")),
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Network"))),
    }
}

/// `Network:testRPC` — probe an RPC endpoint. EVM: net_version + chain registry
/// metadata. (Solana/Bitcoin probes follow the same shape.)
pub fn test_rpc(_env: &Env, params: &Value) -> ApiResult {
    let url = params
        .get("URL")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "URL required"))?;
    let typ = params.get("Type").and_then(Value::as_str).unwrap_or("evm");
    match typ {
        "evm" => {
            let idv = crate::rpc::call(url, "net_version", serde_json::json!([])).map_err(ApiError::internal)?;
            let id: u64 = idv
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| ApiError::new(502, "bad net_version response"))?;
            let mut res = serde_json::json!({ "RPC": url, "Type": "evm", "ChainId": id });
            if let Some(info) = ethrpc_rs::chains::get(id) {
                res["Name"] = serde_json::json!(info.name);
                if let Some(nc) = &info.native_currency {
                    res["CurrencySymbol"] = serde_json::json!(nc.symbol);
                }
            }
            Ok(res)
        }
        other => Err(ApiError::new(400, format!("testRPC type {other} not yet ported"))),
    }
}

/// `Network:resolveRPC` — the RPC URL to dial for a network {Id}. Resolves the
/// modchain/Helius/explicit cases (Go Network.getRPC); auto EVM selection is not
/// ported and returns an error.
pub fn resolve_rpc(env: &Env, params: &Value) -> ApiResult {
    let id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id required"))?;
    let net = crate::models::network::fetch(env, id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "network not found"))?;
    let rpc = net.resolved_rpc().map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "rpc": rpc, "type": net.kind, "chainId": net.chain_id }))
}

/// `Network:setCurrent` — mark a network as the active one.
pub fn set_current(env: &Env, params: &Value) -> ApiResult {
    let id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id required"))?;
    env.set_current("network", id).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "network": id }))
}
