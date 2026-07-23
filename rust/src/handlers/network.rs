//! Network object endpoints — full CRUD parity with the Go `wltnet` object
//! (Fetch/List, Create, ApiUpdate, ApiDelete) plus the `testRPC` probe.

use serde_json::Value;

use crate::models::network::Network;
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
        "POST" => {
            let n = network_from_params(params);
            let created = crate::models::network::create(env, n)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            Ok(created.to_json())
        }
        "PATCH" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            let n = crate::models::network::update(env, id, params)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            Ok(n.to_json())
        }
        "DELETE" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            crate::models::network::delete(env, id).map_err(ApiError::internal)?;
            Ok(serde_json::json!({ "deleted": true }))
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Network"))),
    }
}

/// Build a `Network` from the request params (PascalCase keys, matching the Go
/// wire form). `check()` fills anything missing at create time.
fn network_from_params(params: &Value) -> Network {
    let s = |k: &str| params.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    Network {
        id: String::new(),
        kind: s("Type"),
        chain_id: s("ChainId"),
        name: s("Name"),
        rpc: s("RPC"),
        currency_symbol: s("CurrencySymbol"),
        currency_decimals: params.get("CurrencyDecimals").and_then(Value::as_i64).unwrap_or(0),
        block_explorer: s("BlockExplorer"),
        testnet: params.get("TestNet").and_then(Value::as_bool).unwrap_or(false),
        priority: params.get("Priority").and_then(Value::as_i64).unwrap_or(0),
        created: String::new(),
        updated: String::new(),
    }
}

/// `Network:testRPC` {URL, Type} — probe an RPC endpoint and return a
/// structured health snapshot (port of Go `networkTestRPC`). The URL is run
/// through the same SSRF guard used for stored RPCs before it is dialed.
/// Response shape depends on Type:
///   evm     : {RPC, Type, ChainId, Name?, CurrencySymbol?}
///   solana  : {RPC, Type, SolanaVersion, SolanaCluster}
///   bitcoin : {RPC, Type, Chain, Blocks}
#[cfg(not(target_arch = "wasm32"))]
pub fn test_rpc(_env: &Env, params: &Value) -> ApiResult {
    let url = params
        .get("URL")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "invalid url"))?;
    // Gate the caller-supplied URL through the stored-RPC validator so testRPC
    // can't be used as a blind SSRF / port-fingerprinting oracle (Go audit H1).
    crate::models::network::validate_rpc_url(url).map_err(|e| ApiError::new(400, e.to_string()))?;
    // Back-compat: the endpoint used to accept only EVM URLs.
    let typ = params.get("Type").and_then(Value::as_str).unwrap_or("evm");
    match typ {
        "evm" => test_rpc_evm(url),
        "solana" => test_rpc_solana(url),
        "bitcoin" => test_rpc_bitcoin(url),
        other => Err(ApiError::new(
            400,
            format!("unsupported Type {other:?} (want evm | solana | bitcoin)"),
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn test_rpc_evm(url: &str) -> ApiResult {
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

/// genesis-hash (base58) → named Solana cluster; these hashes are immutable
/// per cluster. Anything else reports "unknown" (Go `solanaClusters`).
fn solana_cluster(genesis: &str) -> &'static str {
    match genesis {
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp1T3LwG9BWb8e" => "mainnet-beta",
        "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG" => "devnet",
        "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY" => "testnet",
        _ => "unknown",
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn test_rpc_solana(url: &str) -> ApiResult {
    // getVersion -> {"solana-core": "1.17.x", "feature-set": 12345}
    let ver = crate::rpc::call(url, "getVersion", serde_json::json!([]))
        .map_err(|e| ApiError::new(502, format!("getVersion: {e}")))?;
    let core = ver.get("solana-core").and_then(Value::as_str).unwrap_or("").to_owned();
    // Identify the cluster via the genesis hash (best-effort).
    let cluster = crate::rpc::call(url, "getGenesisHash", serde_json::json!([]))
        .ok()
        .and_then(|g| g.as_str().map(str::to_owned))
        .map(|g| solana_cluster(&g))
        .unwrap_or("unknown");
    Ok(serde_json::json!({
        "RPC": url,
        "Type": "solana",
        "SolanaVersion": core,
        "SolanaCluster": cluster,
    }))
}

#[cfg(not(target_arch = "wasm32"))]
fn test_rpc_bitcoin(url: &str) -> ApiResult {
    // getblockchaininfo works against modchain proxies, native bitcoind, and
    // any fork (litecoind, dogecoind, ...).
    let info = crate::rpc::call(url, "getblockchaininfo", serde_json::json!([]))
        .map_err(|e| ApiError::new(502, format!("getblockchaininfo: {e}")))?;
    let chain = info.get("chain").and_then(Value::as_str).unwrap_or("").to_owned();
    let blocks = info.get("blocks").and_then(Value::as_u64).unwrap_or(0);
    Ok(serde_json::json!({
        "RPC": url,
        "Type": "bitcoin",
        "Chain": chain,
        "Blocks": blocks,
    }))
}

/// `Network:resolveRPC` — the RPC URL to dial for a network {Id}. Resolves the
/// modchain/Helius/explicit cases (Go Network.getRPC); auto EVM selection is not
/// ported and returns an error.
#[cfg(not(target_arch = "wasm32"))]
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
