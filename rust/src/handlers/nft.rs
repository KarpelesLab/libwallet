//! Nft object endpoints — Fetch/List only (NFTs are discovered, not created).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::nft::fetch(env, id).map_err(ApiError::internal)? {
                Some(n) => Ok(serde_json::to_value(n).unwrap()),
                None => Err(ApiError::new(404, "nft not found")),
            },
            None => list(env, params),
        },
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Nft"))),
    }
}

/// List NFTs for the requested (or current) account/network. Matches Go
/// `apiListNft`: the response is an object wrapping the NFTs together with the
/// network/account context, so the Dart `NftListing.fromJson` can render the
/// listing without re-fetching. Shape: `{"network":…, "account":…, "nfts":[…]}`.
fn list(env: &Env, params: &Value) -> ApiResult {
    // Network: explicit `Network` id if given, otherwise the current one ("@").
    let net_id = params
        .get("Network")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "network not found"))?;

    // Account: explicit `Account` id if given, otherwise the current one.
    let account = match params.get("Account").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(id) => crate::models::account::fetch(env, id)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(404, "account not found"))?,
        None => {
            let cur = env
                .get_current("account")
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(400, "no current account"))?;
            crate::models::account::fetch(env, &cur)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(404, "current account not found"))?
        }
    };

    // Skip the NFT lookup when the account has no valid address on this network
    // (e.g. an ed25519 wallet on EVM): there is nothing to query. NFT discovery
    // over RPC is not ported; surface whatever has been indexed into the DB.
    let nfts = if account.address == "N/A" {
        Vec::new()
    } else {
        crate::models::nft::list(env).map_err(ApiError::internal)?
    };

    Ok(serde_json::json!({
        "network": net.to_json(),
        "account": serde_json::to_value(&account).unwrap(),
        "nfts": serde_json::to_value(&nfts).unwrap(),
    }))
}
