//! Browser (wasm32) twins of the two spot ceremony handlers that must `.await`
//! the async Spot transport: `Wallet:initiateKeygen` and `Wallet:joinSign`. The
//! native `mod spot` is native-only (blocking threads + the sync Spot client),
//! so these small async twins live here and route through
//! [`crate::reshare_wasm`]. Param parsing + response shapes match the native
//! handlers in `handlers::spot` byte-for-byte.

use serde_json::{json, Value};

use crate::reshare_common::JoinPeer;
use crate::Env;

use super::{ApiError, ApiResult};

/// `Spot:status` (wasm) — start the Spot client if needed and report its
/// connection state. Sync (spot_start/connection_count/target_id are all sync on
/// wasm); mirrors [`crate::handlers::spot::status`]. Lets the browser confirm the
/// spotlib client actually comes online before running a ceremony.
pub fn status(env: &Env) -> ApiResult {
    let c = env.spot_start().map_err(ApiError::internal)?;
    let (total, online) = c.connection_count();
    Ok(json!({
        "online": online > 0,
        "target_id": c.target_id(),
        "connections": { "total": total, "online": online },
    }))
}

/// Parse the `peers` array into [`JoinPeer`]s (shared by both handlers).
fn parse_peers(params: &Value) -> Vec<JoinPeer> {
    params
        .get("peers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|p| JoinPeer {
                    spot_id: p.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                    moniker: p.get("moniker").and_then(Value::as_str).unwrap_or("").to_string(),
                    key: p.get("key").and_then(Value::as_str).unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `Wallet:initiateKeygen` (wasm) — see [`crate::handlers::spot::initiate_keygen`].
pub async fn initiate_keygen_async(env: &Env, params: &Value) -> ApiResult {
    let remote_key = params.get("remote_key").and_then(Value::as_str).unwrap_or("");
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let curve = params.get("curve").and_then(Value::as_str).unwrap_or("");
    let me_moniker = params.get("me_moniker").and_then(Value::as_str).unwrap_or("");
    let peers = parse_peers(params);
    if peers.is_empty() {
        return Err(ApiError::new(400, "peers is required"));
    }
    let (wlt_id, solana_address, pubkey) =
        crate::reshare_wasm::initiate_keygen(env, remote_key, &peers, name, curve, me_moniker)
            .await
            .map_err(|e| ApiError::new(500, e.to_string()))?;
    Ok(json!({ "wlt_id": wlt_id, "solana_address": solana_address, "pubkey": pubkey }))
}

/// `Wallet:joinSign` (wasm) — see [`crate::handlers::spot::join_sign`].
pub async fn join_sign_async(env: &Env, params: &Value) -> ApiResult {
    use base64::Engine;
    let wlt_id = params.get("wlt_id").and_then(Value::as_str).unwrap_or("");
    let remote_key = params.get("remote_key").and_then(Value::as_str).unwrap_or("");
    let curve = params.get("curve").and_then(Value::as_str).unwrap_or("");
    let digest_s = params.get("digest").and_then(Value::as_str).unwrap_or("");
    if wlt_id.is_empty() {
        return Err(ApiError::new(400, "wlt_id is required"));
    }
    let digest = base64::engine::general_purpose::STANDARD
        .decode(digest_s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(digest_s))
        .map_err(|_| ApiError::new(400, "invalid base64 digest"))?;
    let peers = parse_peers(params);
    if peers.is_empty() {
        return Err(ApiError::new(400, "peers is required"));
    }
    let sig = crate::reshare_wasm::join_sign(env, wlt_id, remote_key, &peers, curve, &digest)
        .await
        .map_err(|e| ApiError::new(500, e.to_string()))?;
    Ok(json!({ "signature": base64::engine::general_purpose::STANDARD.encode(sig) }))
}
