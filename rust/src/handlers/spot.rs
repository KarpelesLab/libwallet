//! Spot-network endpoints: `Spot:status` + the device-transfer flow
//! (`Wallet:exportToDevice[/Confirm/Cancel]`, `Wallet:importFromDevice`),
//! ported from wltbase/spot_status.go + wltwallet/transfer.go. Runs over the
//! live Spot relay via the Env's spotlib client.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

/// `Spot:status` — start the client if needed and report its connection state.
pub fn status(env: &Arc<Env>) -> ApiResult {
    let c = env.spot_start().map_err(ApiError::internal)?;
    let (total, online) = c.connection_count();
    Ok(json!({
        "online": online > 0,
        "target_id": c.target_id(),
        "connections": { "total": total, "online": online },
    }))
}

/// `Wallet:exportToDevice` {WalletId} — mint a pairing session for transferring
/// the wallet to another device; returns the pairing URL. Requires Spot online.
pub fn export_to_device(env: &Arc<Env>, id: &str, params: &Value) -> ApiResult {
    let wallet_id = params
        .get("WalletId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(id);
    if wallet_id.is_empty() {
        return Err(ApiError::new(400, "WalletId required"));
    }
    let wallet = crate::models::wallet::fetch(env, wallet_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "wallet not found"))?;
    if wallet.keys.is_empty() {
        return Err(ApiError::new(400, "wallet has no keys"));
    }
    let client = env.spot_start().map_err(ApiError::internal)?;
    wait_online(&client)?;

    use base64::Engine;
    let mut token = vec![0u8; crate::transfer::TOKEN_BYTES];
    let mut sid_bytes = [0u8; 16];
    {
        use purecrypto::rng::RngCore;
        purecrypto::rng::OsRng.fill_bytes(&mut token);
        purecrypto::rng::OsRng.fill_bytes(&mut sid_bytes);
    }
    let sid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sid_bytes);
    let token_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token);

    env.transfer_register(&sid, token, wallet_id);
    let pairing = crate::transfer::build_pairing_url(&client.target_id(), &token_b64, &sid);
    Ok(json!({ "sid": sid, "pairingCode": pairing }))
}

/// `Wallet:exportToDevice:confirm` {Sid, DeviceShares} — release the wallet to
/// the waiting peer query with the host-supplied StoreKey device shares.
pub fn export_confirm(env: &Env, params: &Value) -> ApiResult {
    let sid = params.get("Sid").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Sid required"))?;
    let shares = params.get("DeviceShares").cloned().unwrap_or_else(|| json!([]));
    if !env.transfer_resolve(sid, Some(shares)) {
        return Err(ApiError::new(404, "transfer session not found"));
    }
    Ok(json!({ "confirmed": true }))
}

/// `Wallet:exportToDevice:cancel` {Sid} — decline/abort a pending transfer.
pub fn export_cancel(env: &Env, params: &Value) -> ApiResult {
    let sid = params.get("Sid").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Sid required"))?;
    env.transfer_resolve(sid, None);
    Ok(json!({ "cancelled": true }))
}

/// `Wallet:importFromDevice` {PairingCode} — pull a wallet from the source
/// device: query it over Spot, decrypt the sealed payload, and restore the
/// wallet. Returns the restored wallet id + device shares for the host to store.
pub fn import_from_device(env: &Arc<Env>, params: &Value) -> ApiResult {
    let pairing = params.get("PairingCode").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "PairingCode required"))?;
    let (spot_id, token_b64, sid) = crate::transfer::parse_pairing_url(pairing).map_err(|e| ApiError::new(400, e.to_string()))?;
    use base64::Engine;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&token_b64).map_err(|_| ApiError::new(400, "bad token"))?;

    let client = env.spot_start().map_err(ApiError::internal)?;
    wait_online(&client)?;

    let body = json!({
        "v": crate::transfer::PROTOCOL_VERSION,
        "sid": sid,
        "token": token_b64,
        "newSpotID": client.target_id(),
    });
    let buf = serde_json::to_vec(&body).unwrap();
    // Single path segment after the id — spotlib dispatches on the first segment.
    let target = format!("{spot_id}/transfer");
    let resp = client
        .query(&target, &buf, Duration::from_secs(120))
        .map_err(|e| ApiError::new(400, format!("transfer query: {e}")))?;

    let plaintext = crate::transfer::open(&token, &sid, &resp).map_err(|e| ApiError::new(400, e.to_string()))?;
    let payload: Value = serde_json::from_slice(&plaintext).map_err(|e| ApiError::new(400, format!("decode payload: {e}")))?;
    if payload.get("v").and_then(Value::as_i64) != Some(crate::transfer::PROTOCOL_VERSION) {
        return Err(ApiError::new(400, "bad transfer payload version"));
    }
    let wallet_json = payload.get("wallet").ok_or_else(|| ApiError::new(400, "payload missing wallet"))?;
    let device_shares = payload.get("device_shares").cloned().unwrap_or_else(|| json!([]));

    // Restore via the standard restore path (re-encode the wallet JSON to the
    // base64url the backup/restore shape uses).
    let data_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(wallet_json).unwrap());
    let wallet_id = crate::models::wallet::restore_entry(env, &data_b64).map_err(|e| ApiError::new(400, e.to_string()))?;

    Ok(json!({ "wallet_id": wallet_id, "device_shares": device_shares }))
}

/// `Wallet:buildNewAgentBody` {name, agent_spot_id, policy} — compose the body
/// the host POSTs to `Crypto/WalletSign:newAgent`, filling in this device's
/// Spot id. Purely local (Go `apiBuildNewAgentBody`).
pub fn build_new_agent_body(env: &Arc<Env>, params: &Value) -> ApiResult {
    let name = params.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "name is required"))?;
    let agent_spot_id = params.get("agent_spot_id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "agent_spot_id is required"))?;
    // Policy shape is opaque to libwallet; require its presence and pass through.
    let policy = params.get("policy").filter(|v| !v.is_null()).ok_or_else(|| ApiError::new(400, "policy is required"))?.clone();

    let client = env.spot_start().map_err(ApiError::internal)?;
    let mobile_spot_id = client.target_id();
    if mobile_spot_id.is_empty() {
        return Err(ApiError::new(503, "spot client is not online yet — retry shortly"));
    }
    Ok(json!({
        "name": name,
        "agent_spot_id": agent_spot_id,
        "mobile_spot_id": mobile_spot_id,
        "policy": policy,
    }))
}

/// `ClawdWallet:pair` {url} — verify a `tibane://pair?agent&token` link against
/// the agent over Spot (Go `apiClawdWalletPair`). One Query round-trip; the
/// agent's response is dispatched to a verified identity or a typed error code.
pub fn clawd_pair(env: &Arc<Env>, params: &Value) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let (agent_spot_id, token) = crate::clawdpair::parse_clawd_pair_url(url).map_err(|c| ApiError::new(400, c))?;

    let client = env.spot_start().map_err(|e| ApiError::new(400, format!("agent_unreachable: spot client unavailable: {e}")))?;
    // No WaitOnline: the 15s query budget already fails fast if the relay is
    // unreachable, and pairing UX is "tap link, see result".
    let mobile_spot_id = client.target_id();

    let body = serde_json::to_vec(&json!({
        "v": crate::clawdpair::PAIR_PROTOCOL_VERSION,
        "token": token,
        "mobile_spot_id": mobile_spot_id,
    }))
    .unwrap();
    let target = format!("{agent_spot_id}/pair");
    let resp = client
        .query(&target, &body, Duration::from_secs(15))
        .map_err(|e| ApiError::new(400, format!("agent_unreachable: {e}")))?;

    crate::clawdpair::dispatch_pair_response(&resp, &agent_spot_id).map_err(|c| ApiError::new(400, c))
}

/// Wait briefly for at least one online Spot connection (Go `waitOnlineSpot`).
fn wait_online(client: &spotlib::Client) -> Result<(), ApiError> {
    for _ in 0..60 {
        if client.connection_count().1 > 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(ApiError::new(503, "spot client is not online"))
}
