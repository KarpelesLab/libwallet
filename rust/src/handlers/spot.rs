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

/// `Wallet:reshare` {Old, New} — rotate a wallet's TSS shares to a new
/// committee. When the old committee includes a RemoteKey, the wdrone fleet
/// co-reshares over the live walletsign transport (Go `apiWalletReshare` →
/// `Wallet.ReshareFrost`). ed25519/FROST only for now. Returns the updated
/// wallet.
pub fn wallet_reshare(env: &Arc<Env>, id: &str, params: &Value) -> ApiResult {
    let wallet_id = params
        .get("WalletId")
        .or_else(|| params.get("Id"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(id);
    if wallet_id.is_empty() {
        return Err(ApiError::new(400, "wallet id required"));
    }
    let old: Vec<crate::sign::KeyDescription> =
        params.get("Old").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
    let new: Vec<crate::sign::KeyDescription> =
        params.get("New").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
    if old.is_empty() || new.is_empty() {
        return Err(ApiError::new(400, "Old and New key lists are required"));
    }
    // Dispatch on the wallet's curve: ed25519→FROST, secp256k1→DKLs23.
    let w0 = crate::models::wallet::fetch(env, wallet_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "wallet not found"))?;
    let res = match w0.curve.as_str() {
        "ed25519" => crate::reshare::reshare_frost(env, wallet_id, &old, &new),
        "secp256k1" => crate::reshare::reshare_dkls(env, wallet_id, &old, &new),
        other => return Err(ApiError::new(400, format!("reshare unsupported for curve {other}"))),
    };
    res.map_err(|e| ApiError::new(500, e.to_string()))?;
    let w = crate::models::wallet::fetch(env, wallet_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "wallet not found"))?;
    Ok(serde_json::to_value(w).unwrap())
}

/// `Wallet:promote` {Old, New, Threshold} — convert a 1-of-1 imported wallet
/// into an N-of-T secp256k1 DKLs committee (Go `apiWalletPromote`). Local
/// reshare; new RemoteKey shares upload to the wdrone.
pub fn wallet_promote(env: &Arc<Env>, id: &str, params: &Value) -> ApiResult {
    let wallet_id = params.get("WalletId").or_else(|| params.get("Id")).and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(id);
    if wallet_id.is_empty() {
        return Err(ApiError::new(400, "wallet id required"));
    }
    // `Old` carries the import's unlock material (Password/StoreKey/Plain).
    let old: Vec<crate::sign::KeyDescription> = params.get("Old").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
    let new: Vec<crate::sign::KeyDescription> = params.get("New").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
    if new.is_empty() {
        return Err(ApiError::new(400, "New key list is required"));
    }
    let threshold = params.get("Threshold").and_then(Value::as_i64).unwrap_or(1);
    let unlock: Vec<(String, String)> = old.iter().map(|k| (k.id.clone(), k.key.clone())).collect();
    let w = crate::models::wallet::promote(env, wallet_id, &unlock, &new, threshold).map_err(|e| ApiError::new(500, e.to_string()))?;
    Ok(serde_json::to_value(w).unwrap())
}

/// `Wallet:initiateKeygen` {remote_key, peers, name, curve, me_moniker} — the
/// leader-side ClawdWallet Stage-1 keygen (Go `apiInitiateKeygen`). Builds the
/// committee, sends the InitPayload to each peer, runs the mobile's FROST keygen
/// party, and uploads its share to the wdrone. ed25519 only.
pub fn initiate_keygen(env: &Arc<Env>, params: &Value) -> ApiResult {
    let remote_key = params.get("remote_key").and_then(Value::as_str).unwrap_or("");
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let curve = params.get("curve").and_then(Value::as_str).unwrap_or("");
    let me_moniker = params.get("me_moniker").and_then(Value::as_str).unwrap_or("");
    let peers: Vec<crate::reshare::JoinPeer> = params
        .get("peers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|p| crate::reshare::JoinPeer {
                    spot_id: p.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                    moniker: p.get("moniker").and_then(Value::as_str).unwrap_or("").to_string(),
                    key: p.get("key").and_then(Value::as_str).unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    if peers.is_empty() {
        return Err(ApiError::new(400, "peers is required"));
    }
    let (wlt_id, solana_address, pubkey) =
        crate::reshare::initiate_keygen(env, remote_key, &peers, name, curve, me_moniker).map_err(|e| ApiError::new(500, e.to_string()))?;
    Ok(json!({ "wlt_id": wlt_id, "solana_address": solana_address, "pubkey": pubkey }))
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
