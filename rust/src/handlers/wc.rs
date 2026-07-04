//! WalletConnect FFI endpoints (wltwc api). The relay connection lives in the
//! Env (persistent across requests); these endpoints drive the [`WcManager`]
//! stored there.

use std::sync::Arc;

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

/// `WalletConnect:start` {RelayUrl} — connect to the relay (ws://) and start the
/// reader thread. Idempotent-ish: errors if already started.
pub fn start(env: &Arc<Env>, params: &Value) -> ApiResult {
    let url = params
        .get("RelayUrl")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "RelayUrl required (ws://…)"))?;
    let transport = crate::walletconnect::connect_ws(url).map_err(ApiError::internal)?;
    env.wc_start(Box::new(transport)).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "started": true }))
}

/// `WalletConnect:stop` — disconnect the relay and stop the reader.
pub fn stop(env: &Env) -> ApiResult {
    env.wc_stop();
    Ok(serde_json::json!({ "stopped": true }))
}

fn manager(env: &Env) -> Result<std::sync::Arc<std::sync::Mutex<crate::wcmanager::WcManager<Box<dyn crate::walletconnect::RelayTransport + Send>>>>, ApiError> {
    env.wc_manager().ok_or_else(|| ApiError::new(400, "walletconnect not started"))
}

/// `WalletConnect:pair` {Uri} — pair with a dApp from its `wc:` URI.
pub fn pair(env: &Env, params: &Value) -> ApiResult {
    let uri = params.get("Uri").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Uri required"))?;
    let mgr = manager(env)?;
    let topic = mgr.lock().unwrap().pair(env, uri).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "pairingTopic": topic }))
}

/// `WalletConnect:approveSession` {PairingTopic, ProposalId, Proposal, Accounts,
/// Methods?, Events?} — settle a pending proposal.
pub fn approve_session(env: &Env, params: &Value) -> ApiResult {
    let pairing = params.get("PairingTopic").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "PairingTopic required"))?;
    let id = params.get("ProposalId").and_then(Value::as_i64).ok_or_else(|| ApiError::new(400, "ProposalId required"))?;
    let proposal = params.get("Proposal").ok_or_else(|| ApiError::new(400, "Proposal required"))?;
    let strs = |k: &str| -> Vec<String> {
        params.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default()
    };
    let mgr = manager(env)?;
    let topic = mgr
        .lock()
        .unwrap()
        .approve(env, pairing, id, proposal, &strs("Accounts"), &strs("Methods"), &strs("Events"))
        .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "sessionTopic": topic }))
}

/// `WalletConnect:respond` {Topic, Id, Result} — publish a JSON-RPC result for a
/// session request.
pub fn respond(env: &Env, params: &Value) -> ApiResult {
    let topic = params.get("Topic").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Topic required"))?;
    let id = params.get("Id").and_then(Value::as_i64).ok_or_else(|| ApiError::new(400, "Id required"))?;
    let result = params.get("Result").cloned().unwrap_or(Value::Null);
    let mgr = manager(env)?;
    mgr.lock().unwrap().respond(env, topic, id, result).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "responded": true }))
}
