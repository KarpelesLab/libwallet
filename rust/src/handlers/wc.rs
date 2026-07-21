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

/// `WalletConnect:rejectSession` {PairingTopic, Code?, Message?} — reject a
/// pending proposal.
pub fn reject_session(env: &Env, params: &Value) -> ApiResult {
    let pairing = params.get("PairingTopic").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "PairingTopic required"))?;
    let code = params.get("Code").and_then(Value::as_i64).unwrap_or(0);
    let message = params.get("Message").and_then(Value::as_str).unwrap_or("");
    let mgr = manager(env)?;
    mgr.lock().unwrap().reject(env, pairing, code, message).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "rejected": true }))
}

/// `WalletConnect:respondError` {Topic, Id, Code?, Message?} — publish a JSON-RPC
/// error for a session request.
pub fn respond_error(env: &Env, params: &Value) -> ApiResult {
    // Match Go's `wcRespondError` (wltwc/api.go): all fields are deserialized
    // case-insensitively and NONE is validated in the handler. The topic is
    // checked first by the manager (RespondSessionError -> session lookup),
    // which yields "unknown topic" for an inactive session. So the Id must not
    // be rejected before the topic is looked up — Go defaults a missing ID to 0.
    // (The Dart client sends the key as "ID", not "Id".)
    let topic = params.get("Topic").and_then(Value::as_str)
        .or_else(|| params.get("topic").and_then(Value::as_str))
        .unwrap_or("");
    let id = params.get("ID").or_else(|| params.get("Id")).or_else(|| params.get("id"))
        .and_then(Value::as_i64).unwrap_or(0);
    let code = params.get("Code").and_then(Value::as_i64).unwrap_or(0);
    let message = params.get("Message").and_then(Value::as_str).unwrap_or("");
    let mgr = manager(env)?;
    mgr.lock().unwrap().respond_error(env, topic, id, code, message).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "responded": true }))
}

/// `WalletConnect:emitEvent` {Topic, Name, Data?, ChainID?} — push a
/// `wc_sessionEvent` (chainChanged / accountsChanged).
pub fn emit_event(env: &Env, params: &Value) -> ApiResult {
    let topic = params.get("Topic").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Topic required"))?;
    let name = params.get("Name").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Name required"))?;
    let data = params.get("Data").cloned().unwrap_or(Value::Null);
    let chain = params.get("ChainID").and_then(Value::as_str).unwrap_or("");
    let mgr = manager(env)?;
    mgr.lock().unwrap().emit_event(env, topic, name, data, chain).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "emitted": true }))
}

/// `WalletConnect:disconnect` {Topic} — tear down a session (sends
/// `wc_sessionDelete` and marks it disconnected locally).
pub fn disconnect(env: &Env, params: &Value) -> ApiResult {
    let topic = params.get("Topic").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Topic required"))?;
    let mgr = manager(env)?;
    mgr.lock().unwrap().disconnect(env, topic).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "disconnected": true }))
}
