//! `Airgap:*` endpoints — QR-payload interop with external signers. Strings
//! in, strings out; the host owns the camera and the screen.
//!
//! Scanning (any animated QR, frames in any order):
//!   `Airgap:decoderNew` → {Id}; `Airgap:decoderFeed` {Id, Part} → Progress
//!   (…, complete, payload); `Airgap:decoderStatus` {Id}; `Airgap:decoderDelete`.
//!   `Airgap:decode` {Parts:[…]} does it in one call when all frames are in hand.
//! Displaying: `Airgap:encode` {Type|FileType, Cbor|Bytes, Transport, …} → {parts}.
//! Keys: `Airgap:parseKeys` (preview) / `Airgap:importKeys` {Payload|Parts|
//!   DecoderId, Name?, EthAccounts?, Select?} → signer wallet + accounts.
//! Signing: `Airgap:signRequest` {Account, Transaction, Transport?, RPC|Network?,
//!   Offline?} → {requestId, parts, payload}; `Airgap:submitSignature`
//!   {Payload|Parts|DecoderId, RequestId?, Broadcast?, RPC|Network?} → signed tx.
//!   `Airgap:pending` {RequestId} shows an outstanding request.

use serde_json::{json, Value};

use crate::airgap::{self, decoder, import, registry, Transport};
use crate::Env;

use super::{ApiError, ApiResult};

fn bad(e: crate::Error) -> ApiError {
    ApiError::new(400, e.to_string())
}

fn str_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn usize_param(params: &Value, key: &str) -> Option<usize> {
    params.get(key).and_then(Value::as_u64).map(|n| n as usize)
}

fn progress_json(p: &decoder::Progress) -> Value {
    serde_json::to_value(p).unwrap_or(Value::Null)
}

// ── Decoder contexts ─────────────────────────────────────────────────────────

pub fn decoder_new(env: &Env, _params: &Value) -> ApiResult {
    let id = decoder::store_new(env).map_err(ApiError::internal)?;
    Ok(json!({ "Id": id }))
}

pub fn decoder_feed(env: &Env, params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id (decoder context) required"))?;
    let part = str_param(params, "Part").ok_or_else(|| ApiError::new(400, "Part (scanned frame) required"))?;
    let mut ctx = decoder::store_load(env, id).map_err(|e| ApiError::new(404, e.to_string()))?;
    let prog = ctx.feed(part).map_err(bad)?;
    decoder::store_save(env, id, &ctx).map_err(ApiError::internal)?;
    let mut j = progress_json(&prog);
    j["Id"] = Value::String(id.to_owned());
    Ok(j)
}

pub fn decoder_status(env: &Env, params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id (decoder context) required"))?;
    let ctx = decoder::store_load(env, id).map_err(|e| ApiError::new(404, e.to_string()))?;
    let mut j = progress_json(&ctx.progress().map_err(bad)?);
    j["Id"] = Value::String(id.to_owned());
    Ok(j)
}

pub fn decoder_delete(env: &Env, params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id (decoder context) required"))?;
    decoder::store_delete(env, id).map_err(ApiError::internal)?;
    Ok(json!({ "Id": id, "deleted": true }))
}

/// One-shot: all frames at once.
pub fn decode(env: &Env, params: &Value) -> ApiResult {
    let frames = frames_from_params(params)?;
    let _ = env;
    let (prog, _) = decoder::decode_all(&frames).map_err(bad)?;
    Ok(progress_json(&prog))
}

fn frames_from_params(params: &Value) -> Result<Vec<String>, ApiError> {
    if let Some(arr) = params.get("Parts").and_then(Value::as_array) {
        let frames: Vec<String> = arr.iter().filter_map(Value::as_str).map(str::to_owned).collect();
        if frames.is_empty() {
            return Err(ApiError::new(400, "Parts is empty"));
        }
        return Ok(frames);
    }
    if let Some(p) = str_param(params, "Payload") {
        // A pasted multi-line payload (e.g. several xpubs) is one raw frame;
        // several UR/BBQr frames may also be newline-separated.
        let lines: Vec<String> = p.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect();
        if lines.len() > 1 && lines.iter().all(|l| decoder::classify(l) != decoder::Kind::Raw) {
            return Ok(lines);
        }
        return Ok(vec![p.to_owned()]);
    }
    Err(ApiError::new(400, "Payload, Parts or DecoderId required"))
}

/// The complete payload named by `DecoderId`, `Parts` or `Payload`.
fn payload_from_params(env: &Env, params: &Value) -> Result<decoder::Payload, ApiError> {
    if let Some(id) = str_param(params, "DecoderId") {
        let ctx = decoder::store_load(env, id).map_err(|e| ApiError::new(404, e.to_string()))?;
        return ctx.payload().map_err(bad)?.ok_or_else(|| ApiError::new(400, "decoder context is not complete yet"));
    }
    let frames = frames_from_params(params)?;
    let (prog, payload) = decoder::decode_all(&frames).map_err(bad)?;
    payload.ok_or_else(|| ApiError::new(400, format!("payload incomplete: {}/{} frames", prog.received, prog.expected)))
}

// ── Encoding ─────────────────────────────────────────────────────────────────

/// Generic framing for hosts that build their own payloads: a UR `Type` with
/// `Cbor` (hex) — or `Bytes` (base64) for the `bytes` type — or a BBQr
/// `FileType` letter with `Bytes`. `Transport` selects ur (default) or bbqr.
pub fn encode(_env: &Env, params: &Value) -> ApiResult {
    use base64::Engine;
    let transport = Transport::parse(str_param(params, "Transport").unwrap_or("")).map_err(bad)?;
    let bytes = match str_param(params, "Bytes") {
        Some(b) => Some(base64::engine::general_purpose::STANDARD.decode(b).map_err(|e| ApiError::new(400, format!("Bytes: {e}")))?),
        None => None,
    };
    match transport {
        Transport::Ur => {
            let ur_type = str_param(params, "Type").unwrap_or(registry::UR_BYTES);
            let cbor = match (str_param(params, "Cbor"), &bytes) {
                (Some(h), _) => airgap::unhex(h).map_err(bad)?,
                (None, Some(b)) => outscript::bcur::bytes_to_cbor(b),
                (None, None) => return Err(ApiError::new(400, "Cbor (hex) or Bytes (base64) required")),
            };
            let parts = airgap::ur_parts(ur_type, &cbor, usize_param(params, "MaxFragmentLen"), usize_param(params, "ExtraParts")).map_err(bad)?;
            Ok(json!({ "transport": "ur", "type": ur_type, "parts": parts, "count": parts.len() }))
        }
        Transport::Bbqr => {
            let b = bytes.ok_or_else(|| ApiError::new(400, "Bytes (base64) required for bbqr"))?;
            let ft = str_param(params, "FileType").and_then(|s| s.chars().next()).and_then(outscript::bbqr::FileType::from_char).unwrap_or(outscript::bbqr::FileType::BINARY);
            let compress = params.get("Compress").and_then(Value::as_bool).unwrap_or(true);
            let parts = airgap::bbqr_parts(&b, ft, usize_param(params, "MaxPartLen"), compress).map_err(bad)?;
            Ok(json!({ "transport": "bbqr", "fileType": ft.as_char().to_string(), "parts": parts, "count": parts.len() }))
        }
    }
}

// ── Keys ─────────────────────────────────────────────────────────────────────

pub fn parse_keys(env: &Env, params: &Value) -> ApiResult {
    let payload = payload_from_params(env, params)?;
    let export = import::parse(env, &payload).map_err(bad)?;
    Ok(serde_json::to_value(export).unwrap())
}

pub fn import_keys(env: &Env, params: &Value) -> ApiResult {
    let payload = payload_from_params(env, params)?;
    let export = import::parse(env, &payload).map_err(bad)?;
    let opts = import::ImportOptions {
        name: str_param(params, "Name").map(str::to_owned),
        eth_accounts: params.get("EthAccounts").and_then(Value::as_u64).map(|n| n as u32),
        select_paths: params.get("Select").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
    };
    let imported = import::import(env, &export, &opts).map_err(bad)?;
    env.broadcast(&crate::response::event("wallet:created", json!({ "id": imported.wallet.id, "protocol": "airgap", "imported": true })));
    let mut j = serde_json::to_value(&imported).unwrap();
    j["export"] = json!({ "format": export.format, "device": export.device, "masterFingerprint": export.master_fingerprint });
    Ok(j)
}

// ── Signing (native: needs the blocking RPC client) ──────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn framing_from_params(params: &Value) -> Result<airgap::sign::Framing, ApiError> {
    Ok(airgap::sign::Framing {
        transport: Transport::parse(str_param(params, "Transport").unwrap_or("")).map_err(bad)?,
        max_fragment_len: usize_param(params, "MaxFragmentLen"),
        max_part_len: usize_param(params, "MaxPartLen"),
        extra_parts: usize_param(params, "ExtraParts"),
    })
}

/// The node to use: `RPC` > `Network` (id or `type.chainId`) > the current /
/// default network for the account's chain — unless `Offline: true`, in which
/// case none (the Transaction must then be complete).
#[cfg(not(target_arch = "wasm32"))]
fn rpc_from_params(env: &Env, params: &Value, account_kind: &str) -> Result<Option<String>, ApiError> {
    if params.get("Offline").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    if let Some(url) = str_param(params, "RPC") {
        return Ok(Some(url.to_owned()));
    }
    if let Some(net_id) = str_param(params, "Network") {
        let net = crate::models::network::fetch(env, net_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, format!("network {net_id} not found")))?;
        return Ok(Some(net.resolved_rpc().map_err(ApiError::internal)?));
    }
    let want = match account_kind {
        "ethereum" => "evm",
        other => other,
    };
    Ok(super::resolve_rpc_for_kind(env, params, want).ok())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn sign_request(env: &Env, params: &Value) -> ApiResult {
    let account_id = str_param(params, "Account").or_else(|| str_param(params, "Id")).ok_or_else(|| ApiError::new(400, "Account required"))?;
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;
    let account = crate::models::account::fetch(env, account_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "account not found"))?;
    let rpc = rpc_from_params(env, params, &account.kind)?;
    let framing = framing_from_params(params)?;
    let built = airgap::sign::build_request(env, account_id, tx, &framing, rpc.as_deref()).map_err(bad)?;
    let mut j = serde_json::to_value(&built).unwrap();
    j["count"] = json!(built.parts.len());
    Ok(j)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn submit_signature(env: &Env, params: &Value) -> ApiResult {
    let payload = payload_from_params(env, params)?;
    let request_id = str_param(params, "RequestId");
    let accepted = airgap::sign::accept(env, &payload, request_id).map_err(bad)?;
    let mut j = serde_json::to_value(&accepted).unwrap();
    if params.get("Broadcast").and_then(Value::as_bool) == Some(true) {
        let url = rpc_from_params(env, params, &accepted.chain)?.ok_or_else(|| ApiError::new(400, "Broadcast needs an RPC/Network (not Offline)"))?;
        let res = airgap::sign::broadcast(&url, &accepted).map_err(|e| ApiError::new(502, e.to_string()))?;
        j["broadcast"] = res;
    }
    if let Some(id) = str_param(params, "DecoderId") {
        let _ = decoder::store_delete(env, id);
    }
    Ok(j)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn pending(env: &Env, params: &Value) -> ApiResult {
    let rid = str_param(params, "RequestId").ok_or_else(|| ApiError::new(400, "RequestId required"))?;
    match airgap::sign::pending_load(env, rid).map_err(ApiError::internal)? {
        Some(p) => Ok(serde_json::to_value(p).unwrap()),
        None => Err(ApiError::new(404, "no such pending request (expired?)")),
    }
}
