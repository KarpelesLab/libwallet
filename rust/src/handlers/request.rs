//! `Request:*` — the user-approval queue (port of wltbase/request.go). `run`
//! persists a pending request, broadcasts a `request` host event, and blocks
//! until `Request:approve`/`Request:reject` resolves it (2-minute timeout).
//!
//! The `test` request type is fully wired here. `connect` / `transaction_sign`
//! / `message_sign` / `chain_switch` approvals (driven by Web3:request) layer
//! their side effects on top and land with that endpoint.

use std::time::Duration;

use serde_json::{json, Value};

use crate::models::request::{self, Request};
use crate::Env;

use super::{ApiError, ApiResult};

/// Run a request through the approval flow: persist as pending, broadcast the
/// `request` host event, and block on the waiter. Returns the resolved request
/// (accepted) or an ApiError (rejected 4001 / timed out 4001). Runs on the FFI
/// worker thread, so blocking here is fine.
pub fn run(env: &Env, mut req: Request) -> Result<Request, ApiError> {
    if req.id.is_empty() {
        req.id = xuid::Xuid::new("req").to_string();
    }
    req.status = "pending".into();
    let now = crate::now_rfc3339();
    if req.created.is_empty() {
        req.created = now.clone();
    }
    req.updated = now;
    request::save(env, &req).map_err(ApiError::internal)?;

    let rx = env.request_register(&req.id);
    // Emit the full request so the host can render the prompt immediately.
    env.broadcast(&crate::response::event(
        "request",
        json!({ "request_id": req.id, "request": req }),
    ));

    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(status) => {
            // Reload the authoritative row (approve may have set Result etc.).
            let reloaded = request::fetch(env, &req.id).ok().flatten();
            let mut out = reloaded.unwrap_or(req);
            out.status = status;
            Ok(out)
        }
        Err(_) => {
            env.request_take(&req.id);
            if let Ok(Some(mut r)) = request::fetch(env, &req.id) {
                r.status = "timedout".into();
                r.updated = crate::now_rfc3339();
                let _ = request::save(env, &r);
            }
            Err(ApiError::new(4001, "Request timed out."))
        }
    }
}

/// `Request:test` — a self-contained approval round-trip (Go requestTestReq).
pub fn test(env: &Env) -> ApiResult {
    let req = Request { kind: "test".into(), host: "www.example.com".into(), ..Default::default() };
    let out = run(env, req)?;
    Ok(serde_json::to_value(out).unwrap())
}

/// `Request:approve` {Id, ...} — approve a pending request. The `test` type has
/// no side effects; other types (connect/sign/chain_switch) are handled by the
/// Web3 endpoint's approval path (not yet ported) and error here for now.
pub fn approve(env: &Env, params: &Value) -> ApiResult {
    let id = params.get("Id").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Id (request) required"))?;
    let req = claim(env, id)?;
    match req.kind.as_str() {
        "test" => {}
        "connect" => {
            if let Err(e) = approve_connect(env, &req, params) {
                release(env, id);
                return Err(e);
            }
        }
        "message_sign" => {
            if let Err(e) = approve_message_sign(env, &req, params) {
                release(env, id);
                return Err(e);
            }
        }
        "transaction_sign" => {
            if let Err(e) = approve_transaction_sign(env, &req, params) {
                release(env, id);
                return Err(e);
            }
        }
        "chain_switch" => {
            if let Err(e) = approve_chain_switch(env, &req, params) {
                release(env, id);
                return Err(e);
            }
        }
        "add_network" => {
            if let Err(e) = approve_add_network(env, &req) {
                release(env, id);
                return Err(e);
            }
        }
        other => {
            release(env, id);
            return Err(ApiError::new(501, format!("approval of request type {other} not yet ported")));
        }
    }
    respond(env, id, "accepted")?;
    let out = request::fetch(env, id).map_err(ApiError::internal)?.unwrap_or(req);
    Ok(serde_json::to_value(out).unwrap())
}

/// `Request:reject` {Id} — reject a pending request.
pub fn reject(env: &Env, params: &Value) -> ApiResult {
    let id = params.get("Id").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Id (request) required"))?;
    let req = claim(env, id)?;
    respond(env, id, "rejected")?;
    let out = request::fetch(env, id).map_err(ApiError::internal)?.unwrap_or(req);
    Ok(serde_json::to_value(out).unwrap())
}

/// Persist the approved `connect` accounts for the request's host and emit a
/// `js:accountsChanged` host event (Go `requestDoApprove` connect arm).
fn approve_connect(env: &Env, req: &Request, params: &Value) -> Result<(), ApiError> {
    let accounts: Vec<String> = params
        .get("Accounts")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    if accounts.is_empty() {
        return Err(ApiError::new(400, "no accounts in approve connect (empty means rejected)"));
    }
    let mut newly = false;
    for acct_id in &accounts {
        // Resolve by id or address, then link the canonical account id.
        let acct = crate::models::account::find(env, acct_id)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(404, format!("account {acct_id} not found")))?;
        let before = crate::models::connected_site::for_host(env, &req.host).map_err(ApiError::internal)?;
        if !before.iter().any(|c| c.account == acct.id) {
            newly = true;
        }
        crate::models::connected_site::connect(env, &req.host, &acct.id).map_err(ApiError::internal)?;
    }
    if newly {
        let conn = crate::models::connected_site::for_host(env, &req.host).map_err(ApiError::internal)?;
        let addrs: Vec<String> = conn
            .iter()
            .filter_map(|c| crate::models::account::fetch(env, &c.account).ok().flatten())
            .map(|a| a.address)
            .collect();
        env.broadcast(&crate::response::event("js:accountsChanged", json!({ "accounts": addrs })));
    }
    Ok(())
}

/// Persist the approved `add_network` proposal (Go: web3 caller does net.Save
/// after approval). The Network fields ride in the request Value.
fn approve_add_network(env: &Env, req: &Request) -> Result<(), ApiError> {
    let net_json = req
        .value
        .as_ref()
        .and_then(|v| v.get("network"))
        .ok_or_else(|| ApiError::new(400, "add_network: missing network in Value"))?;
    let g = |k: &str| net_json.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let network = crate::models::network::Network {
        id: g("Id"),
        kind: g("Type"),
        chain_id: g("ChainId"),
        name: g("Name"),
        rpc: g("RPC"),
        currency_symbol: g("CurrencySymbol"),
        currency_decimals: net_json.get("CurrencyDecimals").and_then(Value::as_i64).unwrap_or(18),
        block_explorer: g("BlockExplorer"),
        ..Default::default()
    };
    crate::models::network::save(env, &network).map_err(ApiError::internal)
}

/// Apply an approved `chain_switch`: set the current network to the target
/// (Go `applyChainSwitchSelection`, EVM→EVM minimal form — the account address
/// is chain-independent so no re-derivation is needed). The host may override
/// the target via the `Network` param; otherwise the request's target is used.
fn approve_chain_switch(env: &Env, req: &Request, params: &Value) -> Result<(), ApiError> {
    let target = params
        .get("Network")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| req.value.as_ref().and_then(|v| v.get("targetNetwork")).and_then(Value::as_str).map(str::to_owned))
        .ok_or_else(|| ApiError::new(400, "chain_switch: no target network"))?;
    env.set_current("network", &target).map_err(ApiError::internal)?;
    // Record the applied selection on the request for the host.
    if let Ok(Some(mut r)) = request::fetch(env, &req.id) {
        r.result = Some(json!({ "network": target }));
        r.updated = crate::now_rfc3339();
        request::save(env, &r).map_err(ApiError::internal)?;
    }
    Ok(())
}

/// Build, sign, and broadcast the pending `transaction_sign` request and store
/// the tx hash + Transaction in the request Result (Go `approveTransactionSign`).
/// EVM only — reuses transaction::sign_and_send. The host provides Keys (and,
/// for now, the RPC endpoint) in the approve params.
fn approve_transaction_sign(env: &Env, req: &Request, params: &Value) -> Result<(), ApiError> {
    let method = req.value.as_ref().and_then(|v| v.get("method")).and_then(Value::as_str).unwrap_or("eth_sendTransaction");
    let (result, tx_record): (Value, Option<Value>) = match method {
        "eth_sendTransaction" => {
            let tx = req.transaction.clone().ok_or_else(|| ApiError::new(400, "transaction_sign: missing Transaction"))?;
            let mut sas_params = json!({ "Transaction": tx });
            if let Some(keys) = params.get("Keys") {
                sas_params["Keys"] = keys.clone();
            }
            if let Some(rpc) = params.get("RPC") {
                sas_params["RPC"] = rpc.clone();
            }
            let signed = super::transaction::sign_and_send(env, &sas_params)?;
            (signed.get("hash").cloned().unwrap_or(Value::Null), Some(signed))
        }
        "solana_signTransaction" => (approve_solana_sign_tx(env, req, params, false)?, None),
        "solana_signAndSendTransaction" => (approve_solana_sign_tx(env, req, params, true)?, None),
        "mpurse_signRawTransaction" => (approve_mpurse_sign_raw_tx(env, req, params)?, None),
        other => return Err(ApiError::new(501, format!("transaction_sign method {other} not yet ported"))),
    };

    if let Ok(Some(mut r)) = request::fetch(env, &req.id) {
        r.result = Some(result);
        if let Some(t) = tx_record {
            r.transaction = Some(t);
        }
        r.updated = crate::now_rfc3339();
        request::save(env, &r).map_err(ApiError::internal)?;
    }
    Ok(())
}

/// Sign a dApp-provided raw Bitcoin transaction (Go `approveMpurseSignRawTx`):
/// resolve the account + current network's RPC, then sign every input under the
/// account's derived keys (bitcoin::sign_raw_tx). Returns the signed tx hex.
fn approve_mpurse_sign_raw_tx(env: &Env, req: &Request, params: &Value) -> Result<Value, ApiError> {
    let account_id = req.account.as_deref().ok_or_else(|| ApiError::new(400, "bitcoin sign: missing account"))?;
    let raw_hex = req.value.as_ref().and_then(|v| v.get("raw")).and_then(Value::as_str).unwrap_or("");
    let raw = decode_hex(raw_hex).ok_or_else(|| ApiError::new(400, "mpurse_signRawTransaction: bad tx hex"))?;

    let keys: Vec<crate::sign::KeyDescription> = params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    let unlock: Vec<(String, String)> = keys.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey")).map(|k| (k.id.clone(), k.key.clone())).collect();
    if unlock.is_empty() {
        return Err(ApiError::new(400, "transaction_sign approval requires Keys"));
    }
    let net = crate::models::network::fetch(env, "@").map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(400, "no current network"))?;
    if net.kind != "bitcoin" {
        return Err(ApiError::new(400, "mpurse_signRawTransaction: current network is not bitcoin"));
    }
    let rpc = match params.get("RPC").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => net.resolved_rpc().map_err(|e| ApiError::new(400, e.to_string()))?,
    };
    let signed = crate::bitcoin::sign_raw_tx(env, account_id, &unlock, &rpc, &net.chain_id, &raw)
        .map_err(|e| ApiError::new(400, e.to_string()))?;
    Ok(Value::String(signed.iter().map(|b| format!("{b:02x}")).collect()))
}

/// Decode a plain (non-0x) or 0x-prefixed hex string.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// FROST-sign a dApp-provided Solana transaction (Go `approveSolanaSignTx`):
/// extract the message, sign it, splice into the signature slot. When
/// `broadcast`, also `sendTransaction` and return {signature}; otherwise return
/// {transaction: base64(signed)}.
fn approve_solana_sign_tx(env: &Env, req: &Request, params: &Value, broadcast: bool) -> Result<Value, ApiError> {
    use base64::Engine;
    let account_id = req.account.as_deref().ok_or_else(|| ApiError::new(400, "solana sign: missing account"))?;
    let account = crate::models::account::find(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let raw_b64 = req.value.as_ref().and_then(|v| v.get("raw")).and_then(Value::as_str).unwrap_or("");
    let raw = base64::engine::general_purpose::STANDARD.decode(raw_b64).map_err(|e| ApiError::new(400, format!("decode transaction: {e}")))?;

    let keys: Vec<crate::sign::KeyDescription> = params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    let unlock: Vec<(String, String)> = keys.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey")).map(|k| (k.id.clone(), k.key.clone())).collect();
    if unlock.is_empty() {
        return Err(ApiError::new(400, "transaction_sign approval requires Keys"));
    }

    let message = crate::solana::tx_message(&raw).ok_or_else(|| ApiError::new(400, "solana tx: no message"))?.to_vec();
    let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &message).map_err(|e| ApiError::new(400, e.to_string()))?;
    let sig64: [u8; 64] = sig.try_into().map_err(|_| ApiError::new(500, "unexpected signature length"))?;
    let signed = crate::solana::splice_signature(&raw, &sig64).ok_or_else(|| ApiError::new(500, "failed to splice signature"))?;

    if !broadcast {
        return Ok(json!({ "transaction": base64::engine::general_purpose::STANDARD.encode(&signed) }));
    }
    let rpc = match params.get("RPC").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => {
            let net = crate::models::network::fetch(env, "@").map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(400, "no current network"))?;
            net.resolved_rpc().map_err(|e| ApiError::new(400, e.to_string()))?
        }
    };
    let signed_b64 = base64::engine::general_purpose::STANDARD.encode(&signed);
    let res = crate::rpc::call(&rpc, "sendTransaction", json!([signed_b64, { "encoding": "base64" }])).map_err(ApiError::internal)?;
    Ok(json!({ "signature": res.as_str().unwrap_or_default() }))
}

/// Sign the pending `message_sign` request with the host-supplied Keys and
/// store the 0x-hex signature in the request Result (Go `approveMessageSign`).
/// Only `personal_sign` (EVM) is wired; typed-data / solana / mpurse follow.
fn approve_message_sign(env: &Env, req: &Request, params: &Value) -> Result<(), ApiError> {
    use base64::Engine;
    let value = req.value.as_ref().ok_or_else(|| ApiError::new(400, "message_sign: missing Value"))?;
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    let account_id = req.account.as_deref().ok_or_else(|| ApiError::new(400, "message_sign: missing account"))?;

    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let unlock: Vec<(String, String)> = keys
        .iter()
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey"))
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();
    if unlock.is_empty() {
        return Err(ApiError::new(400, "message_sign approval requires Keys"));
    }

    let msg_b64 = value.get("messageBytes").and_then(Value::as_str).unwrap_or("");
    let message = base64::engine::general_purpose::STANDARD
        .decode(msg_b64)
        .map_err(|e| ApiError::new(400, format!("decode message bytes: {e}")))?;

    let result: Value = match method {
        "personal_sign" => {
            let sig = crate::evm::personal_sign(env, account_id, &unlock, &message)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            Value::String(format!("0x{}", sig.iter().map(|b| format!("{b:02x}")).collect::<String>()))
        }
        "solana_signMessage" => {
            let account = crate::models::account::find(env, account_id)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(404, "account not found"))?;
            let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &message)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            json!({ "signature": bs58::encode(&sig).into_string(), "publicKey": account.address })
        }
        "eth_signTypedData" | "eth_signTypedData_v3" | "eth_signTypedData_v4" => {
            let td_str = value.get("typedData").and_then(Value::as_str).unwrap_or("");
            let td = crate::eip712::parse(td_str).map_err(|e| ApiError::new(400, e))?;
            let digest = td.hash().map_err(|e| ApiError::new(400, e))?;
            let sig = crate::evm::sign_eth_digest(env, account_id, &unlock, &digest)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            Value::String(format!("0x{}", sig.iter().map(|b| format!("{b:02x}")).collect::<String>()))
        }
        "mpurse_signMessage" => {
            let chain_id = value.get("chainId").and_then(Value::as_str).unwrap_or("");
            let sig = crate::bitcoin::sign_message(env, account_id, &unlock, chain_id, &message)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            Value::String(base64::engine::general_purpose::STANDARD.encode(&sig))
        }
        other => return Err(ApiError::new(501, format!("message_sign method {other} not yet ported"))),
    };

    // Persist the result into the request row so `run` returns it.
    if let Ok(Some(mut r)) = request::fetch(env, &req.id) {
        r.result = Some(result);
        r.updated = crate::now_rfc3339();
        request::save(env, &r).map_err(ApiError::internal)?;
    }
    Ok(())
}

/// Atomically move a still-pending request into `processing` so approve/reject
/// side effects run at most once (Go `request.claim`). Requires the in-memory
/// waiter to still exist (a timed-out request whose waiter gave up is rejected).
fn claim(env: &Env, id: &str) -> Result<Request, ApiError> {
    if !env.request_pending(id) {
        return Err(ApiError::new(400, "request is no longer awaiting a response"));
    }
    let mut req = request::fetch(env, id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "request not found"))?;
    if req.status != "pending" {
        return Err(ApiError::new(400, format!("request is not pending (status {:?})", req.status)));
    }
    req.status = "processing".into();
    req.updated = crate::now_rfc3339();
    request::save(env, &req).map_err(ApiError::internal)?;
    Ok(req)
}

/// Persist the terminal status and deliver it to the waiter (Go `respond`).
fn respond(env: &Env, id: &str, status: &str) -> Result<(), ApiError> {
    if let Ok(Some(mut r)) = request::fetch(env, id) {
        r.status = status.into();
        r.updated = crate::now_rfc3339();
        let _ = request::save(env, &r);
    }
    if !env.request_resolve(id, status) {
        return Err(ApiError::new(400, "request is no longer awaiting a response"));
    }
    Ok(())
}

/// Roll a claimed-but-unfinished request back to pending (Go `releaseClaim`).
fn release(env: &Env, id: &str) {
    if let Ok(Some(mut r)) = request::fetch(env, id) {
        if r.status == "processing" {
            r.status = "pending".into();
            let _ = request::save(env, &r);
        }
    }
}

/// `Request` object routing: GET/<id> fetch, GET list.
pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match request::fetch(env, id).map_err(ApiError::internal)? {
                Some(r) => Ok(serde_json::to_value(r).unwrap()),
                None => Err(ApiError::new(404, "request not found")),
            },
            None => Ok(serde_json::to_value(request::list(env).map_err(ApiError::internal)?).unwrap()),
        },
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Request"))),
    }
}
