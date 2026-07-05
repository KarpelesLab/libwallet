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
