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

/// How long a request waits for the user before it times out.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Once an approve/reject has claimed a request, how much longer `run` keeps
/// waiting for it to finish (signing + broadcast) before giving up — without
/// declaring a timeout it can no longer vouch for.
const PROCESSING_GRACE: Duration = Duration::from_secs(600);
/// Re-check interval while waiting on a claimed request.
const PROCESSING_POLL: Duration = Duration::from_secs(1);

/// Run a request through the approval flow: persist as pending, broadcast the
/// `request` host event, and block on the waiter. Returns the resolved request
/// (accepted) or an ApiError (rejected 4001 / timed out 4001). Runs on the FFI
/// worker thread, so blocking here is fine.
pub fn run(env: &Env, req: Request) -> Result<Request, ApiError> {
    run_with_timeout(env, req, APPROVAL_TIMEOUT)
}

/// [`run`] for a caller acting on a dApp's behalf: only an approval is a
/// success. A rejection (or any other terminal status) is the EIP-1193 "user
/// rejected" error, so a dApp is never told that a connect / chain switch /
/// signature it was refused went through.
pub fn run_approved(env: &Env, req: Request) -> Result<Request, ApiError> {
    let out = run(env, req)?;
    if out.status != "accepted" {
        return Err(ApiError::new(4001, "User rejected the request."));
    }
    Ok(out)
}

fn run_with_timeout(env: &Env, mut req: Request, timeout: Duration) -> Result<Request, ApiError> {
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

    let mut wait = timeout;
    let mut grace_left = PROCESSING_GRACE;
    loop {
        match rx.recv_timeout(wait) {
            Ok(status) => {
                // Reload the authoritative row (approve may have set Result etc.).
                let reloaded = request::fetch(env, &req.id).ok().flatten();
                let mut out = reloaded.unwrap_or(req);
                out.status = status;
                return Ok(out);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Time the request out ONLY if it is still pending — the same
                // guarded transition `claim` uses, so exactly one of "timed
                // out" and "claimed by an approve/reject" can happen.
                match request::transition(env, &req.id, "pending", "timedout") {
                    Ok(false) => {}
                    // Timed out (or the DB is failing: give up as before).
                    _ => {
                        env.request_take(&req.id);
                        return Err(ApiError::new(4001, "Request timed out."));
                    }
                }
                // Not pending: an approve/reject claimed it and is mid-flight
                // (possibly signing + broadcasting), or its outcome is about to
                // be delivered. Reporting "timed out" now would tell the dApp
                // nothing happened while the transaction still goes out, so keep
                // the waiter registered and wait for the real outcome.
                let status = request::fetch(env, &req.id).ok().flatten().map(|r| r.status);
                match status.as_deref() {
                    // A row that is momentarily unreadable (None) is treated like
                    // one still being processed.
                    Some("processing") | Some("accepted") | Some("rejected") | None if !grace_left.is_zero() => {
                        grace_left = grace_left.saturating_sub(PROCESSING_POLL);
                        wait = PROCESSING_POLL;
                    }
                    Some("processing") | Some("accepted") | Some("rejected") | None => {
                        // Still unresolved after the grace period: stop waiting,
                        // but do not touch the row or claim a clean timeout.
                        env.request_take(&req.id);
                        return Err(ApiError::new(
                            500,
                            "Request approval did not complete in time; its outcome is unknown.",
                        ));
                    }
                    _ => {
                        env.request_take(&req.id);
                        return Err(ApiError::new(4001, "Request timed out."));
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // The waiter was dropped (replaced / cleared): nobody can resolve
                // this request any more.
                env.request_take(&req.id);
                let _ = request::transition(env, &req.id, "pending", "timedout");
                return Err(ApiError::new(4001, "Request timed out."));
            }
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
        // wallet_watchAsset — approval is a pure acknowledgement (Go
        // `requestDoApprove` watch_asset arm); the dApp is told the asset was
        // added to the watch list. No side effect beyond resolving the request.
        "watch_asset" => {}
        other => {
            release(env, id);
            return Err(ApiError::new(400, format!("unknown request type {other}")));
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
    let currency_decimals = match net_json.get("CurrencyDecimals").filter(|d| !d.is_null()) {
        None => 18,
        Some(d) => d
            .as_i64()
            .filter(|d| (0..=36).contains(d))
            .ok_or_else(|| ApiError::new(400, "add_network: CurrencyDecimals must be an integer 0-36"))?,
    };
    // The row is keyed by the deterministic id for its type + chain id, like
    // every other stored network. (The proposal's own `evm.<chainId>` id is the
    // ephemeral-reference form: a row stored under it is never read back.)
    let network = crate::models::network::Network {
        id: crate::models::network::network_id_for("evm", &g("ChainId")),
        kind: g("Type"),
        chain_id: g("ChainId"),
        name: g("Name"),
        rpc: g("RPC"),
        currency_symbol: g("CurrencySymbol"),
        currency_decimals,
        block_explorer: g("BlockExplorer"),
        ..Default::default()
    };
    // `network::save` is the raw row writer and validates nothing, so the
    // proposal is re-checked here, at the moment it becomes a stored network:
    // whatever is in the request row, only an EVM network with a u64 chain id
    // and an RPC endpoint that passes the RPC-URL gate ("" / "auto" excepted)
    // is persisted.
    if network.kind != "evm" {
        return Err(ApiError::new(400, "add_network: only EVM networks can be added"));
    }
    if !network.chain_id.parse::<u64>().is_ok_and(|c| c > 0) {
        return Err(ApiError::new(400, "add_network: invalid chain id"));
    }
    crate::models::network::validate_network_rpc(&network.rpc)
        .map_err(|e| ApiError::new(400, format!("add_network: {e}")))?;
    // A dApp may add a chain, never replace one the wallet already has.
    if crate::models::network::by_id_opt(env, &network.id) {
        return Err(ApiError::new(400, "add_network: this chain is already registered"));
    }
    crate::models::network::save(env, &network).map_err(ApiError::internal)
}

/// The network id a `chain_switch` to `target` selects. A `evm.<chainId>`
/// reference is ephemeral — it resolves from the chain registry alone — so when
/// a stored row exists for that chain (seeded, user-created, or added through
/// `wallet_addEthereumChain`) its id is selected instead and the row's RPC and
/// metadata apply.
fn stored_network_target(env: &Env, target: &str) -> String {
    if let Some(chain) = target.strip_prefix("evm.") {
        let id = crate::models::network::network_id_for("evm", chain);
        if crate::models::network::by_id_opt(env, &id) {
            return id;
        }
    }
    target.to_owned()
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
    let target = stored_network_target(env, &target);
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
        other => return Err(ApiError::new(400, format!("unknown transaction_sign method {other}"))),
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
    let unlock: Vec<(String, String)> = keys.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain")).map(|k| (k.id.clone(), k.key.clone())).collect();
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
    // Hex digits only: besides rejecting junk (`from_str_radix` alone would
    // accept a sign, e.g. "+f"), this guarantees the input is ASCII, so the
    // two-byte slices below can never split a multi-byte UTF-8 character (which
    // panics) — the string comes straight from a web page.
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
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

    let keys: Vec<crate::sign::KeyDescription> = params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    let unlock: Vec<(String, String)> = keys.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain")).map(|k| (k.id.clone(), k.key.clone())).collect();
    if unlock.is_empty() {
        return Err(ApiError::new(400, "transaction_sign approval requires Keys"));
    }

    let (signed, _) = super::account::sign_solana_serialized(env, &account, &unlock, raw_b64)?;

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
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain"))
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
            let sig = crate::models::wallet::sign_ed25519_for_account(env, &account, &unlock, &message)
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
        other => return Err(ApiError::new(400, format!("unknown message_sign method {other}"))),
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
///
/// The claim itself is a single guarded `pending → processing` UPDATE, so of any
/// number of concurrent approve/reject calls (and the `run` timeout, which uses
/// the same guard) exactly one wins.
fn claim(env: &Env, id: &str) -> Result<Request, ApiError> {
    if !env.request_pending(id) {
        return Err(ApiError::new(400, "request is no longer awaiting a response"));
    }
    if !request::transition(env, id, "pending", "processing").map_err(ApiError::internal)? {
        return Err(match request::fetch(env, id).map_err(ApiError::internal)? {
            Some(r) => ApiError::new(400, format!("request is not pending (status {:?})", r.status)),
            None => ApiError::new(404, "request not found"),
        });
    }
    request::fetch(env, id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "request not found"))
}

/// Persist the terminal status and deliver it to the waiter (Go `respond`).
fn respond(env: &Env, id: &str, status: &str) -> Result<(), ApiError> {
    // Only the claimer gets here, so the row is `processing`.
    let _ = request::transition(env, id, "processing", status);
    if !env.request_resolve(id, status) {
        return Err(ApiError::new(400, "request is no longer awaiting a response"));
    }
    Ok(())
}

/// Roll a claimed-but-unfinished request back to pending (Go `releaseClaim`).
fn release(env: &Env, id: &str) {
    let _ = request::transition(env, id, "processing", "pending");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn env() -> Arc<Env> {
        let env = Env::init_memory().unwrap();
        request::init(&env).unwrap();
        Arc::new(env)
    }

    /// Persist a pending request with a registered waiter, as `run` does.
    fn pending(env: &Env, id: &str) -> std::sync::mpsc::Receiver<String> {
        let req = Request { id: id.into(), kind: "test".into(), status: "pending".into(), ..Default::default() };
        request::save(env, &req).unwrap();
        env.request_register(id)
    }

    fn status(env: &Env, id: &str) -> String {
        request::fetch(env, id).unwrap().unwrap().status
    }

    /// Audit F5: of many concurrent approve/reject calls exactly one may claim
    /// the request (and so run its sign-and-broadcast side effect).
    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        for round in 0..20 {
            let env = env();
            let id = format!("req-race-{round}");
            let _rx = pending(&env, &id);
            let start = Arc::new(std::sync::Barrier::new(8));
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let (env, id, start) = (env.clone(), id.clone(), start.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        claim(&env, &id).is_ok()
                    })
                })
                .collect();
            let winners = handles.into_iter().map(|h| h.join().unwrap()).filter(|won| *won).count();
            assert_eq!(winners, 1, "round {round}: {winners} callers claimed the same request");
            assert_eq!(status(&env, &id), "processing");
        }
    }

    #[test]
    fn claim_then_release_then_claim_again() {
        let env = env();
        let _rx = pending(&env, "req-1");
        assert_eq!(claim(&env, "req-1").unwrap().status, "processing");
        assert_eq!(claim(&env, "req-1").unwrap_err().code, 400);
        release(&env, "req-1");
        assert_eq!(status(&env, "req-1"), "pending");
        assert!(claim(&env, "req-1").is_ok());
        assert_eq!(claim(&env, "req-missing").unwrap_err().code, 400); // no waiter
    }

    /// Audit F13: the approve arm re-validates the proposed network instead of
    /// writing whatever the request row holds.
    #[test]
    fn approve_add_network_revalidates_the_proposal() {
        let env = env();
        crate::models::network::init(&env).unwrap();
        let stored_id = crate::models::network::network_id_for("evm", "8453");
        let proposal = |patch: Value| {
            let mut network = json!({
                "Id": "evm.8453", "Type": "evm", "ChainId": "8453", "Name": "Base",
                "RPC": "https://rpc.example", "CurrencySymbol": "ETH", "CurrencyDecimals": 18, "BlockExplorer": "auto",
            });
            for (k, v) in patch.as_object().unwrap() {
                network[k] = v.clone();
            }
            Request { kind: "add_network".into(), value: Some(json!({ "network": network })), ..Default::default() }
        };
        for bad in [
            json!({ "RPC": "http://rpc.evil.example" }),
            json!({ "RPC": "https://192.168.1.1" }),
            json!({ "RPC": "https://169.254.169.254" }),
            json!({ "RPC": "gopher://rpc.example" }),
            json!({ "ChainId": "18446744073709551616" }),
            json!({ "ChainId": "0" }),
            json!({ "ChainId": "abc" }),
            json!({ "CurrencyDecimals": 37 }),
            json!({ "CurrencyDecimals": -1 }),
            json!({ "Type": "bitcoin" }),
        ] {
            let err = approve_add_network(&env, &proposal(bad.clone())).unwrap_err();
            assert_eq!(err.code, 400, "{bad}: {}", err.message);
            assert!(!crate::models::network::by_id_opt(&env, &stored_id), "{bad} was saved");
        }
        // Valid proposals (a concrete https endpoint, or the "auto" sentinel) are saved.
        approve_add_network(&env, &proposal(json!({ "ChainId": "8454", "RPC": "auto" }))).unwrap();
        approve_add_network(&env, &proposal(json!({}))).unwrap();
        // Stored under the deterministic id, so it can be read back …
        let stored = crate::models::network::fetch(&env, &stored_id).unwrap().expect("stored row");
        assert_eq!(stored.rpc, "https://rpc.example");
        assert!(!crate::models::network::by_id_opt(&env, "evm.8453"), "saved under the ephemeral id");
        // … a second proposal for the same chain cannot replace it …
        let err = approve_add_network(&env, &proposal(json!({ "RPC": "https://other.example" }))).unwrap_err();
        assert_eq!(err.code, 400, "{}", err.message);
        assert_eq!(crate::models::network::fetch(&env, &stored_id).unwrap().unwrap().rpc, "https://rpc.example");
        // … and switching to the chain selects the stored row (and its RPC).
        let switch = Request { id: "req-sw".into(), kind: "chain_switch".into(), value: Some(json!({ "targetNetwork": "evm.8453" })), ..Default::default() };
        approve_chain_switch(&env, &switch, &json!({})).unwrap();
        let current = crate::models::network::fetch(&env, "@").unwrap().unwrap();
        assert_eq!(current.resolved_rpc().unwrap(), "https://rpc.example");
        // A chain with no stored row keeps the ephemeral reference.
        assert_eq!(stored_network_target(&env, "evm.999999"), "evm.999999");
    }

    /// Audit F14: non-ASCII input must be rejected, not panic on a char boundary.
    #[test]
    fn decode_hex_rejects_non_ascii_without_panicking() {
        assert_eq!(decode_hex("0x00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex("00FF"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex("0x"), Some(vec![]));
        assert_eq!(decode_hex("0x0"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("+f"), None);
        // Even byte lengths that used to slice through a multi-byte character.
        for evil in ["0x\u{e9}", "a\u{e9}1", "\u{20ac}1", "0x\u{1f600}", "0xab\u{e9}"] {
            assert_eq!(decode_hex(evil), None, "{evil:?}");
        }
    }

    /// Wait for `run_with_timeout` (on another thread) to persist its row.
    fn wait_for_row(env: &Env, id: &str) {
        for _ in 0..200 {
            if env.request_pending(id) && request::fetch(env, id).unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("request {id} never appeared");
    }

    /// An unanswered request times out, and cannot be approved afterwards.
    #[test]
    fn unanswered_request_times_out() {
        let env = env();
        let req = Request { id: "req-t".into(), kind: "test".into(), ..Default::default() };
        let err = run_with_timeout(&env, req, Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.code, 4001);
        assert_eq!(status(&env, "req-t"), "timedout");
        assert!(claim(&env, "req-t").is_err());
    }

    /// Audit F5: when the approval is already mid-flight as the timeout fires,
    /// `run` must not report "timed out" (nor overwrite the row) — it waits for
    /// the approval's real outcome.
    #[test]
    fn timeout_during_processing_waits_for_the_outcome() {
        let env = env();
        let runner = {
            let env = env.clone();
            std::thread::spawn(move || {
                let req = Request { id: "req-p".into(), kind: "test".into(), ..Default::default() };
                run_with_timeout(&env, req, Duration::from_millis(150))
            })
        };
        wait_for_row(&env, "req-p");
        claim(&env, "req-p").unwrap();

        // Well past the timeout: still processing, the caller still parked.
        std::thread::sleep(Duration::from_millis(600));
        assert!(!runner.is_finished(), "run returned while the approval was still processing");
        assert_eq!(status(&env, "req-p"), "processing");

        // The approval completes: the caller gets the real result.
        respond(&env, "req-p", "accepted").unwrap();
        let out = runner.join().unwrap().expect("accepted, not timed out");
        assert_eq!(out.status, "accepted");
        assert_eq!(status(&env, "req-p"), "accepted");
    }

    /// A rejection is the EIP-1193 "user rejected" error, never a success the
    /// Web3 caller could report to the dApp; an approval still returns the row.
    #[test]
    fn rejected_request_is_an_error_for_the_caller() {
        let env = env();
        for (id, approve_it) in [("req-no", false), ("req-yes", true)] {
            let runner = {
                let env = env.clone();
                std::thread::spawn(move || run_approved(&env, Request { id: id.into(), kind: "test".into(), ..Default::default() }))
            };
            wait_for_row(&env, id);
            let params = json!({ "Id": id });
            if approve_it {
                approve(&env, &params).unwrap();
                assert_eq!(runner.join().unwrap().expect("approved").status, "accepted");
            } else {
                reject(&env, &params).unwrap();
                let err = runner.join().unwrap().unwrap_err();
                assert_eq!(err.code, 4001, "{}", err.message);
                assert_eq!(status(&env, id), "rejected");
            }
        }
    }

    /// A failed approval (claim released) after the timeout fired lets the
    /// request time out normally.
    #[test]
    fn released_claim_after_timeout_times_out() {
        let env = env();
        let runner = {
            let env = env.clone();
            std::thread::spawn(move || {
                let req = Request { id: "req-r".into(), kind: "test".into(), ..Default::default() };
                run_with_timeout(&env, req, Duration::from_millis(150))
            })
        };
        wait_for_row(&env, "req-r");
        claim(&env, "req-r").unwrap();
        std::thread::sleep(Duration::from_millis(400));
        release(&env, "req-r");
        let err = runner.join().unwrap().unwrap_err();
        assert_eq!(err.code, 4001);
        assert_eq!(status(&env, "req-r"), "timedout");
    }
}
