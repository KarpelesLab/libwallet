//! Signing for accounts whose keys live on a hardware wallet, behind the
//! generic routes.
//!
//! `Account:signTransaction`, `Account:signAndSendTransaction`,
//! `Account:signMessage`, `Transaction:signAndSend` and the dApp approvals
//! work the same for every account; when the account is on a hardware wallet
//! (`Protocol` `ledger`, `catcard` or `airgap`) the signature comes from the
//! device, which means an interaction:
//!
//! - **Ledger / CatCard** — the call talks to the device (the link params
//!   `Transport`, `Device`, … pass through) and returns once the owner has
//!   answered on its screen.
//! - **Air-gapped** — the call emits an `airgap:sign` event carrying the
//!   request to show (`{request_id, parts, …}`, what `Airgap:signRequest`
//!   returns) and waits for the host to hand the device's answer to
//!   `Airgap:submitSignature` with that `RequestId` — or to give up with
//!   `Airgap:cancelSign`.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::models::account::Account;
use crate::Env;

use super::{ApiError, ApiResult};

/// How long a generic route waits for an air-gapped signer's answer.
#[cfg(not(target_arch = "wasm32"))]
const AIRGAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// The hardware-wallet protocol of `account`'s wallet, if it is on one.
pub(crate) fn hardware_protocol(env: &Env, account: &Account) -> Option<String> {
    let wallet = crate::models::wallet::fetch(env, &account.wallet).ok().flatten()?;
    crate::airgap::import::is_signer_protocol(&wallet.protocol).then_some(wallet.protocol)
}

/// [`hardware_protocol`] for the account a generic request names in `Id`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // the browser's async dispatch
pub(crate) fn hardware_account(env: &Env, params: &Value) -> Option<(Account, String)> {
    let id = params.get("Id").and_then(Value::as_str)?;
    let account = crate::models::account::fetch(env, id).ok().flatten()?;
    let protocol = hardware_protocol(env, &account)?;
    Some((account, protocol))
}

// ── Air-gapped: wait for the host to bring the answer back ───────────────────

type Answer = Result<Value, ApiError>;
#[cfg(not(target_arch = "wasm32"))]
type AnswerSender = std::sync::mpsc::Sender<Answer>;
#[cfg(target_arch = "wasm32")]
type AnswerSender = futures_channel::oneshot::Sender<Answer>;

/// Generic routes waiting on an air-gapped signer, by request id.
static AIRGAP_WAITERS: Mutex<Option<HashMap<String, AnswerSender>>> = Mutex::new(None);

fn waiters<R>(f: impl FnOnce(&mut HashMap<String, AnswerSender>) -> R) -> R {
    let mut g = AIRGAP_WAITERS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// Whether a generic route is waiting for `request_id`'s answer.
pub(crate) fn airgap_waiting(request_id: &str) -> bool {
    waiters(|w| w.contains_key(request_id))
}

/// Hand an accepted answer (or a cancellation) to the route waiting for it.
/// False when nothing is waiting under `request_id`.
pub(crate) fn airgap_deliver(request_id: &str, answer: Answer) -> bool {
    match waiters(|w| w.remove(request_id)) {
        Some(tx) => tx.send(answer).is_ok(),
        None => false,
    }
}

/// Build the request, ask the host to show it (`airgap:sign`), and wait for
/// the accepted answer.
async fn airgap_sign(env: &Env, account: &Account, params: &Value) -> ApiResult {
    let built = super::airgap::sign_request_impl(env, params).await?;
    let rid = built.get("request_id").and_then(Value::as_str).unwrap_or_default().to_owned();
    #[cfg(not(target_arch = "wasm32"))]
    let (tx, rx) = std::sync::mpsc::channel();
    #[cfg(target_arch = "wasm32")]
    let (tx, rx) = futures_channel::oneshot::channel();
    waiters(|w| w.insert(rid.clone(), tx));
    env.broadcast(&crate::response::event("airgap:sign", json!({ "account": account.id, "request": built })));

    #[cfg(not(target_arch = "wasm32"))]
    let got = rx.recv_timeout(AIRGAP_TIMEOUT).map_err(|_| ApiError::new(408, "nobody brought the signer's answer back"));
    #[cfg(target_arch = "wasm32")]
    let got = rx.await.map_err(|_| ApiError::new(4001, "signing was abandoned"));

    waiters(|w| w.remove(&rid));
    if got.is_err() {
        let _ = crate::airgap::sign::pending_delete(env, &rid);
    }
    got?
}

// ── Transactions ─────────────────────────────────────────────────────────────

fn b58_32(s: &str, what: &str) -> Result<[u8; 32], ApiError> {
    bs58::decode(s).into_vec().ok().and_then(|b| b.try_into().ok()).ok_or_else(|| ApiError::new(400, format!("{what} is not a base58 32-byte value")))
}

/// A generic Solana `Transaction` as the `{message}` every device takes: a
/// serialized transaction or message passes through; a native transfer
/// `{to, value, recentBlockhash?}` is built here, the blockhash fetched from
/// `rpc` when it is missing.
async fn solana_transaction(account: &Account, tx: &Value, rpc: Option<&str>) -> Result<Value, ApiError> {
    let pk = crate::solana::pubkey_from_b64url(&account.pubkey).ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    if tx.get("message").or_else(|| tx.get("Message")).is_some() {
        return Ok(tx.clone());
    }
    let serialized = match tx {
        Value::String(s) => Some(s.as_str()),
        _ => ["transaction", "serializedTransaction", "raw"].iter().find_map(|k| tx.get(*k).and_then(Value::as_str)),
    };
    if let Some(s) = serialized {
        let raw = crate::solana::decode_tx_for_signer(s, &pk).ok_or_else(|| ApiError::new(400, "not a Solana transaction this account signs"))?;
        let (sigs_start, sigs_end) = crate::solana::tx_sig_layout(&raw).ok_or_else(|| ApiError::new(400, "malformed Solana transaction"))?;
        if sigs_end - sigs_start != 64 {
            return Err(ApiError::new(501, "a hardware wallet signs single-signer Solana transactions only"));
        }
        let message = crate::solana::tx_message(&raw).ok_or_else(|| ApiError::new(400, "malformed Solana transaction"))?;
        return Ok(json!({ "message": bs58::encode(message).into_string() }));
    }
    let to = tx.get("to").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "to required"))?;
    let lamports: u64 = match tx.get("value").or_else(|| tx.get("amount")) {
        Some(Value::String(s)) => s.parse().map_err(|_| ApiError::new(400, "value must be lamports"))?,
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| ApiError::new(400, "value must be lamports"))?,
        _ => 0,
    };
    let blockhash = match (tx.get("recentBlockhash").and_then(Value::as_str), rpc) {
        (Some(b), _) => b.to_owned(),
        (None, Some(url)) => {
            let bh = crate::rpc::call_async(url, "getLatestBlockhash", json!([])).await.map_err(ApiError::internal)?;
            bh.get("value").and_then(|v| v.get("blockhash")).and_then(Value::as_str).ok_or_else(|| ApiError::new(502, "no blockhash in the node's answer"))?.to_owned()
        }
        (None, None) => return Err(ApiError::new(400, "recentBlockhash required")),
    };
    let message = crate::solana::build_transfer_message(&pk, &b58_32(to, "to")?, lamports, &b58_32(&blockhash, "recentBlockhash")?);
    Ok(json!({ "message": bs58::encode(message).into_string() }))
}

/// Sign `params.Transaction` for a hardware account on its device; with
/// `broadcast`, send it too. `params` are the generic route's (`Network`,
/// `RPC` and the device link params pass through). The result carries `raw`
/// and `id`, plus the id under the name the chain's software path uses
/// (`hash`, `txid`, `signature`).
pub(crate) async fn sign_transaction(env: &Env, account: &Account, protocol: &str, params: &Value, broadcast: bool) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;
    let mut p = params.clone();
    let obj = p.as_object_mut().ok_or_else(|| ApiError::new(400, "params must be an object"))?;
    obj.remove("Keys");
    obj.insert("Account".into(), json!(account.id));
    obj.insert("Broadcast".into(), json!(broadcast));
    if !broadcast {
        // The signing-only routes never consult a node.
        obj.insert("Offline".into(), json!(true));
    }
    match account.kind.as_str() {
        "solana" => {
            let rpc = if broadcast { Some(super::resolve_rpc_for_kind(env, params, "solana")?) } else { None };
            obj.insert("Transaction".into(), solana_transaction(account, tx, rpc.as_deref()).await?);
        }
        "ethereum" | "bitcoin" => {}
        other => return Err(ApiError::new(501, format!("{other} accounts cannot be signed for on a hardware wallet"))),
    }
    let mut out = match protocol {
        "ledger" => super::ledger::route(env, "signTransaction", &p).await?,
        "catcard" => super::catcard::route(env, "signTransaction", &p).await?,
        _ => {
            let mut accepted = airgap_sign(env, account, &p).await?;
            if broadcast {
                accepted["broadcast"] = super::airgap::broadcast_accepted(env, &p, &accepted).await?;
            }
            accepted
        }
    };
    // The node's answer when it is the id, else the id computed locally.
    let id = out.get("broadcast").and_then(Value::as_str).or_else(|| out.get("id").and_then(Value::as_str)).unwrap_or_default().to_owned();
    let name = match account.kind.as_str() {
        "ethereum" => "hash",
        "bitcoin" => "txid",
        _ => "signature",
    };
    out[name] = json!(id);
    Ok(out)
}

// ── Messages ─────────────────────────────────────────────────────────────────

/// Sign `message` with a hardware account on its device: `{signature, …}` in
/// the encoding the chain's software path uses (EVM `0x` hex, Bitcoin base64).
pub(crate) async fn sign_message(env: &Env, account: &Account, protocol: &str, params: &Value, message: &[u8]) -> ApiResult {
    use base64::Engine;
    let mut p = params.clone();
    let obj = p.as_object_mut().ok_or_else(|| ApiError::new(400, "params must be an object"))?;
    obj.remove("Keys");
    obj.insert("Account".into(), json!(account.id));
    obj.insert("Message".into(), json!(base64::engine::general_purpose::STANDARD.encode(message)));
    match protocol {
        "ledger" => super::ledger::route(env, "signMessage", &p).await,
        "catcard" => super::catcard::route(env, "signMessage", &p).await,
        _ => Err(ApiError::new(501, "air-gapped signers do not sign messages through libwallet")),
    }
}

/// `Airgap:cancelSign {RequestId}` — give up on a request a generic route is
/// waiting for; that route fails with 4001.
pub fn cancel_sign(env: &Env, params: &Value) -> ApiResult {
    let rid = params.get("RequestId").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "RequestId required"))?;
    let delivered = airgap_deliver(rid, Err(ApiError::new(4001, "signing was cancelled")));
    let _ = crate::airgap::sign::pending_delete(env, rid);
    Ok(json!({ "cancelled": delivered }))
}
