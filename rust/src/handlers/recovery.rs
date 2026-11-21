//! `Recovery:*` — recover funds from another wallet's secret: open the source,
//! list or scan the addresses it may have used, then prepare, review and
//! broadcast sweeps to the user's own wallet. See [`crate::recovery`] and
//! `docs/wallet-recovery.md`.
//!
//! Secrets live in this process's memory only, under the session id `open`
//! returns, until `close` (or the process ends). Nothing is written to the
//! database.

use serde_json::{json, Value};

use super::{ApiError, ApiResult};
use crate::recovery::{self, sweep, Family};
use crate::Env;

fn text<'a>(params: &'a Value, name: &str) -> Result<&'a str, ApiError> {
    params.get(name).and_then(Value::as_str).ok_or_else(|| ApiError::new(400, format!("{name} required")))
}

fn opt_text<'a>(params: &'a Value, name: &str) -> Option<&'a str> {
    params.get(name).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Run `f` with the request's session.
fn with_session<T>(params: &Value, f: impl FnOnce(&recovery::Session) -> Result<T, ApiError>) -> Result<T, ApiError> {
    let id = text(params, "Session")?;
    let mut out = None;
    recovery::with(id, |s| {
        out = Some(f(s));
        Ok(())
    })
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::new(404, "recovery session not found (closed, or the app restarted): open it again"))?;
    out.expect("ran")
}

fn chains_json(session: &recovery::Session) -> Value {
    json!(session.chains().iter().map(|c| json!({ "Chain": c.name, "Symbol": c.symbol, "Decimals": c.decimals })).collect::<Vec<_>>())
}

/// `Recovery:open` {Type, …} — open a source. `Type` is:
/// - `bitfi` {Salt, Secret}
/// - `mnemonic` {Mnemonic, Passphrase?}
/// - `privateKey` {Key}: 64 hex characters, a WIF, or a Solana keypair
/// - `keystore` {Keystore (the JSON file's text), Password}
///
/// Returns `{Session, Type, Chains: [{Chain, Symbol, Decimals}]}`.
pub fn open(params: &Value) -> ApiResult {
    let kind = text(params, "Type")?;
    let session = match kind {
        "bitfi" => recovery::open_bitfi(text(params, "Salt")?, text(params, "Secret")?),
        "mnemonic" => recovery::open_mnemonic(text(params, "Mnemonic")?, opt_text(params, "Passphrase").unwrap_or("")),
        "privateKey" => recovery::open_private_key(text(params, "Key")?),
        "keystore" => recovery::open_keystore(text(params, "Keystore")?, text(params, "Password")?),
        other => return Err(ApiError::new(400, format!("unknown recovery Type {other:?} (bitfi, mnemonic, privateKey, keystore)"))),
    }
    .map_err(|e| ApiError::new(400, e))?;
    let chains = chains_json(&session);
    let kind = session.kind;
    let id = recovery::insert(session).map_err(ApiError::internal)?;
    Ok(json!({ "Session": id, "Type": kind, "Chains": chains }))
}

/// `{Chains?, Start?, Count?}` from a request.
fn range(params: &Value) -> Result<(Vec<String>, u32, u32), ApiError> {
    let chains = match params.get("Chains") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.iter().map(|c| c.as_str().map(str::to_owned).ok_or_else(|| ApiError::new(400, "Chains must be strings"))).collect::<Result<_, _>>()?,
        Some(_) => return Err(ApiError::new(400, "Chains must be a list")),
    };
    let num = |name: &str, default: u32| -> Result<u32, ApiError> {
        match params.get(name) {
            None | Some(Value::Null) => Ok(default),
            Some(v) => v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| ApiError::new(400, format!("{name} must be a non-negative integer"))),
        }
    };
    let count = num("Count", recovery::DEFAULT_COUNT)?;
    if count > recovery::MAX_COUNT {
        return Err(ApiError::new(400, format!("Count is at most {}", recovery::MAX_COUNT)));
    }
    Ok((chains, num("Start", 0)?, count))
}

fn slots(params: &Value) -> Result<Vec<recovery::Slot>, ApiError> {
    let (chains, start, count) = range(params)?;
    with_session(params, |s| recovery::slots(s, &chains, start, count).map_err(|e| ApiError::new(400, e)))
}

/// `Recovery:addresses` {Session, Chains?, Start?, Count?} — every address the
/// source may have used, for indexes `Start..Start+Count` (default 0..5), with
/// no network access. Returns `{Addresses: [{Id, Chain, Symbol, Kind, Address,
/// Label, Index, Path?}]}`.
pub fn addresses(params: &Value) -> ApiResult {
    let found = slots(params)?;
    Ok(json!({ "Addresses": found.iter().map(recovery::Slot::to_json).collect::<Vec<_>>() }))
}

/// `Recovery:scan` {Session, Chains?, Start?, Count?, RPC?} — what each
/// address holds: [`addresses`] plus `Assets: [{Asset, Symbol, Decimals,
/// Balance}]`, or `Error` when it couldn't be checked (never an empty list in
/// its place). Balances are base units as decimal strings.
pub async fn scan(params: &Value) -> ApiResult {
    let found = slots(params)?;
    let rows = recovery::scan::scan_all(&found, opt_text(params, "RPC")).await;
    Ok(json!({ "Addresses": rows }))
}

/// Where a sweep goes: `To` (an address) or `ToAccount` (a libwallet account
/// id, whose address on the slot's chain is used; it must be an account of
/// that chain).
fn destination(env: &Env, chain: &recovery::Chain, params: &Value) -> Result<String, ApiError> {
    if let Some(to) = opt_text(params, "To") {
        if opt_text(params, "ToAccount").is_some() {
            return Err(ApiError::new(400, "give To or ToAccount, not both"));
        }
        return Ok(to.trim().to_owned());
    }
    let id = opt_text(params, "ToAccount").ok_or_else(|| ApiError::new(400, "To or ToAccount required"))?;
    let account = crate::models::account::fetch(env, id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, format!("account {id} not found")))?;
    let wrong = || ApiError::new(400, format!("account {id} is a {} account: it can't receive {}", account.kind, chain.name));
    match chain.family {
        Family::Bitcoin { .. } if account.kind == "bitcoin" => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let public: [u8; 33] = b64.decode(&account.pubkey).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| ApiError::internal("bad account pubkey"))?;
            let chain_code: [u8; 32] = b64.decode(&account.chaincode).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| ApiError::internal("bad account chain code"))?;
            let formats = crate::bitcoin::address_formats(&public, &chain_code, chain.name).map_err(ApiError::internal)?;
            formats.into_iter().find(|f| f.is_default).map(|f| f.address).ok_or_else(|| ApiError::internal("no address for the account"))
        }
        Family::Ethereum if account.kind == "ethereum" => Ok(account.address),
        Family::Solana if account.kind == "solana" => Ok(account.address),
        Family::Tron if account.kind == "tron" => Ok(account.address),
        _ => Err(wrong()),
    }
}

/// `Recovery:prepareSweep` {Session, Address, To | ToAccount, Asset?, Amount?,
/// FeeRate?, RPC?} — build and sign, without broadcasting, a transfer from the
/// recovered address `Address` (a slot `Id` from addresses/scan). `Asset` is
/// `NATIVE` (default) or a token contract / mint from the scan; `Amount` is
/// `max` (default) or base units. Returns `{Address, Chain, From, To, Asset,
/// Symbol, Decimals, Amount, Fee, Raw, …}` to show the user before
/// [`broadcast`].
pub async fn prepare_sweep(env: &Env, params: &Value) -> ApiResult {
    let id = text(params, "Address")?;
    let (slot, key) = with_session(params, |s| {
        let slot = recovery::slot(s, id).map_err(|e| ApiError::new(400, e))?;
        let key = recovery::key_for(s, slot.chain, &slot.key).map_err(ApiError::internal)?;
        Ok((slot, key))
    })?;
    let to = destination(env, slot.chain, params)?;
    let amount = sweep::Amount::parse(opt_text(params, "Amount").unwrap_or("max"))?;
    let fee_rate = match params.get("FeeRate") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().filter(|r| *r > 0).ok_or_else(|| ApiError::new(400, "FeeRate must be a positive whole number"))?),
    };
    let req = sweep::Request { to: &to, asset: opt_text(params, "Asset").unwrap_or("NATIVE"), amount, fee_rate, rpc: opt_text(params, "RPC") };
    sweep::prepare(env, &slot, key, &req).await
}

/// `Recovery:broadcast` {Chain, Raw, RPC?} — send a transaction from
/// `prepareSweep`. Returns `{Txid}`.
pub async fn broadcast(params: &Value) -> ApiResult {
    let chain = recovery::chain(text(params, "Chain")?).ok_or_else(|| ApiError::new(400, "unknown Chain"))?;
    let txid = sweep::broadcast(chain, text(params, "Raw")?, opt_text(params, "RPC")).await?;
    Ok(json!({ "Txid": txid }))
}

/// `Recovery:export` {Session, Address} — the private key of one recovered
/// address, in the forms other wallets import (`PrivateKey`, plus `Wif` on
/// Bitcoin chains; Monero: `SpendKey`, `ViewKey`). Only on this explicit
/// request: treat the result like the recovery phrase itself.
pub fn export(params: &Value) -> ApiResult {
    let id = text(params, "Address")?;
    with_session(params, |s| {
        let slot = recovery::slot(s, id).map_err(|e| ApiError::new(400, e))?;
        recovery::export(s, &slot).map_err(ApiError::internal)
    })
}

/// `Recovery:close` {Session} — forget the session and wipe its secrets.
pub fn close(params: &Value) -> ApiResult {
    Ok(json!({ "Closed": recovery::remove(text(params, "Session")?) }))
}
