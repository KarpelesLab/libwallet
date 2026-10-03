//! Tron (TRX + TRC-20) over java-tron's native HTTP API.
//!
//! A Tron network's RPC is the base URL of that API — the one tronweb and
//! TronLink take — and calls append `/wallet/<method>` to it: modchain serves it
//! under `/tron/rest`, TronGrid at its root. Every body is JSON with
//! `"visible": true`, so addresses travel in their `T...` form.
//!
//! Transactions are built locally with outscript's `trontx` (no node-side
//! `createtransaction`, so there is nothing the node could slip in): the
//! reference block comes from `getnowblock`, the id is the SHA-256 of the
//! `raw_data`, the account's DKLs key signs it, and the signed protobuf goes out
//! through `broadcasthex`. The recovered signer is checked against the owner
//! before anything is broadcast.

use num_bigint::{BigInt, Sign};
use outscript::tron::TronAddress;
use outscript::trontx::{trc20_transfer_data, TronContract, TronTransfer, TronTriggerSmartContract, TronTx};
use serde_json::{json, Value};

use crate::models::account::Account;
use crate::{Env, Error, Result};

/// TRX has 6 decimals (1 TRX = 1,000,000 sun).
pub const TRX_DECIMALS: i64 = 6;

/// The energy budget (in sun) a TRC-20 transfer may burn unless the caller pins
/// `feeLimit`. A cap, not a charge: only the energy actually used is paid. A
/// USDT transfer to a fresh holder is ~130k energy, well inside this.
pub const DEFAULT_TRC20_FEE_LIMIT: u64 = 100_000_000; // 100 TRX

/// How long after its reference block a transaction stays valid. Nodes accept
/// up to 24h; a short window keeps an unsent tx from lingering.
const EXPIRATION_MS: u64 = 10 * 60 * 1000;

/// Bandwidth reserved for a TRX transfer's fee when the account has no free
/// bandwidth left: ~270 bytes at 1000 sun/byte.
pub const TRANSFER_BANDWIDTH_SUN: u64 = 300_000;

/// What sending TRX to an address that has never been seen costs on top of the
/// bandwidth: the account-creation fee (1 TRX) plus its own bandwidth (0.1 TRX).
pub const NEW_ACCOUNT_SUN: u64 = 1_100_000;

/// Parse a Tron address: the `T...` base58check form, or the `41`-prefixed hex
/// form java-tron prints with `visible: false`.
pub fn parse_address(s: &str) -> Result<TronAddress> {
    let s = s.trim();
    if s.len() == 42 && s[..2].eq_ignore_ascii_case("41") {
        let mut raw = [0u8; 21];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| Error::Env(format!("invalid tron address {s:?}")))?;
        }
        return Ok(raw);
    }
    outscript::tron::address_from_str(s).map_err(|e| Error::Env(format!("invalid tron address {s:?}: {e}")))
}

/// The canonical `T...` form of `s` (accepts either input form).
pub fn normalize_address(s: &str) -> Result<String> {
    let raw = parse_address(s)?;
    outscript::tron::address_to_string(&raw).map_err(|e| Error::Env(e.to_string()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn endpoint(base: &str, method: &str) -> String {
    format!("{}/wallet/{method}", base.trim_end_matches('/'))
}

/// java-tron reports a failed call as `{"Error": "..."}` with a 200 status.
fn check_error(method: &str, v: Value) -> Result<Value> {
    if let Some(e) = v.get("Error").and_then(Value::as_str) {
        return Err(Error::Env(format!("tron {method}: {e}")));
    }
    Ok(v)
}

/// POST `body` to `<base>/wallet/<method>` and decode the JSON reply. Blocking —
/// for the native sync handlers; [`post_async`] is the shared async twin.
#[cfg(not(target_arch = "wasm32"))]
pub fn post(base: &str, method: &str, body: &Value) -> Result<Value> {
    let body = serde_json::to_vec(body).map_err(|e| Error::Env(e.to_string()))?;
    let resp: Value = rsurl::Request::new("POST", &endpoint(base, method))
        .map_err(|e| Error::Env(format!("tron {method} request build failed: {e}")))?
        .header("Content-Type", "application/json")
        .read_timeout(Some(std::time::Duration::from_secs(20)))
        .body(body)
        .send()
        .map_err(|e| Error::Env(format!("tron {method} request failed: {e}")))?
        .json()
        .map_err(|e| Error::Env(format!("tron {method} decode failed: {e}")))?;
    check_error(method, resp)
}

/// Async twin of [`post`] over rsurl's `aio` client (Fetch on wasm).
pub async fn post_async(base: &str, method: &str, body: &Value) -> Result<Value> {
    let body = serde_json::to_vec(body).map_err(|e| Error::Env(e.to_string()))?;
    let req = rsurl::aio::Request::new("POST", &endpoint(base, method))
        .header("Content-Type", "application/json")
        .body(body);
    let resp = crate::rpc::aio_send(&req)
        .await
        .map_err(|e| Error::Env(format!("tron {method} request failed: {e}")))?;
    let v: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Env(format!("tron {method} decode failed: {e}")))?;
    check_error(method, v)
}

// --- request bodies + reply parsing (pure, shared by both transports) --------

pub fn account_body(address: &str) -> Value {
    json!({ "address": address, "visible": true })
}

/// The TRX balance (sun) from a `getaccount` reply. An address that has never
/// received anything answers `{}`: zero, not an error.
pub fn parse_balance(v: &Value) -> u64 {
    v.get("balance").and_then(Value::as_u64).unwrap_or(0)
}

/// Whether a `getaccount` reply names an existing (activated) account.
pub fn account_exists(v: &Value) -> bool {
    v.get("address").is_some() || v.get("create_time").is_some()
}

/// The free bandwidth left today from a `getaccountresource` reply.
pub fn free_bandwidth(v: &Value) -> u64 {
    let get = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let free = get("freeNetLimit").saturating_sub(get("freeNetUsed"));
    let staked = get("NetLimit").saturating_sub(get("NetUsed"));
    free + staked
}

/// A recent block to anchor a transaction on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefBlock {
    pub height: u64,
    pub id: [u8; 32],
    /// Block time, ms since the epoch.
    pub timestamp: u64,
}

/// The reference block from a `getnowblock` reply.
pub fn parse_ref_block(v: &Value) -> Result<RefBlock> {
    let id = v
        .get("blockID")
        .and_then(Value::as_str)
        .and_then(unhex)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| Error::Env("tron getnowblock: missing blockID".into()))?;
    let raw = v.get("block_header").and_then(|h| h.get("raw_data"));
    let get = |k: &str| raw.and_then(|r| r.get(k)).and_then(Value::as_u64);
    let height = get("number").unwrap_or_else(|| u64::from_be_bytes(id[..8].try_into().unwrap()));
    let timestamp = get("timestamp").ok_or_else(|| Error::Env("tron getnowblock: missing timestamp".into()))?;
    Ok(RefBlock { height, id, timestamp })
}

/// The `triggerconstantcontract` body for a read-only call of `contract`.
pub fn constant_call_body(owner: &str, contract: &str, selector: &str, parameter: &[u8]) -> Value {
    json!({
        "owner_address": owner,
        "contract_address": contract,
        "function_selector": selector,
        "parameter": hex(parameter),
        "visible": true,
    })
}

/// The first `constant_result` of a `triggerconstantcontract` reply, decoded.
pub fn parse_constant_result(v: &Value) -> Result<Vec<u8>> {
    if let Some(r) = v.get("result") {
        if r.get("result").and_then(Value::as_bool) != Some(true) {
            let msg = r.get("message").and_then(Value::as_str).map(decode_message).unwrap_or_default();
            let code = r.get("code").and_then(Value::as_str).unwrap_or("error");
            return Err(Error::Env(format!("tron constant call failed: {code} {msg}").trim_end().to_owned()));
        }
    }
    v.get("constant_result")
        .and_then(|a| a.get(0))
        .and_then(Value::as_str)
        .and_then(unhex)
        .ok_or_else(|| Error::Env("tron constant call: no constant_result".into()))
}

/// java-tron hex-encodes some messages (broadcast results) and not others; show
/// the text either way.
fn decode_message(m: &str) -> String {
    unhex(m)
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.chars().any(char::is_control))
        .unwrap_or_else(|| m.to_owned())
}

/// A 32-byte ABI word holding `raw`'s 20-byte account hash.
fn abi_address(raw: &TronAddress) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&raw[1..]);
    w
}

/// `balanceOf(owner)` call parameters.
pub fn balance_of_param(owner: &str) -> Result<[u8; 32]> {
    Ok(abi_address(&parse_address(owner)?))
}

/// A uint256 ABI word as a BigInt.
pub fn parse_uint(word: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &word[..word.len().min(32)])
}

/// The `broadcasthex` body for a signed `Transaction` message.
pub fn broadcast_body(signed: &[u8]) -> Value {
    json!({ "transaction": hex(signed) })
}

/// The txid from a `broadcasthex` reply, or the node's rejection.
pub fn parse_broadcast(v: &Value, txid: &[u8; 32]) -> Result<String> {
    if v.get("result").and_then(Value::as_bool) == Some(true) {
        return Ok(v.get("txid").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| hex(txid)));
    }
    let code = v.get("code").and_then(Value::as_str).unwrap_or("rejected");
    let msg = v.get("message").and_then(Value::as_str).map(decode_message).unwrap_or_default();
    Err(Error::Env(format!("tron broadcast failed: {code} {msg}").trim_end().to_owned()))
}

// --- building + signing -----------------------------------------------------

/// What to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transfer {
    /// Native TRX, `amount` in sun.
    Trx { to: String, amount: u64 },
    /// A TRC-20 `transfer(to, amount)` on `contract`, `amount` in token base
    /// units; `fee_limit` caps the energy burn (sun).
    Trc20 { contract: String, to: String, amount: u128, fee_limit: u64 },
}

/// Build, sign and serialize `transfer` from `account`, anchored on `block`.
/// Returns `(txid, signed Transaction bytes)`. Fails before signing when an
/// address does not parse, and after signing when the signature does not
/// recover to the account (a wrong tweak or path must never reach the network).
pub fn sign_transfer(
    env: &Env,
    account: &Account,
    unlock: &[(String, String)],
    transfer: &Transfer,
    block: &RefBlock,
) -> Result<([u8; 32], Vec<u8>)> {
    let owner = parse_address(&account.address)?;
    let calldata;
    let (contract, fee_limit) = match transfer {
        Transfer::Trx { to, amount } => (
            TronContract::Transfer(TronTransfer { owner, to: parse_address(to)?, amount: *amount }),
            0,
        ),
        Transfer::Trc20 { contract, to, amount, fee_limit } => {
            calldata = trc20_transfer_data(&parse_address(to)?, *amount);
            (
                TronContract::TriggerSmartContract(TronTriggerSmartContract::new(owner, parse_address(contract)?, &calldata)),
                *fee_limit,
            )
        }
    };
    let tx = TronTx {
        timestamp: block.timestamp,
        expiration: block.timestamp + EXPIRATION_MS,
        fee_limit,
        ..TronTx::new(contract)
    }
    .with_ref_block(block.height, &block.id);
    sign_tx(env, account, unlock, &tx)
}

/// Sign an already-built `tx` with `account`'s key, checking the signature
/// recovers to the account. Returns `(txid, signed Transaction bytes)`.
pub fn sign_tx(env: &Env, account: &Account, unlock: &[(String, String)], tx: &TronTx) -> Result<([u8; 32], Vec<u8>)> {
    let owner = parse_address(&account.address)?;
    let txid = tx.txid();
    let sig = crate::evm::sign_digest_recoverable(env, account, unlock, &txid)?;
    match tx.signer(&sig) {
        Ok(signer) if signer == owner => {}
        _ => return Err(Error::Env("tron signature does not recover to the account address".into())),
    }
    Ok((txid, tx.encode_signed(&[sig])))
}

/// The owner of a parsed transaction's contract, when it is one we model.
pub fn tx_owner(tx: &TronTx) -> Option<TronAddress> {
    match &tx.contract {
        TronContract::Transfer(c) => Some(c.owner),
        TronContract::TransferAsset(c) => Some(c.owner),
        TronContract::TriggerSmartContract(c) => Some(c.owner),
        _ => None,
    }
}

/// Offline-sign a node-built `raw_data_hex` (e.g. from `createtransaction` or a
/// dApp) for `account`. The raw data is parsed first: it must be a contract we
/// can read whose owner is the account, so nothing is signed blind.
pub fn sign_raw_data(env: &Env, account: &Account, unlock: &[(String, String)], raw_data_hex: &str) -> Result<([u8; 32], Vec<u8>)> {
    let raw = unhex(raw_data_hex.trim_start_matches("0x")).ok_or_else(|| Error::Env("rawDataHex is not hex".into()))?;
    let tx = TronTx::parse(&raw).map_err(|e| Error::Env(format!("cannot parse tron raw data: {e}")))?;
    let owner = parse_address(&account.address)?;
    match tx_owner(&tx) {
        Some(o) if o == owner => {}
        Some(_) => return Err(Error::Env("tron transaction is not owned by this account".into())),
        None => return Err(Error::Env("refusing to sign an uninterpreted tron contract".into())),
    }
    sign_tx(env, account, unlock, &tx)
}

// --- network round trips (native, blocking) ---------------------------------

/// The account's TRX balance, in sun.
#[cfg(not(target_arch = "wasm32"))]
pub fn balance_sun(base: &str, address: &str) -> Result<u64> {
    Ok(parse_balance(&post(base, "getaccount", &account_body(address))?))
}

/// The TRC-20 `contract` balance of `owner`, in token base units.
#[cfg(not(target_arch = "wasm32"))]
pub fn trc20_balance(base: &str, contract: &str, owner: &str) -> Result<BigInt> {
    let body = constant_call_body(owner, contract, "balanceOf(address)", &balance_of_param(owner)?);
    let out = parse_constant_result(&post(base, "triggerconstantcontract", &body)?)?;
    Ok(parse_uint(&out))
}

/// A no-argument constant call of `contract` (`decimals()`, `symbol()`, …),
/// returning the raw ABI output. Any address works as the caller of a view, so
/// the contract itself is used.
#[cfg(not(target_arch = "wasm32"))]
pub fn trc20_view(base: &str, contract: &str, selector: &str) -> Result<Vec<u8>> {
    let body = constant_call_body(contract, contract, selector, &[]);
    parse_constant_result(&post(base, "triggerconstantcontract", &body)?)
}

/// Build, sign and broadcast `transfer`, returning `(txid hex, signed bytes)`.
#[cfg(not(target_arch = "wasm32"))]
pub fn send(env: &Env, account: &Account, unlock: &[(String, String)], base: &str, transfer: &Transfer) -> Result<(String, Vec<u8>)> {
    let block = parse_ref_block(&post(base, "getnowblock", &json!({}))?)?;
    let (txid, signed) = sign_transfer(env, account, unlock, transfer, &block)?;
    let hash = parse_broadcast(&post(base, "broadcasthex", &broadcast_body(&signed))?, &txid)?;
    Ok((hash, signed))
}

/// Async twin of [`send`].
pub async fn send_async(env: &Env, account: &Account, unlock: &[(String, String)], base: &str, transfer: &Transfer) -> Result<(String, Vec<u8>)> {
    let block = parse_ref_block(&post_async(base, "getnowblock", &json!({})).await?)?;
    let (txid, signed) = sign_transfer(env, account, unlock, transfer, &block)?;
    let hash = parse_broadcast(&post_async(base, "broadcasthex", &broadcast_body(&signed)).await?, &txid)?;
    Ok((hash, signed))
}

/// The most TRX (sun) `address` can send to `to` (empty: unknown recipient,
/// assumed existing): the balance less the bandwidth fee when no free bandwidth
/// is left, and less the account-creation fee when `to` has never been seen.
/// Returns `(balance, fee reserved, max)`.
#[cfg(not(target_arch = "wasm32"))]
pub fn max_sendable(base: &str, address: &str, to: &str) -> Result<(u64, u64, u64)> {
    let balance = balance_sun(base, address)?;
    let mut fee = 0;
    let resource = post(base, "getaccountresource", &account_body(address)).unwrap_or(Value::Null);
    if free_bandwidth(&resource) < 300 {
        fee += TRANSFER_BANDWIDTH_SUN;
    }
    if !to.is_empty() {
        let exists = post(base, "getaccount", &account_body(to)).map(|v| account_exists(&v)).unwrap_or(true);
        if !exists {
            fee += NEW_ACCOUNT_SUN;
        }
    }
    Ok((balance, fee, balance.saturating_sub(fee)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_forms_round_trip() {
        let t = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        let raw = parse_address(t).unwrap();
        assert_eq!(hex(&raw), "41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
        assert_eq!(parse_address("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap(), raw);
        assert_eq!(normalize_address("41A614F803B6FD780986A42C78EC9C7F77E6DED13C").unwrap(), t);
        assert!(parse_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u").is_err()); // checksum
        assert!(parse_address("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c").is_err());
    }

    #[test]
    fn tron_address_matches_evm_hash() {
        // Same key, same 20-byte hash: the Tron address is the EVM one behind 0x41.
        let pk = crate::hdderive::derive_pubkey_for_path(&[7u8; 64], "secp256k1", "m/44'/195'/0'/0/0").unwrap();
        let t = crate::hdderive::tron_address(&pk).unwrap();
        let e = crate::hdderive::evm_address(&pk).unwrap();
        assert!(t.starts_with('T') && t.len() == 34);
        assert_eq!(hex(&parse_address(&t).unwrap()[1..]), e[2..].to_ascii_lowercase());
    }

    #[test]
    fn parses_node_replies() {
        let block = json!({
            "blockID": "00000000052c1ba35c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
            "block_header": { "raw_data": { "number": 86_777_763u64, "timestamp": 1_791_005_153_610u64 } }
        });
        let rb = parse_ref_block(&block).unwrap();
        assert_eq!(rb.height, 86_777_763);
        assert_eq!(rb.timestamp, 1_791_005_153_610);

        assert_eq!(parse_balance(&json!({})), 0);
        assert!(!account_exists(&json!({})));
        assert_eq!(parse_balance(&json!({ "address": "T…", "balance": 7_335_732_710u64 })), 7_335_732_710);

        let ok = json!({ "result": { "result": true }, "constant_result": ["00000000000000000000000000000000000000000000000000000859c468043a"] });
        assert_eq!(parse_uint(&parse_constant_result(&ok).unwrap()), BigInt::from(0x859c468043au64));
        let refused = json!({ "result": { "code": "CONTRACT_VALIDATE_ERROR", "message": "this node does not support constant" } });
        assert!(parse_constant_result(&refused).unwrap_err().to_string().contains("does not support constant"));

        // broadcast messages come back hex-encoded
        let bad = json!({ "result": false, "code": "SIGERROR", "message": hex(b"validate signature error") });
        assert!(parse_broadcast(&bad, &[0; 32]).unwrap_err().to_string().contains("validate signature error"));
        let good = json!({ "result": true, "txid": "ab" });
        assert_eq!(parse_broadcast(&good, &[0; 32]).unwrap(), "ab");
    }
}
