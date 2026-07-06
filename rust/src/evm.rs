//! EVM transaction building + threshold signing (port of the wlttx EVM path).
//!
//! Builds a legacy EIP-155 transaction, signs its keccak digest with the
//! wallet's DKLs shares under the account's HD tweak (so the recovered signer
//! is the account address), and serializes the signed tx. Verified end-to-end
//! via [`recover_sender`] (outscript's ecrecover) — a DKLs-signed tx must
//! recover to the account's own address.
//!
//! EIP-1559 and Bitcoin/Solana tx building follow the same shape.

use num_bigint::{BigInt, Sign};
use outscript::evmtx::{EvmTx, EvmTxType};
use purecrypto::hash::keccak256;

use crate::models::{account, wallet};
use crate::{Env, Error, Result};

/// An EVM transaction request (amounts as decimal-wei strings so the public API
/// stays free of BigInt). `eip1559` selects the type-2 dynamic-fee format;
/// otherwise a legacy EIP-155 tx is built. For legacy, `max_fee` is the gas
/// price and `max_priority` is ignored.
pub struct EvmTxRequest {
    pub nonce: u64,
    pub gas: u64,
    pub max_fee: String,
    pub max_priority: String,
    pub to: String,
    pub value: String,
    pub data: Vec<u8>,
    pub chain_id: u64,
    pub eip1559: bool,
}

/// Build, DKLs-sign, and serialize an EVM transaction (legacy or EIP-1559) for
/// `account_id`. `unlock` provides the Password creds for ALL of the wallet's
/// shares (DKLs signing needs the full set). Returns the raw signed tx bytes.
pub fn sign_tx(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    req: &EvmTxRequest,
) -> Result<Vec<u8>> {
    let acct = account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    let tweak = il_to_tweak(&acct.il)?;

    let mut tx = EvmTx {
        nonce: req.nonce,
        gas: req.gas,
        gas_fee_cap: parse_dec(&req.max_fee)?,
        gas_tip_cap: if req.eip1559 { parse_dec(&req.max_priority)? } else { BigInt::from(0) },
        to: req.to.clone(),
        value: parse_dec(&req.value)?,
        data: req.data.clone(),
        chain_id: req.chain_id,
        tx_type: if req.eip1559 { EvmTxType::Eip1559 } else { EvmTxType::Legacy },
        ..Default::default()
    };

    let sign_bytes = tx.sign_bytes().map_err(Error::Env)?;
    let digest = keccak256(&sign_bytes);
    let (r, s, v) = wallet::dkls_sign_digest(env, &acct.wallet, unlock, &tweak, &digest)?;
    let (s, v) = normalize_low_s(s, v);

    tx.signed = true;
    tx.r = BigInt::from_bytes_be(Sign::Plus, &r);
    tx.s = BigInt::from_bytes_be(Sign::Plus, &s);
    // Legacy EIP-155: v = chain_id*2 + 35 + parity. EIP-1559: v = parity.
    tx.y = if req.eip1559 {
        BigInt::from(v as u64)
    } else {
        BigInt::from(req.chain_id * 2 + 35 + v as u64)
    };

    tx.to_bytes().map_err(Error::Env)
}

/// EIP-191 `personal_sign`: sign `message` under the EVM prefix
/// `"\x19Ethereum Signed Message:\n<len>" + message`, keccak-hashed, with the
/// account's DKLs key. Returns the 65-byte `R ‖ S ‖ V` signature (V ∈ {27, 28},
/// low-S normalized) that off-chain verifiers / ecrecover expect.
pub fn personal_sign(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    message: &[u8],
) -> Result<Vec<u8>> {
    let acct = account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    if acct.kind != "ethereum" {
        return Err(Error::Env("personal_sign is EVM-only".into()));
    }
    let tweak = il_to_tweak(&acct.il)?;

    let mut full = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    full.extend_from_slice(message);
    let digest = keccak256(&full);
    sign_digest_rsv(env, &acct, &tweak, unlock, &digest)
}

/// DKLs-sign a pre-computed 32-byte Ethereum digest for `account_id`, returning
/// the 65-byte `R || S || V` (V ∈ {27, 28}) signature off-chain verifiers
/// expect. Used by `personal_sign` and `eth_signTypedData` (the digest is the
/// EIP-712 hash). `account_id` must be an ethereum account.
pub fn sign_eth_digest(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    digest: &[u8; 32],
) -> Result<Vec<u8>> {
    let acct = account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    if acct.kind != "ethereum" {
        return Err(Error::Env("eth digest signing is EVM-only".into()));
    }
    let tweak = il_to_tweak(&acct.il)?;
    sign_digest_rsv(env, &acct, &tweak, unlock, digest)
}

/// Shared tail: DKLs-sign `digest`, low-S normalize, and pack R || S || V.
fn sign_digest_rsv(
    env: &Env,
    acct: &account::Account,
    tweak: &[u8; 32],
    unlock: &[(String, String)],
    digest: &[u8; 32],
) -> Result<Vec<u8>> {
    let (r, s, v) = wallet::dkls_sign_digest(env, &acct.wallet, unlock, tweak, digest)?;
    let (s, v) = normalize_low_s(s, v);
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&pad32(&r));
    sig.extend_from_slice(&pad32(&s));
    sig.push(27 + v);
    Ok(sig)
}

/// The EIP-191 keccak digest for `message` — the hash `personal_sign` signs and
/// ecrecover uses to recover the signer.
pub fn personal_sign_digest(message: &[u8]) -> [u8; 32] {
    let mut full = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    full.extend_from_slice(message);
    keccak256(&full)
}

/// Recover the 0x-address that signed a serialized EVM transaction.
pub fn recover_sender(raw: &[u8]) -> Result<String> {
    let tx = EvmTx::from_bytes(raw).map_err(Error::Env)?;
    tx.sender_address().map_err(Error::Env)
}

fn parse_dec(s: &str) -> Result<BigInt> {
    if s.is_empty() {
        return Ok(BigInt::from(0));
    }
    BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| Error::Env(format!("bad decimal amount {s:?}")))
}

/// The account IL (stored as a decimal JSON string) as a 32-byte tweak.
fn il_to_tweak(il: &serde_json::Value) -> Result<[u8; 32]> {
    let dec = il.as_str().ok_or_else(|| Error::Env("account has no IL tweak".into()))?;
    let n = BigInt::parse_bytes(dec.as_bytes(), 10).ok_or_else(|| Error::Env("bad IL".into()))?;
    let (_, mut b) = n.to_bytes_be();
    while b.len() < 32 {
        b.insert(0, 0);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[b.len() - 32..]);
    Ok(out)
}

fn secp_n() -> BigInt {
    BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}

/// Right-align `b` into a 32-byte big-endian buffer.
fn pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = b.len().min(32);
    out[32 - n..].copy_from_slice(&b[b.len() - n..]);
    out
}

/// Enforce EIP-2 low-s: if s > n/2, replace with n-s and flip the parity.
fn normalize_low_s(s: Vec<u8>, v: u8) -> (Vec<u8>, u8) {
    let n = secp_n();
    let half = &n >> 1;
    let sv = BigInt::from_bytes_be(Sign::Plus, &s);
    if sv > half {
        let (_, mut b) = (&n - &sv).to_bytes_be();
        while b.len() < 32 {
            b.insert(0, 0);
        }
        (b, v ^ 1)
    } else {
        (s, v)
    }
}
