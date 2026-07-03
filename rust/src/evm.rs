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

/// A legacy EVM transaction request (amounts as decimal-wei strings so the
/// public API stays free of BigInt).
pub struct LegacyTxRequest {
    pub nonce: u64,
    pub gas: u64,
    pub gas_price: String,
    pub to: String,
    pub value: String,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

/// Build, DKLs-sign, and serialize a legacy transaction for `account_id`.
/// `unlock` provides the Password creds for ALL of the wallet's shares (DKLs
/// signing needs the full set). Returns the raw signed transaction bytes.
pub fn sign_legacy_tx(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    req: &LegacyTxRequest,
) -> Result<Vec<u8>> {
    let acct = account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    let tweak = il_to_tweak(&acct.il)?;

    let mut tx = EvmTx {
        nonce: req.nonce,
        gas: req.gas,
        gas_fee_cap: parse_dec(&req.gas_price)?,
        gas_tip_cap: BigInt::from(0),
        to: req.to.clone(),
        value: parse_dec(&req.value)?,
        data: req.data.clone(),
        chain_id: req.chain_id,
        tx_type: EvmTxType::Legacy,
        ..Default::default()
    };

    let sign_bytes = tx.sign_bytes().map_err(Error::Env)?;
    let digest = keccak256(&sign_bytes);
    let (r, s, v) = wallet::dkls_sign_digest(env, &acct.wallet, unlock, &tweak, &digest)?;
    let (s, v) = normalize_low_s(s, v);

    tx.signed = true;
    tx.r = BigInt::from_bytes_be(Sign::Plus, &r);
    tx.s = BigInt::from_bytes_be(Sign::Plus, &s);
    // Legacy EIP-155: v = chain_id*2 + 35 + y_parity.
    tx.y = BigInt::from(req.chain_id * 2 + 35 + v as u64);

    tx.to_bytes().map_err(Error::Env)
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
