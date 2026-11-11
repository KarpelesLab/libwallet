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

/// outscript 0.2 reports a structured `outscript::Error` where it used to hand
/// back a `String`, so the conversion into our own error needs a step.
fn oserr(e: outscript::Error) -> Error {
    Error::Env(e.to_string())
}

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
/// `account_id`. `unlock` provides the creds for at least threshold+1 of the
/// wallet's shares (any 2 of a 2-of-3). Returns the raw signed tx bytes.
pub fn sign_tx(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    req: &EvmTxRequest,
) -> Result<Vec<u8>> {
    let acct = account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    if acct.kind != "ethereum" {
        return Err(Error::Env("EVM transaction signing is ethereum-account-only".into()));
    }
    validate_to(&req.to, &req.data)?;
    let tweak = il_to_tweak(&acct.il)?;

    let tx = build_unsigned(req)?;
    let sign_bytes = tx.sign_bytes().map_err(oserr)?;
    let digest = keccak256(&sign_bytes);
    let (r, s, v) = wallet::dkls_sign_digest_at(env, &acct.wallet, unlock, &acct.path, &tweak, &digest)?;
    let (s, v) = normalize_low_s(s, v);
    let raw = attach_signature(tx, &r, &s, v)?;
    // Never hand back a transaction the account didn't sign: the serialized tx
    // must recover to the account's own address.
    let sender = recover_sender(&raw)?;
    if !sender.eq_ignore_ascii_case(&acct.address) {
        return Err(Error::Env(format!(
            "signed transaction recovers to {sender}, not the account address {}",
            acct.address
        )));
    }
    Ok(raw)
}

/// Check a transaction's `to`: a `0x`-prefixed 20-byte hex address whose EIP-55
/// checksum must hold when it is written in mixed case (all-lowercase and
/// all-uppercase carry no checksum). A bare `0x` — contract creation — is only
/// accepted together with init code in `data`; without it the transaction would
/// send its value to nobody.
pub fn validate_to(to: &str, data: &[u8]) -> Result<()> {
    let digits = to
        .strip_prefix("0x")
        .ok_or_else(|| Error::Env("transaction `to` must be a 0x-prefixed address".into()))?;
    if digits.is_empty() {
        if data.is_empty() {
            return Err(Error::Env("transaction `to` is required (contract creation needs data)".into()));
        }
        return Ok(());
    }
    if digits.len() != 40 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Env(format!("transaction `to` {to:?} is not a 20-byte hex address")));
    }
    let has_upper = digits.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = digits.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        let mut addr = [0u8; 20];
        for (i, pair) in digits.as_bytes().chunks(2).enumerate() {
            // Both are ASCII hex digits (checked above).
            let hi = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
            addr[i] = (hi << 4) | lo;
        }
        if outscript::address::eip55(&addr) != to {
            return Err(Error::Env(format!("transaction `to` {to:?} has a bad EIP-55 checksum")));
        }
    }
    Ok(())
}

/// The unsigned transaction for `req` (legacy EIP-155 or EIP-1559). Its
/// `sign_bytes()` is the signing preimage: for legacy the EIP-155 RLP, for
/// type-2 `0x02 || rlp(...)` — exactly what an external signer's
/// `eth-sign-request` carries as sign-data.
///
/// A zero chain id is refused: a legacy tx signed with it carries a pre-EIP-155
/// signature, valid on every chain. So is one too large for the legacy
/// `v = chain_id*2 + 35 + parity` to fit a u64.
pub fn build_unsigned(req: &EvmTxRequest) -> Result<EvmTx> {
    check_chain_id(req.chain_id)?;
    // EvmTx is #[non_exhaustive]: start from the default and set the fields.
    let mut tx = EvmTx::default();
    tx.nonce = req.nonce;
    tx.gas = req.gas;
    tx.gas_fee_cap = parse_dec(&req.max_fee)?;
    tx.gas_tip_cap = if req.eip1559 { parse_dec(&req.max_priority)? } else { BigInt::from(0) };
    tx.to = req.to.clone();
    tx.value = parse_dec(&req.value)?;
    tx.data = req.data.clone();
    tx.chain_id = req.chain_id;
    tx.tx_type = if req.eip1559 { EvmTxType::Eip1559 } else { EvmTxType::Legacy };
    Ok(tx)
}

/// The largest chain id whose legacy `v` (`chain_id*2 + 35 + parity`) fits a u64.
const MAX_CHAIN_ID: u64 = (u64::MAX - 36) / 2;

fn check_chain_id(chain_id: u64) -> Result<()> {
    if chain_id == 0 {
        return Err(Error::Env("chain id is required (0 would sign a transaction replayable on every chain)".into()));
    }
    if chain_id > MAX_CHAIN_ID {
        return Err(Error::Env(format!("chain id {chain_id} is out of range")));
    }
    Ok(())
}

/// Attach an ECDSA signature (`r`, low-`s`, recovery `parity` 0/1) to an
/// unsigned tx and serialize it. Legacy EIP-155: v = chain_id*2 + 35 + parity;
/// EIP-1559: v = parity.
pub fn attach_signature(mut tx: EvmTx, r: &[u8], s: &[u8], parity: u8) -> Result<Vec<u8>> {
    if parity > 1 {
        return Err(Error::Env(format!("bad signature parity {parity}")));
    }
    check_chain_id(tx.chain_id)?;
    tx.signed = true;
    tx.r = BigInt::from_bytes_be(Sign::Plus, r);
    tx.s = BigInt::from_bytes_be(Sign::Plus, s);
    tx.y = if tx.tx_type == EvmTxType::Eip1559 {
        BigInt::from(parity as u64)
    } else {
        BigInt::from(tx.chain_id * 2 + 35 + parity as u64)
    };
    tx.to_bytes().map_err(oserr)
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
    let (r, s, v) = wallet::dkls_sign_digest_at(env, &acct.wallet, unlock, &acct.path, tweak, digest)?;
    let (s, v) = normalize_low_s(s, v);
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&pad32(&r));
    sig.extend_from_slice(&pad32(&s));
    sig.push(27 + v);
    Ok(sig)
}

/// DKLs-sign a 32-byte `digest` with `acct`'s secp256k1 key (its HD path and IL
/// tweak applied) into the 65-byte recoverable `r || s || v` form, low-S, with
/// `v` the raw recovery id (0/1). The chain-neutral core that Tron signs its
/// transaction ids with; EVM callers add their own `v` offset.
pub fn sign_digest_recoverable(
    env: &Env,
    acct: &account::Account,
    unlock: &[(String, String)],
    digest: &[u8; 32],
) -> Result<[u8; 65]> {
    let tweak = il_to_tweak(&acct.il)?;
    let (r, s, v) = wallet::dkls_sign_digest_at(env, &acct.wallet, unlock, &acct.path, &tweak, digest)?;
    let (s, v) = normalize_low_s(s, v);
    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(&pad32(&r));
    sig[32..64].copy_from_slice(&pad32(&s));
    sig[64] = v;
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
    let tx = EvmTx::from_bytes(raw).map_err(oserr)?;
    tx.sender_address().map_err(oserr)
}

/// Recover the EIP-55 signer address from an EIP-191 personal-sign `message`
/// and its 65-byte `R || S || V` signature (`web3_provider` / `personal_ecRecover`).
pub fn personal_ec_recover(message: &[u8], signature: &[u8]) -> Result<String> {
    recover_digest_address(&personal_sign_digest(message), signature).map_err(|e| Error::Env(format!("personal_ecRecover: {e}")))
}

/// The EIP-55 address whose key made the 65-byte `R || S || V` signature over
/// `digest`. V is 27/28 or a raw 0/1 recovery id.
pub fn recover_digest_address(digest: &[u8; 32], signature: &[u8]) -> Result<String> {
    use purecrypto::bignum::BoxedUint;
    use purecrypto::ec::boxed::BoxedEcdsaSignature;
    use purecrypto::ec::CurveId;
    if signature.len() != 65 {
        return Err(Error::Env("signature must be 65 bytes".into()));
    }
    let r = BoxedUint::from_be_bytes(&signature[0..32]);
    let s = BoxedUint::from_be_bytes(&signature[32..64]);
    let recid = if signature[64] >= 27 { signature[64] - 27 } else { signature[64] };
    let sig = BoxedEcdsaSignature::from_components(r, s);
    let pk = sig.recover_prehash(CurveId::Secp256k1, digest, recid).map_err(|e| Error::Env(format!("{e:?}")))?;
    let addr = outscript::hash::ether_hash(&pk.to_sec1()); // strips the 0x04 prefix
    Ok(outscript::address::eip55(&addr))
}

/// A device's 64/65-byte signature over `digest`, as `R || S || V` with V
/// 27/28 — accepted only if it recovers to `address` (an EVM `0x…` address).
/// The V the device reported is tried first, then the other parity: what
/// decides is the recovered signer.
pub fn rsv_for_address(digest: &[u8; 32], signature: &[u8], address: &str) -> Result<[u8; 65]> {
    if signature.len() != 64 && signature.len() != 65 {
        return Err(Error::Env(format!("signature must be 64/65 bytes, got {}", signature.len())));
    }
    let hint = match signature.get(64).copied() {
        Some(v) if v >= 35 => ((v as u64 - 35) % 2) as u8,
        Some(v) if v >= 27 => (v - 27) & 1,
        Some(v) => v & 1,
        None => 0,
    };
    let mut rsv = [0u8; 65];
    rsv[..64].copy_from_slice(&signature[..64]);
    for parity in [hint, 1 - hint] {
        rsv[64] = 27 + parity;
        if recover_digest_address(digest, &rsv).is_ok_and(|from| from.eq_ignore_ascii_case(address)) {
            return Ok(rsv);
        }
    }
    Err(Error::Env(format!("the signature is not from {address}")))
}

fn parse_dec(s: &str) -> Result<BigInt> {
    if s.is_empty() {
        return Ok(BigInt::from(0));
    }
    BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| Error::Env(format!("bad decimal amount {s:?}")))
}

/// The account IL (stored as a decimal JSON string) as a 32-byte tweak. A
/// Null/absent IL means the account uses null derivation — it IS the group key
/// — so the tweak is the zero tweak (child at tweak 0 == the group key), and
/// signing verifies under `evm_address(group_pub)`.
fn il_to_tweak(il: &serde_json::Value) -> Result<[u8; 32]> {
    let Some(dec) = il.as_str() else { return Ok([0u8; 32]) };
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
