//! Unsigned Solana transfer building, shared by `Transaction:signAndSend` (which
//! signs + broadcasts the message), `Transaction:validate` (which returns it) and
//! `Transaction:simulate` (which runs it through `simulateTransaction`). One
//! builder for the high-level tx fields — `from`/`to`/`amount`/`asset` — so the
//! preview and the send can never disagree about what gets signed.
//!
//! Async (chain I/O over `rpc::call_async`) so the browser's simulate path runs
//! the very same code; native callers drive it with `crate::rt::block_on`.

use base64::Engine as _;
use num_bigint::BigInt;
use serde_json::{json, Value};

use crate::models::account::Account;
use crate::models::network::Network;
use crate::Env;

use super::ApiError;

/// An SPL mint resolved from a tx `asset`: its owning token program and
/// decimals, plus the raw mint account data when it was already fetched.
pub(crate) struct SplMint {
    pub mint: [u8; 32],
    pub mint_b58: String,
    pub program: [u8; 32],
    /// `spl-token` | `spl-token-2022`.
    pub kind: String,
    pub decimals: u8,
    data: Option<Vec<u8>>,
}

/// A built, unsigned Solana transfer.
pub(crate) struct UnsignedSolana {
    /// The legacy message bytes — what the fee payer signs.
    pub message: Vec<u8>,
    /// Network fee in lamports (base signature fee + any priority fee).
    pub fee_lamports: u64,
    /// Transferred amount: lamports, or the token's base units.
    pub amount: u64,
    /// Decimals of [`Self::amount`] (9 for SOL, the mint's for SPL).
    pub decimals: i64,
    /// The tx carried the MAX sentinel, resolved to [`Self::amount`].
    pub amount_was_max: bool,
    /// The SPL mint for a token transfer; `None` for native SOL.
    pub token: Option<SplMint>,
    /// Recipient owner (base58).
    pub to: String,
    /// Recipient ATA for an SPL transfer (provisioned in-tx when missing).
    pub recipient_ata: Option<[u8; 32]>,
    /// The recent blockhash the message is anchored on (base58).
    pub blockhash: String,
}

impl UnsignedSolana {
    /// The wire transaction with an all-zero signature slot — what
    /// `simulateTransaction` (sigVerify false) and an external signer take.
    pub fn unsigned_tx(&self) -> Vec<u8> {
        crate::solana::assemble_tx(&self.message, &[0u8; 64])
    }
}

/// Whether an asset id names the chain's native coin (empty / "NATIVE" /
/// "<type>.<chainId>.NATIVE"), mirroring Go `isNativeAsset`.
pub(crate) fn is_native_asset(asset: &str) -> bool {
    asset.is_empty() || asset == "NATIVE" || asset.ends_with(".NATIVE")
}

/// Resolve a tx `asset` to an SPL mint (port of Go `resolveTokenAsset`, Solana
/// side). `None` for native SOL. Accepts a `tok-…` XUID, the canonical
/// "<type>.<chainId>.<mint>" asset key `Asset:list` returns, or a bare mint.
/// A mint missing from the Token table (Solana assets are discovered on-chain,
/// so most never are) is introspected on-chain: its owner names the token
/// program and byte 44 of the mint layout is its decimals.
pub(crate) async fn resolve_spl_asset(
    env: &Env,
    net: &Network,
    rpc: &str,
    asset: &str,
) -> Result<Option<SplMint>, ApiError> {
    if is_native_asset(asset) {
        return Ok(None);
    }
    let row = if xuid::Xuid::parse_prefix(asset, "tok").is_ok() {
        Some(
            crate::models::token::fetch(env, asset)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(400, format!("token {asset} not found")))?,
        )
    } else {
        None
    };
    let mint_b58 = match &row {
        Some(t) => t.address.clone(),
        None => asset.rsplit('.').next().unwrap_or("").to_string(),
    };
    let mint = b58_32(&mint_b58)
        .map_err(|_| ApiError::new(400, format!("asset {asset:?} is not a native asset, tok-… XUID or SPL mint")))?;

    // Registered token row: the stored id (net-…) or the deterministic id of
    // the canonical "<type>.<chainId>" an ephemeral network carries.
    let row = match row {
        Some(r) => Some(r),
        None => {
            let mut found = None;
            for id in [net.id.clone(), crate::models::network::network_id_for(&net.kind, &net.chain_id)] {
                if id.is_empty() {
                    continue;
                }
                if let Some(t) = crate::models::token::lookup_by_mint(env, &id, &mint_b58).map_err(ApiError::internal)? {
                    found = Some(t);
                    break;
                }
            }
            found
        }
    };
    if let Some(t) = row {
        let program = crate::solana_spl::token_program_for_type(&t.kind).map_err(|e| ApiError::new(400, e))?;
        let decimals = u8::try_from(t.decimals).map_err(|_| ApiError::new(400, "token decimals out of range"))?;
        return Ok(Some(SplMint { mint, mint_b58, program, kind: t.kind, decimals, data: None }));
    }

    // Unregistered: read the mint account.
    let (owner, data) = fetch_account(rpc, &mint_b58)
        .await?
        .ok_or_else(|| ApiError::new(400, format!("SPL mint {mint_b58} not found on chain")))?;
    let kind = match owner.as_str() {
        crate::solana_spl::SPL_TOKEN_PROGRAM_B58 => "spl-token",
        crate::solana_spl::TOKEN_2022_PROGRAM_B58 => "spl-token-2022",
        _ => return Err(ApiError::new(400, format!("{mint_b58} is not an SPL token mint"))),
    };
    let decimals = *data.get(44).ok_or_else(|| ApiError::new(502, format!("mint {mint_b58}: short account data")))?;
    let program = crate::solana_spl::token_program_for_type(kind).map_err(|e| ApiError::new(400, e))?;
    Ok(Some(SplMint { mint, mint_b58, program, kind: kind.to_string(), decimals, data: Some(data) }))
}

/// Build the unsigned transfer a tx describes (Go `buildSolanaTx`): a
/// SystemProgram transfer for native SOL, or for an SPL `asset` an idempotent
/// recipient-ATA create followed by `TransferChecked`. Resolves the MAX amount
/// sentinel on native sends (balance − fee − rent reserves) and anchors the
/// message on a freshly fetched blockhash.
pub(crate) async fn build_unsigned(
    env: &Env,
    account: &Account,
    net: &Network,
    rpc: &str,
    tx: &Value,
) -> Result<UnsignedSolana, ApiError> {
    if account.kind != "solana" {
        return Err(ApiError::new(400, format!("account {} is {}, not solana", account.id, account.kind)));
    }
    let asset = tx.get("asset").and_then(Value::as_str).unwrap_or("");
    let token = resolve_spl_asset(env, net, rpc, asset).await?;
    let to_b58 = tx
        .get("to")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "to is required"))?;
    let to = b58_32(to_b58)?;
    let from = crate::solana::pubkey_from_b64url(&account.pubkey).ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    let amount_was_max = tx
        .get("amount")
        .and_then(|v| serde_json::from_value::<crate::Amount>(v.clone()).ok())
        .map(|a| a.is_max())
        .unwrap_or(false);

    let Some(token) = token else {
        // Native SOL. A MAX send resolves to balance − fee − rent reserve, the
        // same math as Transaction:maxSendable (Go `preflightSolanaNativeSend`).
        let lamports = if amount_was_max {
            crate::solana::resolve_max_lamports(rpc, &account.address, to_b58, native_fee_lamports(tx))
                .await
                .map_err(|e| ApiError::new(400, e.to_string()))?
        } else {
            amount_u64(tx)?
        };
        let (blockhash, bh_b58) = recent_blockhash(rpc).await?;
        return Ok(UnsignedSolana {
            message: crate::solana::build_transfer_message(&from, &to, lamports, &blockhash),
            fee_lamports: crate::solana::SOLANA_BASE_FEE_LAMPORTS,
            amount: lamports,
            decimals: 9,
            amount_was_max,
            token: None,
            to: to_b58.to_string(),
            recipient_ata: None,
            blockhash: bh_b58,
        });
    };

    // SPL. MAX is native-only — reject it rather than silently sending zero.
    if amount_was_max {
        return Err(ApiError::new(400, "MAX amount is not supported for SPL token sends"));
    }
    let amount = amount_u64(tx)?;

    // Token-2022: an active transfer-fee extension needs the fee-carrying
    // instruction the Go build emits — out of scope here, so fail closed rather
    // than build a plain TransferChecked the program would revert.
    if token.kind == "spl-token-2022" {
        let data = match &token.data {
            Some(d) => d.clone(),
            None => fetch_account(rpc, &token.mint_b58)
                .await?
                .map(|(_, d)| d)
                .ok_or_else(|| ApiError::new(502, format!("mint {} not found or missing data", token.mint_b58)))?,
        };
        if let Some(cfg) = crate::solana_spl::token2022_transfer_fee(&data).map_err(|e| ApiError::new(502, e))? {
            if cfg.is_active() {
                return Err(ApiError::new(
                    501,
                    "Token-2022 mints with an active transfer-fee extension are not supported yet",
                ));
            }
        }
    }

    let sender_ata = crate::solana_spl::derive_ata(&from, &token.mint, &token.program)
        .ok_or_else(|| ApiError::new(500, "failed to derive sender ATA"))?;
    let recipient_ata = crate::solana_spl::derive_ata(&to, &token.mint, &token.program)
        .ok_or_else(|| ApiError::new(500, "failed to derive recipient ATA"))?;
    // A caller may pin computeUnitLimit / computeUnitPrice; otherwise the fixed
    // SPL default limit (covers the ATA-create prelude) and no priority price.
    let cu_limit = tx
        .get("computeUnitLimit")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .filter(|v| *v > 0)
        .unwrap_or(crate::solana_spl::SPL_DEFAULT_CU_LIMIT);
    let cu_price = tx.get("computeUnitPrice").and_then(Value::as_u64).unwrap_or(0);
    let (blockhash, bh_b58) = recent_blockhash(rpc).await?;
    let message = crate::solana_spl::build_spl_transfer_message(
        &from,
        &to,
        &token.mint,
        &sender_ata,
        &recipient_ata,
        &token.program,
        amount,
        token.decimals,
        &blockhash,
        cu_limit,
        cu_price,
    );
    Ok(UnsignedSolana {
        message,
        fee_lamports: crate::solana_spl::fee_lamports(cu_limit, cu_price),
        amount,
        decimals: token.decimals as i64,
        amount_was_max,
        token: Some(token),
        to: to_b58.to_string(),
        recipient_ata: Some(recipient_ata),
        blockhash: bh_b58,
    })
}

/// Whether a Solana account exists (`getAccountInfo` value non-null). `None`
/// when the node can't say.
pub(crate) async fn account_exists(rpc: &str, address: &str) -> Option<bool> {
    let info = crate::rpc::call_async(rpc, "getAccountInfo", json!([address, { "encoding": "base64" }]))
        .await
        .ok()?;
    Some(info.get("value").map(|v| !v.is_null()).unwrap_or(false))
}

/// `getAccountInfo` (base64): the owner program (base58) and decoded data, or
/// `None` when the account doesn't exist.
async fn fetch_account(rpc: &str, address: &str) -> Result<Option<(String, Vec<u8>)>, ApiError> {
    let resp = crate::rpc::call_async(rpc, "getAccountInfo", json!([address, { "encoding": "base64" }]))
        .await
        .map_err(ApiError::internal)?;
    let Some(value) = resp.get("value").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let owner = value.get("owner").and_then(Value::as_str).unwrap_or("").to_string();
    let data_b64 = value
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(502, format!("account {address} missing data")))?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| ApiError::new(502, format!("bad base64 account data: {e}")))?;
    Ok(Some((owner, data)))
}

/// A recent blockhash (finalized, matching Go's commitment), raw and base58.
async fn recent_blockhash(rpc: &str) -> Result<([u8; 32], String), ApiError> {
    let bh = crate::rpc::call_async(rpc, "getLatestBlockhash", json!([{ "commitment": "finalized" }]))
        .await
        .map_err(ApiError::internal)?;
    let bh_b58 = bh
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(502, "no blockhash in getLatestBlockhash response"))?;
    Ok((b58_32(bh_b58)?, bh_b58.to_string()))
}

/// The fee (lamports) a MAX native send reserves: the caller's `fee` Amount when
/// present, else the flat base signature fee (Go's priority-inclusive `tx.Fee`
/// with a 5000 fallback).
fn native_fee_lamports(tx: &Value) -> u64 {
    tx.get("fee")
        .and_then(|v| serde_json::from_value::<crate::Amount>(v.clone()).ok())
        .and_then(|a| a.value().and_then(|b| u64::try_from(b).ok()))
        .unwrap_or(crate::solana::SOLANA_BASE_FEE_LAMPORTS)
}

/// The tx `amount` significand ({v,e,f} object or decimal string) as u64 base
/// units.
fn amount_u64(tx: &Value) -> Result<u64, ApiError> {
    let v = tx.get("amount").ok_or_else(|| ApiError::new(400, "amount is required"))?;
    let s = match v {
        Value::Object(m) => m.get("v").and_then(Value::as_str),
        Value::String(s) => Some(s.as_str()),
        _ => None,
    }
    .ok_or_else(|| ApiError::new(400, "amount is required"))?;
    let bi = BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| ApiError::new(400, "invalid amount"))?;
    u64::try_from(&bi).map_err(|_| ApiError::new(400, "amount exceeds representable u64 base units"))
}

/// Decode a base58 string into a 32-byte array (Solana pubkey / blockhash).
fn b58_32(s: &str) -> Result<[u8; 32], ApiError> {
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| ApiError::new(400, format!("bad base58 32-byte value: {s}")))
}
