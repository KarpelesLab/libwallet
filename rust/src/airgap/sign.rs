//! Unsigned requests for an air-gapped signer, and turning its answer into a
//! broadcastable transaction.
//!
//! [`build_request`] takes the same `Transaction` object the TSS
//! `Account:signAndSendTransaction` accepts and produces, per chain:
//!
//! - **bitcoin** → a BIP-174 PSBT with `witness_utxo` (+ `redeem_script` for
//!   wrapped segwit, `non_witness_utxo` for legacy when the node can supply the
//!   previous tx) and a `bip32_derivation` per input/change output naming the
//!   signer's master fingerprint and full path — what Keystone / Coldcard /
//!   SeedSigner need to find the key. UR `crypto-psbt` or BBQr `P`.
//! - **ethereum** → `eth-sign-request` whose sign-data is the exact signing
//!   preimage (EIP-155 RLP for legacy, `0x02||rlp` for type-2), with the leaf
//!   derivation path + fingerprint. The signer answers with just the 65-byte
//!   signature (`eth-signature`); we attach it to the unsigned tx.
//! - **solana** → `sol-sign-request` carrying the serialized message; the
//!   signer answers `sol-signature` (64 bytes) and we assemble the tx.
//!
//! Every request gets a uuid `request-id`; the unsigned material is kept in
//! the Env cache under it so [`accept`] can match the signer's response (or
//! the host passes `RequestId` explicitly for signed PSBTs, which carry none).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use std::time::Duration;

use super::decoder::Payload;
use super::import::{account_key_info, AccountKeyInfo};
use super::registry::{self, EthDataType, EthSignRequest, EthSignature, KeyPath, SolSignRequest, SolSignType, SolSignature};
use super::Transport;
use crate::models::account::Account;
use crate::{Env, Error, Result};

const PENDING_TTL: Duration = Duration::from_secs(24 * 3600);

/// An unsigned request awaiting the signer, as stored in the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub request_id: String,
    pub account: String,
    /// `bitcoin` | `ethereum` | `solana`.
    pub chain: String,
    /// bitcoin: the unsigned PSBT (hex). ethereum: the EvmTxRequest as JSON.
    /// solana: the message bytes (hex).
    pub unsigned: Json,
    /// What the signer is asked to sign (hex): PSBT bytes, EVM sign-data,
    /// Solana message.
    pub sign_data: String,
    pub created: String,
}

fn pending_key(id: &str) -> String {
    format!("airgap:req:{id}")
}

pub fn pending_save(env: &Env, p: &Pending) -> Result<()> {
    env.cache_store(&pending_key(&p.request_id), &serde_json::to_vec(p).map_err(|e| Error::Env(e.to_string()))?, PENDING_TTL)
}

pub fn pending_load(env: &Env, id: &str) -> Result<Option<Pending>> {
    Ok(env.cache_load(&pending_key(id))?.and_then(|b| serde_json::from_slice(&b).ok()))
}

pub fn pending_delete(env: &Env, id: &str) -> Result<()> {
    env.cache_delete(&[&pending_key(id)])
}

/// Framing options.
#[derive(Debug, Clone, Default)]
pub struct Framing {
    pub transport: Transport,
    pub max_fragment_len: Option<usize>,
    pub max_part_len: Option<usize>,
    pub extra_parts: Option<usize>,
}

/// A built request, ready to display.
#[derive(Debug, Clone, Serialize)]
pub struct Built {
    pub request_id: String,
    pub chain: String,
    pub account: String,
    pub transport: String,
    /// UR type (`crypto-psbt`, `eth-sign-request`, `sol-sign-request`) or the
    /// BBQr file type letter.
    pub format: String,
    /// The QR frames, in display order (loop them for an animated QR).
    pub parts: Vec<String>,
    /// The unsigned material for hosts with another channel: `psbt` (base64),
    /// `signData` (hex), `message` (base58) — plus a human summary.
    pub payload: Json,
}

fn fp_bytes(info: &AccountKeyInfo) -> Result<[u8; 4]> {
    let s = info.master_fingerprint.as_deref().ok_or_else(|| Error::Env("signer master fingerprint unknown for this account — re-import the key with its origin".into()))?;
    let b = super::unhex(s)?;
    b.as_slice().try_into().map_err(|_| Error::Env("bad master fingerprint".into()))
}

fn fp_u32(info: &AccountKeyInfo) -> Option<u32> {
    info.master_fingerprint.as_deref().and_then(|s| super::unhex(s).ok()).and_then(|b| b.as_slice().try_into().ok()).map(u32::from_be_bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|e| Error::Env(format!("base64url: {e}")))
}

fn load_airgap_account(env: &Env, account_id: &str) -> Result<(Account, AccountKeyInfo)> {
    let account = crate::models::account::fetch(env, account_id)?.ok_or_else(|| Error::Env("account not found".into()))?;
    let wallet = crate::models::wallet::fetch(env, &account.wallet)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    if wallet.protocol != "airgap" {
        return Err(Error::Env(format!("account {account_id} is not on an air-gapped signer wallet (protocol {})", wallet.protocol)));
    }
    let info = account_key_info(env, account_id)?.unwrap_or(AccountKeyInfo { master_fingerprint: None, path: account.path.clone(), script: String::new(), curve: account.curve.clone() });
    Ok((account, info))
}

/// Build the unsigned request for `account_id`. `tx` is the `Transaction`
/// object; `rpc` (optional) fills nonce/gas/blockhash/UTXOs from the node —
/// without it the host must supply them.
pub fn build_request(env: &Env, account_id: &str, tx: &Json, framing: &Framing, rpc: Option<&str>) -> Result<Built> {
    let (account, info) = load_airgap_account(env, account_id)?;
    let request_id = registry::new_request_id();
    let rid = registry::uuid_hyphenated(&request_id);
    match account.kind.as_str() {
        "bitcoin" => build_bitcoin(env, &account, &info, tx, framing, rpc, &rid),
        "ethereum" => build_ethereum(env, &account, &info, tx, framing, rpc, request_id),
        "solana" => build_solana(env, &account, &info, tx, framing, rpc, request_id),
        other => Err(Error::Env(format!("air-gap signing not supported for {other} accounts"))),
    }
}

fn frames(ur_type: &str, cbor: &[u8], bbqr_type: outscript::bbqr::FileType, raw_for_bbqr: &[u8], f: &Framing) -> Result<(String, Vec<String>)> {
    match f.transport {
        Transport::Ur => Ok((ur_type.to_owned(), super::ur_parts(ur_type, cbor, f.max_fragment_len, f.extra_parts)?)),
        Transport::Bbqr => Ok((bbqr_type.as_char().to_string(), super::bbqr_parts(raw_for_bbqr, bbqr_type, f.max_part_len, true)?)),
    }
}

// ── Bitcoin: PSBT ────────────────────────────────────────────────────────────

fn build_bitcoin(env: &Env, account: &Account, info: &AccountKeyInfo, tx: &Json, framing: &Framing, rpc: Option<&str>, rid: &str) -> Result<Built> {
    use crate::bitcoin::DiscoveredUtxo;
    use outscript::btcraw::{RawTx, RawTxIn, RawTxOut};
    use outscript::psbt::Psbt;

    let to = tx.get("To").or_else(|| tx.get("to")).and_then(Json::as_str).ok_or_else(|| Error::Env("Transaction.To required".into()))?;
    let want_sats = tx.get("Amount").or_else(|| tx.get("amount")).and_then(Json::as_u64).ok_or_else(|| Error::Env("Transaction.Amount (sats) required".into()))?;
    let fee_rate = tx.get("FeeRate").and_then(Json::as_u64).unwrap_or(10);
    let chain_id = tx.get("ChainId").and_then(Json::as_str).unwrap_or("bitcoin");
    let script = if info.script.is_empty() { "p2wpkh" } else { info.script.as_str() };

    let account_pub: [u8; 33] = b64url_decode(&account.pubkey)?.try_into().map_err(|_| Error::Env("account pubkey not 33 bytes".into()))?;
    let account_cc: [u8; 32] = b64url_decode(&account.chaincode)?.try_into().map_err(|_| Error::Env("account chaincode not 32 bytes".into()))?;
    let origin = KeyPath::parse(&info.path)?;
    let fp = fp_bytes(info)?;

    // UTXOs: supplied (offline) or discovered through the node.
    let all: Vec<DiscoveredUtxo> = match tx.get("UTXOs").and_then(Json::as_array) {
        Some(arr) if !arr.is_empty() => arr
            .iter()
            .map(|u| {
                Ok(DiscoveredUtxo {
                    txo: u.get("txo").and_then(Json::as_str).ok_or_else(|| Error::Env("UTXO txo required".into()))?.to_owned(),
                    amount_sats: u.get("amount_sats").or_else(|| u.get("amount")).and_then(Json::as_u64).ok_or_else(|| Error::Env("UTXO amount_sats required".into()))?,
                    height: u.get("height").and_then(Json::as_i64).unwrap_or(0),
                    path: u.get("path").and_then(Json::as_str).unwrap_or("m/0/0").to_owned(),
                    script: u.get("script").and_then(Json::as_str).unwrap_or(script).to_owned(),
                })
            })
            .collect::<Result<_>>()?,
        _ => {
            let url = rpc.ok_or_else(|| Error::Env("no RPC: pass Transaction.UTXOs or an RPC/network to discover them".into()))?;
            crate::bitcoin::list_utxos(url, &account.xpub()?)?
        }
    };
    if all.is_empty() {
        return Err(Error::Env("no spendable UTXOs".into()));
    }
    let (selected, total_in) = crate::bitcoin::select_utxos(&all, want_sats, fee_rate)?;
    let fee = crate::bitcoin::estimate_vsize(&selected, 2) * fee_rate;
    if total_in < want_sats + fee {
        return Err(Error::Env(format!("insufficient funds: {total_in} < {want_sats} + fee {fee}")));
    }
    let change = total_in - want_sats - fee;

    // Per-input key + scriptPubKey.
    struct In {
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        child_pub: [u8; 33],
        path: Vec<u32>,
        script_pubkey: Vec<u8>,
        redeem: Option<Vec<u8>>,
        scheme: String,
    }
    let mut ins = Vec::with_capacity(selected.len());
    for u in &selected {
        let (txid, vout) = crate::bitcoin::parse_txo_ref(&u.txo)?;
        let (child_pub, _) = crate::hdderive::derive_pub_tweak(&account_pub, &account_cc, &[u.chain(), u.child_index()]).map_err(|e| Error::Env(e.to_string()))?;
        let scheme = if u.script.is_empty() { script.to_owned() } else { u.script.clone() };
        let pk = outscript::crypto::secp256k1::SecpPublicKey::from_sec1(&child_pub).map_err(|e| Error::Env(format!("{e:?}")))?;
        let s = outscript::script::Script::new(pk);
        let script_pubkey = s.out(&scheme).map_err(|e| Error::Env(format!("script {scheme}: {e}")))?.bytes().to_vec();
        let redeem = if scheme == "p2sh:p2wpkh" { Some(s.out("p2wpkh").map_err(|e| Error::Env(format!("{e}")))?.bytes().to_vec()) } else { None };
        let mut path = origin.components.clone();
        path.extend([u.chain(), u.child_index()]);
        ins.push(In { txid, vout, amount: u.amount_sats, child_pub, path, script_pubkey, redeem, scheme });
    }

    // Outputs via BtcTx::add_output for address → scriptPubKey.
    let mut btx = outscript::btctx::BtcTx { version: 2, locktime: 0, ..Default::default() };
    btx.add_output(to, want_sats).map_err(|e| Error::Env(format!("recipient: {e}")))?;
    let mut change_info: Option<([u8; 33], Vec<u32>)> = None;
    if change > 546 {
        let idx = crate::bitcoin::next_change_index(&all);
        let (child, _) = crate::hdderive::derive_pub_tweak(&account_pub, &account_cc, &[1, idx]).map_err(|e| Error::Env(e.to_string()))?;
        let tag = if chain_id == "bitcoin-cash" { "bitcoincash" } else { chain_id };
        let addr = crate::bitcoin::address_for(&child, script, tag)?;
        btx.add_output(&addr, change).map_err(|e| Error::Env(format!("change: {e}")))?;
        let mut p = origin.components.clone();
        p.extend([1, idx]);
        change_info = Some((child, p));
    }
    let amounts = [want_sats, change];
    let raw_ins: Vec<RawTxIn> = ins.iter().map(|i| RawTxIn { txid: i.txid, vout: i.vout, script_sig: &[], sequence: 0xffff_fffd, witness: &[] }).collect();
    let raw_outs: Vec<RawTxOut> = btx.outputs.iter().enumerate().map(|(n, o)| RawTxOut { amount: amounts[n], script: &o.script }).collect();
    let raw = RawTx { version: 2, inputs: &raw_ins, outputs: &raw_outs, locktime: 0 };

    let mut psbt = Psbt::create_to_vec(&raw).map_err(|e| Error::Env(format!("psbt create: {e}")))?;
    let sighash: u32 = if chain_id == "bitcoin-cash" { 0x41 } else { 1 };
    for (n, i) in ins.iter().enumerate() {
        psbt = with_psbt(&psbt, |p, out| p.set_witness_utxo(n, i.amount, &i.script_pubkey, out))?;
        if let Some(r) = &i.redeem {
            psbt = with_psbt(&psbt, |p, out| p.set_redeem_script(n, r, out))?;
        }
        if i.scheme == "p2pkh" {
            // Legacy inputs need the whole previous transaction; fetch it when a
            // node is available (bitcoind-style getrawtransaction).
            if let Some(url) = rpc {
                let txid_hex = super::hex(&i.txid);
                if let Ok(Json::String(h)) = crate::rpc::call(url, "getrawtransaction", json!([txid_hex])) {
                    if let Ok(prev) = super::unhex(&h) {
                        psbt = with_psbt(&psbt, |p, out| p.set_non_witness_utxo(n, &prev, out))?;
                    }
                }
            }
        }
        if i.scheme == "p2tr" {
            let xonly: [u8; 32] = i.child_pub[1..].try_into().unwrap();
            psbt = with_psbt(&psbt, |p, out| p.set_tap_internal_key(n, &xonly, out))?;
            // PSBT_IN_TAP_BIP32_DERIVATION (0x16): key = xonly pubkey, value =
            // compact-size(0 leaf hashes) || fingerprint || path (LE u32s).
            let mut key = vec![0x16];
            key.extend_from_slice(&xonly);
            let mut val = vec![0u8];
            val.extend_from_slice(&fp);
            for c in &i.path {
                val.extend_from_slice(&c.to_le_bytes());
            }
            psbt = with_psbt(&psbt, |p, out| p.set_input_record(n, &key, &val, out))?;
        } else {
            psbt = with_psbt(&psbt, |p, out| p.add_input_bip32_derivation(n, &i.child_pub, fp, &i.path, out))?;
        }
        if sighash != 1 {
            psbt = with_psbt(&psbt, |p, out| p.set_sighash_type(n, sighash, out))?;
        }
    }
    if let Some((child, path)) = &change_info {
        psbt = with_psbt(&psbt, |p, out| p.add_output_bip32_derivation(1, child, fp, path, out))?;
    }

    use base64::Engine;
    let psbt_b64 = base64::engine::general_purpose::STANDARD.encode(&psbt);
    let cbor = registry::psbt_to_cbor(&psbt);
    let (format, parts) = frames(registry::UR_PSBT, &cbor, outscript::bbqr::FileType::PSBT, &psbt, framing)?;
    let pending = Pending {
        request_id: rid.to_owned(),
        account: account.id.clone(),
        chain: "bitcoin".into(),
        unsigned: json!({ "psbt": super::hex(&psbt), "chainId": chain_id }),
        sign_data: super::hex(&psbt),
        created: crate::now_rfc3339(),
    };
    pending_save(env, &pending)?;
    Ok(Built {
        request_id: rid.to_owned(),
        chain: "bitcoin".into(),
        account: account.id.clone(),
        transport: framing.transport.as_str().into(),
        format,
        parts,
        payload: json!({
            "psbt": psbt_b64,
            "summary": { "to": to, "amount_sats": want_sats, "fee_sats": fee, "change_sats": change, "inputs": ins.len(), "feeRate": fee_rate, "chainId": chain_id },
        }),
    })
}

/// Apply one `*_to_slice` PSBT updater into a fresh Vec.
fn with_psbt<F>(psbt: &[u8], f: F) -> Result<Vec<u8>>
where
    F: Fn(&outscript::psbt::Psbt<'_>, &mut [u8]) -> std::result::Result<usize, outscript::Error>,
{
    let p = outscript::psbt::Psbt::parse(psbt).map_err(|e| Error::Env(format!("psbt: {e}")))?;
    let mut out = vec![0u8; psbt.len() + 1024];
    let n = f(&p, &mut out).map_err(|e| Error::Env(format!("psbt update: {e}")))?;
    out.truncate(n);
    Ok(out)
}

// ── Ethereum: eth-sign-request ───────────────────────────────────────────────

fn build_ethereum(env: &Env, account: &Account, info: &AccountKeyInfo, tx: &Json, framing: &Framing, rpc: Option<&str>, request_id: [u8; 16]) -> Result<Built> {
    // Fill nonce/gas/fees from the node when asked; otherwise the caller's
    // Transaction must be complete (offline flow).
    let tx = match rpc {
        Some(url) => {
            let params = json!({ "Transaction": tx });
            let filled = crate::rt::block_on(crate::handlers::account::evm_fill(account, url, &params)).map_err(|e| Error::Env(e.message))?;
            filled["Transaction"].clone()
        }
        None => tx.clone(),
    };
    for required in ["nonce", "gas", "chainId"] {
        if tx.get(required).is_none() {
            return Err(Error::Env(format!("Transaction.{required} required (or pass RPC/Network to fill it)")));
        }
    }
    if tx.get("gasPrice").is_none() && tx.get("maxFeePerGas").is_none() {
        return Err(Error::Env("Transaction.gasPrice or maxFeePerGas required (or pass RPC/Network to fill it)".into()));
    }
    let req = crate::handlers::account::evm_request_from_tx(&tx).map_err(|e| Error::Env(e.message))?;
    let unsigned = crate::evm::build_unsigned(&req)?;
    let sign_data = unsigned.sign_bytes().map_err(|e| Error::Env(format!("{e}")))?;

    let mut path = KeyPath::parse(&info.path)?;
    path.source_fingerprint = fp_u32(info);
    let address: Option<[u8; 20]> = super::unhex(&account.address).ok().and_then(|a| a.try_into().ok());
    let r = EthSignRequest {
        request_id,
        sign_data: sign_data.clone(),
        data_type: if req.eip1559 { EthDataType::TypedTransaction } else { EthDataType::Transaction },
        chain_id: Some(req.chain_id),
        derivation_path: path,
        address,
        origin: Some("libwallet".into()),
    };
    let cbor = super::cbor::to_bytes(&r.to_cbor())?;
    let (format, parts) = frames(registry::UR_ETH_SIGN_REQUEST, &cbor, outscript::bbqr::FileType::CBOR, &cbor, framing)?;
    let rid = registry::uuid_hyphenated(&request_id);
    pending_save(
        env,
        &Pending {
            request_id: rid.clone(),
            account: account.id.clone(),
            chain: "ethereum".into(),
            unsigned: tx.clone(),
            sign_data: super::hex(&sign_data),
            created: crate::now_rfc3339(),
        },
    )?;
    Ok(Built {
        request_id: rid,
        chain: "ethereum".into(),
        account: account.id.clone(),
        transport: framing.transport.as_str().into(),
        format,
        parts,
        payload: json!({
            "signData": format!("0x{}", super::hex(&sign_data)),
            "dataType": r.data_type as u8,
            "transaction": tx,
            "derivationPath": info.path,
        }),
    })
}

// ── Solana: sol-sign-request ─────────────────────────────────────────────────

fn build_solana(env: &Env, account: &Account, info: &AccountKeyInfo, tx: &Json, framing: &Framing, rpc: Option<&str>, request_id: [u8; 16]) -> Result<Built> {
    let from = crate::solana::pubkey_from_b64url(&account.pubkey).ok_or_else(|| Error::Env("bad account pubkey".into()))?;
    // Either a prebuilt message (dApp tx) or a transfer {to, value, recentBlockhash?}.
    let message: Vec<u8> = if let Some(m) = tx.get("message").or_else(|| tx.get("Message")).and_then(Json::as_str) {
        decode_b58_or_b64(m)?
    } else {
        let to_b58 = tx.get("to").and_then(Json::as_str).ok_or_else(|| Error::Env("Transaction.to required".into()))?;
        let lamports: u64 = tx.get("value").and_then(Json::as_str).and_then(|s| s.parse().ok()).unwrap_or(0);
        let bh_b58 = match tx.get("recentBlockhash").and_then(Json::as_str) {
            Some(b) => b.to_owned(),
            None => {
                let url = rpc.ok_or_else(|| Error::Env("Transaction.recentBlockhash required (or pass RPC/Network to fetch it)".into()))?;
                let bh = crate::rpc::call(url, "getLatestBlockhash", json!([]))?;
                bh.get("value").and_then(|v| v.get("blockhash")).and_then(Json::as_str).ok_or_else(|| Error::Env("no blockhash in response".into()))?.to_owned()
            }
        };
        let blockhash = b58_32(&bh_b58)?;
        let to = b58_32(to_b58)?;
        crate::solana::build_transfer_message(&from, &to, lamports, &blockhash)
    };
    let mut path = KeyPath::parse(&info.path)?;
    path.source_fingerprint = fp_u32(info);
    let r = SolSignRequest { request_id, sign_data: message.clone(), derivation_path: path, address: Some(from), origin: Some("libwallet".into()), sign_type: SolSignType::Transaction };
    let cbor = super::cbor::to_bytes(&r.to_cbor())?;
    let (format, parts) = frames(registry::UR_SOL_SIGN_REQUEST, &cbor, outscript::bbqr::FileType::CBOR, &cbor, framing)?;
    let rid = registry::uuid_hyphenated(&request_id);
    pending_save(
        env,
        &Pending {
            request_id: rid.clone(),
            account: account.id.clone(),
            chain: "solana".into(),
            unsigned: json!({ "message": super::hex(&message) }),
            sign_data: super::hex(&message),
            created: crate::now_rfc3339(),
        },
    )?;
    Ok(Built {
        request_id: rid,
        chain: "solana".into(),
        account: account.id.clone(),
        transport: framing.transport.as_str().into(),
        format,
        parts,
        payload: json!({ "message": bs58::encode(&message).into_string(), "derivationPath": info.path }),
    })
}

fn b58_32(s: &str) -> Result<[u8; 32]> {
    bs58::decode(s).into_vec().map_err(|e| Error::Env(format!("base58: {e}")))?.try_into().map_err(|_| Error::Env("expected 32 bytes".into()))
}

fn decode_b58_or_b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    if let Ok(b) = bs58::decode(s).into_vec() {
        return Ok(b);
    }
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| Error::Env(format!("message is neither base58 nor base64: {e}")))
}

// ── Accepting the signer's answer ────────────────────────────────────────────

/// A finalized, signed transaction.
#[derive(Debug, Clone, Serialize)]
pub struct Accepted {
    pub request_id: Option<String>,
    pub chain: String,
    pub account: String,
    /// bitcoin/ethereum: `0x`-hex raw tx; solana: base58 raw tx.
    pub raw: String,
    /// bitcoin txid / ethereum tx hash (keccak of raw) / solana signature.
    pub id: String,
    /// The signature as received (hex), for the host's records.
    pub signature: String,
    /// bitcoin only: the finalized PSBT (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psbt: Option<String>,
}

/// Turn the signer's response into a signed transaction. `request_id` is
/// needed only when the payload does not carry one (signed PSBTs, bare
/// signatures); when both are present they must agree.
pub fn accept(env: &Env, payload: &Payload, request_id: Option<&str>) -> Result<Accepted> {
    match payload {
        Payload::Ur { ur_type, cbor } => {
            let v = super::cbor::from_bytes(cbor)?;
            match ur_type.as_str() {
                registry::UR_PSBT | registry::UR_PSBT_NEW => accept_psbt(env, &registry::psbt_from_cbor(cbor)?, request_id),
                registry::UR_ETH_SIGNATURE => {
                    let s = EthSignature::from_cbor(&v)?;
                    let rid = resolve_rid(s.request_id.as_ref(), request_id)?;
                    accept_eth(env, &rid, &s.signature)
                }
                registry::UR_SOL_SIGNATURE => {
                    let s = SolSignature::from_cbor(&v)?;
                    let rid = resolve_rid(s.request_id.as_ref(), request_id)?;
                    accept_sol(env, &rid, &s.signature)
                }
                registry::UR_BYTES => {
                    let b = outscript::bcur::cbor_to_bytes(cbor).map_err(|e| Error::Env(format!("{e}")))?.to_vec();
                    accept_bytes(env, &b, request_id)
                }
                other => Err(Error::Env(format!("UR type {other} is not a signer response"))),
            }
        }
        Payload::Bbqr { file_type, data } => match file_type {
            'P' => accept_psbt(env, data, request_id),
            'T' => accept_signed_raw_tx(env, data, request_id),
            _ => accept_bytes(env, data, request_id),
        },
        Payload::Raw(text) => {
            let t = text.trim();
            use base64::Engine;
            if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(t) {
                if b.starts_with(b"psbt\xff") {
                    return accept_psbt(env, &b, request_id);
                }
            }
            if let Ok(b) = super::unhex(t) {
                return accept_bytes(env, &b, request_id);
            }
            if let Ok(b) = bs58::decode(t).into_vec() {
                return accept_bytes(env, &b, request_id);
            }
            Err(Error::Env("unrecognized signature payload".into()))
        }
    }
}

fn resolve_rid(in_payload: Option<&[u8; 16]>, given: Option<&str>) -> Result<String> {
    match (in_payload, given) {
        (Some(p), Some(g)) => {
            let ps = registry::uuid_hyphenated(p);
            if registry::uuid_parse(g)? != *p {
                return Err(Error::Env(format!("signature is for request {ps}, not {g}")));
            }
            Ok(ps)
        }
        (Some(p), None) => Ok(registry::uuid_hyphenated(p)),
        (None, Some(g)) => Ok(g.to_owned()),
        (None, None) => Err(Error::Env("signature carries no request-id: pass RequestId".into())),
    }
}

/// Raw bytes with no type: decide by the pending request's chain.
fn accept_bytes(env: &Env, bytes: &[u8], request_id: Option<&str>) -> Result<Accepted> {
    if bytes.starts_with(b"psbt\xff") {
        return accept_psbt(env, bytes, request_id);
    }
    let rid = request_id.ok_or_else(|| Error::Env("bare signature: pass RequestId".into()))?;
    let p = pending_load(env, rid)?.ok_or_else(|| Error::Env(format!("no pending request {rid} (expired?)")))?;
    match p.chain.as_str() {
        "ethereum" => accept_eth(env, rid, bytes),
        "solana" => accept_sol(env, rid, bytes),
        "bitcoin" => accept_signed_raw_tx(env, bytes, Some(rid)),
        other => Err(Error::Env(format!("unexpected chain {other}"))),
    }
}

fn accept_psbt(env: &Env, signed: &[u8], request_id: Option<&str>) -> Result<Accepted> {
    use outscript::psbt::Psbt;
    let theirs = Psbt::parse(signed).map_err(|e| Error::Env(format!("signed psbt: {e}")))?;
    // Combine with our unsigned PSBT when we have it (restores any records a
    // signer dropped); otherwise finalize theirs alone.
    let (combined, pending) = match request_id.map(|r| pending_load(env, r)).transpose()?.flatten() {
        Some(p) => {
            let ours_hex = p.unsigned.get("psbt").and_then(Json::as_str).unwrap_or("");
            let ours = super::unhex(ours_hex)?;
            let ours_p = Psbt::parse(&ours).map_err(|e| Error::Env(format!("pending psbt: {e}")))?;
            if ours_p.unsigned_tx().txid() != theirs.unsigned_tx().txid() {
                return Err(Error::Env("signed PSBT is for a different transaction than the pending request".into()));
            }
            (ours_p.combine_to_vec(&theirs).map_err(|e| Error::Env(format!("psbt combine: {e}")))?, Some(p))
        }
        None => (signed.to_vec(), None),
    };
    let c = Psbt::parse(&combined).map_err(|e| Error::Env(format!("{e}")))?;
    let (finalized, done) = if c.is_finalized() { (combined.clone(), c.unsigned_tx().input_count()) } else { c.finalize_to_vec().map_err(|e| Error::Env(format!("psbt finalize: {e}")))? };
    let f = Psbt::parse(&finalized).map_err(|e| Error::Env(format!("{e}")))?;
    if done < f.unsigned_tx().input_count() || !f.is_finalized() {
        return Err(Error::Env(format!("PSBT not fully signed: {done}/{} inputs finalized", f.unsigned_tx().input_count())));
    }
    let raw = f.extract_tx_to_vec().map_err(|e| Error::Env(format!("psbt extract: {e}")))?;
    let txid = {
        let h = outscript::hash::dsha256(&strip_witness(&raw).unwrap_or_else(|| raw.clone()));
        let mut t = h.to_vec();
        t.reverse();
        super::hex(&t)
    };
    use base64::Engine;
    let (rid, account) = pending.as_ref().map(|p| (Some(p.request_id.clone()), p.account.clone())).unwrap_or((request_id.map(str::to_owned), String::new()));
    if let Some(r) = &rid {
        let _ = pending_delete(env, r);
    }
    Ok(Accepted {
        request_id: rid,
        chain: "bitcoin".into(),
        account,
        raw: format!("0x{}", super::hex(&raw)),
        id: txid,
        signature: String::new(),
        psbt: Some(base64::engine::general_purpose::STANDARD.encode(&finalized)),
    })
}

/// A signer that returns the fully signed raw transaction (BBQr `T`).
fn accept_signed_raw_tx(env: &Env, raw: &[u8], request_id: Option<&str>) -> Result<Accepted> {
    let pending = request_id.map(|r| pending_load(env, r)).transpose()?.flatten();
    let txid = {
        let h = outscript::hash::dsha256(&strip_witness(raw).unwrap_or_else(|| raw.to_vec()));
        let mut t = h.to_vec();
        t.reverse();
        super::hex(&t)
    };
    if let Some(p) = &pending {
        let _ = pending_delete(env, &p.request_id);
    }
    Ok(Accepted {
        request_id: pending.as_ref().map(|p| p.request_id.clone()),
        chain: "bitcoin".into(),
        account: pending.map(|p| p.account).unwrap_or_default(),
        raw: format!("0x{}", super::hex(raw)),
        id: txid,
        signature: String::new(),
        psbt: None,
    })
}

/// The non-witness serialization of a segwit tx (for the txid), or None when
/// the tx is not segwit-serialized.
fn strip_witness(raw: &[u8]) -> Option<Vec<u8>> {
    let tx = outscript::btctx::BtcTx::from_bytes(raw).ok()?;
    let mut legacy = tx;
    for i in &mut legacy.inputs {
        i.witnesses.clear();
    }
    Some(legacy.to_bytes())
}

fn accept_eth(env: &Env, rid: &str, signature: &[u8]) -> Result<Accepted> {
    let p = pending_load(env, rid)?.ok_or_else(|| Error::Env(format!("no pending request {rid} (expired?)")))?;
    if p.chain != "ethereum" {
        return Err(Error::Env(format!("request {rid} is a {} request, not ethereum", p.chain)));
    }
    if signature.len() != 65 && signature.len() != 64 {
        return Err(Error::Env(format!("eth signature must be 64/65 bytes, got {}", signature.len())));
    }
    let account = crate::models::account::fetch(env, &p.account)?.ok_or_else(|| Error::Env("account not found".into()))?;
    let req = crate::handlers::account::evm_request_from_tx(&p.unsigned).map_err(|e| Error::Env(e.message))?;
    let r = &signature[..32];
    let s = &signature[32..64];
    // v may be a recovery id (0/1), 27/28, or EIP-155 (chainId*2+35+parity);
    // normalize, then confirm by recovering the sender — trying the other
    // parity if the device's convention surprised us.
    let v_hint = signature.get(64).copied();
    let mut parities: Vec<u8> = match v_hint {
        Some(v) if v < 2 => vec![v, 1 - v],
        Some(v) if v == 27 || v == 28 => vec![v - 27, 1 - (v - 27)],
        Some(v) if v >= 35 => {
            let par = ((v as u64 - 35) % 2) as u8;
            vec![par, 1 - par]
        }
        _ => vec![0, 1],
    };
    let want = account.address.to_lowercase();
    let mut last_err = None;
    for parity in parities.drain(..) {
        let unsigned = crate::evm::build_unsigned(&req)?;
        match crate::evm::attach_signature(unsigned, r, s, parity) {
            Ok(raw) => match crate::evm::recover_sender(&raw) {
                Ok(from) if from.to_lowercase() == want => {
                    let hash = purecrypto::hash::keccak256(&raw);
                    pending_delete(env, rid)?;
                    return Ok(Accepted {
                        request_id: Some(rid.to_owned()),
                        chain: "ethereum".into(),
                        account: p.account.clone(),
                        raw: format!("0x{}", super::hex(&raw)),
                        id: format!("0x{}", super::hex(&hash)),
                        signature: format!("0x{}", super::hex(signature)),
                        psbt: None,
                    });
                }
                Ok(from) => last_err = Some(format!("signature recovers to {from}, expected {}", account.address)),
                Err(e) => last_err = Some(e.to_string()),
            },
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Err(Error::Env(format!("eth signature does not match account {}: {}", account.address, last_err.unwrap_or_default())))
}

fn accept_sol(env: &Env, rid: &str, signature: &[u8]) -> Result<Accepted> {
    let p = pending_load(env, rid)?.ok_or_else(|| Error::Env(format!("no pending request {rid} (expired?)")))?;
    if p.chain != "solana" {
        return Err(Error::Env(format!("request {rid} is a {} request, not solana", p.chain)));
    }
    let sig: [u8; 64] = signature.try_into().map_err(|_| Error::Env(format!("sol signature must be 64 bytes, got {}", signature.len())))?;
    let account = crate::models::account::fetch(env, &p.account)?.ok_or_else(|| Error::Env("account not found".into()))?;
    let pk = crate::solana::pubkey_from_b64url(&account.pubkey).ok_or_else(|| Error::Env("bad account pubkey".into()))?;
    let message = super::unhex(&p.sign_data)?;
    if !crate::tss::ed25519_verify(&pk, &message, &sig) {
        return Err(Error::Env(format!("sol signature does not verify under account {}", account.address)));
    }
    let raw = crate::solana::assemble_tx(&message, &sig);
    pending_delete(env, rid)?;
    Ok(Accepted {
        request_id: Some(rid.to_owned()),
        chain: "solana".into(),
        account: p.account.clone(),
        raw: bs58::encode(&raw).into_string(),
        id: bs58::encode(&sig).into_string(),
        signature: super::hex(&sig),
        psbt: None,
    })
}

/// Broadcast an accepted transaction through the chain's node.
pub fn broadcast(url: &str, a: &Accepted) -> Result<Json> {
    match a.chain.as_str() {
        "ethereum" => crate::rpc::call(url, "eth_sendRawTransaction", json!([a.raw])),
        "bitcoin" => crate::rpc::call(url, "sendrawtransaction", json!([a.raw.trim_start_matches("0x")])),
        "solana" => crate::rpc::call(url, "sendTransaction", json!([a.raw, { "encoding": "base58" }])),
        other => Err(Error::Env(format!("cannot broadcast {other}"))),
    }
}
