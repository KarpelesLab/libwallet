//! Ledger (BOLOS) hardware wallets, through the `lsdk` crate.
//!
//! A Ledger wallet is a signer wallet like an air-gapped one (`protocol:
//! "ledger"`): watch-only accounts whose keys were read from the device, each
//! with the derivation path the device needs to sign for it (kept in the same
//! `airgap:account:<id>` config the air-gap importer writes). The difference is
//! the channel: instead of QR codes the library talks APDUs to the device,
//! through one of the [`transport`] links.
//!
//! The device runs one app at a time, and each app only knows its own chain:
//! [`keys`] reads the keys of whichever of the Ethereum / Bitcoin / Solana /
//! Tron apps is open, and signing needs the account's app open.
//!
//! Nothing the device returns is trusted on its own. A signature is only
//! handed back once it verifies under the account's key over exactly what was
//! asked: the EVM transaction must recover to the account address, the Solana
//! signature must verify over the built message, and a Bitcoin PSBT goes
//! through the same pending-request binding as an air-gapped signer's answer.

pub mod manage;
pub mod transport;
pub mod tron;

use lsdk::apps::eth::EthApp;
use lsdk::apps::sol::SolApp;
use lsdk::path::DerivationPath;
use lsdk::{Device, Transport};
use serde_json::{json, Value};

use crate::airgap::import::{account_key_info, AccountKeyInfo, DiscoveredKey, Export};
use crate::handlers::{ApiError, ApiResult};
use crate::models::account::Account;
use crate::Env;

use transport::{hex, unhex};

const HARDENED: u32 = 0x8000_0000;
/// At most this many accounts are read from the device per request.
const MAX_KEYS: u32 = 20;

/// Map an lsdk error to the API's `(code, message)`.
pub(crate) fn lerr(e: lsdk::Error) -> ApiError {
    let code = match &e {
        lsdk::Error::NoDevice | lsdk::Error::NotFound(_) => 404,
        lsdk::Error::UserRefused | lsdk::Error::Cancelled => 4001,
        lsdk::Error::Locked => 423,
        lsdk::Error::Timeout => 408,
        lsdk::Error::InvalidInput(_) => 400,
        lsdk::Error::DashboardExpected => 409,
        _ => 502,
    };
    ApiError::new(code, format!("ledger: {e}"))
}

fn bad(m: impl Into<String>) -> ApiError {
    ApiError::new(400, m)
}

fn str_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn parse_path(path: &str) -> Result<DerivationPath, ApiError> {
    path.parse::<DerivationPath>().map_err(lerr)
}

/// The app a chain's accounts are signed with.
fn app_for(kind: &str) -> Result<&'static str, ApiError> {
    match kind {
        "ethereum" => Ok("Ethereum"),
        "bitcoin" => Ok("Bitcoin"),
        "solana" => Ok("Solana"),
        "tron" => Ok("Tron"),
        other => Err(bad(format!("Ledger signing is not supported for {other} accounts"))),
    }
}

/// The name of the app the device is running (`BOLOS` on the dashboard).
async fn current_app<T: Transport>(device: &Device<T>) -> Result<lsdk::os::AppAndVersion, ApiError> {
    device.get_app_and_version().await.map_err(lerr)
}

/// Fail early, with something the host can show, when the wrong app is open.
async fn require_app<T: Transport>(device: &Device<T>, want: &str) -> Result<(), ApiError> {
    let app = current_app(device).await?;
    if app.name == want {
        return Ok(());
    }
    let now = if app.name == "BOLOS" { "no app is open".to_owned() } else { format!("the {} app is open", app.name) };
    Err(ApiError::new(409, format!("open the {want} app on the device ({now})")))
}

/// `Ledger:info` — what the device is running.
pub async fn info<T: Transport>(device: &Device<T>) -> ApiResult {
    let app = current_app(device).await?;
    let dashboard = app.name == "BOLOS";
    let mut out = json!({
        "app": { "name": app.name, "version": app.version },
        "dashboard": dashboard,
    });
    // Firmware details are only readable from the dashboard.
    if dashboard {
        if let Ok(v) = device.get_version().await {
            out["model"] = json!(v.model().map(|m| m.name()));
            out["firmware"] = json!(v.se_version);
        }
    }
    Ok(out)
}

/// 65-byte uncompressed secp256k1 point → 33-byte compressed.
fn compress(uncompressed: &[u8]) -> Result<[u8; 33], ApiError> {
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return Err(ApiError::new(502, "ledger: unexpected public key encoding"));
    }
    let mut out = [0u8; 33];
    out[0] = 0x02 | (uncompressed[64] & 1);
    out[1..].copy_from_slice(&uncompressed[1..33]);
    Ok(out)
}

/// Which keys [`keys`] reads.
#[derive(Debug, Clone)]
pub struct KeyQuery {
    /// First account index (the hardened `account'` path component).
    pub account: u32,
    /// How many consecutive accounts.
    pub count: u32,
    /// Bitcoin script kinds to read an account key for (`p2wpkh`,
    /// `p2sh:p2wpkh`, `p2pkh`).
    pub scripts: Vec<String>,
    /// Explicit derivation paths (Ethereum / Solana), instead of the standard
    /// per-account ones.
    pub paths: Vec<String>,
}

impl KeyQuery {
    pub fn from_params(params: &Value) -> Result<Self, ApiError> {
        let num = |k: &str, d: u64| params.get(k).and_then(Value::as_u64).unwrap_or(d);
        let account = u32::try_from(num("Account", 0)).ok().filter(|a| *a < HARDENED).ok_or_else(|| bad("Account out of range"))?;
        let count = u32::try_from(num("Count", 1)).ok().filter(|c| (1..=MAX_KEYS).contains(c)).ok_or_else(|| bad(format!("Count must be 1-{MAX_KEYS}")))?;
        let list = |k: &str| -> Vec<String> {
            params.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default()
        };
        let mut scripts = list("Scripts");
        if scripts.is_empty() {
            scripts.push("p2wpkh".into());
        }
        let paths = list("Paths");
        if paths.len() > MAX_KEYS as usize {
            return Err(bad(format!("at most {MAX_KEYS} Paths")));
        }
        Ok(KeyQuery { account, count, scripts, paths })
    }
}

fn key(chain: &str, curve: &str, coin: u32, path: String, pubkey: &[u8], address: String) -> DiscoveredKey {
    DiscoveredKey {
        chain: chain.into(),
        curve: curve.into(),
        coin_type: Some(coin),
        path,
        master_fingerprint: None,
        pubkey: hex(pubkey),
        chain_code: None,
        script: String::new(),
        address,
        name: None,
        note: None,
        reason: None,
    }
}

/// `Ledger:getKeys` — the public keys of the app that is open on the device,
/// in the shape `Airgap:parseKeys` returns (and `Ledger:import` takes):
///
/// - **Ethereum**: one leaf key per account at `m/44'/60'/i'/0/0` (the layout
///   Ledger Live uses), or at each of `Paths`.
/// - **Bitcoin**: the account extended key at `m/84'/0'/i'` (and/or the BIP-49
///   / BIP-44 accounts named by `Scripts`), with the master fingerprint.
/// - **Solana**: one key per account at `m/44'/501'/i'/0'`, or at each of `Paths`.
/// - **Tron**: one leaf key per account at `m/44'/195'/i'/0/0`, or at each of `Paths`.
pub async fn keys<T: Transport>(env: &Env, device: &Device<T>, q: &KeyQuery) -> Result<Export, ApiError> {
    let app = current_app(device).await?;
    let mut export = Export { format: "ledger".into(), device: Some("Ledger".into()), version: Some(format!("{} {}", app.name, app.version)), ..Default::default() };
    let accounts = q.account..q.account.saturating_add(q.count).min(HARDENED);
    match app.name.as_str() {
        "Ethereum" => {
            let eth = EthApp::new(device);
            let paths: Vec<String> = if q.paths.is_empty() { accounts.map(|i| format!("m/44'/60'/{i}'/0/0")).collect() } else { q.paths.clone() };
            for path in paths {
                let a = eth.get_address(&parse_path(&path)?, false, false).await.map_err(lerr)?;
                let pk = compress(&unhex(&a.public_key).ok_or_else(|| ApiError::new(502, "ledger: bad public key"))?)?;
                // The address is derived here from the key, not taken from the
                // device's reply: the two must agree.
                let address = crate::hdderive::evm_address(&pk).map_err(ApiError::internal)?;
                if !address.eq_ignore_ascii_case(&a.address) {
                    return Err(ApiError::new(502, format!("ledger: device address {} does not match its public key ({address})", a.address)));
                }
                export.keys.push(key("ethereum", "secp256k1", 60, path, &pk, address));
            }
        }
        "Solana" => {
            let sol = SolApp::new(device);
            let paths: Vec<String> = if q.paths.is_empty() { accounts.map(|i| format!("m/44'/501'/{i}'/0'")).collect() } else { q.paths.clone() };
            for path in paths {
                let address = sol.get_address(&parse_path(&path)?, false).await.map_err(lerr)?;
                let pk = bs58::decode(&address).into_vec().ok().filter(|b| b.len() == 32).ok_or_else(|| ApiError::new(502, "ledger: bad solana public key"))?;
                export.keys.push(key("solana", "ed25519", 501, path, &pk, address));
            }
        }
        "Bitcoin" => {
            let btc = lsdk::apps::btc::BtcApp::new(device);
            let fp = hex(&btc.get_master_fingerprint().await.map_err(lerr)?);
            export.master_fingerprint = Some(fp.clone());
            for script in &q.scripts {
                let purpose = btc_purpose(script)?;
                for i in accounts.clone() {
                    let origin = format!("{purpose}'/0'/{i}'");
                    let xpub = btc.get_extended_pubkey(&parse_path(&format!("m/{origin}"))?, false).await.map_err(lerr)?;
                    let k = crate::airgap::import::key_from_extended(env, &format!("[{fp}/{origin}]{}", xpub.trim()), Some(script)).map_err(|e| ApiError::new(502, format!("ledger: {e}")))?;
                    export.keys.push(k);
                }
            }
        }
        "Tron" => {
            let app = tron::TronApp::new(device);
            let paths: Vec<String> = if q.paths.is_empty() { accounts.map(|i| format!("m/44'/195'/{i}'/0/0")).collect() } else { q.paths.clone() };
            for path in paths {
                let (pk, shown) = app.get_address(&parse_path(&path)?, false).await.map_err(lerr)?;
                let pk = compress(&pk)?;
                // As for Ethereum: the address comes from the key, and the
                // device's own must agree with it.
                let address = crate::hdderive::tron_address(&pk).map_err(ApiError::internal)?;
                if address != shown {
                    return Err(ApiError::new(502, format!("ledger: device address {shown} does not match its public key ({address})")));
                }
                export.keys.push(key("tron", "secp256k1", 195, path, &pk, address));
            }
        }
        "BOLOS" => return Err(ApiError::new(409, "open the Ethereum, Bitcoin, Solana or Tron app on the device")),
        other => return Err(ApiError::new(409, format!("the {other} app is not supported: open the Ethereum, Bitcoin, Solana or Tron app"))),
    }
    Ok(export)
}

fn btc_purpose(script: &str) -> Result<u32, ApiError> {
    match script {
        "p2wpkh" => Ok(84),
        "p2sh:p2wpkh" => Ok(49),
        "p2pkh" => Ok(44),
        other => Err(bad(format!("unsupported bitcoin script kind {other:?} (p2wpkh, p2sh:p2wpkh, p2pkh)"))),
    }
}

fn btc_address_type(script: &str) -> Result<lsdk::apps::btc::wallet::AddressType, ApiError> {
    use lsdk::apps::btc::wallet::AddressType;
    match script {
        "" | "p2wpkh" => Ok(AddressType::NativeSegwit),
        "p2sh:p2wpkh" => Ok(AddressType::NestedSegwit),
        "p2pkh" => Ok(AddressType::Legacy),
        other => Err(bad(format!("unsupported bitcoin script kind {other:?}"))),
    }
}

/// An account of a Ledger wallet, with what the device needs to find its key.
pub fn load_account(env: &Env, account_id: &str) -> Result<(Account, AccountKeyInfo), ApiError> {
    let account = crate::models::account::find(env, account_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "account not found"))?;
    let wallet = crate::models::wallet::fetch(env, &account.wallet).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "wallet not found"))?;
    if wallet.protocol != "ledger" {
        return Err(bad(format!("account {} is not on a Ledger wallet (protocol {})", account.id, wallet.protocol)));
    }
    let info = account_key_info(env, &account.id).map_err(ApiError::internal)?.unwrap_or(AccountKeyInfo {
        master_fingerprint: None,
        path: account.path.clone(),
        script: String::new(),
        curve: account.curve.clone(),
    });
    Ok((account, info))
}

/// The wallet policy the Bitcoin app signs a single-sig account under.
fn btc_policy(account: &Account, info: &AccountKeyInfo) -> Result<(lsdk::apps::btc::wallet::AddressType, lsdk::apps::btc::wallet::KeyInfo), ApiError> {
    let kind = btc_address_type(&info.script)?;
    let fp: [u8; 4] = info
        .master_fingerprint
        .as_deref()
        .and_then(unhex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("the device's master fingerprint is unknown for this account: import it again"))?;
    let xpub = account.xpub().map_err(ApiError::internal)?;
    Ok((kind, lsdk::apps::btc::wallet::KeyInfo::new(fp, parse_path(&info.path)?, xpub)))
}

/// `Ledger:showAddress` — display the account's address on the device so the
/// user can compare it, and check the device derives the address we hold.
pub async fn show_address<T: Transport>(device: &Device<T>, account: &Account, info: &AccountKeyInfo) -> ApiResult {
    require_app(device, app_for(&account.kind)?).await?;
    let shown = match account.kind.as_str() {
        "ethereum" => EthApp::new(device).get_address(&parse_path(&info.path)?, true, false).await.map_err(lerr)?.address,
        "solana" => SolApp::new(device).get_address(&parse_path(&info.path)?, true).await.map_err(lerr)?,
        "tron" => tron::TronApp::new(device).get_address(&parse_path(&info.path)?, true).await.map_err(lerr)?.1,
        _ => {
            let (kind, key) = btc_policy(account, info)?;
            lsdk::apps::btc::BtcApp::new(device).get_wallet_address_checked(kind, false, &key, false, 0, true).await.map_err(lerr)?
        }
    };
    let matches = if account.kind == "ethereum" { shown.eq_ignore_ascii_case(&account.address) } else { shown == account.address };
    if !matches {
        return Err(ApiError::new(409, format!("the device shows {shown}, but this account is {}: it is not this device's key", account.address)));
    }
    Ok(json!({ "address": shown, "account": account.id }))
}

/// The Solana off-chain message (v0) the Solana app signs for `message`: the
/// app refuses bare bytes, so the text is wrapped in the header that says it
/// is a message and not a transaction — signing domain, version, application
/// domain (none), format, the one signer, the length.
pub fn solana_offchain_message(signer: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, ApiError> {
    let text = std::str::from_utf8(message).map_err(|_| bad("a Ledger signs Solana text messages only (UTF-8)"))?;
    // Format 0: printable ASCII, which the device shows; 1: other UTF-8.
    let format = u8::from(!text.bytes().all(|b| (0x20..0x7f).contains(&b)));
    let len = u16::try_from(message.len()).ok().filter(|l| *l > 0 && *l <= 1212).ok_or_else(|| bad("a Ledger signs Solana messages of 1 to 1212 bytes"))?;
    let mut out = b"\xffsolana offchain".to_vec();
    out.push(0); // header version
    out.extend_from_slice(&[0u8; 32]); // application domain
    out.push(format);
    out.push(1); // signers
    out.extend_from_slice(signer);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

/// `Ledger:signMessage` — Ethereum `personal_sign` (EIP-191), a Bitcoin
/// message signature (BIP-137), a TronWeb `signMessageV2` signature, or a
/// Solana off-chain message over `message`.
///
/// The Solana signature is over the off-chain message wrapping the text
/// ([`solana_offchain_message`], returned as `signedMessage`), not over the
/// bare bytes: that is the only thing the Solana app signs.
pub async fn sign_message<T: Transport>(device: &Device<T>, account: &Account, info: &AccountKeyInfo, message: &[u8]) -> ApiResult {
    use base64::Engine;
    require_app(device, app_for(&account.kind)?).await?;
    match account.kind.as_str() {
        "ethereum" => {
            let sig = EthApp::new(device).sign_personal_message(&parse_path(&info.path)?, message).await.map_err(lerr)?;
            // r ‖ s ‖ v with v ∈ {27, 28}, whatever convention the app used.
            let mut rsv = Vec::with_capacity(65);
            rsv.extend_from_slice(&sig.r);
            rsv.extend_from_slice(&sig.s);
            rsv.push(27 + (if sig.v >= 27 { sig.v - 27 } else { sig.v } & 1) as u8);
            let from = crate::evm::personal_ec_recover(message, &rsv).map_err(|e| ApiError::new(502, format!("ledger: {e}")))?;
            if !from.eq_ignore_ascii_case(&account.address) {
                return Err(ApiError::new(409, format!("the signature is from {from}, not this account ({}): wrong device?", account.address)));
            }
            Ok(json!({ "signature": format!("0x{}", hex(&rsv)), "account": account.id }))
        }
        "bitcoin" => {
            // Messages are signed with the account's first receive address.
            let mut path = parse_path(&info.path)?;
            path.0.extend([0, 0]);
            let sig = lsdk::apps::btc::BtcApp::new(device).sign_message(&path, message).await.map_err(lerr)?;
            Ok(json!({ "signature": base64::engine::general_purpose::STANDARD.encode(sig), "path": path.to_string(), "account": account.id }))
        }
        "tron" => {
            let sig = tron::TronApp::new(device).sign_message(&parse_path(&info.path)?, message).await.map_err(lerr)?;
            let rsv = crate::tron::message_signature(account, message, &sig).map_err(|e| ApiError::new(409, format!("{e}: wrong device?")))?;
            Ok(json!({ "signature": format!("0x{}", hex(&rsv)), "account": account.id }))
        }
        "solana" => {
            let pk = crate::solana::pubkey_from_b64url(&account.pubkey).ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
            let wrapped = solana_offchain_message(&pk, message)?;
            let sig = SolApp::new(device).sign_offchain_message(&parse_path(&info.path)?, &wrapped).await.map_err(lerr)?;
            if !crate::tss::ed25519_verify(&pk, &wrapped, &sig) {
                return Err(ApiError::new(409, format!("the device's signature is not from this account ({}): wrong device, or wrong passphrase?", account.address)));
            }
            Ok(json!({
                "signature": bs58::encode(sig).into_string(),
                "signedMessage": base64::engine::general_purpose::STANDARD.encode(&wrapped),
                "format": "offchain",
                "account": account.id,
            }))
        }
        other => Err(bad(format!("Ledger message signing is not supported for {other} accounts"))),
    }
}

/// `Ledger:signTypedData` — an EIP-712 signature over `typed_data` (the
/// JSON). The Ethereum app is given the two hashes the digest is made of —
/// the domain separator and the message's struct hash — and shows those: it
/// does not parse the typed data, so the owner cannot read it on the device
/// (the app's blind-signing setting must allow it).
pub async fn sign_typed_data<T: Transport>(device: &Device<T>, account: &Account, info: &AccountKeyInfo, typed_data: &str) -> ApiResult {
    if account.kind != "ethereum" {
        return Err(bad(format!("typed data is signed by ethereum accounts, not {}", account.kind)));
    }
    let td = crate::eip712::parse(typed_data).map_err(bad)?;
    let (domain, message) = td.hashes().map_err(bad)?;
    let digest = td.hash().map_err(bad)?;
    require_app(device, "Ethereum").await?;
    let sig = EthApp::new(device).sign_eip712_hashed(&parse_path(&info.path)?, &domain, &message).await.map_err(lerr)?;
    let mut rsv = Vec::with_capacity(65);
    rsv.extend_from_slice(&sig.r);
    rsv.extend_from_slice(&sig.s);
    rsv.push((sig.v & 0xff) as u8);
    let rsv = crate::evm::rsv_for_address(&digest, &rsv, &account.address).map_err(|e| ApiError::new(409, format!("{e}: wrong device?")))?;
    Ok(json!({ "signature": format!("0x{}", hex(&rsv)), "account": account.id }))
}

/// The node for a signing request: none when `Offline: true`; else the `RPC`
/// override or the account chain's network. Without one the `Transaction` must
/// be complete and cannot be broadcast.
fn rpc_for(env: &Env, params: &Value, kind: &str) -> Result<Option<String>, ApiError> {
    if params.get("Offline").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    if str_param(params, "RPC").is_some() || str_param(params, "Network").is_some() {
        return crate::handlers::resolve_rpc_for_kind(env, params, kind).map(Some);
    }
    Ok(crate::handlers::resolve_rpc_for_kind(env, params, kind).ok())
}

fn wants_broadcast(params: &Value) -> bool {
    params.get("Broadcast").and_then(Value::as_bool) == Some(true)
}

/// `Ledger:signTransaction` for an Ethereum account: fill what the
/// `Transaction` lacks from the node (the chain id comes from the Network
/// model, never the node), have the device sign the exact preimage, and accept
/// the signature only if the signed transaction recovers to the account.
pub async fn sign_evm<T: Transport>(env: &Env, device: &Device<T>, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| bad("Transaction required"))?;
    let rpc = rpc_for(env, params, "evm")?;
    let mut p = json!({ "Transaction": tx });
    if let Some(url) = &rpc {
        // With an explicit RPC there is no Network to vouch for the chain: the
        // caller supplies chainId itself.
        if str_param(params, "RPC").is_none() {
            if let Some(net) = str_param(params, "Network") {
                p["Network"] = json!(net);
            }
            p = crate::handlers::account::evm_pin_chain_id(env, &p)?;
        }
        p = crate::handlers::account::evm_fill(&account.address, url, &p).await?;
    }
    let tx = &p["Transaction"];
    for required in ["nonce", "gas", "chainId"] {
        if tx.get(required).is_none() {
            return Err(bad(format!("Transaction.{required} required (or pass Network to fill it)")));
        }
    }
    if tx.get("gasPrice").is_none() && tx.get("maxFeePerGas").is_none() {
        return Err(bad("Transaction.gasPrice or maxFeePerGas required (or pass Network to fill it)"));
    }
    let req = crate::handlers::account::evm_request_from_tx(tx)?;
    let unsigned = crate::evm::build_unsigned(&req).map_err(|e| bad(e.to_string()))?;
    let sign_data = unsigned.sign_bytes().map_err(|e| bad(format!("{e}")))?;

    require_app(device, "Ethereum").await?;
    let sig = EthApp::new(device).sign_transaction(&parse_path(&info.path)?, &sign_data).await.map_err(lerr)?;

    // The parity the app reports, then the other one: what decides is which
    // signed transaction recovers to the account.
    let hint = match sig.v {
        v if req.eip1559 => (v & 1) as u8,
        v if v >= 35 => ((v - 35) % 2) as u8,
        v => (v.wrapping_sub(27) & 1) as u8,
    };
    let want = account.address.to_lowercase();
    let mut raw = None;
    for parity in [hint, 1 - hint] {
        let unsigned = crate::evm::build_unsigned(&req).map_err(|e| bad(e.to_string()))?;
        if let Ok(candidate) = crate::evm::attach_signature(unsigned, &sig.r, &sig.s, parity) {
            if crate::evm::recover_sender(&candidate).is_ok_and(|from| from.to_lowercase() == want) {
                raw = Some(candidate);
                break;
            }
        }
    }
    let raw = raw.ok_or_else(|| ApiError::new(409, format!("the device's signature is not from this account ({}): wrong device, or wrong passphrase?", account.address)))?;
    let raw_hex = format!("0x{}", hex(&raw));
    let mut out = json!({
        "chain": "ethereum",
        "account": account.id,
        "raw": raw_hex,
        "id": format!("0x{}", hex(&purecrypto::hash::keccak256(&raw))),
        "transaction": tx,
    });
    if wants_broadcast(params) {
        let url = rpc.ok_or_else(|| bad("Broadcast needs an RPC/Network (not Offline)"))?;
        out["broadcast"] = crate::rpc::call_async(&url, "eth_sendRawTransaction", json!([raw_hex])).await.map_err(ApiError::internal)?;
    }
    Ok(out)
}

/// `Ledger:signTransaction` for a Solana account: build the transfer (or take
/// a ready `Transaction.message`, base58 / base64), have the device sign the
/// message, and accept the signature only if it verifies under the account key.
pub async fn sign_solana<T: Transport>(env: &Env, device: &Device<T>, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    use base64::Engine;
    let tx = params.get("Transaction").ok_or_else(|| bad("Transaction required"))?;
    let pk = crate::solana::pubkey_from_b64url(&account.pubkey).ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    let rpc = rpc_for(env, params, "solana")?;
    let message = match tx.get("message").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(m) => {
            let bytes = bs58::decode(m)
                .into_vec()
                .ok()
                .or_else(|| base64::engine::general_purpose::STANDARD.decode(m).ok())
                .ok_or_else(|| bad("Transaction.message must be base58 or base64"))?;
            // Only a message this account is a signer of — never arbitrary bytes.
            if crate::solana::find_signer_slot(&bytes, &pk).is_none() {
                return Err(bad("Transaction.message does not name this account as a signer"));
            }
            bytes
        }
        None => {
            let url = rpc.as_deref().ok_or_else(|| bad("no node: pass Transaction.message, or a Network to build the transfer"))?;
            let net = crate::handlers::network_for_kind(env, params, "solana")?;
            crate::handlers::solana_build::build_unsigned(env, account, &net, url, tx).await?.message
        }
    };

    require_app(device, "Solana").await?;
    let sig = SolApp::new(device).sign_message_bytes(&parse_path(&info.path)?, &message).await.map_err(lerr)?;
    if !crate::tss::ed25519_verify(&pk, &message, &sig) {
        return Err(ApiError::new(409, format!("the device's signature is not from this account ({}): wrong device, or wrong passphrase?", account.address)));
    }
    let raw = bs58::encode(crate::solana::assemble_tx(&message, &sig)).into_string();
    let mut out = json!({
        "chain": "solana",
        "account": account.id,
        "raw": raw,
        "id": bs58::encode(&sig).into_string(),
    });
    if wants_broadcast(params) {
        let url = rpc.ok_or_else(|| bad("Broadcast needs an RPC/Network (not Offline)"))?;
        out["broadcast"] = crate::rpc::call_async(&url, "sendTransaction", json!([raw, { "encoding": "base58" }])).await.map_err(ApiError::internal)?;
    }
    Ok(out)
}

/// `Ledger:signTransaction` for a Bitcoin account: the PSBT is built exactly
/// as for an air-gapped signer and kept as the pending request; the device
/// signs it under the account's default wallet policy, and the answer goes
/// through the air-gap acceptance — it must be that pending transaction,
/// fully signed — before anything is returned or broadcast.
///
/// What the builder needs from the node is fetched here, async, so the same
/// code runs natively and in the browser: the account's UTXOs, and — best
/// effort — the previous transactions of the inputs it will spend, which let
/// the device verify the amounts it shows.
pub async fn sign_bitcoin<T: Transport>(env: &Env, device: &Device<T>, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    use base64::Engine;
    use lsdk::apps::btc::wallet::WalletPolicy;
    let mut tx = params.get("Transaction").cloned().filter(Value::is_object).ok_or_else(|| bad("Transaction required"))?;
    if tx.get("ChainId").and_then(Value::as_str).is_some_and(|c| c != "bitcoin") {
        return Err(bad("the Ledger Bitcoin app signs for bitcoin only"));
    }
    let (kind, key) = btc_policy(account, info)?;
    let rpc = rpc_for(env, params, "bitcoin")?;

    if tx.get("UTXOs").and_then(Value::as_array).map_or(true, |a| a.is_empty()) {
        let url = rpc.as_deref().ok_or_else(|| bad("no node: pass Transaction.UTXOs, or a Network to discover them"))?;
        tx = crate::handlers::airgap::prefill_bitcoin(account, &tx, url).await?;
    }
    require_app(device, "Bitcoin").await?;

    // The node was already consulted: the builder works from the Transaction.
    let built = crate::airgap::sign::build_request(env, &account.id, &tx, &Default::default(), None).map_err(|e| bad(e.to_string()))?;
    let rid = built.request_id.clone();
    let signed = async {
        let psbt = built.payload.get("psbt").and_then(Value::as_str).and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()).ok_or_else(|| ApiError::new(500, "no PSBT was built"))?;
        let policy = WalletPolicy::default_single_sig(kind, key);
        lsdk::apps::btc::BtcApp::new(device).sign_psbt_into(&psbt, &policy, None).await.map_err(lerr)
    }
    .await;
    let accepted = match signed {
        Ok(psbt) => crate::airgap::sign::accept_psbt(env, &psbt, Some(&rid)).map_err(|e| ApiError::new(409, e.to_string())),
        Err(e) => Err(e),
    };
    let accepted = match accepted {
        Ok(a) => a,
        Err(e) => {
            // Nothing will answer this request any more.
            let _ = crate::airgap::sign::pending_delete(env, &rid);
            return Err(e);
        }
    };
    let mut out = serde_json::to_value(&accepted).map_err(ApiError::internal)?;
    out["summary"] = built.payload.get("summary").cloned().unwrap_or(Value::Null);
    if wants_broadcast(params) {
        let url = rpc.ok_or_else(|| bad("Broadcast needs an RPC/Network (not Offline)"))?;
        out["broadcast"] = crate::rpc::call_async(&url, "sendrawtransaction", json!([accepted.raw.trim_start_matches("0x")])).await.map_err(ApiError::internal)?;
    }
    Ok(out)
}

/// `Ledger:signTransaction` for a Tron account: `Transaction.rawDataHex` (it
/// must be a contract we can read, owned by the account) or a transfer `{to,
/// value, token?, feeLimit?}` anchored on the node's current block — or on
/// the `refBlock` given, when there is no node. The device signs the raw
/// data; its signature is attached only if it recovers to the account.
pub async fn sign_tron<T: Transport>(env: &Env, device: &Device<T>, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| bad("Transaction required"))?;
    let rpc = rpc_for(env, params, "tron")?;
    let tx = match &rpc {
        Some(url) => crate::handlers::airgap::prefill_tron(tx, url).await?,
        None => tx.clone(),
    };
    let raw = crate::tron::unsigned_raw_data(account, &tx).map_err(|e| bad(e.to_string()))?;
    require_app(device, "Tron").await?;
    let sig = tron::TronApp::new(device).sign_transaction(&parse_path(&info.path)?, &raw).await.map_err(lerr)?;
    let (txid, signed) = crate::tron::attach_device_signature(account, &raw, &sig).map_err(|e| ApiError::new(409, format!("{e}: wrong device, or wrong passphrase?")))?;
    let mut out = json!({
        "chain": "tron",
        "account": account.id,
        "raw": hex(&signed),
        "id": hex(&txid),
    });
    if wants_broadcast(params) {
        let url = rpc.ok_or_else(|| bad("Broadcast needs an RPC/Network (not Offline)"))?;
        let reply = crate::tron::post_async(&url, "broadcasthex", &crate::tron::broadcast_body(&signed)).await.map_err(ApiError::internal)?;
        out["broadcast"] = json!(crate::tron::parse_broadcast(&reply, &txid).map_err(|e| ApiError::new(502, e.to_string()))?);
    }
    Ok(out)
}

/// `Ledger:signTransaction` — sign (and with `Broadcast: true`, send) the
/// `Transaction` for a Ledger account on the device.
pub async fn sign_transaction<T: Transport>(env: &Env, device: &Device<T>, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    match account.kind.as_str() {
        "ethereum" => sign_evm(env, device, account, info, params).await,
        "solana" => sign_solana(env, device, account, info, params).await,
        "bitcoin" => sign_bitcoin(env, device, account, info, params).await,
        "tron" => sign_tron(env, device, account, info, params).await,
        other => Err(bad(format!("Ledger signing is not supported for {other} accounts"))),
    }
}

#[cfg(test)]
mod tests;
