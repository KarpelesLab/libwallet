//! CatCard hardware wallets (our open firmware for Coldcard hardware), over
//! the device's own USB protocol.
//!
//! A CatCard wallet is a signer wallet like an air-gapped or a Ledger one
//! (`protocol: "catcard"`): watch-only accounts whose keys were read from the
//! device, each with the derivation path the device needs to sign for it (kept
//! in the same `airgap:account:<id>` config the air-gap importer writes). The
//! channel is the device's vendor HID interface — or, on a phone, its
//! smart-card reader, relayed by the host — through one of the [`transport`]
//! links, inside the encrypted, code-paired [`session`].
//!
//! The protocol is the firmware's "host-wallet" one: the host asks, the device
//! puts the question on its own screen, the person holding it answers there,
//! and the host polls for the outcome. Two questions exist — "share this
//! wallet's addresses" and "sign this transaction" (a Bitcoin PSBT, an EVM
//! transaction, a Solana message). The account is chosen on the device, not by
//! the host, and the device only signs with keys below an account it shared in
//! the same session. There is no command to display one address or to sign a
//! message: [`show_address`] and [`sign_message`] say so.
//!
//! Nothing the device returns is trusted on its own. A shared key is only
//! reported once its address derives from it here; a signature is only handed
//! back once it verifies under the account's key over exactly what was asked:
//! the EVM transaction is rebuilt from the request with the device's `r, s`
//! and must recover to the account address, the Solana signature must verify
//! over the built message, and every input of a Bitcoin PSBT must carry a
//! signature that verifies under the account's own derived key before the PSBT
//! goes through the same pending-request binding as an air-gapped signer's.

pub mod proto;
pub mod session;
pub mod transport;

use serde_json::{json, Value};

use crate::airgap::import::{account_key_info, AccountKeyInfo, DiscoveredKey, Export};
use crate::handlers::{ApiError, ApiResult};
use crate::models::account::Account;
use crate::Env;

use proto::{chain, format, op, shape, status, Addresses, Entry, HARDENED};
use session::{reason, Session, POLL_MS};
use transport::{hex, sleep_ms, unhex, Transport};

/// How long the person at the device has to answer a question. They may be in
/// another menu, and a transaction review takes a while.
const ANSWER_WAIT_MS: u32 = 900_000;

fn bad(m: impl Into<String>) -> ApiError {
    ApiError::new(400, m)
}

fn cerr(code: i64, m: impl std::fmt::Display) -> ApiError {
    ApiError::new(code, format!("catcard: {m}"))
}

fn str_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// `CatCard:info` — what the device says about itself (`Identify`, in the
/// clear: no pairing, nobody is asked anything).
pub async fn info<T: Transport>(link: &T) -> ApiResult {
    let id = session::identify(link).await?;
    Ok(json!({
        "board": id.board,
        "firmware": id.version,
        "protocol": id.protocol,
        "unlocked": id.unlocked(),
        "blank": id.state & proto::state::BLANK != 0,
        "pairing": id.caps & proto::caps::PAIRING != 0,
        "hostWallet": id.caps & proto::caps::HOST_WALLET != 0,
        // A development image whose host can press keys or read memory.
        "bench": id.bench(),
        // A session from an earlier request is held for this link.
        "paired": session::held(link),
    }))
}

// ── Asking the person at the device ──────────────────────────────────────────

fn not_now(body: &[u8]) -> ApiError {
    match body.first() {
        Some(1) => cerr(423, "unlock the device first (enter its PIN)"),
        Some(2) => cerr(409, "the device is busy with another request, an upgrade offer, or an answer nobody fetched"),
        _ => cerr(409, "the device cannot take the request now"),
    }
}

/// Poll `HostResult` until the person has answered, then page the result in.
/// `what` names the question in the `catcard:waiting` events
/// (`{for, stage}`: `queued` — the person is in another menu; `deciding`).
async fn await_result<T: Transport>(env: &Env, link: &T, s: &mut Session, what: &str) -> Result<Vec<u8>, ApiError> {
    let mut waited = 0u32;
    let mut said = 0u8;
    loop {
        let (st, body) = s.call(link, op::HOST_RESULT, &0u32.to_le_bytes()).await?;
        match st {
            status::NOT_NOW => {
                let stage = body.first().copied().unwrap_or(0);
                match stage {
                    // An upload still open, queued for the screen, or on it.
                    1..=3 => {}
                    4 => return Err(cerr(409, "the device is busy with another session's request")),
                    _ => return Err(cerr(409, "the device has no answer for this session (the request was lost)")),
                }
                if stage != said {
                    said = stage;
                    env.broadcast(&crate::response::event("catcard:waiting", json!({ "for": what, "stage": if stage == 3 { "deciding" } else { "queued" } })));
                }
                if waited >= ANSWER_WAIT_MS {
                    return Err(cerr(408, "nobody answered on the device"));
                }
                sleep_ms(POLL_MS).await;
                waited += POLL_MS.max(1);
            }
            status::DECLINED => return Err(cerr(4001, "declined on the device")),
            status::REFUSED => return Err(cerr(403, format!("the device refused: {}", reason(&body)))),
            status::OK => {
                let page = |body: &[u8]| -> Result<(usize, Vec<u8>), ApiError> {
                    if body.len() < 4 || body.len() - 4 > proto::PAGE_MAX {
                        return Err(cerr(502, "malformed result page"));
                    }
                    Ok((u32::from_le_bytes(body[..4].try_into().unwrap()) as usize, body[4..].to_vec()))
                };
                let (total, mut got) = page(&body)?;
                while got.len() < total {
                    let (st, body) = s.call(link, op::HOST_RESULT, &(got.len() as u32).to_le_bytes()).await?;
                    if st != status::OK {
                        return Err(cerr(502, format!("HostResult page answered {}", status::name(st))));
                    }
                    let (t, more) = page(&body)?;
                    if t != total || more.is_empty() {
                        return Err(cerr(502, "the result changed while it was being read"));
                    }
                    got.extend_from_slice(&more);
                }
                if got.len() != total {
                    return Err(cerr(502, "the result is longer than announced"));
                }
                return Ok(got);
            }
            other => return Err(cerr(502, format!("HostResult answered {}", status::name(other)))),
        }
    }
}

/// Ask the device to share its addresses. The person chooses the account (and
/// the chains) on the device. The reply replaces what the session knew: the
/// device, too, only remembers the accounts of its latest answer.
async fn share<T: Transport>(env: &Env, link: &T, s: &mut Session) -> Result<Addresses, ApiError> {
    let (st, body) = s.call(link, op::HOST_ADDRESSES, &[]).await?;
    match st {
        status::OK => {}
        status::NOT_NOW => return Err(not_now(&body)),
        other => return Err(cerr(502, format!("HostAddresses answered {}", status::name(other)))),
    }
    let reply = await_result(env, link, s, "addresses").await?;
    let addresses = Addresses::decode(&reply).map_err(|e| cerr(502, format!("address reply: {e}")))?;
    s.fingerprint = Some(addresses.fingerprint);
    s.shared = addresses.entries.clone();
    Ok(addresses)
}

// ── Keys ─────────────────────────────────────────────────────────────────────

/// Which of the shared keys [`keys`] reports.
#[derive(Debug, Clone)]
pub struct KeyQuery {
    /// The account the caller expects the person to pick on the device. The
    /// host cannot choose it: when given, another account is an error.
    pub account: Option<u32>,
    /// Bitcoin script kinds to report an account key for (`p2wpkh`,
    /// `p2sh:p2wpkh`, `p2pkh`, `p2tr`); the device shares all four.
    pub scripts: Vec<String>,
}

impl KeyQuery {
    pub fn from_params(params: &Value) -> Result<Self, ApiError> {
        let account = match params.get("Account").filter(|v| !v.is_null()) {
            Some(v) => Some(v.as_u64().and_then(|a| u32::try_from(a).ok()).filter(|a| *a < HARDENED).ok_or_else(|| bad("Account out of range"))?),
            None => None,
        };
        if params.get("Count").and_then(Value::as_u64).is_some_and(|c| c != 1) {
            return Err(bad("a CatCard shares one account per request (the person picks it on the device): Count must be 1"));
        }
        if params.get("Paths").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
            return Err(bad("a CatCard shares its standard account paths only: Paths is not supported"));
        }
        let mut scripts: Vec<String> = params.get("Scripts").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
        if scripts.is_empty() {
            scripts.push("p2wpkh".into());
        }
        for s in &scripts {
            if script_format(s).is_none() {
                return Err(bad(format!("unsupported bitcoin script kind {s:?} (p2wpkh, p2sh:p2wpkh, p2pkh, p2tr)")));
            }
        }
        Ok(KeyQuery { account, scripts })
    }
}

fn script_format(script: &str) -> Option<u8> {
    match script {
        "" | "p2wpkh" => Some(format::P2WPKH),
        "p2sh:p2wpkh" => Some(format::P2SH_P2WPKH),
        "p2pkh" => Some(format::P2PKH),
        "p2tr" => Some(format::P2TR),
        _ => None,
    }
}

fn format_script(format: u8) -> Option<&'static str> {
    match format {
        format::P2WPKH => Some("p2wpkh"),
        format::P2SH_P2WPKH => Some("p2sh:p2wpkh"),
        format::P2PKH => Some("p2pkh"),
        format::P2TR => Some("p2tr"),
        _ => None,
    }
}

fn unsupported(e: &Entry, fp: &str, why: String) -> DiscoveredKey {
    DiscoveredKey {
        chain: "unsupported".into(),
        curve: if e.pubkey.len() == 32 { "ed25519" } else { "secp256k1" }.into(),
        coin_type: e.account_path.get(1).map(|c| c & !HARDENED),
        path: proto::path_text(if e.shape == shape::UTXO { &e.account_path } else { &e.address_path }),
        master_fingerprint: Some(fp.to_owned()),
        pubkey: hex(&e.pubkey),
        chain_code: None,
        script: String::new(),
        address: e.address.clone(),
        name: Some(chain::name(e.chain)),
        note: None,
        reason: Some(why),
    }
}

/// One shared entry as a key — after checking the device's own claims against
/// each other: the address it reports must be the one its key derives here.
fn discovered(env: &Env, fp: &str, e: &Entry) -> Result<DiscoveredKey, ApiError> {
    let mismatch = |what: &str| cerr(502, format!("the device's {} {what} does not match its key at {}", chain::name(e.chain), proto::path_text(&e.address_path)));
    let leaf = |chain: &str, curve: &str, coin: u32, address: String| DiscoveredKey {
        chain: chain.into(),
        curve: curve.into(),
        coin_type: Some(coin),
        path: proto::path_text(&e.address_path),
        master_fingerprint: Some(fp.to_owned()),
        pubkey: hex(&e.pubkey),
        chain_code: None,
        script: String::new(),
        address,
        name: None,
        note: None,
        reason: None,
    };
    match (e.chain, e.shape) {
        (chain::BITCOIN, shape::UTXO) => {
            let Some(script) = format_script(e.format) else {
                return Ok(unsupported(e, fp, format!("unknown Bitcoin address format {}", e.format)));
            };
            if e.account_path.get(1) != Some(&HARDENED) {
                return Ok(unsupported(e, fp, "Bitcoin test networks are not imported".into()));
            }
            let origin = proto::path_text(&e.account_path);
            let k = crate::airgap::import::key_from_extended(env, &format!("[{fp}/{}]{}", origin.trim_start_matches("m/"), e.xpub.trim()), Some(script)).map_err(|err| cerr(502, format!("account key: {err}")))?;
            // The first receive address, and the key it sits on, as the device
            // reports them, against what the extended key derives.
            let mut first = e.account_path.clone();
            first.extend([0, 0]);
            let cc = k.chain_code.as_deref().and_then(unhex).ok_or_else(|| cerr(502, "the account key has no chain code"))?;
            let child = crate::hdderive::derive_pub(&unhex(&k.pubkey).unwrap_or_default(), &cc, &[0, 0]).map_err(|err| cerr(502, format!("account key: {err}")))?;
            if e.address_path != first || child[..] != e.pubkey[..] {
                return Err(mismatch("public key"));
            }
            if k.address != e.address {
                return Err(mismatch("address"));
            }
            Ok(k)
        }
        (chain::ETHEREUM, shape::ACCOUNT) => {
            let address = crate::hdderive::evm_address(&e.pubkey).map_err(|_| mismatch("public key"))?;
            if !address.eq_ignore_ascii_case(&e.address) {
                return Err(mismatch("address"));
            }
            Ok(leaf("ethereum", "secp256k1", 60, address))
        }
        (chain::SOLANA, shape::ACCOUNT) => {
            if e.pubkey.len() != 32 || bs58::encode(&e.pubkey).into_string() != e.address {
                return Err(mismatch("address"));
            }
            Ok(leaf("solana", "ed25519", 501, e.address.clone()))
        }
        _ => Ok(unsupported(e, fp, format!("the device shares {} addresses but does not sign for them", chain::name(e.chain)))),
    }
}

/// `CatCard:getKeys` — ask the device to share its addresses, in the shape
/// `Airgap:parseKeys` returns (and `CatCard:import` takes). The person at the
/// device picks the account and the chains; for that account the device shares:
///
/// - **Bitcoin**: the account extended key of each script type (`m/84'/0'/n'`,
///   `m/49'/…`, `m/44'/…`, `m/86'/…`) with the master fingerprint — those
///   named by `Scripts` are reported.
/// - **Ethereum**: the key at `m/44'/60'/n'/0/0`.
/// - **Solana**: the key at `m/44'/501'/n'/0'`.
///
/// Chains the device shares but does not sign for come back `unsupported`.
pub async fn keys<T: Transport>(env: &Env, link: &T, q: &KeyQuery) -> Result<Export, ApiError> {
    let mut s = session::connect(env, link).await?;
    let out = keys_in(env, link, &mut s, q).await;
    session::keep(s);
    out
}

async fn keys_in<T: Transport>(env: &Env, link: &T, s: &mut Session, q: &KeyQuery) -> Result<Export, ApiError> {
    let shared = share(env, link, s).await?;
    if q.account.is_some_and(|a| a != shared.account) {
        return Err(cerr(409, format!("the device shared account {}, not account {}: pick account {} on the device", shared.account, q.account.unwrap_or(0), q.account.unwrap_or(0))));
    }
    let fp = hex(&shared.fingerprint);
    let mut export = Export {
        format: "catcard".into(),
        master_fingerprint: Some(fp.clone()),
        device: Some("CatCard".into()),
        version: Some(format!("{} {}", s.identity.board, s.identity.version)),
        ..Default::default()
    };
    for e in &shared.entries {
        if e.chain == chain::BITCOIN && format_script(e.format).is_some_and(|script| !q.scripts.iter().any(|w| w == script)) {
            continue;
        }
        export.keys.push(discovered(env, &fp, e)?);
    }
    Ok(export)
}

// ── Accounts ─────────────────────────────────────────────────────────────────

/// An account of a CatCard wallet, with what the device needs to find its key.
pub fn load_account(env: &Env, account_id: &str) -> Result<(Account, AccountKeyInfo), ApiError> {
    let account = crate::models::account::find(env, account_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "account not found"))?;
    let wallet = crate::models::wallet::fetch(env, &account.wallet).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "wallet not found"))?;
    if wallet.protocol != "catcard" {
        return Err(bad(format!("account {} is not on a CatCard wallet (protocol {})", account.id, wallet.protocol)));
    }
    let info = account_key_info(env, &account.id).map_err(ApiError::internal)?.unwrap_or(AccountKeyInfo {
        master_fingerprint: None,
        path: account.path.clone(),
        script: String::new(),
        curve: account.curve.clone(),
    });
    Ok((account, info))
}

fn chain_of(kind: &str) -> Result<u8, ApiError> {
    match kind {
        "bitcoin" => Ok(chain::BITCOIN),
        "ethereum" => Ok(chain::ETHEREUM),
        "solana" => Ok(chain::SOLANA),
        other => Err(bad(format!("CatCard signing is not supported for {other} accounts"))),
    }
}

fn account_pubkey(account: &Account) -> Result<Vec<u8>, ApiError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&account.pubkey).map_err(|_| ApiError::new(500, "bad account pubkey"))
}

/// The entry of the session's shared accounts that covers `account`, if any:
/// same chain, same `m/purpose'/coin'/account'`.
fn shared_entry<'s>(s: &'s Session, chain: u8, root: &[u32], want_format: Option<u8>) -> Option<&'s Entry> {
    s.shared.iter().find(|e| e.chain == chain && e.account_path == root && want_format.map_or(true, |f| e.format == f))
}

/// Make sure the device will sign for `account` in this session — it only
/// signs with keys below an account it shared in the same session, so ask it
/// to share when it has not — and that the key it shared there is the
/// account's: a device holding other keys (another seed, another passphrase)
/// is turned down before it is asked to sign anything.
async fn require_shared<T: Transport>(env: &Env, link: &T, s: &mut Session, account: &Account, info: &AccountKeyInfo) -> Result<Vec<u32>, ApiError> {
    let chain = chain_of(&account.kind)?;
    let path = proto::parse_path(&info.path).map_err(|e| bad(format!("account path {}: {e}", info.path)))?;
    let min = if chain == chain::BITCOIN { 3 } else { 4 };
    if path.len() < min || path[..3].iter().any(|c| c & HARDENED == 0) {
        return Err(bad(format!("{} is not below a standard account path (m/purpose'/coin'/account')", info.path)));
    }
    let root = &path[..3];
    let want_format = if chain == chain::BITCOIN { Some(script_format(&info.script).ok_or_else(|| bad(format!("unsupported bitcoin script kind {:?}", info.script)))?) } else { None };
    if shared_entry(s, chain, root, want_format).is_none() {
        share(env, link, s).await?;
    }
    let number = root[2] & !HARDENED;
    let entry = shared_entry(s, chain, root, want_format).ok_or_else(|| {
        cerr(409, format!("the device did not share {} account {number} ({}): pick account {number} and that chain when it asks", chain::name(chain), proto::path_text(root)))
    })?;
    let wrong = || cerr(409, format!("the device does not hold this account's key ({}): wrong device, or wrong passphrase?", account.address));
    let pubkey = account_pubkey(account)?;
    if chain == chain::BITCOIN {
        if path.len() != 3 {
            return Err(bad(format!("a bitcoin account's path is its account key's (m/purpose'/coin'/account'), not {}", info.path)));
        }
        let fp = hex(&s.fingerprint.unwrap_or_default());
        let k = discovered(env, &fp, entry)?;
        if k.pubkey != hex(&pubkey) || info.master_fingerprint.as_deref().is_some_and(|have| !have.eq_ignore_ascii_case(&fp)) {
            return Err(wrong());
        }
    } else if entry.address_path == path {
        discovered(env, "", entry)?;
        if entry.pubkey != pubkey {
            return Err(wrong());
        }
    }
    Ok(path)
}

/// `CatCard:showAddress` — not something the device's host protocol can do:
/// it has no command to display one address. (Its own Address Explorer shows
/// them, on the device.)
pub fn show_address(account: &Account) -> ApiResult {
    Err(ApiError::new(
        501,
        format!("the CatCard host protocol has no command to display an address: compare {} with the device's own Address Explorer (CatCard:getKeys checks that the device still derives it)", account.address),
    ))
}

/// `CatCard:signMessage` — not something the device's host protocol can do:
/// its sign request takes a Bitcoin PSBT, an EVM transaction or a Solana
/// transaction, never a message.
pub fn sign_message(account: &Account) -> ApiResult {
    Err(ApiError::new(501, format!("the CatCard host protocol has no message-signing command ({} account {}): sign messages on the device itself", account.kind, account.id)))
}

// ── Signing ──────────────────────────────────────────────────────────────────

/// Upload a sign request, have the person review it on the device, and return
/// the result's bytes.
async fn sign_on_device<T: Transport>(env: &Env, link: &T, s: &mut Session, chain: u8, keys: &[Vec<u32>], tx: &[u8]) -> Result<Vec<u8>, ApiError> {
    let blob = proto::sign_blob(chain, keys, tx).map_err(bad)?;
    let mut begin = vec![chain];
    begin.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    let (st, body) = s.call(link, op::HOST_SIGN_BEGIN, &begin).await?;
    let chunk = match st {
        status::OK => body.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize).unwrap_or(proto::DATA_MAX).clamp(1, proto::DATA_MAX),
        status::NOT_NOW => return Err(not_now(&body)),
        status::REFUSED => return Err(cerr(403, format!("the device refused: {}", reason(&body)))),
        other => return Err(cerr(502, format!("HostSignBegin answered {}", status::name(other)))),
    };
    let uploaded = async {
        let mut at = 0usize;
        while at < blob.len() {
            let part = &blob[at..(at + chunk).min(blob.len())];
            let mut data = (at as u32).to_le_bytes().to_vec();
            data.extend_from_slice(part);
            let (st, _) = s.call(link, op::HOST_SIGN_DATA, &data).await?;
            if st != status::OK {
                return Err(cerr(502, format!("HostSignData answered {} at {at}", status::name(st))));
            }
            at += part.len();
        }
        let (st, body) = s.call(link, op::HOST_SIGN_COMMIT, &[]).await?;
        match st {
            status::OK => Ok(()),
            status::REFUSED => Err(cerr(403, format!("the device refused: {}", reason(&body)))),
            other => Err(cerr(502, format!("HostSignCommit answered {}", status::name(other)))),
        }
    }
    .await;
    if let Err(e) = uploaded {
        // Drop the upload so its memory is freed (a refused commit already did).
        let _ = s.call(link, op::HOST_ABORT, &[]).await;
        return Err(e);
    }
    await_result(env, link, s, "signature").await
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

fn not_this_account(account: &Account) -> ApiError {
    ApiError::new(409, format!("the device's signature is not from this account ({}): wrong device, or wrong passphrase?", account.address))
}

/// `CatCard:signTransaction` for an Ethereum account: fill what the
/// `Transaction` lacks from the node (the chain id comes from the Network
/// model, never the node), have the device sign the exact preimage, and accept
/// its signature only on the transaction built here: the device's `r, s` on
/// our own unsigned transaction must recover to the account.
async fn sign_evm<T: Transport>(env: &Env, link: &T, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
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

    // Only now is the device involved: nothing incomplete reaches it.
    let mut session = session::connect(env, link).await?;
    let result = async {
        let path = require_shared(env, link, &mut session, account, info).await?;
        sign_on_device(env, link, &mut session, chain::ETHEREUM, &[path], &sign_data).await
    }
    .await;
    session::keep(session);
    let result = result?;
    let signed = proto::read_evm(&result).map_err(|e| cerr(502, format!("sign result: {e}")))?;
    let theirs = outscript::evmtx::EvmTx::from_bytes(signed).map_err(|e| cerr(502, format!("signed transaction: {e}")))?;
    let scalar = |v: &num_bigint::BigInt| -> Result<[u8; 32], ApiError> {
        let (_, b) = v.to_bytes_be();
        let mut out = [0u8; 32];
        if !theirs.signed || b.len() > 32 {
            return Err(cerr(502, "the device returned no usable signature"));
        }
        out[32 - b.len()..].copy_from_slice(&b);
        Ok(out)
    };
    let (r, sv) = (scalar(&theirs.r)?, scalar(&theirs.s)?);

    // Only the device's r and s are used: the transaction that goes out is
    // the one built here, under whichever parity recovers to the account.
    let want = account.address.to_lowercase();
    let mut raw = None;
    for parity in [0u8, 1] {
        let unsigned = crate::evm::build_unsigned(&req).map_err(|e| bad(e.to_string()))?;
        if let Ok(candidate) = crate::evm::attach_signature(unsigned, &r, &sv, parity) {
            if crate::evm::recover_sender(&candidate).is_ok_and(|from| from.to_lowercase() == want) {
                raw = Some(candidate);
                break;
            }
        }
    }
    let raw = raw.ok_or_else(|| not_this_account(account))?;
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

/// `CatCard:signTransaction` for a Solana account: build the transfer (or take
/// a ready `Transaction.message`, base58 / base64), have the device sign the
/// message, and accept the signature only if it verifies under the account key.
async fn sign_solana<T: Transport>(env: &Env, link: &T, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    use base64::Engine;
    let tx = params.get("Transaction").ok_or_else(|| bad("Transaction required"))?;
    let pk = crate::solana::pubkey_from_b64url(&account.pubkey).ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    let rpc = rpc_for(env, params, "solana")?;
    let message = match tx.get("message").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(m) => bs58::decode(m)
            .into_vec()
            .ok()
            .or_else(|| base64::engine::general_purpose::STANDARD.decode(m).ok())
            .ok_or_else(|| bad("Transaction.message must be base58 or base64"))?,
        None => {
            let url = rpc.as_deref().ok_or_else(|| bad("no node: pass Transaction.message, or a Network to build the transfer"))?;
            let net = crate::handlers::network_for_kind(env, params, "solana")?;
            crate::handlers::solana_build::build_unsigned(env, account, &net, url, tx).await?.message
        }
    };
    // Only a message this account is a signer of — never arbitrary bytes.
    let slot = crate::solana::find_signer_slot(&message, &pk).ok_or_else(|| bad("Transaction.message does not name this account as a signer"))?;

    if proto::parse_path(&info.path).is_ok_and(|p| p.iter().any(|c| c & HARDENED == 0)) {
        return Err(bad(format!("the device signs Solana with fully hardened paths only, not {}", info.path)));
    }

    let mut session = session::connect(env, link).await?;
    let result = async {
        let path = require_shared(env, link, &mut session, account, info).await?;
        sign_on_device(env, link, &mut session, chain::SOLANA, &[path], &message).await
    }
    .await;
    session::keep(session);
    let result = result?;
    let (sigs, _) = proto::read_solana(&result).map_err(|e| cerr(502, format!("sign result: {e}")))?;
    let sig = sigs.iter().find(|(at, _)| *at as usize == slot).map(|(_, sig)| *sig).ok_or_else(|| cerr(502, "the device returned no signature for this account"))?;
    if !crate::tss::ed25519_verify(&pk, &message, &sig) {
        return Err(not_this_account(account));
    }
    // Assembled here from the message that was asked for, not taken from the
    // device's reply.
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

/// At most this many previous transactions are fetched for one spend.
const MAX_PREV_TXS: usize = 50;

/// Records the digest a PSBT input is signed over instead of signing it: what
/// lets the device's signature be checked against the account's own key.
struct SighashProbe {
    key: outscript::crypto::secp256k1::SecpPublicKey,
    seen: std::cell::Cell<Option<[u8; 32]>>,
}

impl outscript::psbt::PsbtSigner for SighashProbe {
    fn public_key(&self) -> outscript::crypto::secp256k1::SecpPublicKey {
        self.key.clone()
    }
    fn sign_ecdsa(&self, digest: &[u8; 32]) -> Result<outscript::crypto::secp256k1::DerSignature, outscript::psbt::SignerError> {
        self.seen.set(Some(*digest));
        Err(outscript::psbt::SignerError)
    }
    fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], outscript::psbt::SignerError> {
        self.seen.set(Some(*sighash));
        Err(outscript::psbt::SignerError)
    }
}

/// The first item of a serialized witness stack, or the first push of a
/// scriptSig: where a single-key spend carries its signature.
fn first_item(serialized: &[u8], witness: bool) -> Option<&[u8]> {
    let rest = if witness { serialized.get(1..)? } else { serialized };
    let n = *rest.first()? as usize;
    if n == 0 || n > 75 {
        return None;
    }
    rest.get(1..1 + n)
}

/// The keys the pending PSBT's inputs are signed with (their full paths).
fn psbt_keys(ours: &[u8]) -> Result<Vec<Vec<u32>>, ApiError> {
    use outscript::psbt::{input, Psbt};
    let p = Psbt::parse(ours).map_err(|e| ApiError::new(500, format!("pending psbt: {e}")))?;
    let mut keys: Vec<Vec<u32>> = Vec::new();
    for i in p.inputs() {
        let ecdsa = i.map().records_of(input::BIP32_DERIVATION).next().map(|r| r.value);
        // Taproot: compact-size(0 leaf hashes) ‖ fingerprint ‖ path.
        let taproot = i.map().records_of(input::TAP_BIP32_DERIVATION).next().and_then(|r| r.value.get(1..));
        let v = ecdsa.or(taproot).filter(|v| v.len() >= 8 && v.len() % 4 == 0).ok_or_else(|| ApiError::new(500, "an input has no key derivation"))?;
        let path: Vec<u32> = v[4..].chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        if !keys.contains(&path) {
            keys.push(path);
        }
    }
    Ok(keys)
}

/// Check the device's answer: every input must carry a signature that
/// verifies, over that input's own sighash, under the key the PSBT built here
/// names for it — which was derived from the account's extended key.
fn verify_psbt(ours: &[u8], theirs: &[u8], account: &Account) -> Result<(), ApiError> {
    use outscript::crypto::secp256k1::{bip340_verify, parse_der_signature, taproot_tweak, SecpPublicKey};
    use outscript::psbt::{input, Psbt};
    let ours_p = Psbt::parse(ours).map_err(|e| ApiError::new(500, format!("pending psbt: {e}")))?;
    let theirs_p = Psbt::parse(theirs).map_err(|e| cerr(502, format!("signed psbt: {e}")))?;
    let count = ours_p.unsigned_tx().input_count();
    if ours_p.unsigned_tx().txid() != theirs_p.unsigned_tx().txid() || theirs_p.unsigned_tx().input_count() != count {
        return Err(ApiError::new(409, "the device signed a different transaction than the one it was asked to"));
    }
    let internal = || ApiError::new(500, "cannot compute an input's sighash");
    for n in 0..count {
        let (mine, got) = (ours_p.input(n).ok_or_else(internal)?, theirs_p.input(n).ok_or_else(internal)?);
        let witness = got.final_script_witness().and_then(|w| first_item(w, true));
        let ok = if let Some(rec) = mine.map().records_of(input::BIP32_DERIVATION).next() {
            let pubkey = rec.key_data();
            let probe = SighashProbe { key: SecpPublicKey::from_sec1(pubkey).map_err(|_| internal())?, seen: Default::default() };
            let _ = ours_p.sign_input_to_vec(n, &probe);
            let digest = probe.seen.take().ok_or_else(internal)?;
            // Still a partial signature, or already finalised by the device.
            let sig = got.partial_sig(pubkey).or(witness).or_else(|| got.final_script_sig().and_then(|s| first_item(s, false)));
            sig.and_then(|sig| sig.split_last()).and_then(|(_, der)| parse_der_signature(der).ok()).is_some_and(|(r, s)| probe.key.verify(&digest, &r, &s))
        } else if let Some(rec) = mine.map().records_of(input::TAP_BIP32_DERIVATION).next() {
            let xonly: [u8; 32] = rec.key_data().try_into().map_err(|_| internal())?;
            let mut sec1 = vec![0x02];
            sec1.extend_from_slice(&xonly);
            let probe = SighashProbe { key: SecpPublicKey::from_sec1(&sec1).map_err(|_| internal())?, seen: Default::default() };
            let _ = ours_p.sign_input_to_vec(n, &probe);
            let sighash = probe.seen.take().ok_or_else(internal)?;
            let (output_key, _) = taproot_tweak(&xonly).map_err(|_| internal())?;
            let sig = got.tap_key_sig().or(witness);
            sig.and_then(|sig| sig.get(..64)).and_then(|sig| <[u8; 64]>::try_from(sig).ok()).is_some_and(|sig| bip340_verify(&output_key, &sighash, &sig))
        } else {
            return Err(internal());
        };
        if !ok {
            return Err(ApiError::new(409, format!("input {n} is not signed by this account's key ({}): wrong device, wrong passphrase, or it was left unsigned", account.address)));
        }
    }
    Ok(())
}

/// `CatCard:signTransaction` for a Bitcoin account: the PSBT is built exactly
/// as for an air-gapped signer and kept as the pending request; the device
/// reviews and signs it with the keys of its inputs; every input's signature
/// is verified under the account's key, and the answer then goes through the
/// air-gap acceptance — it must be that pending transaction, fully signed —
/// before anything is returned or broadcast.
///
/// What the builder needs from the node is fetched here, async, so the same
/// code runs natively and in the browser: the account's UTXOs, and — best
/// effort — the previous transactions of the inputs it will spend, which let
/// the device verify the amounts it shows.
async fn sign_bitcoin<T: Transport>(env: &Env, link: &T, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    use base64::Engine;
    let mut tx = params.get("Transaction").cloned().filter(Value::is_object).ok_or_else(|| bad("Transaction required"))?;
    if tx.get("ChainId").and_then(Value::as_str).is_some_and(|c| c != "bitcoin") {
        return Err(bad("a CatCard signs Bitcoin PSBTs only (its other UTXO chains are address-only)"));
    }
    let rpc = rpc_for(env, params, "bitcoin")?;

    if tx.get("UTXOs").and_then(Value::as_array).map_or(true, |a| a.is_empty()) {
        let url = rpc.as_deref().ok_or_else(|| bad("no node: pass Transaction.UTXOs, or a Network to discover them"))?;
        let xpub = account.xpub().map_err(ApiError::internal)?;
        let assets = crate::rpc::call_async(url, "modchain_assets", json!([xpub])).await.map_err(ApiError::internal)?;
        let all = crate::bitcoin::parse_native_utxos(&assets).map_err(ApiError::internal)?;
        tx["UTXOs"] = Value::Array(all.iter().map(|u| json!({ "txo": u.txo, "amount_sats": u.amount_sats, "height": u.height, "path": u.path, "script": u.script })).collect());

        // The previous transactions of the inputs the builder will pick. The
        // builder only uses one that hashes to the input's txid.
        let want = tx.get("Amount").or_else(|| tx.get("amount")).and_then(Value::as_u64).unwrap_or(0);
        let fee_rate = tx.get("FeeRate").and_then(Value::as_u64).unwrap_or(10);
        if let Ok((selected, _)) = crate::bitcoin::select_utxos(&all, want, fee_rate) {
            let mut prev = serde_json::Map::new();
            for u in selected.iter().take(MAX_PREV_TXS) {
                let Some((txid, _)) = u.txo.split_once(':') else { continue };
                if prev.contains_key(txid) {
                    continue;
                }
                if let Ok(Value::String(raw)) = crate::rpc::call_async(url, "getrawtransaction", json!([txid])).await {
                    prev.insert(txid.to_owned(), Value::String(raw));
                }
            }
            if !prev.is_empty() && tx.get("PrevTxs").is_none() {
                tx["PrevTxs"] = Value::Object(prev);
            }
        }
    }

    // The node was already consulted: the builder works from the Transaction.
    let built = crate::airgap::sign::build_request(env, &account.id, &tx, &Default::default(), None).map_err(|e| bad(e.to_string()))?;
    let rid = built.request_id.clone();
    let signed = async {
        let psbt = built.payload.get("psbt").and_then(Value::as_str).and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()).ok_or_else(|| ApiError::new(500, "no PSBT was built"))?;
        let keys = psbt_keys(&psbt)?;
        let mut session = session::connect(env, link).await?;
        let result = async {
            require_shared(env, link, &mut session, account, info).await?;
            sign_on_device(env, link, &mut session, chain::BITCOIN, &keys, &psbt).await
        }
        .await;
        session::keep(session);
        let result = result?;
        let (_, theirs, _) = proto::read_bitcoin(&result).map_err(|e| cerr(502, format!("sign result: {e}")))?;
        verify_psbt(&psbt, theirs, account)?;
        Ok(theirs.to_vec())
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

/// `CatCard:signTransaction` — have the person review and sign the
/// `Transaction` for a CatCard account on the device (and with
/// `Broadcast: true`, send it).
pub async fn sign_transaction<T: Transport>(env: &Env, link: &T, account: &Account, info: &AccountKeyInfo, params: &Value) -> ApiResult {
    chain_of(&account.kind)?;
    if params.get("Transaction").is_none() {
        return Err(bad("Transaction required"));
    }
    match account.kind.as_str() {
        "ethereum" => sign_evm(env, link, account, info, params).await,
        "solana" => sign_solana(env, link, account, info, params).await,
        _ => sign_bitcoin(env, link, account, info, params).await,
    }
}

#[cfg(test)]
mod tests;
