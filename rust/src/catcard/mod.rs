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
//! and the host polls for the outcome. Every firmware has two questions —
//! "share this wallet's addresses" (the account is chosen on the device, not
//! by the host) and "sign this transaction" (a Bitcoin PSBT, an EVM
//! transaction, a Solana message). Later firmware has two more — "the address
//! at this path" (optionally shown on the device to be compared) and "sign
//! this message" — and says so in `HostInfo`, asked once per session: a
//! firmware without it answers `UnknownOpcode`, and [`show_address`] and
//! [`sign_message`] then answer 501. The device only signs with keys it shared
//! in the same session: below an account it shared, or a key it shared by its
//! own path.
//!
//! Nothing the device returns is trusted on its own. A shared key is only
//! reported once its address derives from it here; a signature is only handed
//! back once it verifies under the account's key over exactly what was asked:
//! the EVM transaction is rebuilt from the request with the device's `r, s`
//! and must recover to the account address, the Solana signature must verify
//! over the built message, and every input of a Bitcoin PSBT must carry a
//! signature that verifies under the account's own derived key before the PSBT
//! goes through the same pending-request binding as an air-gapped signer's. A
//! message signature must recover to the account's key (EIP-191, BIP-137); a
//! BIP-322 one is not checked here — nothing in this library verifies those —
//! and is returned marked as such.

pub mod proto;
pub mod session;
pub mod transport;

use serde_json::{json, Value};

use crate::airgap::import::{account_key_info, AccountKeyInfo, DiscoveredKey, Export};
use crate::handlers::{ApiError, ApiResult};
use crate::models::account::Account;
use crate::Env;

use proto::{can, chain, feature, format, op, scheme, shape, status, AddressAt, Addresses, Entry, HostInfo, HARDENED};
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
///
/// What its firmware answers beyond that (`HostInfo`) only travels inside the
/// encrypted channel, so `hostInfo` is there when a session is already held
/// for the link — it is asked afresh, the session's own bits move — and null
/// otherwise: no pairing is started for this.
pub async fn info<T: Transport>(link: &T) -> ApiResult {
    let id = session::identify(link).await?;
    let mut host = Value::Null;
    let mut paired = false;
    if let Some(mut s) = session::take(link) {
        if let Ok(known) = host_info(link, &mut s, true).await {
            host = host_json(known.as_ref());
        }
        // A session the device no longer honours ended with that call.
        paired = s.alive();
        session::keep(s);
    }
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
        "paired": paired,
        "hostInfo": host,
    }))
}

// ── What the firmware answers ────────────────────────────────────────────────

/// The device's `HostInfo`: which requests beyond the first six its firmware
/// answers, what each chain can be asked for, and what this session has been
/// given. Asked once per session and remembered (`refresh` asks again). `None`
/// is a firmware that predates the request — it answers `UnknownOpcode`.
async fn host_info<T: Transport>(link: &T, s: &mut Session, refresh: bool) -> Result<Option<HostInfo>, ApiError> {
    match &s.host {
        // A firmware that did not know the request has not learned it since.
        Some(None) => return Ok(None),
        Some(known) if !refresh => return Ok(known.clone()),
        _ => {}
    }
    let (st, body) = s.call(link, op::HOST_INFO, &[]).await?;
    let info = match st {
        status::OK => Some(HostInfo::decode(&body).map_err(|e| cerr(502, format!("HostInfo: {e}")))?),
        status::UNKNOWN_OPCODE => None,
        other => return Err(cerr(502, format!("HostInfo answered {}", status::name(other)))),
    };
    s.host = Some(info.clone());
    Ok(info)
}

/// `HostInfo` as `CatCard:info` reports it.
fn host_json(info: Option<&HostInfo>) -> Value {
    let Some(i) = info else {
        // The firmware has the first six requests only.
        return json!({ "legacy": true, "addressAt": false, "signMessage": false, "pathsAllowed": false, "shared": false, "messageMax": 0, "chains": [] });
    };
    json!({
        "legacy": false,
        "addressAt": i.features & feature::ADDRESS_AT != 0,
        "signMessage": i.features & feature::SIGN_MESSAGE != 0,
        // The owner ticked "Allow during session": addresses by path are
        // answered without a question until the session ends.
        "pathsAllowed": i.session & proto::granted::PATHS_ALLOWED != 0,
        "shared": i.session & proto::granted::SHARED != 0,
        "messageMax": i.message_max,
        "chains": i.chains.iter().map(|c| json!({
            "chain": c.chain,
            "name": chain::name(c.chain),
            "addresses": c.can & can::ADDRESSES != 0,
            "sign": c.can & can::SIGN != 0,
            "messages": c.can & can::MESSAGES != 0,
            "formats": c.formats.iter().map(|f| format::name(*f)).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

/// The firmware's `HostInfo`, provided it has the request `bit` names and can
/// do it for `chain` — else a 501 saying what the firmware cannot do.
async fn require_feature<T: Transport>(link: &T, s: &mut Session, bit: u8, chain: u8, needs: u8, what: &str) -> Result<HostInfo, ApiError> {
    let info = host_info(link, s, false).await?.filter(|i| i.features & bit != 0);
    let Some(info) = info else {
        return Err(cerr(501, format!("the device's firmware is too old to {what} (CatCard {} has no such request): update its firmware", s.identity.version)));
    };
    if info.can(chain) & needs == 0 {
        return Err(cerr(501, format!("this CatCard firmware cannot {what} for {}", chain::name(chain))));
    }
    Ok(info)
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

/// A refusal's error. One that says a key "was not shared this session"
/// contradicts what this side remembers of the session — the device's owner
/// changed the wallet in force (a passphrase), which drops everything it had
/// shared — so that memory is dropped too, and the next request asks again.
fn refused(s: &mut Session, body: &[u8]) -> ApiError {
    let why = reason(body);
    if why.contains("not shared") {
        s.forget_shared();
        return cerr(409, format!("the device refused: {why} (it no longer shares this key: try again)"));
    }
    cerr(403, format!("the device refused: {why}"))
}

/// A question that fits one request (`HostAddressAt`, `HostSignMessage`):
/// send it, and wait for the answer of the person at the device.
async fn ask<T: Transport>(env: &Env, link: &T, s: &mut Session, opcode: u16, payload: &[u8], name: &str, what: &str) -> Result<Vec<u8>, ApiError> {
    let (st, body) = s.call(link, opcode, payload).await?;
    match st {
        status::OK => await_result(env, link, s, what).await,
        status::UNKNOWN_OPCODE => Err(cerr(501, format!("the device's firmware is too old: it has no {name} request"))),
        status::NOT_NOW => Err(not_now(&body)),
        status::REFUSED => Err(refused(s, &body)),
        other => Err(cerr(502, format!("{name} answered {}", status::name(other)))),
    }
}

/// The address `pubkey` has on `chain` written as `format`, for the chains
/// this library holds accounts on (Bitcoin: its main network).
fn address_of(chain: u8, fmt: u8, pubkey: &[u8]) -> Option<String> {
    match (chain, fmt) {
        (chain::BITCOIN, _) => crate::bitcoin::address_for(pubkey.try_into().ok()?, format_script(fmt)?, "bitcoin").ok(),
        (chain::ETHEREUM, format::EVM) => crate::hdderive::evm_address(pubkey).ok(),
        (chain::SOLANA, format::SOLANA) => (pubkey.len() == 32).then(|| bs58::encode(pubkey).into_string()),
        _ => None,
    }
}

/// Ask the device for the one key at `path` (`HostAddressAt`). Its owner is
/// asked "Computer asks for the <chain> address at <path>" — unless they
/// ticked "Allow during session" at an earlier one — and, with `show`, then
/// sees the address itself with "Same as the computer shows?", whatever the
/// session was allowed.
///
/// The reply must be for the key that was asked, and its address must be the
/// one its public key has here. The device then lets this session sign with
/// exactly that key, which is remembered.
async fn address_at<T: Transport>(env: &Env, link: &T, s: &mut Session, chain: u8, fmt: u8, path: &[u32], show: bool) -> Result<AddressAt, ApiError> {
    let request = proto::address_at_request(chain, fmt, show, path).map_err(bad)?;
    let reply = ask(env, link, s, op::HOST_ADDRESS_AT, &request, "HostAddressAt", "address").await?;
    let a = AddressAt::decode(&reply).map_err(|e| cerr(502, format!("address reply: {e}")))?;
    let (name, at) = (chain::name(chain), proto::path_text(path));
    if a.chain != chain || a.format != fmt || a.path != path {
        return Err(cerr(502, format!("the device answered for another key than the {name} one asked for at {at}")));
    }
    let derived = address_of(chain, fmt, &a.pubkey).ok_or_else(|| cerr(502, format!("the device's {name} public key at {at} cannot be used")))?;
    let same = if chain == chain::ETHEREUM { derived.eq_ignore_ascii_case(&a.address) } else { derived == a.address };
    if !same {
        let hint = if chain == chain::BITCOIN { " (is the device set to a test network?)" } else { "" };
        return Err(cerr(502, format!("the device's {name} address does not match its key at {at}{hint}")));
    }
    s.fingerprint = Some(a.fingerprint);
    s.remember(a.clone());
    Ok(a)
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
    /// Individual keys to read by their path instead (`HostAddressAt`):
    /// `(chain, format, path)`. Empty: the account-sharing flow.
    pub paths: Vec<(u8, u8, Vec<u32>)>,
}

/// Most keys one `CatCard:getKeys {Paths}` reads: each is a question on the
/// device unless its owner allows them for the session.
const MAX_PATHS: usize = 32;

impl KeyQuery {
    pub fn from_params(params: &Value) -> Result<Self, ApiError> {
        let account = match params.get("Account").filter(|v| !v.is_null()) {
            Some(v) => Some(v.as_u64().and_then(|a| u32::try_from(a).ok()).filter(|a| *a < HARDENED).ok_or_else(|| bad("Account out of range"))?),
            None => None,
        };
        if params.get("Count").and_then(Value::as_u64).is_some_and(|c| c != 1) {
            return Err(bad("a CatCard shares one account per request (the person picks it on the device): Count must be 1"));
        }
        let mut paths = Vec::new();
        if let Some(list) = params.get("Paths").filter(|v| !v.is_null()) {
            let list = list.as_array().ok_or_else(|| bad("Paths must be a list of derivation paths"))?;
            if list.len() > MAX_PATHS {
                return Err(bad(format!("at most {MAX_PATHS} Paths per request")));
            }
            if !list.is_empty() && account.is_some() {
                return Err(bad("Account selects nothing with Paths: each path names its own key"));
            }
            let chain = str_param(params, "Chain").map(|c| chain_of(c).map_err(|_| bad(format!("Chain must be bitcoin, ethereum or solana, not {c:?}")))).transpose()?;
            let wanted = str_param(params, "Format");
            for p in list {
                let text = p.as_str().ok_or_else(|| bad("Paths must be a list of derivation paths"))?;
                let path = proto::parse_path(text).map_err(|e| bad(format!("path {text:?}: {e}")))?;
                // The chain a path's coin type means, when none was named.
                let chain = match (chain, path.get(1).filter(|c| path.len() >= 2 && **c & HARDENED != 0).map(|c| c & !HARDENED)) {
                    (Some(c), _) => c,
                    (None, Some(0)) => chain::BITCOIN,
                    (None, Some(60)) => chain::ETHEREUM,
                    (None, Some(501)) => chain::SOLANA,
                    _ => return Err(bad(format!("Chain (bitcoin, ethereum or solana) required: {text} does not say which chain it is for"))),
                };
                let fmt = match chain {
                    chain::ETHEREUM => format::EVM,
                    chain::SOLANA => format::SOLANA,
                    // The script kind asked for, else the one the path's
                    // purpose means (native segwit when it means none).
                    _ => match wanted {
                        Some(f) => script_format(f).ok_or_else(|| bad(format!("unsupported bitcoin Format {f:?} (p2wpkh, p2sh:p2wpkh, p2pkh, p2tr)")))?,
                        None => match path[0] ^ HARDENED {
                            44 => format::P2PKH,
                            49 => format::P2SH_P2WPKH,
                            86 => format::P2TR,
                            _ => format::P2WPKH,
                        },
                    },
                };
                if chain == chain::SOLANA && path.iter().any(|c| c & HARDENED == 0) {
                    return Err(bad(format!("a Solana key path is hardened throughout, not {text}")));
                }
                paths.push((chain, fmt, path));
            }
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
        Ok(KeyQuery { account, scripts, paths })
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
///
/// With `Paths` the host names the keys instead (later firmware only): each
/// is asked for by its path with `HostAddressAt` — a question on the device
/// per key, unless its owner ticks "Allow during session" at the first.
/// Ethereum and Solana keys come back as the leaf keys an import takes. A
/// Bitcoin path names a single address key, not an account: it has no
/// extended key to derive addresses from, so it is reported `unsupported`
/// (with its address, key and script kind) and an import skips it.
pub async fn keys<T: Transport>(env: &Env, link: &T, q: &KeyQuery) -> Result<Export, ApiError> {
    let mut s = session::connect(env, link).await?;
    let out = if q.paths.is_empty() { keys_in(env, link, &mut s, q).await } else { keys_by_path(env, link, &mut s, q).await };
    session::keep(s);
    out
}

async fn keys_by_path<T: Transport>(env: &Env, link: &T, s: &mut Session, q: &KeyQuery) -> Result<Export, ApiError> {
    let mut export = Export { format: "catcard".into(), device: Some("CatCard".into()), version: Some(format!("{} {}", s.identity.board, s.identity.version)), ..Default::default() };
    for (chain, fmt, path) in &q.paths {
        require_feature(link, s, feature::ADDRESS_AT, *chain, can::ADDRESSES, "share a key by its path").await?;
        let a = address_at(env, link, s, *chain, *fmt, path, false).await?;
        let fp = hex(&a.fingerprint);
        if export.master_fingerprint.get_or_insert_with(|| fp.clone()) != &fp {
            s.forget_shared();
            return Err(cerr(409, "the device's wallet changed between two keys (a passphrase?): read them again"));
        }
        let (name, curve, coin) = match *chain {
            chain::ETHEREUM => ("ethereum", "secp256k1", 60),
            chain::SOLANA => ("solana", "ed25519", 501),
            _ => ("unsupported", "secp256k1", 0),
        };
        let single = *chain == chain::BITCOIN;
        export.keys.push(DiscoveredKey {
            chain: name.into(),
            curve: curve.into(),
            coin_type: Some(coin),
            path: proto::path_text(path),
            master_fingerprint: Some(fp),
            pubkey: hex(&a.pubkey),
            chain_code: None,
            script: if single { format_script(*fmt).unwrap_or_default().into() } else { String::new() },
            address: a.address,
            name: single.then(|| chain::name(*chain)),
            note: None,
            reason: single.then(|| "a single Bitcoin address key, not an account: it has no extended key to derive addresses from (share the account with CatCard:getKeys without Paths)".into()),
        });
    }
    Ok(export)
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

fn wrong_device(account: &Account) -> ApiError {
    cerr(409, format!("the device does not hold this account's key ({}): wrong device, or wrong passphrase?", account.address))
}

fn not_shared(chain: u8, root: &[u32]) -> ApiError {
    let number = root[2] & !HARDENED;
    cerr(409, format!("the device did not share {} account {number} ({}): pick account {number} and that chain when it asks", chain::name(chain), proto::path_text(root)))
}

/// The one key of an account that a single-key request names — an address to
/// show, a message to sign, an Ethereum or Solana transaction: where it is,
/// how its address is written, and the public key libwallet holds for it.
struct KeyRef {
    chain: u8,
    format: u8,
    /// Ethereum, Solana: the account's path. Bitcoin: the first receive
    /// address, `…/0/0` below the account key.
    path: Vec<u32>,
    pubkey: Vec<u8>,
}

fn key_of(account: &Account, info: &AccountKeyInfo) -> Result<KeyRef, ApiError> {
    use base64::Engine;
    let chain = chain_of(&account.kind)?;
    let mut path = proto::parse_path(&info.path).map_err(|e| bad(format!("account path {}: {e}", info.path)))?;
    let pubkey = account_pubkey(account)?;
    match chain {
        chain::BITCOIN => {
            let format = script_format(&info.script).ok_or_else(|| bad(format!("unsupported bitcoin script kind {:?}", info.script)))?;
            let cc = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&account.chaincode).ok().filter(|c| c.len() == 32).ok_or_else(|| bad("this bitcoin account has no account key to derive its first address from"))?;
            let first = crate::hdderive::derive_pub(&pubkey, &cc, &[0, 0]).map_err(|e| ApiError::new(500, format!("account key: {e}")))?;
            if path.len() + 2 > proto::MAX_DEPTH {
                return Err(bad(format!("account path {} is too deep", info.path)));
            }
            path.extend([0, 0]);
            Ok(KeyRef { chain, format, path, pubkey: first.to_vec() })
        }
        chain::ETHEREUM => Ok(KeyRef { chain, format: format::EVM, path, pubkey }),
        _ => Ok(KeyRef { chain, format: format::SOLANA, path, pubkey }),
    }
}

/// The standard account path `m/purpose'/coin'/account'` a key sits below,
/// if it sits below one.
fn account_root(path: &[u32]) -> Option<&[u32]> {
    (path.len() > 3 && path[..3].iter().all(|c| c & HARDENED != 0)).then(|| &path[..3])
}

/// What the accounts shared in this session (`HostAddresses`) say of `key`:
/// `None` when none covers it; else the public key the device reported at
/// exactly that path, when that is the path it reported (after checking the
/// entry's own claims against each other).
fn covered(env: &Env, s: &Session, key: &KeyRef) -> Result<Option<Option<Vec<u8>>>, ApiError> {
    let want_format = (key.chain == chain::BITCOIN).then_some(key.format);
    let Some(entry) = account_root(&key.path).and_then(|root| shared_entry(s, key.chain, root, want_format)) else { return Ok(None) };
    if entry.address_path != key.path {
        return Ok(Some(None));
    }
    discovered(env, &hex(&s.fingerprint.unwrap_or_default()), entry)?;
    Ok(Some(Some(entry.pubkey.clone())))
}

/// Make sure the device will sign with `key` in this session, and that the
/// key it holds there is the account's: a device holding other keys (another
/// seed, another passphrase) is turned down before it is asked to sign
/// anything.
///
/// The device only signs with keys it shared in the same session. One it has
/// not shared yet is asked for by its path (`HostAddressAt`: one question
/// about one key, none once its owner allowed them for the session); a
/// firmware without that request is asked to share its addresses instead, and
/// its owner must then pick the account the key belongs to.
async fn require_key<T: Transport>(env: &Env, link: &T, s: &mut Session, account: &Account, key: &KeyRef) -> Result<(), ApiError> {
    let check = |have: &[u8]| if have == &key.pubkey[..] { Ok(()) } else { Err(wrong_device(account)) };
    if let Some(k) = s.by_path.iter().find(|k| k.chain == key.chain && k.path == key.path) {
        return check(&k.pubkey);
    }
    if let Some(known) = covered(env, s, key)? {
        return known.map_or(Ok(()), |pubkey| check(&pubkey));
    }
    if host_info(link, s, false).await?.is_some_and(|i| i.features & feature::ADDRESS_AT != 0 && i.can(key.chain) & can::ADDRESSES != 0) {
        let a = address_at(env, link, s, key.chain, key.format, &key.path, false).await?;
        return check(&a.pubkey);
    }
    let Some(root) = account_root(&key.path) else {
        return Err(bad(format!("{} is not below a standard account path (m/purpose'/coin'/account'), and this device's firmware is too old to share a key by its path", proto::path_text(&key.path))));
    };
    share(env, link, s).await?;
    match covered(env, s, key)? {
        Some(known) => known.map_or(Ok(()), |pubkey| check(&pubkey)),
        None => Err(not_shared(key.chain, root)),
    }
}

/// Make sure the device will sign a transaction for `account` in this
/// session, and that the key it shared for it is the account's.
///
/// An Ethereum or a Solana account signs with one key: see [`require_key`].
/// A Bitcoin spend's inputs span many keys below the account, so the account
/// itself must have been shared (`HostAddresses`): the device is asked to
/// share when it has not, and its owner picks the account.
async fn require_shared<T: Transport>(env: &Env, link: &T, s: &mut Session, account: &Account, info: &AccountKeyInfo) -> Result<Vec<u32>, ApiError> {
    let chain = chain_of(&account.kind)?;
    if chain != chain::BITCOIN {
        let key = key_of(account, info)?;
        require_key(env, link, s, account, &key).await?;
        return Ok(key.path);
    }
    let path = proto::parse_path(&info.path).map_err(|e| bad(format!("account path {}: {e}", info.path)))?;
    if path.len() != 3 || path.iter().any(|c| c & HARDENED == 0) {
        return Err(bad(format!("a bitcoin account's path is its account key's (m/purpose'/coin'/account'), not {}", info.path)));
    }
    let want_format = Some(script_format(&info.script).ok_or_else(|| bad(format!("unsupported bitcoin script kind {:?}", info.script)))?);
    if shared_entry(s, chain, &path, want_format).is_none() {
        share(env, link, s).await?;
    }
    let entry = shared_entry(s, chain, &path, want_format).ok_or_else(|| not_shared(chain, &path))?;
    let fp = hex(&s.fingerprint.unwrap_or_default());
    let k = discovered(env, &fp, entry)?;
    if k.pubkey != hex(&account_pubkey(account)?) || info.master_fingerprint.as_deref().is_some_and(|have| !have.eq_ignore_ascii_case(&fp)) {
        return Err(wrong_device(account));
    }
    Ok(path)
}

// ── One address, one message ─────────────────────────────────────────────────

/// `CatCard:showAddress` — have the device put the account's address on its
/// screen ("Same as the computer shows?") for its owner to compare, and check
/// that the key and the address it shows are the ones held for the account.
/// Bitcoin: the account's first receive address, `…/0/0`.
///
/// Later firmware only (`HostAddressAt` with the show flag): 501 otherwise.
pub async fn show_address<T: Transport>(env: &Env, link: &T, account: &Account, info: &AccountKeyInfo) -> ApiResult {
    let key = key_of(account, info)?;
    let mut s = session::connect(env, link).await?;
    let shown = async {
        require_feature(link, &mut s, feature::ADDRESS_AT, key.chain, can::ADDRESSES, "display an address").await?;
        // A device already known to hold another key there has nothing to show.
        if s.by_path.iter().any(|k| k.chain == key.chain && k.path == key.path && k.pubkey != key.pubkey) {
            return Err(wrong_device(account));
        }
        address_at(env, link, &mut s, key.chain, key.format, &key.path, true).await
    }
    .await;
    session::keep(s);
    let shown = shown?;
    let same = if key.chain == chain::ETHEREUM { shown.address.eq_ignore_ascii_case(&account.address) } else { shown.address == account.address };
    if !same || shown.pubkey != key.pubkey {
        return Err(ApiError::new(409, format!("the device shows {}, but this account is {}: it is not this device's key", shown.address, account.address)));
    }
    Ok(json!({ "address": shown.address, "account": account.id, "path": proto::path_text(&key.path) }))
}

/// Longest Bitcoin message the device signs (what its Sign → Message takes).
const BITCOIN_MESSAGE_MAX: usize = 240;
/// Most lines of an EIP-191 message the device signs.
const EIP191_LINES_MAX: usize = 24;

/// Why the device would refuse to sign `message` under `scheme`, in its own
/// words: it only signs text its screen shows faithfully (the firmware's
/// `docs/USB.md`, "Signing a message"). Checked here first, so that its owner
/// is not asked to share a key for a message it will not sign; the device
/// checks again, and its panel may hold less.
fn unshowable(scheme: u8, message: &[u8]) -> Option<&'static str> {
    if message.is_empty() {
        return Some("nothing to sign in that");
    }
    let printable = |b: &u8| (0x20..0x7f).contains(b);
    if scheme != scheme::EIP191 {
        // One line of printable ASCII.
        return if message.len() > BITCOIN_MESSAGE_MAX {
            Some("message too long")
        } else if !message.iter().all(printable) {
            Some("plain ASCII only")
        } else {
            None
        };
    }
    if message.len() > proto::MESSAGE_MAX {
        return Some("message too long");
    }
    if !message.iter().all(|b| printable(b) || *b == b'\n') {
        return Some("plain ASCII text only");
    }
    if message.split(|b| *b == b'\n').count() > EIP191_LINES_MAX {
        return Some("message has too many lines");
    }
    // What a screen would swallow: a line beginning or ending in a space, a
    // blank first or last line.
    let blank_edge = message.first() == Some(&b'\n') || message.last() == Some(&b'\n');
    if blank_edge || message.split(|b| *b == b'\n').any(|line| line.first() == Some(&b' ') || line.last() == Some(&b' ')) {
        return Some("a line starts or ends blank");
    }
    None
}

/// The scheme a message is signed with for `key`: the one asked for, else
/// EIP-191 (Ethereum), BIP-137 (Bitcoin), or BIP-322 for a taproot address,
/// which BIP-137 has no form for.
fn message_scheme(key: &KeyRef, wanted: Option<&str>) -> Result<u8, ApiError> {
    let fitting = || [scheme::BIP137, scheme::BIP322, scheme::BIP322_FULL, scheme::EIP191].into_iter().filter(|s| scheme::fits(*s, key.format)).map(scheme::name).collect::<Vec<_>>().join(", ");
    let chosen = match wanted {
        Some(name) => scheme::parse(name).ok_or_else(|| bad(format!("unknown Scheme {name:?}: this account signs with {}", fitting())))?,
        None if key.chain == chain::ETHEREUM => scheme::EIP191,
        None if key.format == format::P2TR => scheme::BIP322,
        None => scheme::BIP137,
    };
    if !scheme::fits(chosen, key.format) {
        return Err(bad(format!("{} does not sign for a {} address: this account signs with {}", scheme::name(chosen), format::name(key.format), fitting())));
    }
    Ok(chosen)
}

/// The code a refused message is reported with: what the device says of the
/// message itself is the caller's to fix (400).
fn message_refusal(mut e: ApiError) -> ApiError {
    if e.code == 403 {
        e.code = if ["cannot be signed here", "does not sign", "not in this build"].iter().any(|w| e.message.contains(w)) {
            501
        } else if e.message.contains("memory") {
            403
        } else {
            400
        };
    }
    e
}

/// `CatCard:signMessage` — have the device's owner read `message` on its
/// screen and sign it: Ethereum `personal_sign` (EIP-191), or a Bitcoin
/// message signature by the account's first receive address (BIP-137 by
/// default; `Scheme` asks for `bip322` or `bip322-full`, and a taproot account
/// has those only). The device signs printable ASCII text only, of a bounded
/// length; typed data (EIP-712) and Solana messages are not signed.
///
/// The key must have been shared in this session, so it is asked for first
/// when it has not ([`require_key`]). An EIP-191 or BIP-137 signature is only
/// returned once it recovers to the account's key over `message`; a BIP-322
/// one is returned as the device gave it, `verified: false`.
///
/// Later firmware only (`HostSignMessage`): 501 otherwise.
pub async fn sign_message<T: Transport>(env: &Env, link: &T, account: &Account, info: &AccountKeyInfo, message: &[u8], wanted: Option<&str>) -> ApiResult {
    use base64::Engine;
    if !matches!(account.kind.as_str(), "bitcoin" | "ethereum") {
        return Err(bad(format!("a CatCard signs Bitcoin and Ethereum messages only, not {} ones", account.kind)));
    }
    let key = key_of(account, info)?;
    let how = message_scheme(&key, wanted)?;
    if let Some(why) = unshowable(how, message) {
        return Err(bad(format!("catcard: the device does not sign this message: {why}")));
    }
    let request = proto::message_request(key.chain, key.format, how, &key.path, message).map_err(bad)?;

    let mut s = session::connect(env, link).await?;
    let reply = async {
        let can_do = require_feature(link, &mut s, feature::SIGN_MESSAGE, key.chain, can::MESSAGES, "sign a message").await?;
        if message.len() > can_do.message_max as usize {
            return Err(bad("catcard: the device does not sign this message: message too long"));
        }
        require_key(env, link, &mut s, account, &key).await?;
        ask(env, link, &mut s, op::HOST_SIGN_MESSAGE, &request, "HostSignMessage", "message").await.map_err(message_refusal)
    }
    .await;
    session::keep(s);
    let signed = proto::SignedMessage::decode(&reply?).map_err(|e| cerr(502, format!("message result: {e}")))?;
    if signed.chain != key.chain || signed.scheme != how || signed.path != key.path {
        return Err(cerr(502, "the device answered for another message request than the one made"));
    }
    let same = if key.chain == chain::ETHEREUM { signed.address.eq_ignore_ascii_case(&account.address) } else { signed.address == account.address };
    if !same {
        return Err(ApiError::new(409, format!("the device signed for {}, not this account ({}): wrong device, or wrong passphrase?", signed.address, account.address)));
    }
    let mut out = json!({ "account": account.id, "address": signed.address, "scheme": scheme::name(how), "verified": true });
    match how {
        scheme::EIP191 => {
            // r ‖ s ‖ v, v 27 or 28: it must recover to the account.
            if signed.signature.len() != 65 || !matches!(signed.signature[64], 27 | 28) {
                return Err(cerr(502, "the device returned no usable signature"));
            }
            let from = crate::evm::personal_ec_recover(message, &signed.signature).map_err(|e| cerr(502, e))?;
            if !from.eq_ignore_ascii_case(&account.address) {
                return Err(not_this_account(account));
            }
            out["signature"] = json!(format!("0x{}", hex(&signed.signature)));
        }
        _ => {
            let text = String::from_utf8(signed.signature).ok().filter(|t| !t.is_empty()).ok_or_else(|| cerr(502, "the device returned no usable signature"))?;
            let raw = base64::engine::general_purpose::STANDARD.decode(&text).map_err(|_| cerr(502, "the device's signature is not base64"))?;
            if how == scheme::BIP137 {
                // A header saying which address type signed and the recovery
                // id, then r and s: it must recover to the key at the path.
                let base = match key.format {
                    format::P2PKH => 31,
                    format::P2SH_P2WPKH => 35,
                    _ => 39,
                };
                let digest = crate::bitcoin::message_digest("bitcoin", message).ok_or_else(|| ApiError::new(500, "no bitcoin message prefix"))?;
                let recovered = <&[u8; 65]>::try_from(&raw[..]).ok().filter(|sig| (base..base + 4).contains(&sig[0])).and_then(|sig| {
                    let (r, sv): ([u8; 32], [u8; 32]) = (sig[1..33].try_into().unwrap(), sig[33..].try_into().unwrap());
                    outscript::crypto::secp256k1::recover_public_key(&r, &sv, sig[0] - base, &digest).ok()
                });
                let recovered = recovered.ok_or_else(|| cerr(502, format!("the device returned no usable {} signature", format::name(key.format))))?;
                if recovered.serialize_compressed()[..] != key.pubkey[..] {
                    return Err(not_this_account(account));
                }
            } else {
                // Nothing in this library verifies BIP-322: handed back as
                // the device gave it, and said so.
                out["verified"] = json!(false);
            }
            out["signature"] = json!(text);
            out["path"] = json!(proto::path_text(&key.path));
        }
    }
    Ok(out)
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
        status::REFUSED => return Err(refused(s, &body)),
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
            status::REFUSED => Err(refused(s, &body)),
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
