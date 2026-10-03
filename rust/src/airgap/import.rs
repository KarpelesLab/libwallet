//! Importing an external signer's public keys.
//!
//! One air-gapped transmission can carry many keys for many chains (a
//! Keystone `crypto-multi-accounts` has BTC xpubs, ETH and SOL leaf keys…).
//! [`parse`] turns whatever the host scanned into a flat list of
//! [`DiscoveredKey`]s, from any of:
//!
//! - UR `crypto-multi-accounts` (Keystone), `crypto-account` (BlockchainCommons
//!   / Keystone BTC, Passport, SeedSigner…), `crypto-hdkey` (a single xpub);
//! - a BBQr `J` file or raw JSON in the Coldcard / Sparrow "generic wallet
//!   export" shape (`{"xfp": …, "bip84": {"xpub"/"_pub", "deriv", "name"}}`);
//! - a SLIP-132 extended key (`xpub`/`ypub`/`zpub`, testnet and LTC/DOGE
//!   prefixes), optionally with a key origin `[xfp/84'/0'/0']zpub…`;
//! - an output descriptor `wpkh([xfp/84h/0h/0h]xpub…/0/*)` (also `pkh`,
//!   `sh(wpkh(…))`, `tr`).
//!
//! [`import`] persists them: one Wallet (protocol `airgap`) per transmission,
//! and one Account per usable key — bitcoin xpubs become HD (xpub-scanned)
//! accounts, ethereum xpubs become leaf accounts at `…/0/i`, ethereum/solana
//! leaf keys become one account each. The signer's master fingerprint and each
//! account's full origin path are kept in config so sign requests can name the
//! key the device must use (PSBT `bip32_derivation`, `derivation-path` in
//! eth/sol requests).

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use super::decoder::Payload;
use super::registry::{self, CryptoAccount, HdKey, KeyPath, MultiAccounts, HARDENED};
use crate::{Env, Error, Result};

/// One public key found in a signer export, normalized.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredKey {
    /// `bitcoin` | `ethereum` | `solana` | `unsupported`.
    pub chain: String,
    /// `secp256k1` | `ed25519`.
    pub curve: String,
    /// SLIP-44 coin type, when known.
    pub coin_type: Option<u32>,
    /// Full derivation path from the signer's master (`m/84'/0'/0'`).
    pub path: String,
    /// Signer master fingerprint, hex (8 chars), when known.
    pub master_fingerprint: Option<String>,
    /// Key bytes, hex: 33-byte compressed secp256k1 or 32-byte ed25519.
    pub pubkey: String,
    /// Chain code hex when this is an extended key (further derivation
    /// possible); absent for leaf keys.
    pub chain_code: Option<String>,
    /// Bitcoin script kind (`p2wpkh`, `p2sh:p2wpkh`, `p2pkh`, `p2tr`); for
    /// other chains empty.
    pub script: String,
    /// The address this key maps to (bitcoin: first receive address m/0/0 for
    /// an xpub; ethereum/solana leaf: its address; ethereum xpub: …/0/0).
    pub address: String,
    /// Device-provided label/note, if any.
    pub name: Option<String>,
    pub note: Option<String>,
    /// Why `chain` is `unsupported`, when it is.
    pub reason: Option<String>,
}

/// A parsed export: device identity + keys.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Export {
    /// `crypto-multi-accounts` | `crypto-account` | `crypto-hdkey` | `json` |
    /// `xpub` | `descriptor`.
    pub format: String,
    pub master_fingerprint: Option<String>,
    pub device: Option<String>,
    pub device_id: Option<String>,
    pub version: Option<String>,
    pub keys: Vec<DiscoveredKey>,
}

fn fp_hex(fp: u32) -> String {
    format!("{fp:08x}")
}

fn parse_fp(s: &str) -> Option<u32> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 8 {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// Script kind implied by a BIP-43 purpose.
fn script_for_purpose(purpose: u32) -> &'static str {
    match purpose {
        44 => "p2pkh",
        49 => "p2sh:p2wpkh",
        86 => "p2tr",
        _ => "p2wpkh",
    }
}

/// Chain for a SLIP-44 coin type.
fn chain_for_coin(coin: u32) -> &'static str {
    match coin {
        0 | 1 | 2 | 3 | 145 => "bitcoin", // btc, testnet, ltc, doge, bch share the bitcoin account model
        60 => "ethereum",
        501 => "solana",
        _ => "unsupported",
    }
}

fn bitcoin_display_address(env: &Env, root: &[u8; 33], cc: &[u8; 32], script: &str) -> String {
    let child = crate::hdderive::derive_pub(root, cc, &[0, 0]).unwrap_or(*root);
    let tag = crate::models::network::fetch(env, "@")
        .ok()
        .flatten()
        .filter(|n| n.kind == "bitcoin")
        .map(|n| if n.chain_id == "bitcoin-cash" { "bitcoincash".to_owned() } else { n.chain_id })
        .unwrap_or_else(|| "bitcoin".into());
    crate::bitcoin::address_for(&child, script, &tag)
        .or_else(|_| crate::bitcoin::address_for(&child, script, "bitcoin"))
        .unwrap_or_else(|_| outscript::address::encode_base58_addr(0x00, &outscript::hash::hash160(&child)))
}

/// Normalize one hdkey (+ optional script wrapper) into a DiscoveredKey.
fn key_from_hdkey(env: &Env, k: &HdKey, script_hint: Option<&str>, xfp: Option<u32>) -> DiscoveredKey {
    let origin = k.origin.clone().unwrap_or_default();
    let xfp = k.master_fingerprint().or(xfp);
    let coin = k.coin_type();
    let purpose = origin.components.first().map(|c| c & !HARDENED);
    let mut dk = DiscoveredKey {
        chain: coin.map(chain_for_coin).unwrap_or("unsupported").to_owned(),
        curve: if k.is_ed25519() { "ed25519" } else { "secp256k1" }.to_owned(),
        coin_type: coin,
        path: origin.to_string(),
        master_fingerprint: xfp.map(fp_hex),
        pubkey: super::hex(&k.key_data),
        chain_code: k.chain_code.map(|c| super::hex(&c)),
        script: String::new(),
        address: String::new(),
        name: k.name.clone(),
        note: k.note.clone(),
        reason: None,
    };
    match dk.chain.as_str() {
        "bitcoin" => {
            let Some(root) = k.secp_key() else {
                dk.chain = "unsupported".into();
                dk.reason = Some("bitcoin key is not a compressed secp256k1 key".into());
                return dk;
            };
            let Some(cc) = k.chain_code else {
                dk.chain = "unsupported".into();
                dk.reason = Some("bitcoin key has no chain code (need an xpub)".into());
                return dk;
            };
            dk.script = script_hint.map(str::to_owned).unwrap_or_else(|| script_for_purpose(purpose.unwrap_or(84)).to_owned());
            if dk.script == "multi" || dk.script == "pk" || dk.script == "combo" || dk.script == "addr" {
                dk.chain = "unsupported".into();
                dk.reason = Some(format!("{} descriptors are not supported", dk.script));
                return dk;
            }
            dk.address = bitcoin_display_address(env, &root, &cc, &dk.script);
        }
        "ethereum" => {
            let Some(pk) = k.secp_key() else {
                dk.chain = "unsupported".into();
                dk.reason = Some("ethereum key is not a compressed secp256k1 key".into());
                return dk;
            };
            // An account-level xpub (chain code present, depth 3) addresses …/0/0;
            // a leaf key is its own address.
            let leaf = match k.chain_code {
                Some(cc) if origin.components.len() <= 3 => crate::hdderive::derive_pub(&pk, &cc, &[0, 0]).unwrap_or(pk),
                _ => pk,
            };
            dk.address = crate::hdderive::evm_address(&leaf).unwrap_or_default();
        }
        "solana" => {
            let Some(pk) = k.ed25519_key() else {
                dk.chain = "unsupported".into();
                dk.reason = Some("solana key is not a 32-byte ed25519 key".into());
                return dk;
            };
            dk.pubkey = super::hex(&pk);
            dk.chain_code = None;
            dk.address = bs58::encode(pk).into_string();
        }
        _ => {
            dk.reason = Some(match coin {
                Some(c) => format!("coin type {c} is not supported by libwallet accounts"),
                None => "key has no coin type / recognizable path".into(),
            });
        }
    }
    dk
}

// ── SLIP-132 extended keys ───────────────────────────────────────────────────

/// Decoded SLIP-132 extended public key.
pub struct Slip132 {
    pub pubkey: [u8; 33],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: u32,
    pub child_number: u32,
    /// Script kind the version bytes imply (`xpub` → p2pkh-or-unknown).
    pub script: &'static str,
    /// Coin: 0 bitcoin, 1 testnet, 2 litecoin, 3 dogecoin.
    pub coin_type: u32,
}

/// Parse an `xpub`/`ypub`/`zpub`/`tpub`/`upub`/`vpub`/`Ltub`/`Mtub`/`dgub`
/// (and the multisig `Ypub`/`Zpub`) string.
pub fn parse_slip132(s: &str) -> Result<Slip132> {
    let data = bs58::decode(s.trim()).into_vec().map_err(|e| Error::Env(format!("extended key: {e}")))?;
    if data.len() != 82 {
        return Err(Error::Env(format!("extended key: expected 82 bytes, got {}", data.len())));
    }
    let (payload, checksum) = data.split_at(78);
    let h = purecrypto::hash::sha256(&purecrypto::hash::sha256(payload));
    if h[..4] != *checksum {
        return Err(Error::Env("extended key: bad checksum".into()));
    }
    let version = u32::from_be_bytes(payload[..4].try_into().unwrap());
    let (script, coin_type) = match version {
        0x0488_b21e => ("", 0),           // xpub (script from the path/descriptor)
        0x049d_7cb2 => ("p2sh:p2wpkh", 0), // ypub
        0x04b2_4746 => ("p2wpkh", 0),      // zpub
        0x0295_b43f => ("multi", 0),       // Ypub (sh(wsh(multi)))
        0x02aa_7ed3 => ("multi", 0),       // Zpub (wsh(multi))
        0x0435_87cf => ("", 1),            // tpub
        0x044a_5262 => ("p2sh:p2wpkh", 1), // upub
        0x045f_1cf6 => ("p2wpkh", 1),      // vpub
        0x019d_a462 => ("p2pkh", 2),       // Ltub
        0x01b2_6ef6 => ("p2sh:p2wpkh", 2), // Mtub
        0x02fa_cafd => ("p2pkh", 3),       // dgub
        v => return Err(Error::Env(format!("extended key: unknown version 0x{v:08x} (private key or unsupported coin?)"))),
    };
    let pubkey: [u8; 33] = payload[45..78].try_into().unwrap();
    if !matches!(pubkey[0], 2 | 3) {
        return Err(Error::Env("extended key: not a public key".into()));
    }
    Ok(Slip132 {
        pubkey,
        chain_code: payload[13..45].try_into().unwrap(),
        depth: payload[4],
        parent_fingerprint: u32::from_be_bytes(payload[5..9].try_into().unwrap()),
        child_number: u32::from_be_bytes(payload[9..13].try_into().unwrap()),
        script,
        coin_type,
    })
}

fn is_extended_key(s: &str) -> bool {
    let s = s.trim();
    s.len() > 100 && s.len() < 120 && s.chars().all(|c| c.is_ascii_alphanumeric()) && bs58::decode(s).into_vec().map(|v| v.len() == 82).unwrap_or(false)
}

/// Key origin `[xfp/84'/0'/0']` → (fingerprint, path).
fn parse_origin(s: &str) -> Result<(Option<u32>, KeyPath)> {
    let inner = s.trim().trim_start_matches('[').trim_end_matches(']');
    let (fp, path) = inner.split_once('/').unwrap_or((inner, ""));
    let fp = parse_fp(fp);
    let path = KeyPath::parse(&path.replace('h', "'").replace('H', "'"))?;
    Ok((fp, path))
}

/// `[origin]xpub…` or bare `xpub…` → a bitcoin/ethereum hdkey-shaped key.
fn key_from_extended(env: &Env, text: &str, script_hint: Option<&str>) -> Result<DiscoveredKey> {
    let t = text.trim();
    let (origin, key_str) = match t.strip_prefix('[') {
        Some(rest) => {
            let end = rest.find(']').ok_or_else(|| Error::Env("unterminated key origin".into()))?;
            (Some(parse_origin(&rest[..end])?), rest[end + 1..].trim())
        }
        None => (None, t),
    };
    // A descriptor key may end with /0/* or /<0;1>/* — strip the children.
    let key_str = key_str.split('/').next().unwrap_or(key_str);
    let x = parse_slip132(key_str)?;
    let (fp, mut path) = match origin {
        Some((fp, p)) => (fp, p),
        None => (None, KeyPath::default()),
    };
    // Without an origin, guess the standard account path from the version bytes
    // and depth so the device can still be told which key to use.
    if path.is_empty() && x.depth == 3 {
        let purpose = match x.script {
            "p2wpkh" => 84,
            "p2sh:p2wpkh" => 49,
            "p2tr" => 86,
            _ => 44,
        };
        path = KeyPath { components: vec![purpose | HARDENED, x.coin_type | HARDENED, (x.child_number & !HARDENED) | HARDENED], source_fingerprint: None, depth: Some(3) };
    }
    path.source_fingerprint = fp;
    let script = script_hint.map(str::to_owned).or_else(|| if x.script.is_empty() { None } else { Some(x.script.to_owned()) });
    let coin = if path.components.len() >= 2 { path.components[1] & !HARDENED } else { x.coin_type };
    let hd = HdKey {
        key_data: x.pubkey.to_vec(),
        chain_code: Some(x.chain_code),
        use_info: Some(registry::CoinInfo { coin_type: coin, network: if x.coin_type == 1 { 1 } else { 0 } }),
        origin: Some(path),
        parent_fingerprint: Some(x.parent_fingerprint),
        ..Default::default()
    };
    Ok(key_from_hdkey(env, &hd, script.as_deref(), fp))
}

/// `wpkh([xfp/84h/0h/0h]zpub…/0/*)` and friends.
fn parse_descriptor(env: &Env, text: &str) -> Result<Option<DiscoveredKey>> {
    let t = text.trim();
    // Strip a `#checksum`.
    let t = t.split('#').next().unwrap_or(t).trim();
    let (script, inner) = if let Some(i) = t.strip_prefix("sh(wpkh(").and_then(|s| s.strip_suffix("))")) {
        ("p2sh:p2wpkh", i)
    } else if let Some(i) = t.strip_prefix("wpkh(").and_then(|s| s.strip_suffix(')')) {
        ("p2wpkh", i)
    } else if let Some(i) = t.strip_prefix("pkh(").and_then(|s| s.strip_suffix(')')) {
        ("p2pkh", i)
    } else if let Some(i) = t.strip_prefix("tr(").and_then(|s| s.strip_suffix(')')) {
        ("p2tr", i)
    } else {
        return Ok(None);
    };
    Ok(Some(key_from_extended(env, inner, Some(script))?))
}

/// Coldcard / Sparrow "generic JSON" export.
fn parse_coldcard_json(env: &Env, j: &Json) -> Result<Option<Export>> {
    let obj = match j.as_object() {
        Some(o) => o,
        None => return Ok(None),
    };
    let xfp = obj.get("xfp").and_then(Json::as_str).and_then(parse_fp);
    let mut keys = Vec::new();
    let mut saw_any = false;
    for (k, v) in obj {
        let Some(entry) = v.as_object() else { continue };
        let script = match k.as_str() {
            "bip44" => "p2pkh",
            "bip49" => "p2sh:p2wpkh",
            "bip84" => "p2wpkh",
            "bip86" => "p2tr",
            // Multisig entries (bip45/bip48_*) are not single-key accounts.
            _ => continue,
        };
        saw_any = true;
        let xpub = entry.get("xpub").or_else(|| entry.get("_pub")).and_then(Json::as_str);
        let Some(xpub) = xpub else { continue };
        let deriv = entry.get("deriv").and_then(Json::as_str).unwrap_or("");
        let origin = match (xfp, deriv) {
            (Some(fp), d) if !d.is_empty() => format!("[{}/{}]", fp_hex(fp), d.trim_start_matches("m/")),
            _ => String::new(),
        };
        let mut dk = key_from_extended(env, &format!("{origin}{xpub}"), Some(script))?;
        if let Some(name) = entry.get("name").and_then(Json::as_str) {
            dk.note = Some(name.to_owned());
        }
        keys.push(dk);
    }
    if !saw_any && xfp.is_none() {
        return Ok(None);
    }
    Ok(Some(Export {
        format: "json".into(),
        master_fingerprint: xfp.map(fp_hex),
        device: obj.get("chain").and_then(Json::as_str).map(|_| "Coldcard".to_owned()),
        device_id: None,
        version: None,
        keys,
    }))
}

/// Parse a complete payload into an [`Export`].
pub fn parse(env: &Env, payload: &Payload) -> Result<Export> {
    match payload {
        Payload::Ur { ur_type, cbor } => {
            let v = super::cbor::from_bytes(cbor)?;
            match ur_type.as_str() {
                registry::UR_MULTI_ACCOUNTS => {
                    let m = MultiAccounts::from_cbor(&v)?;
                    Ok(Export {
                        format: registry::UR_MULTI_ACCOUNTS.into(),
                        master_fingerprint: Some(fp_hex(m.master_fingerprint)),
                        device: m.device.clone(),
                        device_id: m.device_id.clone(),
                        version: m.version.clone(),
                        keys: m.keys.iter().map(|k| key_from_hdkey(env, k, None, Some(m.master_fingerprint))).collect(),
                    })
                }
                registry::UR_ACCOUNT => {
                    let a = CryptoAccount::from_cbor(&v)?;
                    Ok(Export {
                        format: registry::UR_ACCOUNT.into(),
                        master_fingerprint: Some(fp_hex(a.master_fingerprint)),
                        keys: a.outputs.iter().map(|o| key_from_hdkey(env, &o.key, Some(&o.script), Some(a.master_fingerprint))).collect(),
                        ..Default::default()
                    })
                }
                registry::UR_HDKEY => {
                    let k = HdKey::from_cbor(&v)?;
                    Ok(Export {
                        format: registry::UR_HDKEY.into(),
                        master_fingerprint: k.master_fingerprint().map(fp_hex),
                        keys: vec![key_from_hdkey(env, &k, None, None)],
                        ..Default::default()
                    })
                }
                registry::UR_BYTES => {
                    let b = outscript::bcur::cbor_to_bytes(cbor).map_err(|e| Error::Env(format!("bytes: {e}")))?;
                    let text = std::str::from_utf8(b).map_err(|_| Error::Env("ur:bytes payload is not text".into()))?;
                    parse_text(env, text)
                }
                other => Err(Error::Env(format!("UR type {other} does not carry public keys"))),
            }
        }
        Payload::Bbqr { file_type, data } => match file_type {
            'J' | 'U' => parse_text(env, std::str::from_utf8(data).map_err(|_| Error::Env("BBQr text is not UTF-8".into()))?),
            other => Err(Error::Env(format!("BBQr file type {other} does not carry public keys (expected J)"))),
        },
        Payload::Raw(text) => parse_text(env, text),
    }
}

/// JSON export, descriptor, or extended key as text.
pub fn parse_text(env: &Env, text: &str) -> Result<Export> {
    let t = text.trim();
    if t.starts_with('{') {
        let j: Json = serde_json::from_str(t).map_err(|e| Error::Env(format!("json: {e}")))?;
        if let Some(e) = parse_coldcard_json(env, &j)? {
            return Ok(e);
        }
        return Err(Error::Env("JSON is not a recognized wallet export (expected Coldcard/Sparrow xfp + bipNN entries)".into()));
    }
    if let Some(dk) = parse_descriptor(env, t)? {
        return Ok(Export { format: "descriptor".into(), master_fingerprint: dk.master_fingerprint.clone(), keys: vec![dk], ..Default::default() });
    }
    // One or more extended keys, possibly with [origin] prefixes, one per line.
    let mut keys = Vec::new();
    for line in t.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let bare = line.split(']').next_back().unwrap_or(line);
        if line.starts_with('[') || is_extended_key(bare) {
            keys.push(key_from_extended(env, line, None)?);
        } else {
            return Err(Error::Env(format!("unrecognized key payload: {}…", &line[..line.len().min(24)])));
        }
    }
    if keys.is_empty() {
        return Err(Error::Env("empty payload".into()));
    }
    Ok(Export { format: "xpub".into(), master_fingerprint: keys[0].master_fingerprint.clone(), keys, ..Default::default() })
}

// ── Persistence ─────────────────────────────────────────────────────────────

/// Signer identity kept per airgap wallet (config `airgap:wallet:<id>`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignerInfo {
    pub master_fingerprint: Option<String>,
    pub device: Option<String>,
    pub device_id: Option<String>,
    pub version: Option<String>,
    pub format: String,
}

/// Key provenance kept per airgap account (config `airgap:account:<id>`): what
/// a sign request must tell the device.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountKeyInfo {
    pub master_fingerprint: Option<String>,
    /// Full path of the account key (bitcoin: the xpub root; eth/sol: the leaf).
    pub path: String,
    pub script: String,
    pub curve: String,
}

pub fn wallet_signer(env: &Env, wallet_id: &str) -> Result<Option<SignerInfo>> {
    Ok(env.config_get(&format!("airgap:wallet:{wallet_id}"))?.and_then(|b| serde_json::from_slice(&b).ok()))
}

pub fn account_key_info(env: &Env, account_id: &str) -> Result<Option<AccountKeyInfo>> {
    Ok(env.config_get(&format!("airgap:account:{account_id}"))?.and_then(|b| serde_json::from_slice(&b).ok()))
}

/// Options for [`import`].
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Wallet name; defaults to the device name or "Air-gapped signer".
    pub name: Option<String>,
    /// How many leaf accounts (…/0/i) to create per ethereum xpub (default 1).
    pub eth_accounts: Option<u32>,
    /// Only import keys whose `path` is in this list (default: all usable).
    pub select_paths: Option<Vec<String>>,
}

/// Result of [`import`].
#[derive(Debug, Clone, Serialize)]
pub struct Imported {
    pub wallet: crate::models::wallet::Wallet,
    pub accounts: Vec<crate::models::account::Account>,
    /// Keys that were not imported, with the reason.
    pub skipped: Vec<DiscoveredKey>,
}

/// Persist an export as a signer wallet with one account per usable key.
pub fn import(env: &Env, export: &Export, opts: &ImportOptions) -> Result<Imported> {
    use crate::models::account::Account;
    use crate::models::wallet::Wallet;
    use xuid::Xuid;

    let usable: Vec<&DiscoveredKey> = export
        .keys
        .iter()
        .filter(|k| k.chain != "unsupported")
        .filter(|k| opts.select_paths.as_ref().map_or(true, |sel| sel.iter().any(|p| p == &k.path)))
        .collect();
    if usable.is_empty() {
        return Err(Error::Env("export contains no importable keys".into()));
    }
    let skipped: Vec<DiscoveredKey> = export.keys.iter().filter(|k| k.chain == "unsupported").cloned().collect();

    let now = crate::now_rfc3339();
    let name = opts
        .name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| export.device.clone())
        .unwrap_or_else(|| "Air-gapped signer".into());
    let wallet = Wallet {
        id: Xuid::new("wlt").to_string(),
        name,
        curve: String::new(), // mixed: each account records its own curve
        protocol: "airgap".into(),
        threshold: 0,
        generation: 0,
        pubkey: String::new(),
        chaincode: String::new(),
        created: now.clone(),
        modified: now.clone(),
        keys: Vec::new(),
    };
    crate::models::wallet::persist(env, &wallet)?;
    let signer = SignerInfo {
        master_fingerprint: export.master_fingerprint.clone().or_else(|| usable.iter().find_map(|k| k.master_fingerprint.clone())),
        device: export.device.clone(),
        device_id: export.device_id.clone(),
        version: export.version.clone(),
        format: export.format.clone(),
    };
    env.config_set(&format!("airgap:wallet:{}", wallet.id), &serde_json::to_vec(&signer).map_err(|e| Error::Env(e.to_string()))?)?;

    let mut accounts = Vec::new();
    let mut index_for: std::collections::HashMap<String, i64> = Default::default();
    let mut push = |env: &Env, chain: &str, curve: &str, path: String, pubkey: &[u8], chaincode: Option<&[u8]>, address: String, script: &str, k: &DiscoveredKey, label: Option<&str>| -> Result<()> {
        let idx = index_for.entry(chain.to_owned()).or_insert(0);
        let index = *idx;
        *idx += 1;
        let uri_scheme = chain;
        let a = Account {
            id: Xuid::new("acct").to_string(),
            wallet: wallet.id.clone(),
            name: label.map(str::to_owned).unwrap_or_else(|| format!("{} {}", signer.device.clone().unwrap_or_else(|| "Signer".into()), index + 1)),
            index,
            kind: chain.to_owned(),
            curve: curve.to_owned(),
            path: path.clone(),
            address: address.clone(),
            uri: format!("{uri_scheme}:{address}"),
            pubkey: b64url(pubkey),
            chaincode: chaincode.map(b64url).unwrap_or_default(),
            il: Json::Null,
            created: now.clone(),
            updated: now.clone(),
        };
        crate::models::account::persist(env, &a)?;
        let info = AccountKeyInfo { master_fingerprint: k.master_fingerprint.clone(), path, script: script.to_owned(), curve: curve.to_owned() };
        env.config_set(&format!("airgap:account:{}", a.id), &serde_json::to_vec(&info).map_err(|e| Error::Env(e.to_string()))?)?;
        accounts.push(a);
        Ok(())
    };

    for k in &usable {
        let pk = super::unhex(&k.pubkey)?;
        let cc = k.chain_code.as_deref().map(super::unhex).transpose()?;
        match k.chain.as_str() {
            "bitcoin" => {
                push(env, "bitcoin", "secp256k1", k.path.clone(), &pk, cc.as_deref(), k.address.clone(), &k.script, k, None)?;
            }
            "ethereum" => match (&cc, k.path.matches('/').count()) {
                // Account-level xpub → leaf accounts …/0/i.
                (Some(cc), depth) if depth <= 3 => {
                    let root: [u8; 33] = pk.as_slice().try_into().map_err(|_| Error::Env("ethereum xpub key is not 33 bytes".into()))?;
                    let ccb: [u8; 32] = cc.as_slice().try_into().map_err(|_| Error::Env("chain code is not 32 bytes".into()))?;
                    let origin = KeyPath::parse(&k.path)?;
                    for i in 0..opts.eth_accounts.unwrap_or(1).max(1) {
                        let leaf = crate::hdderive::derive_pub(&root, &ccb, &[0, i]).map_err(|e| Error::Env(e.to_string()))?;
                        let addr = crate::hdderive::evm_address(&leaf).map_err(|e| Error::Env(e.to_string()))?;
                        push(env, "ethereum", "secp256k1", origin.child(&[0, i]).to_string(), &leaf, None, addr, "", k, None)?;
                    }
                }
                _ => {
                    push(env, "ethereum", "secp256k1", k.path.clone(), &pk, None, k.address.clone(), "", k, None)?;
                }
            },
            "solana" => {
                push(env, "solana", "ed25519", k.path.clone(), &pk, None, k.address.clone(), "", k, None)?;
            }
            _ => {}
        }
    }
    if let Some(first) = accounts.first() {
        env.set_current("account", &first.id)?;
    }
    Ok(Imported { wallet, accounts, skipped })
}

fn b64url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        let env = Env::init_memory().unwrap();
        crate::models::wallet::init(&env).unwrap();
        crate::models::account::init(&env).unwrap();
        env
    }

    // BIP-84 test vector for "abandon … about": account xpub at m/84'/0'/0'.
    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    const XPUB84: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    const BIP84_FIRST: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

    #[test]
    fn zpub_and_xpub_import_to_the_same_bip84_account() {
        let env = env();
        let e = parse_text(&env, ZPUB).unwrap();
        assert_eq!(e.format, "xpub");
        let k = &e.keys[0];
        assert_eq!((k.chain.as_str(), k.script.as_str(), k.path.as_str()), ("bitcoin", "p2wpkh", "m/84'/0'/0'"));
        assert_eq!(k.address, BIP84_FIRST);

        let e2 = parse_text(&env, &format!("[73c5da0a/84h/0h/0h]{XPUB84}")).unwrap();
        let k2 = &e2.keys[0];
        assert_eq!(k2.pubkey, k.pubkey);
        assert_eq!(k2.master_fingerprint.as_deref(), Some("73c5da0a"));
        assert_eq!(k2.address, BIP84_FIRST, "an xpub with origin derives the same BIP-84 address");

        let e3 = parse_text(&env, &format!("wpkh([73c5da0a/84h/0h/0h]{XPUB84}/0/*)#abcdefgh")).unwrap();
        assert_eq!(e3.format, "descriptor");
        assert_eq!(e3.keys[0].address, BIP84_FIRST);
        assert_eq!(e3.keys[0].script, "p2wpkh");
    }

    #[test]
    fn coldcard_json_export_parses_and_imports() {
        let env = env();
        let json = format!(
            r#"{{"chain":"BTC","xfp":"73C5DA0A","account":0,"bip84":{{"name":"p2wpkh","xfp":"...","deriv":"m/84'/0'/0'","xpub":"{XPUB84}","_pub":"{ZPUB}","first":"{BIP84_FIRST}"}},"bip48_2":{{"name":"p2wsh","xpub":"{XPUB84}"}}}}"#
        );
        let e = parse_text(&env, &json).unwrap();
        assert_eq!(e.format, "json");
        assert_eq!(e.master_fingerprint.as_deref(), Some("73c5da0a"));
        assert_eq!(e.keys.len(), 1, "multisig entries are skipped");
        assert_eq!(e.keys[0].address, BIP84_FIRST);
        assert_eq!(e.keys[0].master_fingerprint.as_deref(), Some("73c5da0a"));

        let imported = import(&env, &e, &ImportOptions { name: Some("My Coldcard".into()), ..Default::default() }).unwrap();
        assert_eq!(imported.wallet.protocol, "airgap");
        assert_eq!(imported.accounts.len(), 1);
        let a = &imported.accounts[0];
        assert_eq!(a.kind, "bitcoin");
        assert_eq!(a.path, "m/84'/0'/0'");
        assert_eq!(a.address, BIP84_FIRST);
        // The stored node IS the BIP-84 account key (Account::xpub re-serializes
        // it at depth 0, so compare key material, not the string).
        let stored = parse_slip132(&a.xpub().unwrap()).unwrap();
        let want = parse_slip132(XPUB84).unwrap();
        assert_eq!((stored.pubkey, stored.chain_code), (want.pubkey, want.chain_code));
        let info = account_key_info(&env, &a.id).unwrap().unwrap();
        assert_eq!((info.master_fingerprint.as_deref(), info.script.as_str()), (Some("73c5da0a"), "p2wpkh"));
        assert_eq!(wallet_signer(&env, &imported.wallet.id).unwrap().unwrap().format, "json");
    }

    #[test]
    fn keystone_multi_accounts_imports_btc_eth_sol() {
        let env = env();
        // Build a Keystone-style export from the abandon…about seed.
        let seed = crate::bip39::mnemonic_to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
        let (btc_root, btc_cc) = {
            let (_, cc) = crate::hdderive::derive_secp_privkey_and_chaincode(&seed, "m/84'/0'/0'").unwrap();
            (crate::hdderive::derive_pubkey_for_path(&seed, "secp256k1", "m/84'/0'/0'").unwrap(), cc)
        };
        let (eth_root, eth_cc) = {
            let (_, cc) = crate::hdderive::derive_secp_privkey_and_chaincode(&seed, "m/44'/60'/0'").unwrap();
            (crate::hdderive::derive_pubkey_for_path(&seed, "secp256k1", "m/44'/60'/0'").unwrap(), cc)
        };
        let sol_leaf = crate::hdderive::derive_pubkey_for_path(&seed, "ed25519", "m/44'/501'/0'/0'").unwrap();
        let xfp = 0x73c5_da0au32;
        let m = MultiAccounts {
            master_fingerprint: xfp,
            keys: vec![
                HdKey { key_data: btc_root, chain_code: Some(btc_cc), origin: Some(KeyPath { components: KeyPath::parse("m/84'/0'/0'").unwrap().components, source_fingerprint: Some(xfp), depth: Some(3) }), ..Default::default() },
                HdKey { key_data: eth_root, chain_code: Some(eth_cc), origin: Some(KeyPath { components: KeyPath::parse("m/44'/60'/0'").unwrap().components, source_fingerprint: Some(xfp), depth: Some(3) }), children: Some(KeyPath::parse("0/*").ok().unwrap_or_default()), note: Some("account.standard".into()), ..Default::default() },
                HdKey { key_data: sol_leaf.clone(), origin: Some(KeyPath { components: KeyPath::parse("m/44'/501'/0'/0'").unwrap().components, source_fingerprint: Some(xfp), depth: None }), note: Some("account.standard".into()), ..Default::default() },
                // A Tron key: reported but not importable.
                HdKey { key_data: vec![2; 33], chain_code: Some([0; 32]), origin: Some(KeyPath::parse("m/44'/195'/0'").unwrap()), ..Default::default() },
            ],
            device: Some("Keystone 3 Pro".into()),
            device_id: Some("K3P-1".into()),
            version: Some("1.2".into()),
        };
        let cbor = super::super::cbor::to_bytes(&m.to_cbor()).unwrap();
        let export = parse(&env, &Payload::Ur { ur_type: registry::UR_MULTI_ACCOUNTS.into(), cbor }).unwrap();
        assert_eq!(export.device.as_deref(), Some("Keystone 3 Pro"));
        assert_eq!(export.keys.len(), 4);
        assert_eq!(export.keys[0].address, BIP84_FIRST);
        assert_eq!(export.keys[1].address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "eth xpub → …/0/0 = MetaMask vector");
        assert_eq!(export.keys[2].chain, "solana");
        assert_eq!(export.keys[3].chain, "unsupported");
        assert!(export.keys[3].reason.as_deref().unwrap().contains("195"));

        let imported = import(&env, &export, &ImportOptions { eth_accounts: Some(2), ..Default::default() }).unwrap();
        assert_eq!(imported.wallet.name, "Keystone 3 Pro");
        assert_eq!(imported.skipped.len(), 1);
        let kinds: Vec<(&str, &str)> = imported.accounts.iter().map(|a| (a.kind.as_str(), a.path.as_str())).collect();
        assert_eq!(kinds, vec![("bitcoin", "m/84'/0'/0'"), ("ethereum", "m/44'/60'/0'/0/0"), ("ethereum", "m/44'/60'/0'/0/1"), ("solana", "m/44'/501'/0'/0'")]);
        assert_eq!(imported.accounts[1].address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_ne!(imported.accounts[2].address, imported.accounts[1].address);
        assert_eq!(imported.accounts[3].address, bs58::encode(&sol_leaf).into_string());
        // Per-type indexes start at 0 each.
        assert_eq!(imported.accounts.iter().map(|a| a.index).collect::<Vec<_>>(), vec![0, 0, 1, 0]);
        assert_eq!(crate::models::account::for_wallet(&env, &imported.wallet.id).unwrap().len(), 4);
    }
}
