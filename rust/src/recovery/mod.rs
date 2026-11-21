//! Wallet recovery: open another wallet's secret, find what its addresses hold,
//! and sweep it to an address of the user's choosing (typically one of their
//! own libwallet accounts). See `docs/wallet-recovery.md`.
//!
//! A **source** is the secret another wallet left the user with: a Bitfi salt
//! and phrase, a BIP-39 mnemonic, a single private key, or an Ethereum keystore
//! file. Opening it derives what's needed and keeps it **in this process's
//! memory only**, under a random session id; nothing is written to the
//! database, and closing the session (or the process) forgets it.
//!
//! A source can have used many addresses: several chains, script types and
//! derivation paths. Each one is a **slot**, named by a stable id such as
//! `bitcoin:p2wpkh:m/84'/0'/0'/0/3`, `ethereum:evm:key` or
//! `litecoin:p2pukh:bitfi:2`. The id says how to re-derive the slot's key, so
//! later calls only need the session and the id.

pub mod keystore;
pub mod scan;
pub mod sweep;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use purecrypto::zeroize::{Zeroize, Zeroizing};
use serde_json::{json, Value};

use crate::bitfi::{self, PrivateKey};

/// The most slots one request may derive.
pub const MAX_SLOTS: usize = 2000;
/// The most indexes (or Bitfi positions) one request may ask about.
pub const MAX_COUNT: u32 = 100;
/// Indexes scanned when the request doesn't say.
pub const DEFAULT_COUNT: u32 = 5;

/// How a chain's addresses and transfers work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// A Bitcoin-family UTXO chain.
    Bitcoin {
        /// outscript network tag.
        network: &'static str,
        /// BIP-44 coin type.
        coin_type: u32,
        /// WIF version byte.
        wif: u8,
        /// `(scheme, BIP purpose, label)` a mnemonic wallet may have used.
        schemes: &'static [(&'static str, u32, &'static str)],
    },
    Ethereum,
    Solana,
    Tron,
    /// Keys only: balances and sends aren't available.
    Monero,
}

/// A chain recovery can look at.
#[derive(Debug)]
pub struct Chain {
    /// libwallet's chain name (`bitcoin`, `ethereum`, …).
    pub name: &'static str,
    pub symbol: &'static str,
    pub decimals: u32,
    pub family: Family,
    /// The Bitfi coin symbol, when Bitfi wallets hold this chain.
    pub bitfi: Option<&'static str>,
}

const BIP_BTC: &[(&str, u32, &str)] =
    &[("p2wpkh", 84, "Native SegWit (BIP84)"), ("p2sh:p2wpkh", 49, "SegWit (BIP49)"), ("p2pkh", 44, "Legacy (BIP44)")];
const BIP_MONA: &[(&str, u32, &str)] = &[("p2wpkh", 84, "Native SegWit (BIP84)"), ("p2pkh", 44, "Legacy (BIP44)")];
const BIP_LEGACY: &[(&str, u32, &str)] = &[("p2pkh", 44, "Legacy (BIP44)")];

pub const CHAINS: &[Chain] = &[
    Chain { name: "bitcoin", symbol: "BTC", decimals: 8, family: Family::Bitcoin { network: "bitcoin", coin_type: 0, wif: 0x80, schemes: BIP_BTC }, bitfi: Some("btc") },
    Chain { name: "litecoin", symbol: "LTC", decimals: 8, family: Family::Bitcoin { network: "litecoin", coin_type: 2, wif: 0xb0, schemes: BIP_BTC }, bitfi: Some("ltc") },
    Chain { name: "dogecoin", symbol: "DOGE", decimals: 8, family: Family::Bitcoin { network: "dogecoin", coin_type: 3, wif: 0x9e, schemes: BIP_LEGACY }, bitfi: Some("doge") },
    Chain { name: "bitcoin-cash", symbol: "BCH", decimals: 8, family: Family::Bitcoin { network: "bitcoincash", coin_type: 145, wif: 0x80, schemes: BIP_LEGACY }, bitfi: Some("bch") },
    Chain { name: "monacoin", symbol: "MONA", decimals: 8, family: Family::Bitcoin { network: "monacoin", coin_type: 22, wif: 0xb0, schemes: BIP_MONA }, bitfi: Some("mona") },
    Chain { name: "ethereum", symbol: "ETH", decimals: 18, family: Family::Ethereum, bitfi: Some("eth") },
    Chain { name: "solana", symbol: "SOL", decimals: 9, family: Family::Solana, bitfi: None },
    Chain { name: "tron", symbol: "TRX", decimals: 6, family: Family::Tron, bitfi: None },
    Chain { name: "monero", symbol: "XMR", decimals: 12, family: Family::Monero, bitfi: Some("xmr") },
];

pub fn chain(name: &str) -> Option<&'static Chain> {
    CHAINS.iter().find(|c| c.name.eq_ignore_ascii_case(name))
}

/// An opened source's secret material. Wiped when dropped.
pub enum Secret {
    Bitfi(bitfi::Node),
    /// A BIP-39 seed (mnemonic + passphrase).
    Seed(Zeroizing<[u8; 64]>),
    /// One private key. A 32-byte hex key is ambiguous, so it may be both a
    /// secp256k1 scalar and an ed25519 (Solana) seed; `compressed` is `false`
    /// only for a WIF that says its addresses use the uncompressed public key.
    Key { secp: Option<PrivateKey>, ed25519: Option<Zeroizing<[u8; 32]>>, compressed: Option<bool> },
}

/// An open recovery session.
pub struct Session {
    /// `bitfi`, `mnemonic`, `privateKey` or `keystore`.
    pub kind: &'static str,
    pub secret: Secret,
}

impl Session {
    /// The chains this source can hold funds on.
    pub fn chains(&self) -> Vec<&'static Chain> {
        CHAINS
            .iter()
            .filter(|c| match (&self.secret, c.family) {
                (Secret::Bitfi(_), _) => c.bitfi.is_some(),
                (Secret::Seed(_), Family::Monero) => false,
                (Secret::Seed(_), _) => true,
                (Secret::Key { ed25519, .. }, Family::Solana) => ed25519.is_some(),
                (Secret::Key { .. }, Family::Monero) => false,
                (Secret::Key { secp, .. }, _) => secp.is_some(),
            })
            .collect()
    }
}

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    SESSIONS.get_or_init(Default::default)
}

/// Keep `session` under a new random id.
pub fn insert(session: Session) -> Result<String, String> {
    let id = uuid::Uuid::new_v4().to_string();
    sessions().lock().map_err(|_| "session store unavailable".to_string())?.insert(id.clone(), session);
    Ok(id)
}

/// Run `f` with an open session. `None` from the store means it was closed.
pub fn with<T>(id: &str, f: impl FnOnce(&Session) -> Result<T, String>) -> Result<Option<T>, String> {
    let store = sessions().lock().map_err(|_| "session store unavailable".to_string())?;
    match store.get(id) {
        Some(s) => f(s).map(Some),
        None => Ok(None),
    }
}

/// Forget a session. Its secrets are wiped as it drops.
pub fn remove(id: &str) -> bool {
    sessions().lock().map(|mut s| s.remove(id).is_some()).unwrap_or(false)
}

// --- opening sources --------------------------------------------------------

/// Open a Bitfi wallet from its salt and secret phrase.
pub fn open_bitfi(salt: &str, secret: &str) -> Result<Session, String> {
    Ok(Session { kind: "bitfi", secret: Secret::Bitfi(bitfi::master(salt, secret)?) })
}

/// Open a BIP-39 mnemonic. The checksum must be valid: a mistyped word would
/// otherwise derive a wallet that never held anything.
pub fn open_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Session, String> {
    let normalized = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    if !crate::walletcore::validate_mnemonic(&normalized) {
        return Err("That isn't a valid recovery phrase: a word is misspelled, missing or in the wrong place.".into());
    }
    let seed = Zeroizing::new(crate::bip39::mnemonic_to_seed(&normalized, passphrase));
    Ok(Session { kind: "mnemonic", secret: Secret::Seed(seed) })
}

/// Open a single private key: 32-byte hex (secp256k1, and also tried as a
/// Solana seed), a Bitcoin-family WIF, or a Solana keypair (base58 or a JSON
/// byte array, as Phantom and solana-keygen export it).
pub fn open_private_key(input: &str) -> Result<Session, String> {
    let input = input.trim();
    let hex_body = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")).unwrap_or(input);
    if hex_body.len() == 64 && hex_body.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut bytes = Zeroizing::new([0u8; 32]);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex_body[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
        }
        let secp = valid_secp(&bytes).then(|| PrivateKey(*bytes));
        return Ok(Session { kind: "privateKey", secret: Secret::Key { secp, ed25519: Some(bytes), compressed: None } });
    }
    if let Some((key, compressed)) = decode_wif(input) {
        if !valid_secp(&key) {
            return Err("That WIF key is out of range.".into());
        }
        return Ok(Session { kind: "privateKey", secret: Secret::Key { secp: Some(PrivateKey(*key)), ed25519: None, compressed: Some(compressed) } });
    }
    match crate::handlers::wallet::decode_private_key("ed25519", input, "seed") {
        Ok(crate::handlers::wallet::DecodedKey::Ed25519Seed(seed)) => {
            Ok(Session { kind: "privateKey", secret: Secret::Key { secp: None, ed25519: Some(Zeroizing::new(seed)), compressed: None } })
        }
        _ => Err("That isn't a private key libwallet recognises: expected 64 hex characters, a WIF key, or a Solana keypair.".into()),
    }
}

/// Open an Ethereum keystore (v3 JSON) with its password.
pub fn open_keystore(json: &str, password: &str) -> Result<Session, String> {
    let (key, _address) = keystore::decrypt_v3(json, password.as_bytes())?;
    if !valid_secp(&key) {
        return Err("The keystore's key is out of range.".into());
    }
    Ok(Session { kind: "keystore", secret: Secret::Key { secp: Some(PrivateKey(*key)), ed25519: None, compressed: Some(true) } })
}

fn valid_secp(key: &[u8; 32]) -> bool {
    PrivateKey(*key).compressed_pub().is_ok()
}

/// A WIF key and whether it's marked compressed.
fn decode_wif(input: &str) -> Option<(Zeroizing<[u8; 32]>, bool)> {
    let mut raw = Zeroizing::new(bs58::decode(input).into_vec().ok()?);
    if raw.len() != 37 && raw.len() != 38 {
        return None;
    }
    let (body, check) = raw.split_at(raw.len() - 4);
    if purecrypto::hash::sha256(&purecrypto::hash::sha256(body))[..4] != *check {
        return None;
    }
    let compressed = match body.len() {
        34 if body[33] == 0x01 => true,
        33 => false,
        _ => return None,
    };
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&body[1..33]);
    raw.zeroize();
    Some((key, compressed))
}

// --- slots ------------------------------------------------------------------

/// How a slot's key is derived from the session's secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRef {
    /// A Bitfi position.
    Bitfi(u32),
    /// A BIP-32 / SLIP-10 path below the seed.
    Path(String),
    /// The first 32 bytes of the seed as an ed25519 key (Sollet).
    Seed32,
    /// The session's single key.
    Key,
}

impl KeyRef {
    fn to_id(&self) -> String {
        match self {
            KeyRef::Bitfi(n) => format!("bitfi:{n}"),
            KeyRef::Path(p) => p.clone(),
            KeyRef::Seed32 => "seed32".into(),
            KeyRef::Key => "key".into(),
        }
    }

    fn parse(s: &str) -> Option<KeyRef> {
        match s {
            "seed32" => Some(KeyRef::Seed32),
            "key" => Some(KeyRef::Key),
            _ if s.starts_with("bitfi:") => s[6..].parse().ok().filter(|n| *n < 0x8000_0000).map(KeyRef::Bitfi),
            _ if s.starts_with("m/") && crate::hdderive::parse_bip32_path(s).is_ok() => Some(KeyRef::Path(s.to_owned())),
            _ => None,
        }
    }
}

/// One address a source may have used.
#[derive(Debug, Clone)]
pub struct Slot {
    pub chain: &'static Chain,
    /// The address type: `p2wpkh`, `p2sh:p2wpkh`, `p2pkh`, `p2pukh` (legacy,
    /// uncompressed key), `evm`, `solana`, `tron` or `monero`.
    pub scheme: &'static str,
    pub key: KeyRef,
    pub address: String,
    /// What wallets use this slot, for display.
    pub label: String,
    /// The address index or Bitfi position.
    pub index: u32,
}

impl Slot {
    pub fn id(&self) -> String {
        format!("{}:{}:{}", self.chain.name, self.scheme, self.key.to_id())
    }

    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "Id": self.id(), "Chain": self.chain.name, "Symbol": self.chain.symbol, "Kind": self.scheme,
            "Address": self.address, "Label": self.label, "Index": self.index,
        });
        if let KeyRef::Path(p) = &self.key {
            v["Path"] = json!(p);
        }
        v
    }
}

/// The schemes a single secp256k1 key's coins may sit at on a Bitcoin chain.
fn key_schemes(network_schemes: &'static [(&'static str, u32, &'static str)], compressed: Option<bool>) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    if compressed != Some(false) {
        out.extend(network_schemes.iter().map(|(s, _, _)| *s));
    }
    if compressed != Some(true) {
        out.push("p2pukh");
    }
    out
}

fn scheme_label(scheme: &str) -> &'static str {
    match scheme {
        "p2wpkh" => "Native SegWit",
        "p2sh:p2wpkh" => "SegWit (P2SH)",
        "p2pkh" => "Legacy",
        "p2pukh" => "Legacy (uncompressed key)",
        _ => "",
    }
}

/// Every slot of `session` on `chains` (all the source's chains when empty),
/// for indexes `start..start + count`. Duplicates (the same address reached by
/// two paths, as index 0 of Ethereum's two layouts is) are listed once.
pub fn slots(session: &Session, chains: &[String], start: u32, count: u32) -> Result<Vec<Slot>, String> {
    let count = count.min(MAX_COUNT);
    let end = start.checked_add(count).filter(|e| *e <= 0x8000_0000).ok_or("index out of range")?;
    let mut wanted: Vec<&'static Chain> = Vec::new();
    let available = session.chains();
    if chains.is_empty() {
        wanted = available;
    } else {
        for name in chains {
            let c = chain(name).ok_or_else(|| format!("unknown chain {name:?}"))?;
            if !available.iter().any(|a| a.name == c.name) {
                return Err(format!("a {} source holds nothing on {}", session.kind, c.name));
            }
            if !wanted.iter().any(|w| w.name == c.name) {
                wanted.push(c);
            }
        }
    }

    let mut out: Vec<Slot> = Vec::new();
    for c in wanted {
        let mut refs: Vec<(&'static str, KeyRef, String, u32)> = Vec::new();
        match (&session.secret, c.family) {
            (Secret::Bitfi(_), family) => {
                for i in start..end {
                    match family {
                        Family::Bitcoin { schemes, .. } => {
                            refs.push(("p2pukh", KeyRef::Bitfi(i), format!("Bitfi position {i}, legacy"), i));
                            if schemes.iter().any(|(s, _, _)| *s == "p2wpkh") {
                                refs.push(("p2wpkh", KeyRef::Bitfi(i), format!("Bitfi position {i}, SegWit"), i));
                            }
                        }
                        Family::Ethereum => refs.push(("evm", KeyRef::Bitfi(i), format!("Bitfi position {i}"), i)),
                        Family::Monero => refs.push(("monero", KeyRef::Bitfi(i), format!("Bitfi position {i}"), i)),
                        _ => {}
                    }
                }
            }
            (Secret::Seed(_), Family::Bitcoin { coin_type, schemes, .. }) => {
                for (scheme, purpose, label) in schemes {
                    for change in [0u32, 1] {
                        for i in start..end {
                            let path = format!("m/{purpose}'/{coin_type}'/0'/{change}/{i}");
                            let which = if change == 0 { "receive" } else { "change" };
                            refs.push((scheme, KeyRef::Path(path), format!("{label}, {which} {i}"), i));
                        }
                    }
                }
            }
            (Secret::Seed(_), Family::Ethereum) => {
                for i in start..end {
                    refs.push(("evm", KeyRef::Path(format!("m/44'/60'/0'/0/{i}")), format!("MetaMask / standard, account {i}"), i));
                    refs.push(("evm", KeyRef::Path(format!("m/44'/60'/{i}'/0/0")), format!("Ledger Live, account {i}"), i));
                }
            }
            (Secret::Seed(_), Family::Tron) => {
                for i in start..end {
                    refs.push(("tron", KeyRef::Path(format!("m/44'/195'/0'/0/{i}")), format!("Standard, account {i}"), i));
                }
            }
            (Secret::Seed(_), Family::Solana) => {
                if start == 0 && end > 0 {
                    refs.push(("solana", KeyRef::Seed32, "Sollet (seed, no derivation)".into(), 0));
                }
                for i in start..end {
                    refs.push(("solana", KeyRef::Path(format!("m/44'/501'/{i}'/0'")), format!("Phantom / Solflare, account {i}"), i));
                    refs.push(("solana", KeyRef::Path(format!("m/44'/501'/{i}'")), format!("Trust Wallet / older Solflare, account {i}"), i));
                }
            }
            (Secret::Key { compressed, .. }, Family::Bitcoin { schemes, .. }) => {
                if start == 0 && end > 0 {
                    for scheme in key_schemes(schemes, *compressed) {
                        refs.push((scheme, KeyRef::Key, scheme_label(scheme).into(), 0));
                    }
                }
            }
            (Secret::Key { .. }, family) if start == 0 && end > 0 => {
                let scheme = match family {
                    Family::Ethereum => "evm",
                    Family::Tron => "tron",
                    Family::Solana => "solana",
                    _ => continue,
                };
                refs.push((scheme, KeyRef::Key, "Private key".into(), 0));
            }
            _ => {}
        }
        for (scheme, key, label, index) in refs {
            if out.len() >= MAX_SLOTS {
                return Err(format!("that's more than {MAX_SLOTS} addresses: ask for fewer chains or indexes"));
            }
            let address = address_for(session, c, scheme, &key)?;
            if out.iter().any(|s| s.chain.name == c.name && s.address == address) {
                continue;
            }
            out.push(Slot { chain: c, scheme, key, address, label, index });
        }
    }
    Ok(out)
}

/// The slot an id names, checked against what this session can derive.
pub fn slot(session: &Session, id: &str) -> Result<Slot, String> {
    let bad = || format!("unknown address {id:?}");
    let mut parts = id.splitn(3, ':');
    let (c, scheme, key) = (parts.next().ok_or_else(bad)?, parts.next().ok_or_else(bad)?, parts.next().ok_or_else(bad)?);
    // `p2sh:p2wpkh` itself holds a colon.
    let (scheme, key) = if scheme == "p2sh" {
        let (rest, key) = key.split_once(':').ok_or_else(bad)?;
        if rest != "p2wpkh" {
            return Err(bad());
        }
        ("p2sh:p2wpkh", key)
    } else {
        (scheme, key)
    };
    let c = chain(c).ok_or_else(bad)?;
    let key = KeyRef::parse(key).ok_or_else(bad)?;
    let scheme: &'static str = match (c.family, scheme) {
        (Family::Bitcoin { .. }, "p2wpkh") => "p2wpkh",
        (Family::Bitcoin { .. }, "p2sh:p2wpkh") => "p2sh:p2wpkh",
        (Family::Bitcoin { .. }, "p2pkh") => "p2pkh",
        (Family::Bitcoin { .. }, "p2pukh") => "p2pukh",
        (Family::Ethereum, "evm") => "evm",
        (Family::Solana, "solana") => "solana",
        (Family::Tron, "tron") => "tron",
        (Family::Monero, "monero") => "monero",
        _ => return Err(bad()),
    };
    let fits = match (&session.secret, &key) {
        (Secret::Bitfi(_), KeyRef::Bitfi(_)) => c.bitfi.is_some(),
        (Secret::Seed(_), KeyRef::Path(_)) => !matches!(c.family, Family::Monero),
        (Secret::Seed(_), KeyRef::Seed32) => matches!(c.family, Family::Solana),
        (Secret::Key { .. }, KeyRef::Key) => session.chains().iter().any(|a| a.name == c.name),
        _ => false,
    };
    if !fits {
        return Err(format!("address {id:?} isn't one this source can have used"));
    }
    let address = address_for(session, c, scheme, &key)?;
    let index = match &key {
        KeyRef::Bitfi(n) => *n,
        KeyRef::Path(p) => crate::hdderive::parse_bip32_path(p).ok().and_then(|v| v.last().copied()).unwrap_or(0) & 0x7fff_ffff,
        _ => 0,
    };
    Ok(Slot { chain: c, scheme, key, address, label: String::new(), index })
}

/// A slot's signing key.
pub enum SlotKey {
    Secp(PrivateKey),
    /// An ed25519 seed (RFC 8032), as Solana wallets hold it.
    Ed25519(Zeroizing<[u8; 32]>),
}

/// Derive the key a slot's address belongs to.
pub fn key_for(session: &Session, c: &Chain, key: &KeyRef) -> Result<SlotKey, String> {
    let ed = matches!(c.family, Family::Solana);
    match (&session.secret, key) {
        (Secret::Bitfi(node), KeyRef::Bitfi(n)) => {
            let symbol = c.bitfi.ok_or_else(|| format!("Bitfi wallets don't hold {}", c.name))?;
            Ok(SlotKey::Secp(node.derive(symbol, *n)?))
        }
        (Secret::Seed(seed), KeyRef::Path(path)) => {
            let curve = if ed { "ed25519" } else { "secp256k1" };
            let k = Zeroizing::new(crate::hdderive::derive_privkey_from_seed(&seed[..], curve, path).map_err(|e| e.to_string())?);
            Ok(if ed { SlotKey::Ed25519(k) } else { SlotKey::Secp(PrivateKey(*k)) })
        }
        (Secret::Seed(seed), KeyRef::Seed32) if ed => {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&seed[..32]);
            Ok(SlotKey::Ed25519(k))
        }
        (Secret::Key { ed25519: Some(k), .. }, KeyRef::Key) if ed => Ok(SlotKey::Ed25519(k.clone())),
        (Secret::Key { secp: Some(k), .. }, KeyRef::Key) if !ed => Ok(SlotKey::Secp(PrivateKey(k.0))),
        _ => Err("this source has no key for that address".into()),
    }
}

/// The address of a slot.
fn address_for(session: &Session, c: &Chain, scheme: &str, key: &KeyRef) -> Result<String, String> {
    match key_for(session, c, key)? {
        SlotKey::Ed25519(seed) => {
            let public = purecrypto::ec::ed25519::Ed25519PrivateKey::from_bytes(*seed).public_key().to_bytes();
            Ok(bs58::encode(public).into_string())
        }
        SlotKey::Secp(k) => {
            let public = k.compressed_pub()?;
            match c.family {
                Family::Bitcoin { network, .. } => crate::bitcoin::address_for(&public, scheme, network).map_err(|e| e.to_string()),
                Family::Ethereum => crate::hdderive::evm_address(&public).map_err(|e| e.to_string()),
                Family::Tron => crate::hdderive::tron_address(&public).map_err(|e| e.to_string()),
                Family::Monero => Ok(k.monero().address()),
                Family::Solana => Err("not a Solana key".into()),
            }
        }
    }
}

/// A slot's private key in the forms other wallets import. Only ever returned
/// on an explicit export request.
pub fn export(session: &Session, s: &Slot) -> Result<Value, String> {
    Ok(match (key_for(session, s.chain, &s.key)?, s.chain.family) {
        (SlotKey::Ed25519(seed), _) => {
            let public = purecrypto::ec::ed25519::Ed25519PrivateKey::from_bytes(*seed).public_key().to_bytes();
            let mut pair = Zeroizing::new([0u8; 64]);
            pair[..32].copy_from_slice(&seed[..]);
            pair[32..].copy_from_slice(&public);
            json!({ "Address": s.address, "PrivateKey": bs58::encode(&pair[..]).into_string() })
        }
        (SlotKey::Secp(k), Family::Bitcoin { wif, .. }) => {
            json!({ "Address": s.address, "PrivateKey": k.to_hex(), "Wif": k.to_wif(wif, s.scheme != "p2pukh") })
        }
        (SlotKey::Secp(k), Family::Monero) => {
            let keys = k.monero();
            let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            json!({ "Address": keys.address(), "SpendKey": hex(&keys.spend), "ViewKey": hex(&keys.view) })
        }
        (SlotKey::Secp(k), _) => json!({ "Address": s.address, "PrivateKey": k.to_hex() }),
    })
}
