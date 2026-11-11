//! The UR registry types exchanged with air-gapped signers, as Rust structs
//! with CBOR codecs (BCR-2020-006/007/008/009/015 and Keystone's extensions).
//!
//! Tags: `crypto-hdkey` 303, `crypto-keypath` 304, `crypto-coin-info` 305,
//! `crypto-output` 308 (+ script-expression tags 400–409), `crypto-psbt` 310,
//! `crypto-account` 311, `eth-sign-request` 401, `eth-signature` 402,
//! `sol-sign-request` 1101, `sol-signature` 1102, `crypto-multi-accounts`
//! 1103, `uuid` 37. A UR's top-level item is untagged (the UR type names it);
//! nested items carry their tags. Decoders accept both.

use ciborium::value::Value;

use super::cbor::{self, MapBuilder};
use crate::{Error, Result};

pub const UR_HDKEY: &str = "crypto-hdkey";
pub const UR_ACCOUNT: &str = "crypto-account";
pub const UR_MULTI_ACCOUNTS: &str = "crypto-multi-accounts";
pub const UR_PSBT: &str = "crypto-psbt";
pub const UR_PSBT_NEW: &str = "psbt";
pub const UR_ETH_SIGN_REQUEST: &str = "eth-sign-request";
pub const UR_ETH_SIGNATURE: &str = "eth-signature";
pub const UR_SOL_SIGN_REQUEST: &str = "sol-sign-request";
pub const UR_SOL_SIGNATURE: &str = "sol-signature";
pub const UR_TRON_SIGN_REQUEST: &str = "tron-sign-request";
pub const UR_TRON_SIGNATURE: &str = "tron-signature";
pub const UR_BTC_SIGN_REQUEST: &str = "btc-sign-request";
pub const UR_BTC_SIGNATURE: &str = "btc-signature";
pub const UR_BYTES: &str = "bytes";

pub const TAG_UUID: u64 = 37;
pub const TAG_HDKEY: u64 = 303;
pub const TAG_KEYPATH: u64 = 304;
pub const TAG_COIN_INFO: u64 = 305;
pub const TAG_OUTPUT: u64 = 308;
pub const TAG_PSBT: u64 = 310;
pub const TAG_ACCOUNT: u64 = 311;
pub const TAG_ETH_SIGN_REQUEST: u64 = 401;
pub const TAG_ETH_SIGNATURE: u64 = 402;
pub const TAG_SOL_SIGN_REQUEST: u64 = 1101;
pub const TAG_SOL_SIGNATURE: u64 = 1102;
pub const TAG_MULTI_ACCOUNTS: u64 = 1103;

// crypto-output script expressions (BCR-2020-010).
pub const TAG_SH: u64 = 400;
pub const TAG_WSH: u64 = 401;
pub const TAG_PK: u64 = 402;
pub const TAG_PKH: u64 = 403;
pub const TAG_WPKH: u64 = 404;
pub const TAG_COMBO: u64 = 405;
pub const TAG_MULTI: u64 = 406;
pub const TAG_SORTED_MULTI: u64 = 407;
pub const TAG_ADDRESS: u64 = 408;
/// 409 is `tr` in the Keystone/BlockchainCommons registry (it was `raw` in an
/// early draft); 410 is accepted as taproot too.
pub const TAG_TR: u64 = 409;

pub const HARDENED: u32 = 0x8000_0000;

// ── crypto-keypath ───────────────────────────────────────────────────────────

/// A BIP-32 path with its optional source fingerprint and depth.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyPath {
    /// Child indexes with the hardened bit set where hardened.
    pub components: Vec<u32>,
    /// Fingerprint of the key the path starts from (the master, for signers).
    pub source_fingerprint: Option<u32>,
    pub depth: Option<u8>,
}

impl KeyPath {
    pub fn new(components: Vec<u32>, source_fingerprint: Option<u32>) -> Self {
        Self { components, source_fingerprint, depth: None }
    }

    /// Parse `m/44'/60'/0'/0/0` (also `h`/`H` for hardened; `m/` optional).
    pub fn parse(path: &str) -> Result<Self> {
        let p = path.trim();
        let p = p.strip_prefix("m/").or_else(|| p.strip_prefix("M/")).unwrap_or(if p == "m" || p == "M" { "" } else { p });
        let mut components = Vec::new();
        for seg in p.split('/').filter(|s| !s.is_empty()) {
            let (num, hardened) = match seg.strip_suffix('\'').or_else(|| seg.strip_suffix('h')).or_else(|| seg.strip_suffix('H')) {
                Some(n) => (n, true),
                None => (seg, false),
            };
            let n: u32 = num.parse().map_err(|_| Error::Env(format!("bad path component {seg:?} in {path:?}")))?;
            if n >= HARDENED {
                return Err(Error::Env(format!("path component {seg} out of range")));
            }
            components.push(if hardened { n | HARDENED } else { n });
        }
        Ok(Self { components, source_fingerprint: None, depth: None })
    }

    /// `m/44'/60'/0'/0/0`.
    pub fn to_string_hardened_apostrophe(&self) -> String {
        let mut s = String::from("m");
        for c in &self.components {
            s.push('/');
            if c & HARDENED != 0 {
                s.push_str(&format!("{}'", c & !HARDENED));
            } else {
                s.push_str(&c.to_string());
            }
        }
        s
    }

    pub fn len(&self) -> usize {
        self.components.len()
    }
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
    /// The path extended by non-hardened `children` (e.g. `[0, 5]`).
    pub fn child(&self, children: &[u32]) -> KeyPath {
        let mut c = self.components.clone();
        c.extend_from_slice(children);
        KeyPath { components: c, source_fingerprint: self.source_fingerprint, depth: None }
    }

    pub fn to_cbor(&self) -> Value {
        let mut comps = Vec::with_capacity(self.components.len() * 2);
        for c in &self.components {
            comps.push(cbor::uint((c & !HARDENED) as u64));
            comps.push(Value::Bool(c & HARDENED != 0));
        }
        MapBuilder::new()
            .put(1, Value::Array(comps))
            .opt(2, self.source_fingerprint.map(|f| cbor::uint(f as u64)))
            .opt(3, self.depth.map(|d| cbor::uint(d as u64)))
            .build()
    }

    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, tag) = cbor::untag(v);
        if let Some(t) = tag {
            if t != TAG_KEYPATH {
                return Err(Error::Env(format!("expected crypto-keypath (304), got tag {t}")));
            }
        }
        let comps = cbor::as_array(cbor::need(v, 1, "keypath")?).ok_or_else(|| Error::Env("keypath components not an array".into()))?;
        let mut components = Vec::new();
        let mut i = 0;
        while i < comps.len() {
            // Each component is `index, hardened` — a range `[lo, hi]` or a
            // wildcard `[]` as index is not a single key; reject those.
            let idx = match &comps[i] {
                // Negative (or > u64) integers are valid CBOR but not an index.
                Value::Integer(_) => cbor::as_u64(&comps[i]).ok_or_else(|| Error::Env("keypath index out of range".into()))?,
                Value::Array(a) if a.is_empty() => return Err(Error::Env("wildcard keypath components are not supported".into())),
                _ => return Err(Error::Env("unsupported keypath component".into())),
            };
            let hardened = comps.get(i + 1).and_then(cbor::as_bool).ok_or_else(|| Error::Env("keypath component missing hardened flag".into()))?;
            if idx >= HARDENED as u64 {
                return Err(Error::Env("keypath index out of range".into()));
            }
            components.push(idx as u32 | if hardened { HARDENED } else { 0 });
            i += 2;
        }
        Ok(Self {
            components,
            source_fingerprint: cbor::opt_uint::<u32>(v, 2, "keypath source-fingerprint")?,
            depth: cbor::opt_uint::<u8>(v, 3, "keypath depth")?,
        })
    }
}

impl std::fmt::Display for KeyPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string_hardened_apostrophe())
    }
}

// ── crypto-coin-info ─────────────────────────────────────────────────────────

/// SLIP-44 coin type + network (0 mainnet, 1 testnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinInfo {
    pub coin_type: u32,
    pub network: u32,
}

impl CoinInfo {
    pub fn to_cbor(&self) -> Value {
        cbor::tagged(TAG_COIN_INFO, MapBuilder::new().put(1, cbor::uint(self.coin_type as u64)).put(2, cbor::uint(self.network as u64)).build())
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        Ok(Self {
            coin_type: cbor::opt_uint::<u32>(v, 1, "coin-info type")?.unwrap_or(0),
            network: cbor::opt_uint::<u32>(v, 2, "coin-info network")?.unwrap_or(0),
        })
    }
}

// ── crypto-hdkey ─────────────────────────────────────────────────────────────

/// An extended (or bare) public key with its provenance. `key_data` is the
/// 33-byte compressed secp256k1 key, or 32 bytes (optionally 0x00-prefixed to
/// 33) for ed25519 keys as Keystone exports Solana accounts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HdKey {
    pub is_master: bool,
    pub is_private: bool,
    pub key_data: Vec<u8>,
    pub chain_code: Option<[u8; 32]>,
    pub use_info: Option<CoinInfo>,
    pub origin: Option<KeyPath>,
    pub children: Option<KeyPath>,
    pub parent_fingerprint: Option<u32>,
    pub name: Option<String>,
    pub note: Option<String>,
}

impl HdKey {
    pub fn to_cbor(&self) -> Value {
        let mut m = MapBuilder::new();
        if self.is_master {
            m = m.put(1, Value::Bool(true));
        }
        if self.is_private {
            m = m.put(2, Value::Bool(true));
        }
        m = m.put(3, cbor::bytes(&self.key_data));
        m = m
            .opt(4, self.chain_code.map(|c| cbor::bytes(&c)))
            .opt(5, self.use_info.map(|u| u.to_cbor()))
            .opt(6, self.origin.as_ref().map(|o| cbor::tagged(TAG_KEYPATH, o.to_cbor())))
            .opt(7, self.children.as_ref().map(|o| cbor::tagged(TAG_KEYPATH, o.to_cbor())))
            .opt(8, self.parent_fingerprint.map(|f| cbor::uint(f as u64)))
            .opt(9, self.name.as_ref().map(|s| cbor::text(s)))
            .opt(10, self.note.as_ref().map(|s| cbor::text(s)));
        m.build()
    }

    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, tag) = cbor::untag(v);
        if let Some(t) = tag {
            if t != TAG_HDKEY {
                return Err(Error::Env(format!("expected crypto-hdkey (303), got tag {t}")));
            }
        }
        let key_data = cbor::as_bytes(cbor::need(v, 3, "hdkey")?).ok_or_else(|| Error::Env("hdkey key-data not bytes".into()))?.to_vec();
        let chain_code = match cbor::get(v, 4).and_then(cbor::as_bytes) {
            Some(c) if c.len() == 32 => Some(<[u8; 32]>::try_from(c).unwrap()),
            Some(_) => return Err(Error::Env("hdkey chain-code is not 32 bytes".into())),
            None => None,
        };
        Ok(Self {
            is_master: cbor::get(v, 1).and_then(cbor::as_bool).unwrap_or(false),
            is_private: cbor::get(v, 2).and_then(cbor::as_bool).unwrap_or(false),
            key_data,
            chain_code,
            use_info: cbor::get(v, 5).map(CoinInfo::from_cbor).transpose()?,
            origin: cbor::get(v, 6).map(KeyPath::from_cbor).transpose()?,
            children: cbor::get(v, 7).map(KeyPath::from_cbor).transpose()?,
            parent_fingerprint: cbor::opt_uint::<u32>(v, 8, "hdkey parent-fingerprint")?,
            name: cbor::get(v, 9).and_then(cbor::as_text).map(str::to_owned),
            note: cbor::get(v, 10).and_then(cbor::as_text).map(str::to_owned),
        })
    }

    /// The origin's source fingerprint (the signer's master fingerprint).
    pub fn master_fingerprint(&self) -> Option<u32> {
        self.origin.as_ref().and_then(|o| o.source_fingerprint)
    }

    /// SLIP-44 coin type: from use-info, else the second path component.
    pub fn coin_type(&self) -> Option<u32> {
        if let Some(u) = self.use_info {
            return Some(u.coin_type);
        }
        let o = self.origin.as_ref()?;
        if o.components.len() >= 2 && o.components[0] & !HARDENED == 44 || o.components.len() >= 2 && matches!(o.components[0] & !HARDENED, 49 | 84 | 86) {
            return Some(o.components[1] & !HARDENED);
        }
        None
    }

    /// Whether this is an ed25519 key (32 bytes, or 0x00 || 32 bytes).
    pub fn is_ed25519(&self) -> bool {
        self.key_data.len() == 32 || (self.key_data.len() == 33 && self.key_data[0] == 0 && self.chain_code.is_none())
    }

    /// The raw 32-byte ed25519 key, if this is one.
    pub fn ed25519_key(&self) -> Option<[u8; 32]> {
        match self.key_data.len() {
            32 => self.key_data.as_slice().try_into().ok(),
            33 if self.key_data[0] == 0 => self.key_data[1..].try_into().ok(),
            _ => None,
        }
    }

    /// The compressed secp256k1 key, if this is one.
    pub fn secp_key(&self) -> Option<[u8; 33]> {
        if self.key_data.len() == 33 && matches!(self.key_data[0], 2 | 3) {
            self.key_data.as_slice().try_into().ok()
        } else {
            None
        }
    }
}

// ── crypto-output / crypto-account ───────────────────────────────────────────

/// A single-key output descriptor: the script kind wrapping one hdkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDescriptor {
    /// libwallet script name: `p2pkh`, `p2wpkh`, `p2sh:p2wpkh`, `p2tr`, or
    /// `pk`/`combo`/`multi`/`addr` (unsupported for import).
    pub script: String,
    pub key: HdKey,
}

impl OutputDescriptor {
    fn tags_for(script: &str) -> Result<Vec<u64>> {
        Ok(match script {
            "p2pkh" => vec![TAG_PKH],
            "p2wpkh" => vec![TAG_WPKH],
            "p2sh:p2wpkh" | "p2sh-p2wpkh" => vec![TAG_SH, TAG_WPKH],
            "p2tr" => vec![TAG_TR],
            other => return Err(Error::Env(format!("unsupported output script {other}"))),
        })
    }

    pub fn to_cbor(&self) -> Value {
        // Build inside-out: hdkey, wrapped by each script tag.
        let mut v = cbor::tagged(TAG_HDKEY, self.key.to_cbor());
        for t in Self::tags_for(&self.script).unwrap_or_else(|_| vec![TAG_WPKH]).into_iter().rev() {
            v = cbor::tagged(t, v);
        }
        cbor::tagged(TAG_OUTPUT, v)
    }

    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (mut cur, tag) = cbor::untag(v);
        if tag == Some(TAG_OUTPUT) {
            // fine, outer wrapper
        } else if let Some(t) = tag {
            // The outer 308 may be omitted: `cur` is then the first script tag.
            cur = v;
            let _ = t;
        }
        let mut tags = Vec::new();
        loop {
            match cur {
                Value::Tag(t, inner) if *t != TAG_HDKEY && *t != TAG_OUTPUT => {
                    tags.push(*t);
                    cur = inner;
                }
                Value::Tag(t, inner) if *t == TAG_OUTPUT => cur = inner,
                _ => break,
            }
        }
        let key = HdKey::from_cbor(cur)?;
        let script = match tags.as_slice() {
            [TAG_PKH] => "p2pkh",
            [TAG_WPKH] => "p2wpkh",
            [TAG_SH, TAG_WPKH] => "p2sh:p2wpkh",
            [TAG_TR] | [410] => "p2tr",
            [TAG_PK] => "pk",
            [TAG_COMBO] => "combo",
            [TAG_MULTI, ..] | [TAG_SORTED_MULTI, ..] | [TAG_SH, TAG_MULTI, ..] | [TAG_WSH, ..] => "multi",
            [TAG_ADDRESS] => "addr",
            [] => "p2wpkh", // bare hdkey in an account: assume native segwit
            other => return Err(Error::Env(format!("unsupported crypto-output script tags {other:?}"))),
        }
        .to_owned();
        Ok(Self { script, key })
    }
}

/// `crypto-account`: a master fingerprint and one descriptor per script type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CryptoAccount {
    pub master_fingerprint: u32,
    pub outputs: Vec<OutputDescriptor>,
}

impl CryptoAccount {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .put(1, cbor::uint(self.master_fingerprint as u64))
            .put(2, Value::Array(self.outputs.iter().map(|o| o.to_cbor()).collect()))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        let fp = cbor::opt_uint::<u32>(v, 1, "crypto-account master-fingerprint")?.unwrap_or(0);
        let outs = cbor::as_array(cbor::need(v, 2, "crypto-account")?).ok_or_else(|| Error::Env("output-descriptors not an array".into()))?;
        let mut outputs = Vec::new();
        for o in outs {
            // Tolerate descriptors we can't model (multisig…) by skipping them.
            if let Ok(d) = OutputDescriptor::from_cbor(o) {
                outputs.push(d);
            }
        }
        Ok(Self { master_fingerprint: fp, outputs })
    }
}

// ── crypto-multi-accounts (Keystone) ─────────────────────────────────────────

/// Keystone's multi-chain key export: several hdkeys (BTC xpubs, ETH, SOL
/// leaf keys…) under one master fingerprint, plus the device identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MultiAccounts {
    pub master_fingerprint: u32,
    pub keys: Vec<HdKey>,
    pub device: Option<String>,
    pub device_id: Option<String>,
    pub version: Option<String>,
}

impl MultiAccounts {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .put(1, cbor::uint(self.master_fingerprint as u64))
            .put(2, Value::Array(self.keys.iter().map(|k| cbor::tagged(TAG_HDKEY, k.to_cbor())).collect()))
            .opt(3, self.device.as_ref().map(|s| cbor::text(s)))
            .opt(4, self.device_id.as_ref().map(|s| cbor::text(s)))
            .opt(5, self.version.as_ref().map(|s| cbor::text(s)))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        let keys = cbor::as_array(cbor::need(v, 2, "crypto-multi-accounts")?).ok_or_else(|| Error::Env("keys not an array".into()))?;
        Ok(Self {
            master_fingerprint: cbor::opt_uint::<u32>(v, 1, "crypto-multi-accounts master-fingerprint")?.unwrap_or(0),
            keys: keys.iter().map(HdKey::from_cbor).collect::<Result<_>>()?,
            device: cbor::get(v, 3).and_then(cbor::as_text).map(str::to_owned),
            device_id: cbor::get(v, 4).and_then(cbor::as_text).map(str::to_owned),
            version: cbor::get(v, 5).and_then(cbor::as_text).map(str::to_owned),
        })
    }
}

// ── crypto-psbt ──────────────────────────────────────────────────────────────

pub fn psbt_to_cbor(psbt: &[u8]) -> Vec<u8> {
    outscript::bcur::bytes_to_cbor(psbt)
}
pub fn psbt_from_cbor(cbor_bytes: &[u8]) -> Result<Vec<u8>> {
    outscript::bcur::cbor_to_bytes(cbor_bytes).map(|b| b.to_vec()).map_err(|e| Error::Env(format!("crypto-psbt: {e}")))
}

// ── uuid (tag 37) ────────────────────────────────────────────────────────────

pub fn uuid_to_cbor(id: &[u8; 16]) -> Value {
    cbor::tagged(TAG_UUID, cbor::bytes(id))
}
pub fn uuid_from_cbor(v: &Value) -> Result<[u8; 16]> {
    let (v, _) = cbor::untag(v);
    cbor::as_bytes(v).and_then(|b| <[u8; 16]>::try_from(b).ok()).ok_or_else(|| Error::Env("request-id is not a 16-byte uuid".into()))
}
pub fn new_request_id() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}
pub fn uuid_hyphenated(id: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*id).hyphenated().to_string()
}
pub fn uuid_parse(s: &str) -> Result<[u8; 16]> {
    uuid::Uuid::parse_str(s.trim()).map(|u| *u.as_bytes()).map_err(|e| Error::Env(format!("bad request id: {e}")))
}

// ── eth-sign-request / eth-signature ─────────────────────────────────────────

/// `data-type` of an eth-sign-request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EthDataType {
    /// RLP-encoded unsigned legacy transaction (EIP-155 preimage).
    Transaction = 1,
    /// EIP-712 typed data (JSON).
    TypedData = 2,
    /// Raw bytes signed as an EIP-191 personal message.
    PersonalMessage = 3,
    /// EIP-2718 typed transaction (e.g. `0x02 || rlp(...)`).
    TypedTransaction = 4,
}

impl EthDataType {
    pub fn from_u64(n: u64) -> Result<Self> {
        Ok(match n {
            1 => Self::Transaction,
            2 => Self::TypedData,
            3 => Self::PersonalMessage,
            4 => Self::TypedTransaction,
            o => return Err(Error::Env(format!("unknown eth data-type {o}"))),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthSignRequest {
    pub request_id: [u8; 16],
    pub sign_data: Vec<u8>,
    pub data_type: EthDataType,
    pub chain_id: Option<u64>,
    pub derivation_path: KeyPath,
    /// 20-byte address, when known (lets the signer double-check the key).
    pub address: Option<[u8; 20]>,
    pub origin: Option<String>,
}

impl EthSignRequest {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .put(1, uuid_to_cbor(&self.request_id))
            .put(2, cbor::bytes(&self.sign_data))
            .put(3, cbor::uint(self.data_type as u64))
            .opt(4, self.chain_id.map(cbor::uint))
            .put(5, cbor::tagged(TAG_KEYPATH, self.derivation_path.to_cbor()))
            .opt(6, self.address.map(|a| cbor::bytes(&a)))
            .opt(7, self.origin.as_ref().map(|s| cbor::text(s)))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        Ok(Self {
            request_id: uuid_from_cbor(cbor::need(v, 1, "eth-sign-request")?)?,
            sign_data: cbor::as_bytes(cbor::need(v, 2, "eth-sign-request")?).ok_or_else(|| Error::Env("sign-data not bytes".into()))?.to_vec(),
            data_type: EthDataType::from_u64(cbor::get(v, 3).and_then(cbor::as_u64).unwrap_or(1))?,
            chain_id: cbor::get(v, 4).and_then(cbor::as_u64),
            derivation_path: KeyPath::from_cbor(cbor::need(v, 5, "eth-sign-request")?)?,
            address: cbor::get(v, 6).and_then(cbor::as_bytes).and_then(|b| <[u8; 20]>::try_from(b).ok()),
            origin: cbor::get(v, 7).and_then(cbor::as_text).map(str::to_owned),
        })
    }
}

/// The signer's answer: `r || s || v` (65 bytes; `v` is a recovery id, 27/28,
/// or an EIP-155 value depending on the device — `sign::accept` normalizes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthSignature {
    pub request_id: Option<[u8; 16]>,
    pub signature: Vec<u8>,
    pub origin: Option<String>,
}

impl EthSignature {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .opt(1, self.request_id.map(|id| uuid_to_cbor(&id)))
            .put(2, cbor::bytes(&self.signature))
            .opt(3, self.origin.as_ref().map(|s| cbor::text(s)))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        Ok(Self {
            request_id: cbor::get(v, 1).map(uuid_from_cbor).transpose()?,
            signature: cbor::as_bytes(cbor::need(v, 2, "eth-signature")?).ok_or_else(|| Error::Env("signature not bytes".into()))?.to_vec(),
            origin: cbor::get(v, 3).and_then(cbor::as_text).map(str::to_owned),
        })
    }
}

// ── sol-sign-request / sol-signature ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SolSignType {
    /// Serialized transaction *message* bytes.
    Transaction = 1,
    /// Arbitrary message bytes.
    Message = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolSignRequest {
    pub request_id: [u8; 16],
    pub sign_data: Vec<u8>,
    pub derivation_path: KeyPath,
    /// 32-byte account key, when known.
    pub address: Option<[u8; 32]>,
    pub origin: Option<String>,
    pub sign_type: SolSignType,
}

impl SolSignRequest {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .put(1, uuid_to_cbor(&self.request_id))
            .put(2, cbor::bytes(&self.sign_data))
            .put(3, cbor::tagged(TAG_KEYPATH, self.derivation_path.to_cbor()))
            .opt(4, self.address.map(|a| cbor::bytes(&a)))
            .opt(5, self.origin.as_ref().map(|s| cbor::text(s)))
            .put(6, cbor::uint(self.sign_type as u64))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        Ok(Self {
            request_id: uuid_from_cbor(cbor::need(v, 1, "sol-sign-request")?)?,
            sign_data: cbor::as_bytes(cbor::need(v, 2, "sol-sign-request")?).ok_or_else(|| Error::Env("sign-data not bytes".into()))?.to_vec(),
            derivation_path: KeyPath::from_cbor(cbor::need(v, 3, "sol-sign-request")?)?,
            address: cbor::get(v, 4).and_then(cbor::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok()),
            origin: cbor::get(v, 5).and_then(cbor::as_text).map(str::to_owned),
            sign_type: match cbor::get(v, 6).and_then(cbor::as_u64).unwrap_or(1) {
                2 => SolSignType::Message,
                _ => SolSignType::Transaction,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolSignature {
    pub request_id: Option<[u8; 16]>,
    /// 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
}

impl SolSignature {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new().opt(1, self.request_id.map(|id| uuid_to_cbor(&id))).put(2, cbor::bytes(&self.signature)).build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        Ok(Self {
            request_id: cbor::get(v, 1).map(uuid_from_cbor).transpose()?,
            signature: cbor::as_bytes(cbor::need(v, 2, "sol-signature")?).ok_or_else(|| Error::Env("signature not bytes".into()))?.to_vec(),
        })
    }
}

// ── tron-sign-request / tron-signature (Keystone) ───────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TronDataType {
    /// The transaction's protobuf `raw_data`.
    Transaction = 1,
    /// Arbitrary message bytes (`\x19TRON Signed Message:\n` + length + message).
    PersonalMessage = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronSignRequest {
    pub request_id: [u8; 16],
    pub sign_data: Vec<u8>,
    pub data_type: TronDataType,
    pub derivation_path: KeyPath,
    /// 21-byte address (`41` + key hash), when known.
    pub address: Option<Vec<u8>>,
    pub origin: Option<String>,
}

impl TronSignRequest {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .put(1, uuid_to_cbor(&self.request_id))
            .put(2, cbor::bytes(&self.sign_data))
            .put(3, cbor::uint(self.data_type as u64))
            .put(4, cbor::tagged(TAG_KEYPATH, self.derivation_path.to_cbor()))
            .opt(5, self.address.as_ref().map(|a| cbor::bytes(a)))
            .opt(6, self.origin.as_ref().map(|s| cbor::text(s)))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        Ok(Self {
            request_id: uuid_from_cbor(cbor::need(v, 1, "tron-sign-request")?)?,
            sign_data: cbor::as_bytes(cbor::need(v, 2, "tron-sign-request")?).ok_or_else(|| Error::Env("sign-data not bytes".into()))?.to_vec(),
            data_type: match cbor::get(v, 3).and_then(cbor::as_u64).unwrap_or(1) {
                2 => TronDataType::PersonalMessage,
                _ => TronDataType::Transaction,
            },
            derivation_path: KeyPath::from_cbor(cbor::need(v, 4, "tron-sign-request")?)?,
            address: cbor::get(v, 5).and_then(cbor::as_bytes).map(<[u8]>::to_vec),
            origin: cbor::get(v, 6).and_then(cbor::as_text).map(str::to_owned),
        })
    }
}

/// `tron-signature`: the same `{1: request-id, 2: signature}` map as
/// `eth-signature` (65 bytes, r ‖ s ‖ v).
pub type TronSignature = EthSignature;

// ── btc-sign-request / btc-signature (Keystone, messages only) ──────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcSignRequest {
    pub request_id: [u8; 16],
    /// The message to sign (data type 1, the only one there is).
    pub sign_data: Vec<u8>,
    pub derivation_paths: Vec<KeyPath>,
    pub addresses: Option<Vec<String>>,
    pub origin: Option<String>,
}

impl BtcSignRequest {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .put(1, uuid_to_cbor(&self.request_id))
            .put(2, cbor::bytes(&self.sign_data))
            .put(3, cbor::uint(1))
            .put(4, Value::Array(self.derivation_paths.iter().map(|p| cbor::tagged(TAG_KEYPATH, p.to_cbor())).collect()))
            .opt(5, self.addresses.as_ref().map(|a| Value::Array(a.iter().map(|s| cbor::text(s)).collect())))
            .opt(6, self.origin.as_ref().map(|s| cbor::text(s)))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        let paths = cbor::as_array(cbor::need(v, 4, "btc-sign-request")?).ok_or_else(|| Error::Env("derivation-paths not an array".into()))?;
        Ok(Self {
            request_id: uuid_from_cbor(cbor::need(v, 1, "btc-sign-request")?)?,
            sign_data: cbor::as_bytes(cbor::need(v, 2, "btc-sign-request")?).ok_or_else(|| Error::Env("sign-data not bytes".into()))?.to_vec(),
            derivation_paths: paths.iter().map(KeyPath::from_cbor).collect::<Result<_>>()?,
            addresses: cbor::get(v, 5).and_then(cbor::as_array).map(|a| a.iter().filter_map(cbor::as_text).map(str::to_owned).collect()),
            origin: cbor::get(v, 6).and_then(cbor::as_text).map(str::to_owned),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcSignature {
    pub request_id: Option<[u8; 16]>,
    /// The 65-byte compact (BIP-137) signature.
    pub signature: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
}

impl BtcSignature {
    pub fn to_cbor(&self) -> Value {
        MapBuilder::new()
            .opt(1, self.request_id.map(|id| uuid_to_cbor(&id)))
            .put(2, cbor::bytes(&self.signature))
            .opt(3, self.public_key.as_ref().map(|k| cbor::bytes(k)))
            .build()
    }
    pub fn from_cbor(v: &Value) -> Result<Self> {
        let (v, _) = cbor::untag(v);
        Ok(Self {
            request_id: cbor::get(v, 1).map(uuid_from_cbor).transpose()?,
            signature: cbor::as_bytes(cbor::need(v, 2, "btc-signature")?).ok_or_else(|| Error::Env("signature not bytes".into()))?.to_vec(),
            public_key: cbor::get(v, 3).and_then(cbor::as_bytes).map(<[u8]>::to_vec),
        })
    }
}

// ── Generic description (for the decoder's `decoded` view) ──────────────────

fn fp_hex(fp: u32) -> String {
    format!("{fp:08x}")
}

fn hdkey_json(k: &HdKey) -> serde_json::Value {
    serde_json::json!({
        "key": format!("0x{}", super::hex(&k.key_data)),
        "chainCode": k.chain_code.map(|c| format!("0x{}", super::hex(&c))),
        "curve": if k.is_ed25519() { "ed25519" } else { "secp256k1" },
        "coinType": k.coin_type(),
        "origin": k.origin.as_ref().map(|o| o.to_string()),
        "masterFingerprint": k.master_fingerprint().map(fp_hex),
        "children": k.children.as_ref().map(|c| c.to_string()),
        "parentFingerprint": k.parent_fingerprint.map(fp_hex),
        "name": k.name,
        "note": k.note,
        "isMaster": k.is_master,
        "isPrivate": k.is_private,
    })
}

/// A JSON rendering of a UR body by type — structured for the types we know,
/// a generic CBOR→JSON dump otherwise. Never fails: unknown/invalid payloads
/// fall back to the dump (or hex).
pub fn describe(ur_type: &str, cbor_bytes: &[u8]) -> serde_json::Value {
    let Ok(v) = cbor::from_bytes(cbor_bytes) else {
        return serde_json::json!({ "hex": super::hex(cbor_bytes) });
    };
    let structured = match ur_type {
        UR_HDKEY => HdKey::from_cbor(&v).ok().map(|k| hdkey_json(&k)),
        UR_ACCOUNT => CryptoAccount::from_cbor(&v).ok().map(|a| {
            serde_json::json!({
                "masterFingerprint": fp_hex(a.master_fingerprint),
                "outputs": a.outputs.iter().map(|o| serde_json::json!({ "script": o.script, "key": hdkey_json(&o.key) })).collect::<Vec<_>>(),
            })
        }),
        UR_MULTI_ACCOUNTS => MultiAccounts::from_cbor(&v).ok().map(|m| {
            serde_json::json!({
                "masterFingerprint": fp_hex(m.master_fingerprint),
                "device": m.device, "deviceId": m.device_id, "version": m.version,
                "keys": m.keys.iter().map(hdkey_json).collect::<Vec<_>>(),
            })
        }),
        UR_PSBT | UR_PSBT_NEW => psbt_from_cbor(cbor_bytes).ok().map(|p| {
            use base64::Engine;
            let parsed = outscript::psbt::Psbt::parse(&p).ok();
            serde_json::json!({
                "psbt": base64::engine::general_purpose::STANDARD.encode(&p),
                "inputs": parsed.as_ref().map(|x| x.unsigned_tx().input_count()),
                "outputs": parsed.as_ref().map(|x| x.unsigned_tx().output_count()),
                "finalized": parsed.as_ref().map(|x| x.is_finalized()),
            })
        }),
        UR_ETH_SIGN_REQUEST => EthSignRequest::from_cbor(&v).ok().map(|r| {
            serde_json::json!({
                "requestId": uuid_hyphenated(&r.request_id),
                "signData": format!("0x{}", super::hex(&r.sign_data)),
                "dataType": r.data_type as u8, "chainId": r.chain_id,
                "derivationPath": r.derivation_path.to_string(),
                "masterFingerprint": r.derivation_path.source_fingerprint.map(fp_hex),
                "address": r.address.map(|a| format!("0x{}", super::hex(&a))), "origin": r.origin,
            })
        }),
        UR_ETH_SIGNATURE => EthSignature::from_cbor(&v).ok().map(|s| {
            serde_json::json!({ "requestId": s.request_id.map(|id| uuid_hyphenated(&id)), "signature": format!("0x{}", super::hex(&s.signature)), "origin": s.origin })
        }),
        UR_SOL_SIGN_REQUEST => SolSignRequest::from_cbor(&v).ok().map(|r| {
            serde_json::json!({
                "requestId": uuid_hyphenated(&r.request_id),
                "signData": format!("0x{}", super::hex(&r.sign_data)),
                "derivationPath": r.derivation_path.to_string(),
                "masterFingerprint": r.derivation_path.source_fingerprint.map(fp_hex),
                "address": r.address.map(|a| bs58::encode(a).into_string()), "origin": r.origin,
                "type": r.sign_type as u8,
            })
        }),
        UR_SOL_SIGNATURE => SolSignature::from_cbor(&v).ok().map(|s| {
            serde_json::json!({ "requestId": s.request_id.map(|id| uuid_hyphenated(&id)), "signature": format!("0x{}", super::hex(&s.signature)) })
        }),
        UR_TRON_SIGN_REQUEST => TronSignRequest::from_cbor(&v).ok().map(|r| {
            serde_json::json!({
                "requestId": uuid_hyphenated(&r.request_id),
                "signData": format!("0x{}", super::hex(&r.sign_data)),
                "dataType": r.data_type as u8,
                "derivationPath": r.derivation_path.to_string(),
                "masterFingerprint": r.derivation_path.source_fingerprint.map(fp_hex),
                "origin": r.origin,
            })
        }),
        UR_TRON_SIGNATURE => TronSignature::from_cbor(&v).ok().map(|s| {
            serde_json::json!({ "requestId": s.request_id.map(|id| uuid_hyphenated(&id)), "signature": format!("0x{}", super::hex(&s.signature)) })
        }),
        UR_BTC_SIGN_REQUEST => BtcSignRequest::from_cbor(&v).ok().map(|r| {
            serde_json::json!({
                "requestId": uuid_hyphenated(&r.request_id),
                "signData": format!("0x{}", super::hex(&r.sign_data)),
                "dataType": 1,
                "derivationPath": r.derivation_paths.first().map(|p| p.to_string()),
                "masterFingerprint": r.derivation_paths.first().and_then(|p| p.source_fingerprint).map(fp_hex),
                "addresses": r.addresses, "origin": r.origin,
            })
        }),
        UR_BTC_SIGNATURE => BtcSignature::from_cbor(&v).ok().map(|s| {
            use base64::Engine;
            serde_json::json!({
                "requestId": s.request_id.map(|id| uuid_hyphenated(&id)),
                "signature": base64::engine::general_purpose::STANDARD.encode(&s.signature),
                "publicKey": s.public_key.map(|k| format!("0x{}", super::hex(&k))),
            })
        }),
        UR_BYTES => outscript::bcur::cbor_to_bytes(cbor_bytes).ok().map(|b| {
            use base64::Engine;
            serde_json::json!({ "bytes": base64::engine::general_purpose::STANDARD.encode(b), "text": std::str::from_utf8(b).ok() })
        }),
        _ => None,
    };
    structured.unwrap_or_else(|| cbor::to_json(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keystone's own test vector for `tron-sign-request` (ur-registry).
    #[test]
    fn tron_sign_request_matches_keystone_vector() {
        let sign_data = crate::airgap::unhex("0a0207902208e1b9de559665c6714080c49789bb2c5aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541c79f045e4d48ad8dae00e6a6714dae1e000adfcd1215410d292c98a5eca06c2085fff993996423cf66c93b2244a9059cbb0000000000000000000000009bbce520d984c3b95ad10cb4e32a9294e6338da300000000000000000000000000000000000000000000000000000000000f424070c0b6e087bb2c90018094ebdc03").unwrap();
        let mut path = KeyPath::parse("m/44'/195'/0'/0/0").unwrap();
        path.source_fingerprint = Some(0x1212_1212);
        let r = TronSignRequest {
            request_id: crate::airgap::unhex("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d").unwrap().try_into().unwrap(),
            sign_data: sign_data.clone(),
            data_type: TronDataType::Transaction,
            derivation_path: path,
            address: None,
            origin: Some("tron wallet".into()),
        };
        let want = format!("a501d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d0258d4{}030104d90130a2018a182cf518c3f500f500f400f4021a12121212066b74726f6e2077616c6c6574", crate::airgap::hex(&sign_data));
        let bytes = cbor::to_bytes(&r.to_cbor()).unwrap();
        assert_eq!(crate::airgap::hex(&bytes), want);
        assert_eq!(TronSignRequest::from_cbor(&cbor::from_bytes(&bytes).unwrap()).unwrap(), r);
    }

    #[test]
    fn btc_sign_request_roundtrip() {
        let mut path = KeyPath::parse("m/84'/0'/0'/0/0").unwrap();
        path.source_fingerprint = Some(7);
        let r = BtcSignRequest { request_id: [9; 16], sign_data: b"hello".to_vec(), derivation_paths: vec![path], addresses: Some(vec!["bc1qexample".into()]), origin: Some("libwallet".into()) };
        let bytes = cbor::to_bytes(&r.to_cbor()).unwrap();
        assert_eq!(BtcSignRequest::from_cbor(&cbor::from_bytes(&bytes).unwrap()).unwrap(), r);
        let s = BtcSignature { request_id: Some([9; 16]), signature: vec![1; 65], public_key: Some(vec![2; 33]) };
        assert_eq!(BtcSignature::from_cbor(&cbor::from_bytes(&cbor::to_bytes(&s.to_cbor()).unwrap()).unwrap()).unwrap(), s);
    }

    #[test]
    fn keypath_parse_format_cbor_roundtrip() {
        let p = KeyPath::parse("m/44'/60'/0'/0/5").unwrap();
        assert_eq!(p.components, vec![44 | HARDENED, 60 | HARDENED, HARDENED, 0, 5]);
        assert_eq!(p.to_string(), "m/44'/60'/0'/0/5");
        assert_eq!(KeyPath::parse("84h/0h/0h").unwrap().to_string(), "m/84'/0'/0'");
        let mut p2 = p.clone();
        p2.source_fingerprint = Some(0x1234_5678);
        let back = KeyPath::from_cbor(&cbor::tagged(TAG_KEYPATH, p2.to_cbor())).unwrap();
        assert_eq!(back, p2);
        // BCR-2020-007 keypath example: m/44'/1'/1'/0/1 with fingerprint.
        let hex = super::super::hex(&cbor::to_bytes(&KeyPath::parse("m/44'/1'/1'/0/1").unwrap().to_cbor()).unwrap());
        assert_eq!(hex, "a1018a182cf501f501f500f401f4");
    }

    #[test]
    fn scanned_integers_are_range_checked_not_truncated() {
        use ciborium::value::Integer;
        let neg = || Value::Integer(Integer::from(-1));
        let big = || cbor::uint(0x1_0000_0001); // would truncate to 1 as u32
        let path = |comps: Vec<Value>| MapBuilder::new().put(1, Value::Array(comps));

        // AG-03: a negative keypath index is an error, not a panic.
        assert!(KeyPath::from_cbor(&path(vec![neg(), Value::Bool(true)]).build()).is_err());
        assert!(KeyPath::from_cbor(&path(vec![cbor::uint(u64::MAX), Value::Bool(false)]).build()).is_err());
        assert!(KeyPath::from_cbor(&path(vec![cbor::uint(HARDENED as u64), Value::Bool(false)]).build()).is_err());
        // The same through a whole scanned hdkey / multi-accounts body.
        let hd = |origin: Value| MapBuilder::new().put(3, cbor::bytes(&[2; 33])).put(6, cbor::tagged(TAG_KEYPATH, origin)).build();
        assert!(HdKey::from_cbor(&hd(path(vec![neg(), Value::Bool(true)]).build())).is_err());
        let bytes = cbor::to_bytes(&MapBuilder::new().put(1, cbor::uint(1)).put(2, Value::Array(vec![cbor::tagged(TAG_HDKEY, hd(path(vec![neg(), Value::Bool(true)]).build()))])).build()).unwrap();
        let _ = describe(UR_MULTI_ACCOUNTS, &bytes); // falls back to the dump
        assert!(MultiAccounts::from_cbor(&cbor::from_bytes(&bytes).unwrap()).is_err());

        // AG-11: fingerprints, depth, coin type, network must fit their type.
        let ok = path(vec![cbor::uint(44), Value::Bool(true)]);
        assert!(KeyPath::from_cbor(&path(vec![]).put(2, big()).build()).is_err());
        assert!(KeyPath::from_cbor(&path(vec![]).put(2, neg()).build()).is_err());
        assert!(KeyPath::from_cbor(&path(vec![]).put(3, cbor::uint(256)).build()).is_err());
        let p = KeyPath::from_cbor(&ok.put(2, cbor::uint(u32::MAX as u64)).put(3, cbor::uint(255)).build()).unwrap();
        assert_eq!((p.source_fingerprint, p.depth), (Some(u32::MAX), Some(255)));
        assert!(CoinInfo::from_cbor(&MapBuilder::new().put(1, big()).build()).is_err());
        assert!(CoinInfo::from_cbor(&MapBuilder::new().put(2, big()).build()).is_err());
        assert_eq!(CoinInfo::from_cbor(&MapBuilder::new().build()).unwrap(), CoinInfo { coin_type: 0, network: 0 });
        assert!(HdKey::from_cbor(&MapBuilder::new().put(3, cbor::bytes(&[2; 33])).put(8, big()).build()).is_err());
        assert!(CryptoAccount::from_cbor(&MapBuilder::new().put(1, big()).put(2, Value::Array(vec![])).build()).is_err());
        assert!(MultiAccounts::from_cbor(&MapBuilder::new().put(1, big()).put(2, Value::Array(vec![])).build()).is_err());
        assert_eq!(MultiAccounts::from_cbor(&MapBuilder::new().put(2, Value::Array(vec![])).build()).unwrap().master_fingerprint, 0);
    }

    #[test]
    fn hdkey_master_matches_bip32_vector1_cbor() {
        // BCR-2020-007 §Example 1: the BIP-32 test-vector-1 master key as a
        // crypto-hdkey: {1: true, 3: h'00e8f3…6b35', 4: h'873d…d508'}.
        let key_hex = "00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        let cc_hex = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
        let k = HdKey {
            is_master: true,
            is_private: true,
            key_data: super::super::unhex(key_hex).unwrap(),
            chain_code: Some(super::super::unhex(cc_hex).unwrap().try_into().unwrap()),
            ..Default::default()
        };
        let bytes = cbor::to_bytes(&k.to_cbor()).unwrap();
        assert_eq!(super::super::hex(&bytes), format!("a401f502f5035821{key_hex}045820{cc_hex}"));
        let back = HdKey::from_cbor(&cbor::from_bytes(&bytes).unwrap()).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn hdkey_with_origin_and_coin_type() {
        let k = HdKey {
            key_data: vec![2; 33],
            chain_code: Some([7; 32]),
            use_info: Some(CoinInfo { coin_type: 60, network: 0 }),
            origin: Some(KeyPath { components: vec![44 | HARDENED, 60 | HARDENED, HARDENED], source_fingerprint: Some(0xdeadbeef), depth: Some(3) }),
            children: Some(KeyPath::parse("0/0").unwrap()),
            parent_fingerprint: Some(1),
            name: Some("Keystone".into()),
            note: Some("account.standard".into()),
            ..Default::default()
        };
        let bytes = cbor::to_bytes(&cbor::tagged(TAG_HDKEY, k.to_cbor())).unwrap();
        let back = HdKey::from_cbor(&cbor::from_bytes(&bytes).unwrap()).unwrap();
        assert_eq!(back, k);
        assert_eq!(back.coin_type(), Some(60));
        assert_eq!(back.master_fingerprint(), Some(0xdeadbeef));
        assert!(!back.is_ed25519());
        assert!(back.secp_key().is_some());
    }

    #[test]
    fn crypto_account_wraps_script_tags() {
        let key = HdKey { key_data: vec![3; 33], chain_code: Some([1; 32]), origin: Some(KeyPath::parse("m/84'/0'/0'").unwrap()), ..Default::default() };
        let acct = CryptoAccount {
            master_fingerprint: 0x0f05_6943,
            outputs: vec![
                OutputDescriptor { script: "p2wpkh".into(), key: key.clone() },
                OutputDescriptor { script: "p2sh:p2wpkh".into(), key: key.clone() },
                OutputDescriptor { script: "p2pkh".into(), key: key.clone() },
                OutputDescriptor { script: "p2tr".into(), key },
            ],
        };
        let bytes = cbor::to_bytes(&acct.to_cbor()).unwrap();
        // tag 308 → tag 404 → tag 303 for the first descriptor.
        assert!(super::super::hex(&bytes).contains("d90134d90194d9012f"));
        // sh(wpkh()) nests 400 → 404.
        assert!(super::super::hex(&bytes).contains("d90134d90190d90194d9012f"));
        let back = CryptoAccount::from_cbor(&cbor::from_bytes(&bytes).unwrap()).unwrap();
        assert_eq!(back, acct);
    }

    #[test]
    fn multi_accounts_roundtrip_with_ed25519_key() {
        let sol = HdKey {
            key_data: vec![9; 32],
            origin: Some(KeyPath { components: vec![44 | HARDENED, 501 | HARDENED, HARDENED, HARDENED], source_fingerprint: Some(0x1111_2222), depth: None }),
            name: Some("Keystone".into()),
            note: Some("account.standard".into()),
            ..Default::default()
        };
        let m = MultiAccounts { master_fingerprint: 0x1111_2222, keys: vec![sol], device: Some("Keystone 3 Pro".into()), device_id: Some("abc".into()), version: Some("1.0".into()) };
        let bytes = cbor::to_bytes(&m.to_cbor()).unwrap();
        let back = MultiAccounts::from_cbor(&cbor::from_bytes(&bytes).unwrap()).unwrap();
        assert_eq!(back, m);
        assert!(back.keys[0].is_ed25519());
        assert_eq!(back.keys[0].coin_type(), Some(501));
        let j = describe(UR_MULTI_ACCOUNTS, &bytes);
        assert_eq!(j["device"], "Keystone 3 Pro");
        assert_eq!(j["keys"][0]["curve"], "ed25519");
    }

    #[test]
    fn eth_and_sol_requests_roundtrip() {
        let id = new_request_id();
        let req = EthSignRequest {
            request_id: id,
            sign_data: vec![0xf8, 0x49, 1, 2, 3],
            data_type: EthDataType::Transaction,
            chain_id: Some(1),
            derivation_path: KeyPath { components: KeyPath::parse("m/44'/60'/0'/0/0").unwrap().components, source_fingerprint: Some(0x1234_5678), depth: None },
            address: Some([0xaa; 20]),
            origin: Some("libwallet".into()),
        };
        let bytes = cbor::to_bytes(&req.to_cbor()).unwrap();
        // request-id is uuid tag 37 over 16 bytes: a7 01 d8 25 50 …
        assert!(super::super::hex(&bytes).starts_with("a701d82550"));
        assert_eq!(EthSignRequest::from_cbor(&cbor::from_bytes(&bytes).unwrap()).unwrap(), req);

        let sig = EthSignature { request_id: Some(id), signature: vec![1; 65], origin: Some("Keystone".into()) };
        let b = cbor::to_bytes(&sig.to_cbor()).unwrap();
        assert_eq!(EthSignature::from_cbor(&cbor::from_bytes(&b).unwrap()).unwrap(), sig);

        let sreq = SolSignRequest {
            request_id: id,
            sign_data: vec![1, 0, 1, 3],
            derivation_path: KeyPath { components: KeyPath::parse("m/44'/501'/0'/0'").unwrap().components, source_fingerprint: Some(7), depth: None },
            address: Some([5; 32]),
            origin: None,
            sign_type: SolSignType::Transaction,
        };
        let b = cbor::to_bytes(&sreq.to_cbor()).unwrap();
        assert_eq!(SolSignRequest::from_cbor(&cbor::from_bytes(&b).unwrap()).unwrap(), sreq);
        let ssig = SolSignature { request_id: None, signature: vec![2; 64] };
        let b = cbor::to_bytes(&ssig.to_cbor()).unwrap();
        assert_eq!(SolSignature::from_cbor(&cbor::from_bytes(&b).unwrap()).unwrap(), ssig);
        let j = describe(UR_ETH_SIGN_REQUEST, &bytes);
        assert_eq!(j["derivationPath"], "m/44'/60'/0'/0/0");
        assert_eq!(j["masterFingerprint"], "12345678");
    }
}
