//! WalletConnect v2 envelope cryptography + pairing-URI parsing (port of the
//! deterministic parts of `wltwc`). The relay transport (WebSocket to the `irn`
//! relay) and session state machine need a live relay and land separately; this
//! module is the self-contained, verifiable crypto core.
//!
//! Envelope formats (then base64-encoded):
//!   Type 0 — `[0x00][nonce:12][ciphertext][tag:16]`, keyed by the shared symKey.
//!   Type 1 — `[0x01][senderPub:32][nonce:12][ciphertext][tag:16]`, keyed by a
//!            per-message symKey derived via X25519 + HKDF-SHA256.

use base64::Engine as _;
use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::ec::x25519::x25519;

use crate::{Error, Result};

const SYM_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const X25519_BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// A parsed WalletConnect v2 pairing URI
/// (`wc:<topic>@2?relay-protocol=irn&symKey=<hex>`).
#[derive(Debug, Clone)]
pub struct PairingUri {
    pub topic: String,
    pub version: String,
    pub protocol: String,
    pub sym_key: [u8; 32],
}

/// The pairing topic for a symKey: `hex(sha256(symKey))` (Go `topicFromSymKey`).
pub fn derive_topic(sym_key: &[u8; 32]) -> String {
    purecrypto::hash::sha256(sym_key).iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse and validate a WalletConnect v2 pairing URI (Go `parsePairingURI`).
/// Only v2 is accepted; the URI topic must equal the symKey-derived topic.
pub fn parse_pairing_uri(raw: &str) -> Result<PairingUri> {
    let rest = raw.strip_prefix("wc:").ok_or_else(|| Error::Env("not a wc: URI".into()))?;
    let (opaque, query) = rest.split_once('?').unwrap_or((rest, ""));
    let opaque = opaque.trim_start_matches('/'); // tolerate wc://
    let (topic, version) =
        opaque.split_once('@').ok_or_else(|| Error::Env("URI missing @version".into()))?;
    if version != "2" {
        return Err(Error::Env(format!("unsupported WalletConnect version {version}")));
    }

    let mut sym_key_hex = "";
    let mut protocol = "irn";
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = kv.split_once('=') {
            match k {
                "symKey" => sym_key_hex = v,
                "relay-protocol" => protocol = v,
                _ => {}
            }
        }
    }
    if sym_key_hex.is_empty() {
        return Err(Error::Env("symKey query param missing".into()));
    }
    let sym_key = decode_hex32(sym_key_hex).ok_or_else(|| Error::Env("symKey not 32-byte hex".into()))?;

    let derived = derive_topic(&sym_key);
    if topic != derived {
        return Err(Error::Env(format!("topic mismatch: URI says {topic}, derives to {derived}")));
    }
    Ok(PairingUri {
        topic: topic.to_owned(),
        version: version.to_owned(),
        protocol: protocol.to_owned(),
        sym_key,
    })
}

/// Seal a Type-0 (symmetric) envelope with an explicit nonce (deterministic).
pub fn seal_type0_with_nonce(sym_key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> String {
    let aead = ChaCha20Poly1305::new(sym_key);
    let mut buf = plaintext.to_vec();
    let tag = aead.encrypt(nonce, &[], &mut buf);
    let mut env = Vec::with_capacity(1 + NONCE_SIZE + buf.len() + TAG_SIZE);
    env.push(0x00);
    env.extend_from_slice(nonce);
    env.extend_from_slice(&buf);
    env.extend_from_slice(&tag);
    base64::engine::general_purpose::STANDARD.encode(env)
}

/// The X25519 public key for a private scalar.
pub fn x25519_public(priv_key: &[u8; 32]) -> [u8; 32] {
    x25519(priv_key, &X25519_BASEPOINT)
}

/// Derive the per-message symKey for a Type-1 envelope: `HKDF-SHA256(X25519(priv,
/// peerPub))` with empty salt/info (Go `deriveSymKey`).
pub fn derive_sym_key(priv_key: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let shared = x25519(priv_key, peer_pub);
    let mut out = [0u8; 32];
    purecrypto::kdf::hkdf::<purecrypto::hash::Sha256>(&[], &shared, &[], &mut out);
    out
}

/// Seal a Type-1 (asymmetric) envelope from `sender_priv` to `peer_pub` with an
/// explicit nonce. Returns `(base64 envelope, sender public key)`.
pub fn seal_type1_with_nonce(
    peer_pub: &[u8; 32],
    sender_priv: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> (String, [u8; 32]) {
    let sender_pub = x25519_public(sender_priv);
    let sym_key = derive_sym_key(sender_priv, peer_pub);
    let aead = ChaCha20Poly1305::new(&sym_key);
    let mut buf = plaintext.to_vec();
    let tag = aead.encrypt(nonce, &[], &mut buf);
    let mut env = Vec::with_capacity(1 + 32 + NONCE_SIZE + buf.len() + TAG_SIZE);
    env.push(0x01);
    env.extend_from_slice(&sender_pub);
    env.extend_from_slice(nonce);
    env.extend_from_slice(&buf);
    env.extend_from_slice(&tag);
    (base64::engine::general_purpose::STANDARD.encode(env), sender_pub)
}

/// Decrypt a base64 envelope (Go `openEnvelope`). Type-0 needs `sym_key`;
/// Type-1 needs `recipient_priv` (the wallet's proposal keypair) and returns the
/// sender's public key so the caller can pin it.
pub fn open_envelope(
    sym_key: Option<&[u8; 32]>,
    recipient_priv: Option<&[u8; 32]>,
    raw: &str,
) -> Result<(Vec<u8>, Option<[u8; 32]>)> {
    let buf = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| Error::Env(format!("envelope base64: {e}")))?;
    if buf.is_empty() {
        return Err(Error::Env("envelope empty".into()));
    }
    match buf[0] {
        0x00 => {
            let key = sym_key.ok_or_else(|| Error::Env("type-0 envelope but no symKey".into()))?;
            if buf.len() < 1 + NONCE_SIZE + TAG_SIZE {
                return Err(Error::Env("type-0 envelope truncated".into()));
            }
            let nonce: [u8; 12] = buf[1..1 + NONCE_SIZE].try_into().unwrap();
            let (ct, tag) = split_ct_tag(&buf[1 + NONCE_SIZE..])?;
            let pt = decrypt(key, &nonce, ct, tag)?;
            Ok((pt, None))
        }
        0x01 => {
            let priv_key =
                recipient_priv.ok_or_else(|| Error::Env("type-1 envelope but no private key".into()))?;
            if buf.len() < 1 + SYM_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
                return Err(Error::Env("type-1 envelope truncated".into()));
            }
            let sender_pub: [u8; 32] = buf[1..1 + 32].try_into().unwrap();
            let nonce: [u8; 12] = buf[1 + 32..1 + 32 + NONCE_SIZE].try_into().unwrap();
            let key = derive_sym_key(priv_key, &sender_pub);
            let (ct, tag) = split_ct_tag(&buf[1 + 32 + NONCE_SIZE..])?;
            let pt = decrypt(&key, &nonce, ct, tag)?;
            Ok((pt, Some(sender_pub)))
        }
        other => Err(Error::Env(format!("unknown envelope type {other}"))),
    }
}

/// Build the session-settle `namespaces` object for an approval (Go
/// `buildNamespaces`). For each namespace in the proposal's required + optional
/// namespaces (first occurrence wins), emit `{accounts, methods, events,
/// chains}`: accounts filtered to that namespace's CAIP prefix, and methods /
/// events intersected with the wallet's allow-lists (empty allow-list = echo
/// the requested set). `accounts` are CAIP-10 (e.g. "eip155:1:0x…").
pub fn build_namespaces(
    proposal: &serde_json::Value,
    accounts: &[String],
    methods: &[String],
    events: &[String],
) -> serde_json::Value {
    use serde_json::{Map, Value};
    let mut result = Map::new();
    for key in ["requiredNamespaces", "optionalNamespaces"] {
        let ns = match proposal.get(key).and_then(Value::as_object) {
            Some(m) => m,
            None => continue,
        };
        for (name, desc) in ns {
            if result.contains_key(name) {
                continue;
            }
            let req_methods = desc.get("methods").and_then(Value::as_array).cloned().unwrap_or_default();
            let req_events = desc.get("events").and_then(Value::as_array).cloned().unwrap_or_default();
            let req_chains = desc.get("chains").and_then(Value::as_array).cloned().unwrap_or_default();

            let prefix = format!("{name}:");
            let ns_accounts: Vec<Value> = accounts
                .iter()
                .filter(|a| a.starts_with(&prefix))
                .map(|a| Value::String(a.clone()))
                .collect();

            let mut entry = Map::new();
            entry.insert("accounts".into(), Value::Array(ns_accounts));
            entry.insert("methods".into(), Value::Array(merge_string_list(&req_methods, methods)));
            entry.insert("events".into(), Value::Array(merge_string_list(&req_events, events)));
            entry.insert("chains".into(), Value::Array(req_chains));
            result.insert(name.clone(), Value::Object(entry));
        }
    }
    Value::Object(result)
}

/// Intersect `requested` (JSON strings) with `allowed`, preserving requested
/// order (Go `mergeStringList`). An empty allow-list echoes the requested set.
fn merge_string_list(requested: &[serde_json::Value], allowed: &[String]) -> Vec<serde_json::Value> {
    let strs = requested.iter().filter_map(|v| v.as_str());
    if allowed.is_empty() {
        return strs.map(|s| serde_json::Value::String(s.to_owned())).collect();
    }
    strs.filter(|s| allowed.iter().any(|a| a == s))
        .map(|s| serde_json::Value::String(s.to_owned()))
        .collect()
}

fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new(key);
    let mut buf = ct.to_vec();
    aead.decrypt(nonce, &[], &mut buf, tag)
        .map_err(|_| Error::Env("envelope authentication failed".into()))?;
    Ok(buf)
}

fn split_ct_tag(rest: &[u8]) -> Result<(&[u8], &[u8; 16])> {
    if rest.len() < TAG_SIZE {
        return Err(Error::Env("envelope missing tag".into()));
    }
    let (ct, tag) = rest.split_at(rest.len() - TAG_SIZE);
    Ok((ct, tag.try_into().unwrap()))
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
