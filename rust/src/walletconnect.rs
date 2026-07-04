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

/// A fresh random X25519 keypair `(private, public)` (the wallet's per-session
/// proposal keypair).
pub fn new_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    use purecrypto::rng::RngCore;
    let mut priv_key = [0u8; 32];
    purecrypto::rng::OsRng.fill_bytes(&mut priv_key);
    let pub_key = x25519_public(&priv_key);
    (priv_key, pub_key)
}

/// Seal a Type-0 envelope with a fresh random nonce (production path).
pub fn seal_type0(sym_key: &[u8; 32], plaintext: &[u8]) -> String {
    use purecrypto::rng::RngCore;
    let mut nonce = [0u8; 12];
    purecrypto::rng::OsRng.fill_bytes(&mut nonce);
    seal_type0_with_nonce(sym_key, &nonce, plaintext)
}

/// Lowercase-hex encode (WC uses hex for public keys in JSON-RPC bodies).
pub fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode a hex or base64url 32-byte public key (Go `hexOrB64Decode`).
pub fn decode_pubkey32(s: &str) -> Option<[u8; 32]> {
    if s.len() == 64 {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        return Some(out);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()?.try_into().ok()
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

// ── Relay JSON-RPC protocol (irn) — transport-independent message layer ──────
// The relay is a JSON-RPC 2.0 endpoint over WebSocket. These builders/parsers
// are deterministic and testable; only the socket I/O (the write/read loops)
// needs a live `irn` relay.

/// Default publish TTL in seconds (Go `irnDefaultTTL`).
pub const IRN_DEFAULT_TTL: i64 = 300;

/// Relay message tags (Go `tagSession*`).
pub const TAG_SESSION_PROPOSE: i64 = 1100;
pub const TAG_SESSION_SETTLE: i64 = 1102;
pub const TAG_SESSION_REQUEST: i64 = 1108;
pub const TAG_SESSION_RESPONSE: i64 = 1109;
pub const TAG_SESSION_EVENT: i64 = 1110;
pub const TAG_SESSION_DELETE: i64 = 1112;

/// A JSON-RPC 2.0 request for the relay.
pub fn build_relay_request(id: i64, method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "id": id, "jsonrpc": "2.0", "method": method, "params": params })
}

/// `irn_subscribe(topic)` request.
pub fn build_subscribe(id: i64, topic: &str) -> serde_json::Value {
    build_relay_request(id, "irn_subscribe", serde_json::json!({ "topic": topic }))
}

/// `irn_publish(topic, message, tag, ttl)` request. `prompt` is set for the
/// session-propose / session-request tags (Go `Publish`). `ttl <= 0` defaults.
pub fn build_publish(id: i64, topic: &str, message: &str, tag: i64, ttl: i64) -> serde_json::Value {
    let ttl = if ttl <= 0 { IRN_DEFAULT_TTL } else { ttl };
    let prompt = tag == TAG_SESSION_PROPOSE || tag == TAG_SESSION_REQUEST;
    build_relay_request(
        id,
        "irn_publish",
        serde_json::json!({ "topic": topic, "message": message, "ttl": ttl, "tag": tag, "prompt": prompt }),
    )
}

/// The ack a subscriber sends for an inbound `irn_subscription` so the relay
/// doesn't redeliver: `{id, jsonrpc:"2.0", result:true}`.
pub fn build_ack(id: i64) -> serde_json::Value {
    serde_json::json!({ "id": id, "jsonrpc": "2.0", "result": true })
}

/// A decoded inbound relay frame.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayFrame {
    /// A reply to one of our requests.
    Response { id: i64, error: Option<String> },
    /// An inbound `irn_subscription` event carrying a topic message.
    Subscription { ack_id: i64, topic: String, message: String, tag: i64 },
    /// Anything else (ignored by the client).
    Other,
}

/// Parse an inbound relay JSON frame (Go `readLoop` peek + subscription decode).
pub fn parse_relay_frame(data: &[u8]) -> Result<RelayFrame> {
    let v: serde_json::Value =
        serde_json::from_slice(data).map_err(|e| Error::Env(format!("relay frame json: {e}")))?;
    let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if v.get("method").and_then(|m| m.as_str()) == Some("irn_subscription") {
        let data = v.get("params").and_then(|p| p.get("data"));
        let topic = data.and_then(|d| d.get("topic")).and_then(|t| t.as_str()).unwrap_or("").to_owned();
        let message = data.and_then(|d| d.get("message")).and_then(|m| m.as_str()).unwrap_or("").to_owned();
        let tag = data.and_then(|d| d.get("tag")).and_then(|t| t.as_i64()).unwrap_or(0);
        return Ok(RelayFrame::Subscription { ack_id: id, topic, message, tag });
    }
    if v.get("result").is_some() || v.get("error").is_some() {
        let error = v
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(|s| s.to_owned());
        return Ok(RelayFrame::Response { id, error });
    }
    Ok(RelayFrame::Other)
}

/// The relay transport: a bidirectional text-frame channel (the WebSocket to
/// the `irn` relay). Abstracted so the client loop is testable with a mock and
/// the live socket (tungstenite) is a thin impl.
pub trait RelayTransport {
    /// Send one text frame.
    fn send_text(&mut self, text: &str) -> Result<()>;
    /// Receive the next text frame, or `None` if none is available / closed.
    fn recv_text(&mut self) -> Result<Option<String>>;
}

/// A JSON-RPC relay client over a [`RelayTransport`] (Go `RelayClient`): assigns
/// request ids, subscribes/publishes, and dispatches inbound frames, auto-acking
/// `irn_subscription` events. The transport (socket) I/O is injected.
pub struct RelayClient<T: RelayTransport> {
    transport: T,
    next_id: i64,
}

impl<T: RelayTransport> RelayClient<T> {
    pub fn new(transport: T) -> Self {
        RelayClient { transport, next_id: 0 }
    }

    fn next_id(&mut self) -> i64 {
        self.next_id += 1;
        self.next_id
    }

    /// `irn_subscribe(topic)` — returns the request id sent.
    pub fn subscribe(&mut self, topic: &str) -> Result<i64> {
        let id = self.next_id();
        self.transport.send_text(&build_subscribe(id, topic).to_string())?;
        Ok(id)
    }

    /// `irn_publish(topic, message, tag, ttl)` — returns the request id sent.
    pub fn publish(&mut self, topic: &str, message: &str, tag: i64, ttl: i64) -> Result<i64> {
        let id = self.next_id();
        self.transport.send_text(&build_publish(id, topic, message, tag, ttl).to_string())?;
        Ok(id)
    }

    /// Receive and parse the next relay frame, auto-acking subscription events
    /// (so the relay stops redelivering). Returns `None` when no frame is ready.
    pub fn poll(&mut self) -> Result<Option<RelayFrame>> {
        let raw = match self.transport.recv_text()? {
            Some(r) => r,
            None => return Ok(None),
        };
        let frame = parse_relay_frame(raw.as_bytes())?;
        if let RelayFrame::Subscription { ack_id, .. } = &frame {
            self.transport.send_text(&build_ack(*ack_id).to_string())?;
        }
        Ok(Some(frame))
    }

    /// Consume the client, returning the underlying transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// A [`RelayTransport`] backed by a tungstenite WebSocket over any byte stream
/// (`S`). The caller performs the ws/wss handshake (TLS is out of scope for this
/// layer); this wraps the resulting socket. Set the stream non-blocking for a
/// `recv_text` that returns `None` instead of blocking.
pub struct WsTransport<S: std::io::Read + std::io::Write> {
    socket: tungstenite::WebSocket<S>,
}

impl<S: std::io::Read + std::io::Write> WsTransport<S> {
    pub fn new(socket: tungstenite::WebSocket<S>) -> Self {
        WsTransport { socket }
    }
}

impl<S: std::io::Read + std::io::Write> RelayTransport for WsTransport<S> {
    fn send_text(&mut self, text: &str) -> Result<()> {
        self.socket
            .send(tungstenite::Message::Text(text.to_owned()))
            .map_err(|e| Error::Env(format!("ws send: {e}")))
    }

    fn recv_text(&mut self) -> Result<Option<String>> {
        match self.socket.read() {
            Ok(tungstenite::Message::Text(t)) => Ok(Some(t)),
            Ok(_) => Ok(None), // ping/pong/binary/close — no payload for the client
            Err(tungstenite::Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Error::Env(format!("ws read: {e}"))),
        }
    }
}

/// A decoded inbound WalletConnect JSON-RPC message (Go `handleIncoming`
/// dispatch), after the relay envelope is decrypted.
#[derive(Debug, Clone, PartialEq)]
pub enum WcInbound {
    /// `wc_sessionPropose` — a dApp requests a session.
    Propose { id: i64, params: serde_json::Value },
    /// `wc_sessionSettle` — the peer confirms the session.
    Settle { id: i64 },
    /// `wc_sessionRequest` — a signing/RPC request within a session.
    Request { id: i64, method: String, params: serde_json::Value },
    /// `wc_sessionDelete` — the peer ends the session.
    Delete { id: i64 },
    /// A JSON-RPC reply to one of our requests.
    Response { id: i64, error: Option<String> },
    /// An unrecognized method.
    Other { id: i64, method: String },
}

/// Decrypt a relay envelope and classify the WalletConnect JSON-RPC message it
/// carries (the core of Go `handleIncoming`). `active` toggles the envelope
/// type-confusion guard: a settled (active) session only accepts Type-0
/// (symmetric) envelopes, so no private key is offered and any Type-1 envelope
/// is rejected; before settle the proposal keypair is supplied for Type-1.
pub fn process_inbound(
    sym_key: &[u8; 32],
    self_priv: Option<&[u8; 32]>,
    active: bool,
    envelope: &str,
) -> Result<WcInbound> {
    let priv_for_open = if active { None } else { self_priv };
    let (plain, _sender) = open_envelope(Some(sym_key), priv_for_open, envelope)?;
    let v: serde_json::Value =
        serde_json::from_slice(&plain).map_err(|e| Error::Env(format!("wc rpc json: {e}")))?;
    let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or(0);

    if v.get("result").is_some() || v.get("error").is_some() {
        let error = v
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(|s| s.to_owned());
        return Ok(WcInbound::Response { id, error });
    }
    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = v.get("params").cloned().unwrap_or(serde_json::Value::Null);
    Ok(match method {
        "wc_sessionPropose" => WcInbound::Propose { id, params },
        "wc_sessionSettle" => WcInbound::Settle { id },
        "wc_sessionRequest" => WcInbound::Request {
            id,
            method: params.get("request").and_then(|r| r.get("method")).and_then(|m| m.as_str()).unwrap_or("").to_owned(),
            params: params.get("request").and_then(|r| r.get("params")).cloned().unwrap_or(serde_json::Value::Null),
        },
        "wc_sessionDelete" => WcInbound::Delete { id },
        other => WcInbound::Other { id, method: other.to_owned() },
    })
}

/// A JSON-RPC 2.0 success reply `{id, jsonrpc, result}` (Go response payload).
pub fn build_jsonrpc_result(id: i64, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "id": id, "jsonrpc": "2.0", "result": result })
}

/// A JSON-RPC 2.0 error reply `{id, jsonrpc, error:{code, message}}`.
pub fn build_jsonrpc_error(id: i64, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "jsonrpc": "2.0", "error": { "code": code, "message": message } })
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
