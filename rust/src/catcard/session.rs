//! The encrypted channel (`ncry` v2) and its pairing.
//!
//! Every connection is paired afresh — nothing is stored on either side beyond
//! the life of the session. The host commits to an ephemeral X25519 key, the
//! device answers with its own, the host reveals; both derive two
//! ChaCha20-Poly1305 keys and a six-digit code from the shared secret and the
//! whole transcript. A person compares the code on the host and on the device,
//! and only then does the channel carry commands.
//!
//! The code is the whole defence against a relay in the middle, so it is never
//! accepted here on anyone's behalf: it is broadcast as a `catcard:pair` event
//! `{id, code, board, version}` and the host answers with `CatCard:pairResponse
//! {Id, Accept}` once its user has compared it with the device's screen.
//!
//! A paired session is kept in memory (never persisted, never returned, never
//! logged) and reused by later requests over the same link, so the code is
//! compared once per connection rather than once per request. It ends when the
//! device ends it (unplug, bus reset, logout), on any record that fails to
//! authenticate, or with `CatCard:disconnect`.

use std::collections::HashMap;
use std::sync::Mutex;

use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::hash::Sha256;
use purecrypto::zeroize::Zeroize;
use serde_json::json;

use super::proto::{self, op, status, Identity};
use super::transport::{sleep_ms, Transport, Waiters};
use crate::handlers::ApiError;
use crate::Env;

const INFO: &[u8] = b"catcard-ncry-v2";
const COMMIT_LABEL: &[u8] = b"catcard-pair-v2/commit";
const CODE_INFO: &[u8] = b"catcard-pair-v2/code";
const TAG_LEN: usize = 16;

/// How long the host's user has to compare the code. The device drops its own
/// prompt after two minutes.
const CONFIRM_TIMEOUT_MS: u32 = 120_000;
/// How long to keep asking the device whether its user has answered: a little
/// longer than its own two minutes, so its answer is what ends a slow one.
const DEVICE_WAIT_MS: u32 = 130_000;
/// Pause between two polls of the device.
#[cfg(not(test))]
pub(crate) const POLL_MS: u32 = 500;
#[cfg(test)]
pub(crate) const POLL_MS: u32 = 1;

fn cerr(code: i64, m: impl std::fmt::Display) -> ApiError {
    ApiError::new(code, format!("catcard: {m}"))
}

// ── The cipher ───────────────────────────────────────────────────────────────

/// `SHA-256("catcard-pair-v2/commit" ‖ host_pub)`: the `PairCommit` payload.
pub fn commitment(host_pub: &[u8; 32]) -> [u8; 32] {
    let mut data = COMMIT_LABEL.to_vec();
    data.extend_from_slice(host_pub);
    purecrypto::hash::sha256(&data)
}

/// Six digits, zero padded, grouped the way both screens show them: `123 456`.
pub fn code_text(code: u32) -> String {
    let s = format!("{:06}", code % 1_000_000);
    format!("{} {}", &s[..3], &s[3..])
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

/// The two directional keys and the pairing code, from the shared secret and
/// the transcript `commit ‖ device_pub ‖ host_pub` (the order the bytes
/// crossed the wire). Returns `(host→device, device→host, code)`.
pub(crate) fn schedule(shared: &[u8; 32], commit: &[u8; 32], device_pub: &[u8; 32], host_pub: &[u8; 32]) -> ([u8; 32], [u8; 32], u32) {
    let mut transcript = [0u8; 96];
    transcript[..32].copy_from_slice(commit);
    transcript[32..64].copy_from_slice(device_pub);
    transcript[64..].copy_from_slice(host_pub);
    let mut okm = [0u8; 64];
    purecrypto::kdf::hkdf::<Sha256>(&transcript, shared, INFO, &mut okm);
    let (mut h2d, mut d2h) = ([0u8; 32], [0u8; 32]);
    h2d.copy_from_slice(&okm[..32]);
    d2h.copy_from_slice(&okm[32..]);
    okm.zeroize();
    let mut code = [0u8; 8];
    purecrypto::kdf::hkdf::<Sha256>(&transcript, shared, CODE_INFO, &mut code);
    (h2d, d2h, (u64::from_be_bytes(code) % 1_000_000) as u32)
}

/// One end of an established channel: a key and a record counter per
/// direction. No `Clone` and no `Debug`: a copied counter would seal two
/// records under one nonce, and the keys are nobody's to print.
pub struct Cipher {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl Cipher {
    pub(crate) fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Cipher { send_key, recv_key, send_ctr: 0, recv_ctr: 0 }
    }

    /// `ciphertext ‖ 16-byte tag` under the next send nonce.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let tag = ChaCha20Poly1305::new(&self.send_key).encrypt(&nonce(self.send_ctr), &[], &mut buf);
        self.send_ctr += 1;
        buf.extend_from_slice(&tag);
        buf
    }

    /// Open a record under the next receive nonce. A replayed, reordered or
    /// altered record does not authenticate.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, ()> {
        if record.len() < TAG_LEN {
            return Err(());
        }
        let (ct, tag) = record.split_at(record.len() - TAG_LEN);
        let mut buf = ct.to_vec();
        let tag: [u8; TAG_LEN] = tag.try_into().unwrap();
        ChaCha20Poly1305::new(&self.recv_key).decrypt(&nonce(self.recv_ctr), &[], &mut buf, &tag).map_err(|_| ())?;
        self.recv_ctr += 1;
        Ok(buf)
    }
}

/// The host's half of the handshake: commit first, reveal after the device
/// has answered.
pub struct Initiator {
    key: X25519PrivateKey,
    pub public: [u8; 32],
    pub commit: [u8; 32],
}

impl Initiator {
    /// A fresh ephemeral key from the system's generator.
    pub fn new() -> Self {
        Self::from_key(X25519PrivateKey::generate(&mut purecrypto::rng::OsRng))
    }

    pub(crate) fn from_key(key: X25519PrivateKey) -> Self {
        let public = key.public_key();
        Initiator { commit: commitment(&public), public, key }
    }

    /// The channel and its pairing code, from the device's public key. A
    /// small-order key (an all-zero shared secret) is refused.
    pub fn finish(self, device_pub: &[u8; 32]) -> Result<(Cipher, u32), ApiError> {
        let mut shared = self.key.diffie_hellman(device_pub).map_err(|_| cerr(502, "the device sent an invalid pairing key"))?;
        let (send, recv, code) = schedule(&shared, &self.commit, device_pub, &self.public);
        shared.zeroize();
        Ok((Cipher::new(send, recv), code))
    }
}

impl Default for Initiator {
    fn default() -> Self {
        Self::new()
    }
}

// ── A paired session ─────────────────────────────────────────────────────────

/// A paired channel to one device, and what the device shared over it.
pub struct Session {
    cipher: Cipher,
    /// The link it was paired over ([`Transport::id`]).
    link: String,
    /// Cleared by anything that ends the session: it is then dropped rather
    /// than kept.
    alive: bool,
    pub identity: Identity,
    /// The device's master fingerprint, once it shared addresses.
    pub fingerprint: Option<[u8; 4]>,
    /// The accounts shared in this session (the device only signs with keys
    /// below them): the entries of every address reply, newest last.
    pub shared: Vec<proto::Entry>,
}

impl Session {
    pub(crate) fn new(cipher: Cipher, link: String, identity: Identity) -> Self {
        Session { cipher, link, alive: true, identity, fingerprint: None, shared: Vec::new() }
    }

    /// Run one command inside the channel: `(inner status, inner payload)`.
    pub async fn call<T: Transport>(&mut self, link: &T, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
        if !self.alive {
            return Err(cerr(410, "the session has ended"));
        }
        let mut plain = Vec::with_capacity(2 + payload.len());
        plain.extend_from_slice(&opcode.to_le_bytes());
        plain.extend_from_slice(payload);
        if plain.len() > proto::PLAIN_MAX {
            return Err(cerr(400, "request too long for one sealed record"));
        }
        let sealed = self.cipher.seal(&plain);
        plain.zeroize();
        let (outer, body) = match link.request(op::NCRY_MSG, &sealed).await {
            Ok(r) => r,
            Err(e) => {
                // The record may or may not have arrived: the counters can no
                // longer be trusted to agree.
                self.alive = false;
                return Err(e);
            }
        };
        if outer != status::OK {
            self.alive = false;
            return Err(match outer {
                status::DECLINED => cerr(4001, "refused on the device"),
                status::NOT_NOW => cerr(410, "the device has no session with this host (it was unplugged, logged out, or timed out): pair again"),
                other => cerr(410, format!("the device ended the session ({})", status::name(other))),
            });
        }
        let inner = match self.cipher.open(&body) {
            Ok(p) if p.len() >= 2 => p,
            _ => {
                self.alive = false;
                return Err(cerr(502, "a reply failed to authenticate; the session was dropped"));
            }
        };
        Ok((u16::from_le_bytes([inner[0], inner[1]]), inner[2..].to_vec()))
    }
}

/// At most this many sessions are held at once.
const MAX_HELD: usize = 8;

/// The paired sessions this process holds, by link.
static HELD: Mutex<Option<HashMap<String, Session>>> = Mutex::new(None);

fn held_sessions<R>(f: impl FnOnce(&mut HashMap<String, Session>) -> R) -> R {
    let mut g = HELD.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// Hand a session back after a request, to be reused by the next one over the
/// same link — unless something ended it.
pub fn keep(session: Session) {
    if session.alive {
        held_sessions(|h| {
            // Links that went away (a replugged device has a new path) leave
            // their sessions behind: a handful is all that is ever live.
            if h.len() >= MAX_HELD && !h.contains_key(&session.link) {
                h.clear();
            }
            h.insert(session.link.clone(), session);
        });
    }
}

/// Whether a paired session is held for `link` (it may still turn out to have
/// ended on the device's side).
pub fn held<T: Transport>(link: &T) -> bool {
    held_sessions(|h| h.contains_key(&link.id()))
}

/// Forget the session held for `link` and tell the device (`PairAbort`), which
/// also takes a pairing prompt off its screen.
pub async fn disconnect<T: Transport>(link: &T) -> Result<bool, ApiError> {
    let had = held_sessions(|h| h.remove(&link.id())).is_some();
    link.request(op::PAIR_ABORT, &[]).await?;
    Ok(had)
}

// ── Pairing ──────────────────────────────────────────────────────────────────

static PAIR_WAITERS: Waiters<bool> = Waiters::new();

/// Deliver the host user's answer to a `catcard:pair` event.
pub fn pair_resolve(id: &str, accept: bool) -> bool {
    PAIR_WAITERS.resolve(id, accept)
}

/// `Identify`, in the clear.
pub async fn identify<T: Transport>(link: &T) -> Result<Identity, ApiError> {
    let (st, body) = link.request(op::IDENTIFY, &[]).await?;
    if st != status::OK {
        return Err(cerr(502, format!("Identify answered {}", status::name(st))));
    }
    Identity::decode(&body).map_err(|e| cerr(502, format!("Identify: {e}")))
}

/// A paired session over `link`: the one held from an earlier request if the
/// device still honours it, else a new pairing.
pub async fn connect<T: Transport>(env: &Env, link: &T) -> Result<Session, ApiError> {
    let cached = held_sessions(|h| h.remove(&link.id()));
    if let Some(mut session) = cached {
        // A sealed Identify proves the session on both ends, and refreshes
        // what we know of the device.
        if let Ok((status::OK, body)) = session.call(link, op::IDENTIFY, &[]).await {
            if let Ok(identity) = Identity::decode(&body) {
                session.identity = identity;
                return Ok(session);
            }
        }
    }
    pair(env, link).await
}

async fn pair<T: Transport>(env: &Env, link: &T) -> Result<Session, ApiError> {
    let identity = identify(link).await?;
    if identity.protocol != proto::PROTOCOL_VERSION {
        return Err(cerr(501, format!("the device speaks protocol version {}, this library version {}", identity.protocol, proto::PROTOCOL_VERSION)));
    }
    if identity.caps & proto::caps::PAIRING == 0 || identity.caps & proto::caps::HOST_WALLET == 0 {
        return Err(cerr(501, "this firmware does not offer the paired channel and the host-wallet commands"));
    }
    if !identity.unlocked() {
        return Err(cerr(423, "unlock the device first (enter its PIN)"));
    }

    // One handshake per request, never a retry loop: the device charges a
    // cooldown for every key it hands out and blocks pairing after three
    // abandoned handshakes.
    let host = Initiator::new();
    let (st, body) = link.request(op::PAIR_COMMIT, &host.commit).await?;
    let device_pub: [u8; 32] = match st {
        status::OK => body.as_slice().try_into().map_err(|_| cerr(502, "bad pairing key from the device"))?,
        status::BUSY => return Err(cerr(409, "the device is busy pairing: answer the code on its screen, or wait a few seconds and try again")),
        status::REFUSED => return Err(cerr(403, format!("the device refused to pair: {}", reason(&body)))),
        status::NOT_NOW => return Err(cerr(423, "unlock the device first (enter its PIN)")),
        other => return Err(cerr(502, format!("PairCommit answered {}", status::name(other)))),
    };
    let public = host.public;
    let (cipher, code) = host.finish(&device_pub)?;
    let (st, _) = link.request(op::PAIR_REVEAL, &public).await?;
    if st != status::OK {
        return Err(cerr(502, format!("PairReveal answered {}", status::name(st))));
    }
    let mut session = Session::new(cipher, link.id(), identity);

    // The host's user compares the code with the device's screen.
    let id = xuid::Xuid::new("pair").to_string();
    let event = json!({ "id": id, "code": code_text(code), "board": session.identity.board, "version": session.identity.version, "bench": session.identity.bench() });
    let accepted = PAIR_WAITERS.wait(&id, CONFIRM_TIMEOUT_MS, || env.broadcast(&crate::response::event("catcard:pair", event))).await;
    if accepted != Some(true) {
        let _ = link.request(op::PAIR_ABORT, &[]).await;
        return Err(match accepted {
            Some(_) => cerr(4001, "the pairing code was not confirmed"),
            None => cerr(408, "nobody confirmed the pairing code (answer the catcard:pair event with CatCard:pairResponse)"),
        });
    }

    // Send the sealed PairConfirm until the device's user has answered too.
    let mut waited = 0u32;
    loop {
        let (st, _) = session.call(link, op::PAIR_CONFIRM, &[]).await?;
        match st {
            status::OK => return Ok(session),
            status::NOT_NOW if waited < DEVICE_WAIT_MS => {
                sleep_ms(POLL_MS).await;
                waited += POLL_MS.max(1);
            }
            status::NOT_NOW => {
                let _ = link.request(op::PAIR_ABORT, &[]).await;
                return Err(cerr(408, "nobody accepted the pairing code on the device"));
            }
            other => {
                let _ = link.request(op::PAIR_ABORT, &[]).await;
                return Err(cerr(502, format!("PairConfirm answered {}", status::name(other))));
            }
        }
    }
}

/// A refusal's text, for a person to read.
pub(crate) fn reason(body: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(body).chars().filter(|c| !c.is_control()).take(80).collect();
    if text.is_empty() {
        "no reason given".into()
    } else {
        text
    }
}
