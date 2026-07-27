//! Interactive RemoteKey reshare over the live WalletSign wdrone fleet — the
//! one ceremony where a wdrone participates as a live TSS party (a RemoteKey
//! share is never opened locally; the wdrone holds it and co-reshares over the
//! Spot `walletsign` transport). Port of wltwallet/reshare.go (FROST path) +
//! broker.go (`tssHub` / `localBroker` / `spotPeer`).
//!
//! Topology: the new committee + the local (non-RemoteKey) old parties run
//! in-process through a [`Hub`] of [`LocalBroker`]s; each old RemoteKey party is
//! a [`WdronePeer`] reached over Spot. selectPeer pings the fleet, the winner
//! gets a `walletsign/<remotekey>/init` handshake carrying the old/new
//! committees, then the tss-lib resharing rounds flow over the same transport.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tsslib::frosttss::{Key as FrostKey, Keygen, Resharing};
use tsslib::tss::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver, Parameters, PartyId, ReSharingParameters};

use crate::sign::KeyDescription;
use crate::{Env, Error, Result};

// The transport-free committee helpers live in `reshare_common` so the browser
// (wasm32) ceremonies can reuse them (this module is native-only). Re-exported
// here so `crate::reshare::{JoinPeer, sid_from_remote_key, ...}` paths — and the
// tests below via `super::*` — keep resolving unchanged.
pub use crate::reshare_common::{build_party_ids, open_local_share, sid_from_remote_key, JoinPeer};

/// Per-operation router: local (in-process) brokers + remote (Spot) wdrone
/// peers, keyed by tss `PartyId.id` (Go `tssHub`).
pub struct Hub {
    local: Mutex<HashMap<String, Arc<LocalBroker>>>,
    remote: Mutex<HashMap<String, Arc<WdronePeer>>>,
    /// Invoked (once) with the reason carried by a `walletsign:error` frame — a
    /// remote (wdrone) participant reporting a terminal ceremony failure (e.g.
    /// its resharing party failed to start on a stale share). Ceremony owners
    /// wire this to their [`RoundsGuard`] so the ceremony fails fast with the
    /// remote's reason instead of waiting out the rounds deadline. Fleet
    /// versions that predate the frame simply never send it (Go `tssHub.onError`).
    on_error: Mutex<Option<Box<dyn Fn(String) + Send + Sync>>>,
    error_fired: AtomicBool,
}

impl Hub {
    fn new() -> Arc<Hub> {
        Arc::new(Hub {
            local: Mutex::new(HashMap::new()),
            remote: Mutex::new(HashMap::new()),
            on_error: Mutex::new(None),
            error_fired: AtomicBool::new(false),
        })
    }

    /// Wire the terminal-failure handler (Go `hub.onError = failRounds`).
    fn set_on_error(&self, f: Box<dyn Fn(String) + Send + Sync>) {
        *self.on_error.lock().unwrap() = Some(f);
    }

    /// Deliver a remote-reported terminal error to the ceremony owner, once
    /// (Go `tssHub.fail` guarded by `errorOnce`).
    fn fail(&self, reason: String) {
        if self.error_fired.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(f) = self.on_error.lock().unwrap().as_ref() {
            f(reason);
        }
        // No handler wired: the reason is dropped (Go logs it). In this port
        // the handler is always installed before remotes start.
    }

    /// Register an in-process party and return its broker (Go `addLocal`).
    fn add_local(self: &Arc<Self>, id: &PartyId) -> Arc<LocalBroker> {
        let b = Arc::new(LocalBroker {
            hub: Arc::downgrade(self),
            self_id: id.id.clone(),
            handlers: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        });
        self.local.lock().unwrap().insert(id.id.clone(), b.clone());
        b
    }

    fn add_remote(&self, p: Arc<WdronePeer>) {
        self.remote.lock().unwrap().insert(p.party_id.id.clone(), p);
    }

    /// Route an outbound message produced by a local party (Go `dispatch`).
    fn dispatch(&self, msg: &JsonMessage) -> BrokerResult {
        let from_id = msg.from.as_ref().map(|f| f.id.clone());
        if let Some(to) = msg.to.as_ref() {
            // Release the map lock BEFORE delivering: delivery re-enters the hub
            // (a party's round callback runs inline and may dispatch again), and
            // std Mutex is not reentrant — holding the guard here would deadlock.
            let lb = self.local.lock().unwrap().get(&to.id).cloned();
            if let Some(lb) = lb {
                return lb.receive(msg);
            }
            let rp = self.remote.lock().unwrap().get(&to.id).cloned();
            if let Some(rp) = rp {
                return rp.send(msg);
            }
            return Err(format!("tssHub: unknown target party {}", to.id).into());
        }
        // Broadcast: every party except the sender.
        let locals: Vec<Arc<LocalBroker>> = self
            .local
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| from_id.as_deref() != Some(id.as_str()))
            .map(|(_, b)| b.clone())
            .collect();
        let remotes: Vec<Arc<WdronePeer>> = self
            .remote
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| from_id.as_deref() != Some(id.as_str()))
            .map(|(_, p)| p.clone())
            .collect();
        let mut first_err: BrokerResult = Ok(());
        for lb in locals {
            if let Err(e) = lb.receive(msg) {
                if first_err.is_ok() {
                    first_err = Err(e);
                }
            }
        }
        for rp in remotes {
            if let Err(e) = rp.send(msg) {
                if first_err.is_ok() {
                    first_err = Err(e);
                }
            }
        }
        first_err
    }

    /// Route a message that arrived from outside the process (Go `deliver`):
    /// only local parties are candidates.
    fn deliver(&self, msg: &JsonMessage) -> BrokerResult {
        let from_id = msg.from.as_ref().map(|f| f.id.clone());
        if let Some(to) = msg.to.as_ref() {
            let lb = self.local.lock().unwrap().get(&to.id).cloned(); // guard dropped before receive
            return match lb {
                Some(lb) => lb.receive(msg),
                None => Err(format!("tssHub: no local party {}", to.id).into()),
            };
        }
        let locals: Vec<Arc<LocalBroker>> = self
            .local
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| from_id.as_deref() != Some(id.as_str()))
            .map(|(_, b)| b.clone())
            .collect();
        let mut first_err: BrokerResult = Ok(());
        for lb in locals {
            if let Err(e) = lb.receive(msg) {
                if first_err.is_ok() {
                    first_err = Err(e);
                }
            }
        }
        first_err
    }
}

/// tss `MessageBroker` for one in-process party (Go `localBroker`). Outbound
/// (from == self) routes through the hub; inbound dispatches to a handler or
/// buffers until one connects.
struct LocalBroker {
    hub: Weak<Hub>,
    self_id: String,
    handlers: Mutex<HashMap<String, Arc<dyn MessageReceiver + Send + Sync>>>,
    pending: Mutex<HashMap<String, Vec<JsonMessage>>>,
}

impl MessageReceiver for LocalBroker {
    fn receive(&self, msg: &JsonMessage) -> BrokerResult {
        if msg.from.as_ref().map(|f| f.id.as_str()) == Some(self.self_id.as_str()) {
            return match self.hub.upgrade() {
                Some(hub) => hub.dispatch(msg),
                None => Ok(()),
            };
        }
        let handler = self.handlers.lock().unwrap().get(&msg.typ).cloned();
        match handler {
            Some(h) => h.receive(msg),
            None => {
                self.pending.lock().unwrap().entry(msg.typ.clone()).or_default().push(msg.clone());
                Ok(())
            }
        }
    }
}

impl MessageBroker for LocalBroker {
    fn connect(&self, typ: &str, dest: Arc<dyn MessageReceiver + Send + Sync>) {
        let queued = {
            let mut h = self.handlers.lock().unwrap();
            h.insert(typ.to_string(), dest.clone());
            self.pending.lock().unwrap().remove(typ).unwrap_or_default()
        };
        for m in queued {
            let _ = dest.receive(&m);
        }
    }
}

/// A TSS party living on the other end of the Spot network (Go `spotPeer`) — a
/// wdrone that holds a RemoteKey share. Forwards outbound tss messages over
/// Spot and feeds inbound ones back into the hub.
pub struct WdronePeer {
    hub: Weak<Hub>,
    party_id: PartyId,
    client: Arc<spotlib::Client>,
    sid: String,
    self_spot_id: String,
    peer: Mutex<String>,
}

impl WdronePeer {
    /// Arm the inbound handler on `<sid>`: the peer replies to our sender path
    /// `<self>/<sid>/<party>`, so our client dispatches those on the first
    /// segment == sid. Must run before any TSS round.
    fn arm_handler(self: &Arc<Self>) {
        let weak: Weak<WdronePeer> = Arc::downgrade(self);
        self.client.set_handler(
            &self.sid,
            Some(move |m: &spotlib::Message| {
                if let Some(rp) = weak.upgrade() {
                    rp.deliver_inbound(&m.body);
                }
                Ok(None)
            }),
        );
    }

    /// Reshare mode (Go non-joiner `spotPeer.Start`): arm the handler, selectPeer
    /// (ping the fleet), then the `walletsign/<sid>/init` query handshake.
    fn start(self: &Arc<Self>, base: &str, client_id: Option<&str>, info: &Value) -> Result<()> {
        self.arm_handler();
        let peer = select_peer(base, client_id, &self.client)?;
        *self.peer.lock().unwrap() = peer.clone();
        let body = serde_json::to_vec(info).map_err(|e| Error::Env(e.to_string()))?;
        let target = format!("{peer}/walletsign/{}/init", self.sid);
        self.client
            .query(&target, &body, Duration::from_secs(15))
            .map_err(|e| Error::Env(format!("reshare: wdrone init failed: {e}")))?;
        Ok(())
    }

    /// Joiner mode (Go `apiInitiateKeygen`): the peer's Spot id is already known
    /// (from the committee), so just arm the handler and fire the InitPayload at
    /// `<peer>/walletsign/<sid>/init` (send-to, not a query — the peer answers
    /// with TSS round frames, not an init reply).
    fn start_joiner(self: &Arc<Self>, info: &Value) -> Result<()> {
        self.arm_handler();
        let peer = self.peer.lock().unwrap().clone();
        let body = serde_json::to_vec(info).map_err(|e| Error::Env(e.to_string()))?;
        let target = format!("{peer}/walletsign/{}/init", self.sid);
        let me = self.party_id.id.clone();
        let sender = format!("/{}/{}", self.sid, me);
        self.client
            .send_to_with_from(&target, &body, &sender, Duration::from_secs(30))
            .map_err(|e| Error::Env(format!("initiateKeygen: send init to {peer}: {e}")))?;
        Ok(())
    }

    /// Forward an outbound tss message to the wdrone (Go `spotPeer.Send`). The
    /// sender uses the relative `/<sid>/<party>` form so the relay prepends this
    /// client's authenticated id → Go-identical `k.<self>/<sid>/<party>`.
    fn send(&self, msg: &JsonMessage) -> BrokerResult {
        let body = serde_json::to_vec(msg).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        let peer = self.peer.lock().unwrap().clone();
        let base = format!("{peer}/walletsign/{}", self.sid);
        let target = if msg.to.is_some() { format!("{base}/single") } else { format!("{base}/broadcast") };
        let from_id = msg.from.as_ref().map(|f| f.id.clone()).unwrap_or_default();
        let sender = format!("/{}/{}", self.sid, from_id);
        let _ = self.self_spot_id; // sender is relative on purpose (see doc above)
        self.client
            .send_to_with_from(&target, &body, &sender, Duration::from_secs(20))
            .map_err(|e| Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(())
    }

    fn deliver_inbound(&self, bytes: &[u8]) {
        // The wdrone also emits a non-tss `{step,...}` diagnostic stream on this
        // channel; anything that isn't a well-formed JsonMessage is ignored.
        let jm: JsonMessage = match serde_json::from_slice(bytes) {
            Ok(m) => m,
            Err(_) => return,
        };
        if jm.typ.is_empty() {
            return;
        }
        // Terminal-failure frame from a wdrone participant (Go `spotPeer.
        // messageHandler`): fail the ceremony immediately with the remote's
        // reason rather than waiting out the rounds deadline in silence.
        if jm.typ == "walletsign:error" {
            let reason = jm.data.as_str().unwrap_or("").to_string();
            let reason = if reason.is_empty() {
                "remote participant reported an unspecified failure".to_string()
            } else {
                reason
            };
            if let Some(hub) = self.hub.upgrade() {
                hub.fail(reason);
            }
            return;
        }
        if let Some(hub) = self.hub.upgrade() {
            let _ = hub.deliver(&jm);
        }
    }
}

/// selectPeer: fetch the fleet's Spot ids, ping each, return the first that
/// answers within the deadline (Go `selectPeer`).
fn select_peer(base: &str, client_id: Option<&str>, client: &spotlib::Client) -> Result<String> {
    let ids = crate::walletsign::fetch_peer_spot_ids(base, client_id)?;
    for k in &ids {
        let ping = vec![0u8; 32];
        if client.query(&format!("{k}/ping"), &ping, Duration::from_secs(10)).is_ok() {
            return Ok(k.clone());
        }
    }
    Err(Error::Env("reshare: no wdrone peer answered ping".into()))
}

/// tss `PartyId` for a WalletKey id (party key = its UUID bytes), matching Go
/// `tss.NewPartyID(id, id, big.Int(UUID))`.
fn party_for(wk_id: &str) -> Result<PartyId> {
    let xid: xuid::Xuid = wk_id.parse().map_err(|e| Error::Env(format!("bad walletkey id {wk_id}: {e}")))?;
    let uuid = xid.uuid().as_bytes().to_vec();
    Ok(PartyId::new(wk_id.to_string(), wk_id.to_string(), uuid))
}

/// Serialize a sorted committee to the Go `tss.SortedPartyIDs` JSON shape.
fn peers_json(sorted: &[PartyId]) -> Value {
    Value::Array(sorted.iter().map(|p| serde_json::to_value(p).unwrap_or(Value::Null)).collect())
}

// ── Reshare rounds deadline + remote-reported failures (Go reshare.go) ───────

/// Bounds the interactive TSS reshare rounds (remote peer init + message
/// exchange). The rounds themselves complete in seconds, but the window must
/// also cover the remote-peer init worst case (`maxInitAttempts=3 × (15s
/// selectPeer + 15s init query) ≈ 90s`) plus ~30s of rounds headroom. Without
/// a bound, a remote party that goes silent after init hangs the ceremony
/// forever (Go `reshareRoundsTimeout`).
pub const RESHARE_ROUNDS_TIMEOUT: Duration = Duration::from_secs(120);

/// Bounds a [`RoundsGuard`]-wrapped reshare and turns the terminal condition
/// into a descriptive, actionable error (Go `reshareRoundsContext`). Because
/// the Rust reshare runs its parties on threads (not ctx-aware goroutines), the
/// guard carries the deadline plus a slot for a remote-reported failure reason;
/// the collection loop consults both.
pub struct RoundsGuard {
    /// When the interactive rounds must be abandoned.
    deadline: Instant,
    /// Set once by the [`Hub`] `on_error` hook when a `walletsign:error` frame
    /// arrives (Go: the remote's reason becomes the ctx cancel cause).
    fail_reason: Arc<Mutex<Option<String>>>,
    /// The host/caller aborted (Go `parent.Err() != nil`): errors pass through
    /// untouched. No parent ctx exists in this synchronous port, so this is only
    /// set in tests to exercise the passthrough branch.
    caller_canceled: bool,
}

impl RoundsGuard {
    /// A fresh guard whose deadline starts now (Go derives the bounded ctx).
    pub fn new() -> RoundsGuard {
        RoundsGuard {
            deadline: Instant::now() + RESHARE_ROUNDS_TIMEOUT,
            fail_reason: Arc::new(Mutex::new(None)),
            caller_canceled: false,
        }
    }

    /// Builder for the caller-cancelled variant (test parity with Go's
    /// "caller cancel passes through untouched").
    pub fn with_caller_canceled(mut self) -> RoundsGuard {
        self.caller_canceled = true;
        self
    }

    /// The [`Hub`] `on_error` hook: records the remote's reason once (Go
    /// `fail(reason)` cancelling the ctx with the reason as cause).
    pub fn on_error_hook(&self) -> Box<dyn Fn(String) + Send + Sync> {
        let slot = self.fail_reason.clone();
        Box::new(move |reason| {
            let mut g = slot.lock().unwrap();
            if g.is_none() {
                *g = Some(reason);
            }
        })
    }

    /// The remote-reported failure reason, if any arrived.
    pub fn remote_failure(&self) -> Option<String> {
        self.fail_reason.lock().unwrap().clone()
    }

    /// Whether the rounds deadline has elapsed.
    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Turn the rounds' terminal condition into a descriptive error, mirroring
    /// Go `reshareRoundsContext`'s wrap. Priorities: caller cancel → passthrough;
    /// remote-reported reason → surface it; our deadline → "stopped responding";
    /// otherwise the party error is returned unchanged.
    pub fn wrap(&self, err_msg: String, hit_deadline: bool) -> Error {
        // Caller-initiated cancel: pass the error through untouched.
        if self.caller_canceled {
            return Error::Env(err_msg);
        }
        // A remote participant reported a terminal failure — surface its reason
        // (not a timeout), with the committee-unchanged assurance.
        if let Some(reason) = self.remote_failure() {
            return Error::Env(format!(
                "reshare failed — remote participant reported: {reason}; the wallet committee is unchanged"
            ));
        }
        // Our own deadline fired: a participant went silent mid-ceremony.
        if hit_deadline {
            return Error::Env(format!(
                "reshare TSS rounds timed out after {}s — a committee participant stopped responding mid-ceremony (for a RemoteKey this can indicate the server-side share is out of sync); the wallet committee is unchanged: {err_msg}",
                RESHARE_ROUNDS_TIMEOUT.as_secs()
            ));
        }
        Error::Env(err_msg)
    }
}

impl Default for RoundsGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Collect one result per reshare party over `rx`, bounded by `guard`'s deadline
/// and interrupted fast by a remote-reported failure. New-committee parties
/// occupy indices `0..new_sorted.len()`; only their (non-`None`) shares are
/// returned, keyed by `PartyId.id` (Go: `wg.Wait()` + the `wrapRoundsErr` gate).
fn collect_reshared<K>(
    guard: &RoundsGuard,
    new_sorted: &[PartyId],
    rx: mpsc::Receiver<(usize, std::result::Result<Option<K>, String>)>,
    total: usize,
) -> Result<HashMap<String, K>> {
    let mut new_shares: HashMap<String, K> = HashMap::new();
    let mut got = 0usize;
    while got < total {
        // A wdrone reported a terminal failure: abort now with its reason.
        if guard.remote_failure().is_some() {
            return Err(guard.wrap(String::new(), false));
        }
        if guard.expired() {
            return Err(guard.wrap("rounds deadline exceeded".into(), true));
        }
        // Poll in short slices so a mid-flight remote failure / the deadline is
        // observed promptly even while a party thread is still running.
        let remaining = guard.deadline.saturating_duration_since(Instant::now());
        let poll = remaining.min(Duration::from_millis(250));
        match rx.recv_timeout(poll) {
            Ok((i, res)) => {
                got += 1;
                match res {
                    Ok(share) => {
                        if i < new_sorted.len() {
                            if let Some(k) = share {
                                new_shares.insert(new_sorted[i].id.clone(), k);
                            }
                        }
                    }
                    // A party failed: wrap prefers a remote reason if one landed.
                    Err(e) => return Err(guard.wrap(format!("reshare failed: {e}"), false)),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(new_shares)
}

// ── Tenacious RemoteKey share upload (Go restretry.go restDoRetryCritical) ───

const CRITICAL_RETRY_BUDGET: Duration = Duration::from_secs(300);
const CRITICAL_RETRY_BACKOFF: Duration = Duration::from_secs(2);
const CRITICAL_RETRY_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// A classified upload failure, mirroring the shapes Go's
/// `isRetryableCriticalError` distinguishes on a `rest.Error`.
#[derive(Debug, Clone, PartialEq)]
pub enum UploadError {
    /// A rest-level HTTP error carrying a status code (Go `rest.Error` with a
    /// non-nil `Response`).
    Rest(u16),
    /// A rest-level error with no HTTP response attached (Go `rest.Error{}` /
    /// `Response == nil`): the transport failed, retry.
    RestNoResponse,
    /// A transport-level failure — http2 header timeout, connection reset, … —
    /// (not a `rest.Error`): the request may already have landed, retry.
    Transport(String),
}

/// Retry 5xx AND anything that is not a definitive rest-level 4xx: a non-rest
/// (transport) error means we cannot know whether the server processed the
/// request, and abandoning a share upload can desync server-side state (Go
/// `isRetryableCriticalError`). `None` (no error) is not retryable.
pub fn is_retryable_critical_error(err: Option<&UploadError>) -> bool {
    match err {
        None => false,
        Some(UploadError::Rest(code)) => *code >= 500,
        Some(UploadError::RestNoResponse) => true,
        Some(UploadError::Transport(_)) => true,
    }
}

/// Recover a classification from the REST layer's stringly-typed error. The
/// `rest` module collapses HTTP status into the error message; when a
/// `status code <N>` is present we treat it as a rest-level HTTP error,
/// otherwise as a transport failure (Go's default for a non-`rest.Error`).
pub fn classify_upload_error(err: &Error) -> UploadError {
    let s = err.to_string();
    match parse_status_code(&s) {
        Some(code) => UploadError::Rest(code),
        None => UploadError::Transport(s),
    }
}

/// Extract an HTTP status code from a REST error string (`… status code 404 …`).
fn parse_status_code(s: &str) -> Option<u16> {
    let idx = s.find("status code ")?;
    let rest = &s[idx + "status code ".len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Keep attempting `Crypto/WalletSign:setGeneratedKey` (via [`crate::rest::
/// do_post`]) until it succeeds, hits a deterministic 4xx, or
/// [`CRITICAL_RETRY_BUDGET`] elapses — retrying 5xx and transport failures with
/// exponential backoff (Go `restDoRetryCritical`). Used for the one reshare step
/// whose abandonment can desync the server-side RemoteKey share.
pub fn rest_do_retry_critical(base: &str, path: &str, params: &Value, client_id: Option<&str>) -> Result<Value> {
    let deadline = Instant::now() + CRITICAL_RETRY_BUDGET;
    let mut backoff = CRITICAL_RETRY_BACKOFF;
    loop {
        match crate::rest::do_post(base, path, params, client_id) {
            Ok(v) => return Ok(v),
            Err(e) => {
                let ue = classify_upload_error(&e);
                if !is_retryable_critical_error(Some(&ue)) {
                    return Err(e);
                }
                if Instant::now() >= deadline {
                    return Err(e);
                }
                std::thread::sleep(backoff);
                if backoff < CRITICAL_RETRY_BACKOFF_MAX {
                    backoff = (backoff * 2).min(CRITICAL_RETRY_BACKOFF_MAX);
                }
            }
        }
    }
}

/// The transport + committee scaffolding shared by every reshare protocol: the
/// resolved old/new committees, the wired [`Hub`], and the started wdrone peers.
struct Ceremony {
    old_sorted: Vec<PartyId>,
    new_sorted: Vec<PartyId>,
    new_parties: Vec<PartyId>,
    new_wk_ids: Vec<xuid::Xuid>,
    hub: Arc<Hub>,
    /// Kept alive for the duration of the ceremony (their handlers feed the hub).
    _remotes: Vec<Arc<WdronePeer>>,
}

/// Resolve the committees, wire the hub (local new + local non-RemoteKey old),
/// and run the `walletsign/<remotekey>/init` handshake for each old RemoteKey
/// (Go `startReshareRemotes`). Protocol-agnostic — the caller then spawns the
/// FROST/DKLs resharing parties over `hub`.
fn setup_ceremony(
    env: &Arc<Env>,
    wallet: &crate::models::wallet::Wallet,
    old_keys: &[KeyDescription],
    new_keys: &[KeyDescription],
    threshold: usize,
    curve: &str,
    protocol: &str,
    on_error: Box<dyn Fn(String) + Send + Sync>,
) -> Result<Ceremony> {
    let mut old_parties: Vec<PartyId> = Vec::with_capacity(old_keys.len());
    for kd in old_keys {
        let wk = wallet.keys.iter().find(|k| k.id == kd.id).ok_or_else(|| Error::Env(format!("old key {} not on wallet", kd.id)))?;
        old_parties.push(party_for(&wk.id)?);
    }
    let old_sorted = PartyId::sort(old_parties.clone(), 0);

    let new_wk_ids: Vec<xuid::Xuid> = (0..new_keys.len()).map(|_| xuid::Xuid::new("wkey")).collect();
    let new_parties: Vec<PartyId> = new_wk_ids.iter().map(|x| party_for(&x.to_string())).collect::<Result<_>>()?;
    let new_sorted = PartyId::sort(new_parties.clone(), 0);

    let hub = Hub::new();
    // Wire the terminal-failure handler before any remote starts, so a
    // `walletsign:error` frame during init or rounds fails fast (Go sets
    // `hub.onError = failRounds` before `startReshareRemotes`).
    hub.set_on_error(on_error);
    for p in &new_sorted {
        hub.add_local(p);
    }
    for (kd, party) in old_keys.iter().zip(old_parties.iter()) {
        let wk = wallet.keys.iter().find(|k| k.id == kd.id).unwrap();
        if wk.kind != "RemoteKey" {
            if let Some(sp) = old_sorted.iter().find(|s| s.id == party.id) {
                hub.add_local(sp);
            }
        }
    }

    let base = crate::rest::DEFAULT_HOST;
    let client_id = env
        .config_get("walletinfo:clientId")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.is_empty());
    let client = env.spot_start().map_err(|e| Error::Env(e.to_string()))?;
    for _ in 0..60 {
        if client.connection_count().1 > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let self_spot_id = client.target_id();

    let mut remotes: Vec<Arc<WdronePeer>> = Vec::new();
    for (kd, party) in old_keys.iter().zip(old_parties.iter()) {
        let wk = wallet.keys.iter().find(|k| k.id == kd.id).unwrap();
        if wk.kind != "RemoteKey" {
            continue;
        }
        let sorted_party = old_sorted.iter().find(|s| s.id == party.id).unwrap().clone();
        // reshare uses the FULL RemoteKey string as the walletsign sid.
        let sid = if kd.key.is_empty() { wk.key.clone() } else { kd.key.clone() };
        let rp = Arc::new(WdronePeer {
            hub: Arc::downgrade(&hub),
            party_id: sorted_party.clone(),
            client: client.clone(),
            sid,
            self_spot_id: self_spot_id.clone(),
            peer: Mutex::new(String::new()),
        });
        hub.add_remote(rp.clone());
        // Descriptive spot-offline error (Go `waitOnlineSpot` wrap at the
        // remote-init sites): a bare timeout here is indistinguishable from a
        // ceremony failure, so name the real cause.
        if client.connection_count().1 == 0 {
            return Err(Error::Env(
                "spot network unavailable (could not reach the relay mesh to contact the remote 2FA participant): spot client is not online"
                    .into(),
            ));
        }
        let info = json!({
            "old_peers": peers_json(&old_sorted),
            "new_peers": peers_json(&new_sorted),
            "name": serde_json::to_value(&sorted_party).unwrap_or(Value::Null),
            "old_partycount": old_keys.len(),
            "new_partycount": new_keys.len(),
            "old_threshold": threshold,
            "new_threshold": threshold,
            "curve": curve,
            "protocol": protocol,
        });
        rp.start(base, client_id.as_deref(), &info)?;
        remotes.push(rp);
    }

    Ok(Ceremony { old_sorted, new_sorted, new_parties, new_wk_ids, hub, _remotes: remotes })
}

/// FROST reshare of an ed25519 wallet whose committee includes a RemoteKey held
/// by the wdrone fleet (Go `Wallet.ReshareFrost`). Rotates the shares to
/// `new_keys`, preserving the group pubkey.
pub fn reshare_frost(
    env: &Arc<Env>,
    wallet_id: &str,
    old_keys: &[KeyDescription],
    new_keys: &[KeyDescription],
) -> Result<()> {
    let wallet = crate::models::wallet::fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    if wallet.curve != "ed25519" || wallet.protocol != "frost" {
        return Err(Error::Env("reshare_frost requires an ed25519/FROST wallet".into()));
    }
    let threshold = wallet.threshold.max(0) as usize;
    if new_keys.is_empty() || threshold >= new_keys.len() {
        return Err(Error::Env("invalid new committee size/threshold".into()));
    }

    // Bound the interactive rounds so a silent remote party errors out instead
    // of hanging the ceremony forever (Go `reshareRoundsContext`). The guard's
    // deadline covers the remote-peer init inside setup_ceremony too.
    let guard = RoundsGuard::new();
    let cx = setup_ceremony(env, &wallet, old_keys, new_keys, threshold, "ed25519", "frost", guard.on_error_hook())?;

    // Spawn resharing parties: new committee (input None) + local old committee
    // (input = decrypted old share). Each runs on its own thread and reports its
    // result over `tx`; new-committee parties occupy indices 0..new_sorted.len().
    let (tx, rx) = mpsc::channel::<(usize, std::result::Result<Option<FrostKey>, String>)>();
    let mut idx = 0usize;
    for p in &cx.new_sorted {
        let broker = cx.hub.local.lock().unwrap().get(&p.id).cloned().unwrap();
        let params = ReSharingParameters::new(cx.old_sorted.clone(), cx.new_sorted.clone(), threshold, threshold, p.clone(), broker as Arc<dyn MessageBroker + Send + Sync>);
        let tx = tx.clone();
        let i = idx;
        idx += 1;
        std::thread::spawn(move || {
            let r = Resharing::new(params, None).map_err(|e| format!("{e:?}")).and_then(|r| r.wait().map_err(|e| format!("{e:?}")));
            let _ = tx.send((i, r));
        });
    }
    for kd in old_keys {
        let wk = wallet.keys.iter().find(|k| k.id == kd.id).unwrap();
        if wk.kind == "RemoteKey" {
            continue;
        }
        let sp = cx.old_sorted.iter().find(|s| s.id == wk.id).unwrap().clone();
        let key = FrostKey::from_json(&open_local_share(wk, &kd.key)?).map_err(|e| Error::Env(format!("load old frost share: {e:?}")))?;
        let broker = cx.hub.local.lock().unwrap().get(&sp.id).cloned().unwrap();
        let params = ReSharingParameters::new(cx.old_sorted.clone(), cx.new_sorted.clone(), threshold, threshold, sp.clone(), broker as Arc<dyn MessageBroker + Send + Sync>);
        let tx = tx.clone();
        let i = idx;
        idx += 1;
        std::thread::spawn(move || {
            let r = Resharing::new(params, Some(key)).map_err(|e| format!("{e:?}")).and_then(|r| r.wait().map_err(|e| format!("{e:?}")));
            let _ = tx.send((i, r));
        });
    }
    let total = idx;
    drop(tx);

    let new_shares = collect_reshared(&guard, &cx.new_sorted, rx, total)?;
    crate::models::wallet::persist_reshared_frost(env, &wallet, new_keys, &cx.new_wk_ids, &cx.new_parties, &new_shares)?;
    Ok(())
}

/// DKLs23 reshare of a secp256k1 wallet whose committee includes a RemoteKey
/// (Go `Wallet.ReshareDkls`). dkls23 requires exactly T+1 old signers, and every
/// party binds to the wallet's existing group pubkey (`old_ecdsa_pub`).
pub fn reshare_dkls(
    env: &Arc<Env>,
    wallet_id: &str,
    old_keys: &[KeyDescription],
    new_keys: &[KeyDescription],
) -> Result<()> {
    use tsslib::dklstss::{Key as DklsKey, ResharingParty};

    let wallet = crate::models::wallet::fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    if wallet.curve != "secp256k1" || wallet.protocol != "dkls23" {
        return Err(Error::Env("reshare_dkls requires a secp256k1/DKLs23 wallet".into()));
    }
    let threshold = wallet.threshold.max(0) as usize;
    if new_keys.is_empty() || threshold >= new_keys.len() {
        return Err(Error::Env("invalid new committee size/threshold".into()));
    }
    if old_keys.len() != threshold + 1 {
        return Err(Error::Env(format!("dkls23 reshare needs exactly T+1={} old signers, got {}", threshold + 1, old_keys.len())));
    }

    // The wallet's compressed group pubkey → the ProjectivePoint every party
    // binds to (Go `oldECDSAPub`).
    let pk = crate::models::wallet::b64url_decode(&wallet.pubkey)?;
    let old_ecdsa_pub = purecrypto::ec::secp256k1::AffinePoint::from_sec1(&pk)
        .map_err(|e| Error::Env(format!("bad wallet pubkey: {e:?}")))?
        .to_projective();

    // Bound the interactive rounds — see RESHARE_ROUNDS_TIMEOUT (Go
    // `reshareRoundsContext`).
    let guard = RoundsGuard::new();
    let cx = setup_ceremony(env, &wallet, old_keys, new_keys, threshold, "secp256k1", "dkls23", guard.on_error_hook())?;

    let (tx, rx) = mpsc::channel::<(usize, std::result::Result<Option<DklsKey>, String>)>();
    let mut idx = 0usize;
    for p in &cx.new_sorted {
        let broker = cx.hub.local.lock().unwrap().get(&p.id).cloned().unwrap();
        let params = ReSharingParameters::new(cx.old_sorted.clone(), cx.new_sorted.clone(), threshold, threshold, p.clone(), broker as Arc<dyn MessageBroker + Send + Sync>);
        let pub_pt = old_ecdsa_pub.clone();
        let tx = tx.clone();
        let i = idx;
        idx += 1;
        std::thread::spawn(move || {
            let r = ResharingParty::new(params, pub_pt, None).map_err(|e| format!("{e:?}")).and_then(|r| r.wait().map_err(|e| format!("{e:?}")));
            let _ = tx.send((i, r));
        });
    }
    for kd in old_keys {
        let wk = wallet.keys.iter().find(|k| k.id == kd.id).unwrap();
        if wk.kind == "RemoteKey" {
            continue;
        }
        let sp = cx.old_sorted.iter().find(|s| s.id == wk.id).unwrap().clone();
        let key = DklsKey::from_json(&open_local_share(wk, &kd.key)?).map_err(|e| Error::Env(format!("load old dkls share: {e:?}")))?;
        let broker = cx.hub.local.lock().unwrap().get(&sp.id).cloned().unwrap();
        let params = ReSharingParameters::new(cx.old_sorted.clone(), cx.new_sorted.clone(), threshold, threshold, sp.clone(), broker as Arc<dyn MessageBroker + Send + Sync>);
        let pub_pt = old_ecdsa_pub.clone();
        let tx = tx.clone();
        let i = idx;
        idx += 1;
        std::thread::spawn(move || {
            let r = ResharingParty::new(params, pub_pt, Some(key)).map_err(|e| format!("{e:?}")).and_then(|r| r.wait().map_err(|e| format!("{e:?}")));
            let _ = tx.send((i, r));
        });
    }
    let total = idx;
    drop(tx);

    let new_shares = collect_reshared(&guard, &cx.new_sorted, rx, total)?;
    crate::models::wallet::persist_reshared_dkls(env, &wallet, new_keys, &cx.new_wk_ids, &cx.new_parties, &new_shares)?;
    Ok(())
}

// ── ClawdWallet Stage-1 multi-device keygen (Wallet:initiateKeygen) ──────────
//
// Port of wltwallet/join.go. The mobile is the keygen LEADER: it builds the
// canonical committee from the caller-supplied `peers`, sends the InitPayload to
// every other peer over the walletsign transport, runs its own FROST keygen
// party against the shared hub, and uploads its resulting share to the wdrone as
// a RemoteKey. ed25519/FROST only (Stage 1). The other parties (agent + wdrone)
// must be online and running their joiner parties — that half of the committee
// lives on other devices / the backend, so the full ceremony is exercised in the
// field, not in this repo's tests; the transport it rides on is proven by the
// reshare + walletsign-routing tests.

/// `Wallet:initiateKeygen` — the leader-side FROST keygen ceremony. Returns
/// `(wallet_id, solana_address, pubkey_b64url)`.
pub fn initiate_keygen(
    env: &Arc<Env>,
    remote_key: &str,
    peers: &[JoinPeer],
    name: &str,
    curve: &str,
    me_moniker: &str,
) -> Result<(String, String, String)> {
    if remote_key.is_empty() {
        return Err(Error::Env("remote_key is required".into()));
    }
    let curve = if curve.is_empty() { "ed25519" } else { curve };
    if curve != "ed25519" {
        return Err(Error::Env(format!("initiateKeygen: curve {curve:?} not supported in Stage 1 (ed25519 only)")));
    }

    let client = env.spot_start().map_err(|e| Error::Env(e.to_string()))?;
    for _ in 0..60 {
        if client.connection_count().1 > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let me_spot = client.target_id();
    let self_spot_id = me_spot.clone();

    let (sorted, by_moniker, me_idx) = build_party_ids(peers, &me_spot, me_moniker)?;
    let sid = sid_from_remote_key(remote_key).to_string();
    let me = sorted[me_idx].clone();

    let hub = Hub::new();
    let me_broker = hub.add_local(&me);

    // A remote peer per non-self committee member; arm handlers + send init.
    let mut remotes: Vec<Arc<WdronePeer>> = Vec::new();
    for (i, id) in sorted.iter().enumerate() {
        if i == me_idx {
            continue;
        }
        let p = by_moniker.get(&id.moniker).ok_or_else(|| Error::Env(format!("initiateKeygen: peer {} missing", id.moniker)))?;
        if p.spot_id.is_empty() {
            return Err(Error::Env(format!("initiateKeygen: peer {} missing spot_id", id.moniker)));
        }
        let rp = Arc::new(WdronePeer {
            hub: Arc::downgrade(&hub),
            party_id: id.clone(),
            client: client.clone(),
            sid: sid.clone(),
            self_spot_id: self_spot_id.clone(),
            peer: Mutex::new(p.spot_id.clone()),
        });
        hub.add_remote(rp.clone());
        remotes.push(rp);
    }
    // Canonical InitPayload sent to every non-self peer (verbatim peer list).
    let peers_json_val = Value::Array(
        peers
            .iter()
            .map(|p| json!({ "id": p.spot_id, "moniker": p.moniker, "key": p.key }))
            .collect(),
    );
    let info = json!({
        "sid": sid,
        "type": "keygen",
        "curve": "ed25519",
        "protocol": "frost",
        "threshold": 1,
        "peers": peers_json_val,
    });
    for rp in &remotes {
        rp.start_joiner(&info)?;
    }

    // Run the mobile's FROST keygen party over the shared hub.
    let params = Parameters::new(sorted.clone(), &me, 1, me_broker as Arc<dyn MessageBroker + Send + Sync>);
    let key = Keygen::new(params).map_err(|e| Error::Env(format!("initiateKeygen: start keygen: {e:?}")))?
        .wait()
        .map_err(|e| Error::Env(format!("initiateKeygen: keygen failed: {e:?}")))?;

    use base64::Engine;
    let pk = crate::tss::frost_group_pubkey(&key);
    let pubkey = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk);
    let solana_addr = bs58::encode(pk).into_string();

    // Persist the mobile's wallet: one RemoteKey share (uploaded to the wdrone).
    let wallet_id = crate::models::wallet::persist_agent_keygen(env, name, &pubkey, remote_key, &key)?;
    Ok((wallet_id, solana_addr, pubkey))
}

/// `Wallet:joinSign` — the mobile joins a FROST signing ceremony led by the
/// agent (Go `apiJoinSign`, joiner-only). Decrypts the wallet's local FROST
/// share, arms handlers for the committee peers, runs its signing party over the
/// shared hub, and returns the 64-byte Ed25519 signature. ed25519 only.
///
/// Note: the standard ClawdWallet mobile share is Type=RemoteKey (sealed to the
/// wdrone), which cannot be opened on-device — decrypt errors, matching Go's
/// opener (which has no RemoteKey arm). A locally-held FROST share (Plain /
/// Password / StoreKey) signs normally.
pub fn join_sign(
    env: &Arc<Env>,
    wallet_id: &str,
    remote_key: &str,
    peers: &[JoinPeer],
    curve: &str,
    digest: &[u8],
) -> Result<Vec<u8>> {
    if remote_key.is_empty() {
        return Err(Error::Env("remote_key is required".into()));
    }
    if digest.len() != 32 {
        return Err(Error::Env(format!("joinSign: digest must be 32 bytes, got {}", digest.len())));
    }
    let curve = if curve.is_empty() { "ed25519" } else { curve };
    if curve != "ed25519" {
        return Err(Error::Env(format!("joinSign: curve {curve:?} not supported in Stage 1 (ed25519 only)")));
    }
    let wallet = crate::models::wallet::fetch(env, wallet_id)?.ok_or_else(|| Error::Env("joinSign: wallet not found".into()))?;
    if wallet.curve != "ed25519" {
        return Err(Error::Env(format!("joinSign: wallet curve is {:?}, expected ed25519", wallet.curve)));
    }

    // Locate the local signing share: the RemoteKey-typed key matching the
    // session (else the first RemoteKey), same as Go.
    let local_key = wallet
        .keys
        .iter()
        .find(|k| k.kind == "RemoteKey" && k.key == remote_key)
        .or_else(|| wallet.keys.iter().find(|k| k.kind == "RemoteKey"))
        .ok_or_else(|| Error::Env("joinSign: no RemoteKey share on wallet".into()))?;
    if local_key.kind == "RemoteKey" {
        // Matches Go: the mobile's own share is wdrone-sealed and cannot be
        // opened locally (the opener has no RemoteKey arm).
        return Err(Error::Env("joinSign: RemoteKey share cannot be opened on-device".into()));
    }
    let share_json = open_local_share(local_key, "")?;
    let key = FrostKey::from_json(&share_json).map_err(|e| Error::Env(format!("joinSign: load frost share: {e:?}")))?;

    let client = env.spot_start().map_err(|e| Error::Env(e.to_string()))?;
    for _ in 0..60 {
        if client.connection_count().1 > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let me_spot = client.target_id();
    let self_spot_id = me_spot.clone();
    let (sorted, by_moniker, me_idx) = build_party_ids(peers, &me_spot, "")?;
    let sid = sid_from_remote_key(remote_key).to_string();
    let me = sorted[me_idx].clone();

    let hub = Hub::new();
    let me_broker = hub.add_local(&me);
    // Joiner mode: arm handlers for the peers (the agent leads, so no init send).
    for (i, id) in sorted.iter().enumerate() {
        if i == me_idx {
            continue;
        }
        let p = by_moniker.get(&id.moniker).ok_or_else(|| Error::Env(format!("joinSign: peer {} missing", id.moniker)))?;
        let rp = Arc::new(WdronePeer {
            hub: Arc::downgrade(&hub),
            party_id: id.clone(),
            client: client.clone(),
            sid: sid.clone(),
            self_spot_id: self_spot_id.clone(),
            peer: Mutex::new(p.spot_id.clone()),
        });
        hub.add_remote(rp.clone());
        rp.arm_handler();
    }

    let params = Parameters::new(sorted.clone(), &me, wallet.threshold.max(0) as usize, me_broker as Arc<dyn MessageBroker + Send + Sync>);
    let sig = key
        .new_signing(digest.to_vec(), params)
        .map_err(|e| Error::Env(format!("joinSign: start signing: {e:?}")))?
        .wait()
        .map_err(|e| Error::Env(format!("joinSign: signing failed: {e:?}")))?;
    if sig.signature.len() != 64 {
        return Err(Error::Env(format!("joinSign: expected 64-byte signature, got {}", sig.signature.len())));
    }
    Ok(sig.signature)
}

#[cfg(test)]
mod keygen_tests {
    use super::*;
    use base64::Engine;

    fn peer(moniker: &str, key: &[u8]) -> JoinPeer {
        JoinPeer {
            spot_id: format!("k.{moniker}"),
            moniker: moniker.into(),
            key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
        }
    }

    #[test]
    fn sid_extraction() {
        assert_eq!(sid_from_remote_key("crws-abc:crwsv-xyz"), "crwsv-xyz");
        assert_eq!(sid_from_remote_key("crwsv-only"), "crwsv-only");
    }

    #[test]
    fn party_ids_sort_by_key_and_locate_me() {
        // Keys chosen so sort order differs from input order.
        let peers = vec![peer("mobile", &[3u8; 32]), peer("agent", &[1u8; 32]), peer("wdrone", &[2u8; 32])];
        // Locate by moniker.
        let (sorted, by_moniker, me_idx) = build_party_ids(&peers, "", "mobile").unwrap();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[me_idx].moniker, "mobile");
        // Sorted ascending by key bytes → agent(1), wdrone(2), mobile(3).
        assert_eq!(sorted.iter().map(|p| p.moniker.as_str()).collect::<Vec<_>>(), ["agent", "wdrone", "mobile"]);
        assert_eq!(by_moniker.len(), 3);
        // Locate by spot id when moniker hint is absent.
        let (_, _, idx2) = build_party_ids(&peers, "k.agent", "").unwrap();
        assert_eq!(idx2, 0);
        // Caller not in list → error.
        assert!(build_party_ids(&peers, "k.stranger", "nobody").is_err());
        // Too few peers → error.
        assert!(build_party_ids(&peers[..1], "", "mobile").is_err());
    }
}
