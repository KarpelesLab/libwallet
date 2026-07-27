//! Browser (wasm32) TSS ceremonies over spotlib's async transport. Mirrors
//! `reshare::{initiate_keygen, join_sign}` but single-threaded/async: the spotlib
//! `Client` is `!Send`, so it never enters the tsslib broker graph. The broker
//! enqueues addressed outbound frames to a `Send+Sync` channel drained by a
//! `spawn_local` task that owns the `Client`; inbound arrives via `set_handler`;
//! completion is polled with tsslib's non-blocking `try_result()`.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_util::future::{select, Either};
use futures_util::StreamExt;
use serde_json::{json, Value};

use tsslib::frosttss::{Key as FrostKey, Keygen};
use tsslib::tss::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver, Parameters};

use crate::env::Env;
use crate::error::{Error, Result};
use crate::reshare_common::{build_party_ids, open_local_share, sid_from_remote_key, JoinPeer};

/// An addressed outbound frame queued for the drainer task.
struct OutMsg { target: String, sender: String, body: Vec<u8> }

#[derive(Default)]
struct Inner {
    handlers: HashMap<String, Arc<dyn MessageReceiver + Send + Sync>>,
    pending: HashMap<String, Vec<JsonMessage>>,
}

/// Single-local-party wasm ceremony broker (tsslib `MessageBroker`). Outbound
/// (from the local party) is addressed to the wdrone (`single`/`broadcast`) and
/// enqueued; inbound dispatches to the connected handler (buffered until
/// `connect`). Holds only `Send+Sync` state — the `!Send` Client is elsewhere.
struct WasmBroker {
    self_id: String,
    sid: String,
    /// tss PartyId.id -> wdrone spot id (for `single`/to-addressed routing).
    peers: HashMap<String, String>,
    out: UnboundedSender<OutMsg>,
    inner: Mutex<Inner>,
}

impl WasmBroker {
    fn distinct_peers(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.peers.values().filter(|p| seen.insert((*p).clone())).cloned().collect()
    }
    fn enqueue_raw(&self, o: OutMsg) { let _ = self.out.unbounded_send(o); }
    fn enqueue_out(&self, msg: &JsonMessage) {
        let body = match serde_json::to_vec(msg) { Ok(b) => b, Err(_) => return };
        let from_id = msg.from.as_ref().map(|f| f.id.clone()).unwrap_or_default();
        let sender = format!("/{}/{}", self.sid, from_id);
        match msg.to.as_ref() {
            Some(to) => {
                if let Some(peer) = self.peers.get(&to.id) {
                    self.enqueue_raw(OutMsg { target: format!("{peer}/walletsign/{}/single", self.sid), sender, body });
                }
            }
            None => {
                for peer in self.distinct_peers() {
                    self.enqueue_raw(OutMsg { target: format!("{peer}/walletsign/{}/broadcast", self.sid), sender: sender.clone(), body: body.clone() });
                }
            }
        }
    }
    fn dispatch_inbound(&self, msg: JsonMessage) {
        let h = self.inner.lock().unwrap().handlers.get(&msg.typ).cloned();
        match h {
            Some(h) => { let _ = h.receive(&msg); }
            None => { self.inner.lock().unwrap().pending.entry(msg.typ.clone()).or_default().push(msg); }
        }
    }
    /// Feed one inbound serialized frame; `Err(reason)` on a terminal
    /// `walletsign:error`, `Ok` otherwise (non-tss diagnostics are ignored).
    fn deliver_inbound_bytes(&self, bytes: &[u8]) -> std::result::Result<(), String> {
        let jm: JsonMessage = match serde_json::from_slice(bytes) { Ok(m) => m, Err(_) => return Ok(()) };
        if jm.typ.is_empty() { return Ok(()); }
        if jm.typ == "walletsign:error" {
            let r = jm.data.as_str().unwrap_or("").to_string();
            return Err(if r.is_empty() { "remote participant reported an unspecified failure".into() } else { r });
        }
        self.dispatch_inbound(jm);
        Ok(())
    }
}

impl MessageReceiver for WasmBroker {
    fn receive(&self, msg: &JsonMessage) -> BrokerResult {
        if msg.from.as_ref().map(|f| f.id.as_str()) == Some(self.self_id.as_str()) {
            self.enqueue_out(msg);
        } else {
            self.dispatch_inbound(msg.clone());
        }
        Ok(())
    }
}
impl MessageBroker for WasmBroker {
    fn connect(&self, typ: &str, dest: Arc<dyn MessageReceiver + Send + Sync>) {
        let queued = {
            let mut i = self.inner.lock().unwrap();
            i.handlers.insert(typ.to_string(), dest.clone());
            i.pending.remove(typ).unwrap_or_default()
        };
        for m in queued { let _ = dest.receive(&m); }
    }
}

/// Wire the inbound handler + outbound drainer, then run tsslib rounds as inbound
/// frames arrive, polling `poll` (a party's `try_result`) after each until it
/// yields a result. Idle timeout: fail if no inbound frame for 120s.
async fn run_ceremony<T>(
    client: Rc<spotlib::Client>,
    sid: String,
    broker: Arc<WasmBroker>,
    mut out_rx: UnboundedReceiver<OutMsg>,
    mut poll: impl FnMut() -> Option<std::result::Result<T, tsslib::frosttss::Error>>,
) -> Result<T> {
    let (in_tx, mut in_rx) = unbounded::<Vec<u8>>();
    // Inbound: closure captures only the Send+Sync sender (never Client/Env).
    client.set_handler(&sid, Some(move |m: &spotlib::Message| {
        let _ = in_tx.unbounded_send(m.body.clone());
        Ok(None)
    }));
    // Outbound drainer owns the Client; FIFO await preserves frame order.
    {
        let client = client.clone();
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(o) = out_rx.next().await {
                let _ = client.send_to_with_from(&o.target, &o.body, &o.sender, Duration::from_secs(20)).await;
            }
        });
    }
    if let Some(r) = poll() { return r.map_err(|e| Error::Env(format!("ceremony failed: {e:?}"))); }
    loop {
        let timeout = gloo_timers::future::TimeoutFuture::new(120_000);
        match select(in_rx.next(), timeout).await {
            Either::Left((Some(bytes), _)) => {
                if let Err(reason) = broker.deliver_inbound_bytes(&bytes) {
                    return Err(Error::Env(format!("ceremony failed: {reason}")));
                }
                if let Some(r) = poll() { return r.map_err(|e| Error::Env(format!("ceremony failed: {e:?}"))); }
            }
            Either::Left((None, _)) => return Err(Error::Env("ceremony inbound channel closed".into())),
            Either::Right(_) => return Err(Error::Env("ceremony timed out (no progress for 120s)".into())),
        }
    }
}

fn build_peer_map(sorted: &[tsslib::tss::PartyId], by_moniker: &HashMap<String, &JoinPeer>, me_idx: usize) -> Result<HashMap<String, String>> {
    let mut m = HashMap::new();
    for (i, id) in sorted.iter().enumerate() {
        if i == me_idx { continue; }
        let p = by_moniker.get(&id.moniker).ok_or_else(|| Error::Env(format!("peer {} missing", id.moniker)))?;
        if p.spot_id.is_empty() { return Err(Error::Env(format!("peer {} missing spot_id", id.moniker))); }
        m.insert(id.id.clone(), p.spot_id.clone());
    }
    Ok(m)
}

/// `Wallet:initiateKeygen` (wasm): leader-side FROST keygen. Returns
/// `(wallet_id, solana_address, pubkey_b64url)`.
pub async fn initiate_keygen(env: &Env, remote_key: &str, peers: &[JoinPeer], name: &str, curve: &str, me_moniker: &str) -> Result<(String, String, String)> {
    use base64::Engine;
    if remote_key.is_empty() { return Err(Error::Env("remote_key is required".into())); }
    let curve = if curve.is_empty() { "ed25519" } else { curve };
    if curve != "ed25519" { return Err(Error::Env(format!("initiateKeygen: curve {curve:?} not supported (ed25519 only)"))); }

    let client = env.spot_start().map_err(|e| Error::Env(e.to_string()))?;
    client.wait_online(Duration::from_secs(15)).await.map_err(|e| Error::Env(format!("initiateKeygen: spot not online: {e}")))?;
    let me_spot = client.target_id();
    let (sorted, by_moniker, me_idx) = build_party_ids(peers, &me_spot, me_moniker)?;
    let sid = sid_from_remote_key(remote_key).to_string();
    let me = sorted[me_idx].clone();
    let peer_map = build_peer_map(&sorted, &by_moniker, me_idx)?;

    let (out_tx, out_rx) = unbounded::<OutMsg>();
    let broker = Arc::new(WasmBroker { self_id: me.id.clone(), sid: sid.clone(), peers: peer_map, out: out_tx, inner: Mutex::new(Inner::default()) });

    // InitPayload (verbatim peer list) sent to each distinct peer FIRST (before
    // round1 — the FIFO queue preserves this order).
    let peers_json = Value::Array(peers.iter().map(|p| json!({"id": p.spot_id, "moniker": p.moniker, "key": p.key})).collect());
    let info = json!({"sid": sid, "type": "keygen", "curve": "ed25519", "protocol": "frost", "threshold": 1, "peers": peers_json});
    let info_body = serde_json::to_vec(&info).map_err(|e| Error::Env(e.to_string()))?;
    for peer in broker.distinct_peers() {
        broker.enqueue_raw(OutMsg { target: format!("{peer}/walletsign/{}/init", sid), sender: format!("/{}/{}", sid, me.id), body: info_body.clone() });
    }

    let params = Parameters::new(sorted.clone(), &me, 1, broker.clone() as Arc<dyn MessageBroker + Send + Sync>);
    let kg = Keygen::new(params).map_err(|e| Error::Env(format!("initiateKeygen: start keygen: {e:?}")))?;
    let key = run_ceremony(client.clone(), sid.clone(), broker.clone(), out_rx, || kg.try_result()).await?;

    let pk = crate::tss::frost_group_pubkey(&key);
    let pubkey = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk);
    let solana_addr = bs58::encode(pk).into_string();
    let wallet_id = crate::models::wallet::persist_agent_keygen_async(env, name, &pubkey, remote_key, &key).await?;
    Ok((wallet_id, solana_addr, pubkey))
}

/// `Wallet:joinSign` (wasm): mobile joins a FROST signing ceremony. Returns the
/// 64-byte Ed25519 signature. Errors if the mobile's share is RemoteKey-typed
/// (wdrone-sealed, unopenable on-device) — matching native.
pub async fn join_sign(env: &Env, wallet_id: &str, remote_key: &str, peers: &[JoinPeer], curve: &str, digest: &[u8]) -> Result<Vec<u8>> {
    if remote_key.is_empty() { return Err(Error::Env("remote_key is required".into())); }
    if digest.len() != 32 { return Err(Error::Env(format!("joinSign: digest must be 32 bytes, got {}", digest.len()))); }
    let curve = if curve.is_empty() { "ed25519" } else { curve };
    if curve != "ed25519" { return Err(Error::Env(format!("joinSign: curve {curve:?} not supported (ed25519 only)"))); }
    let wallet = crate::models::wallet::fetch(env, wallet_id)?.ok_or_else(|| Error::Env("joinSign: wallet not found".into()))?;
    if wallet.curve != "ed25519" { return Err(Error::Env(format!("joinSign: wallet curve is {:?}, expected ed25519", wallet.curve))); }
    let local_key = wallet.keys.iter().find(|k| k.kind == "RemoteKey" && k.key == remote_key)
        .or_else(|| wallet.keys.iter().find(|k| k.kind == "RemoteKey"))
        .ok_or_else(|| Error::Env("joinSign: no RemoteKey share on wallet".into()))?;
    if local_key.kind == "RemoteKey" {
        return Err(Error::Env("joinSign: RemoteKey share cannot be opened on-device".into()));
    }
    let share_json = open_local_share(local_key, "")?;
    let key = FrostKey::from_json(&share_json).map_err(|e| Error::Env(format!("joinSign: load frost share: {e:?}")))?;

    let client = env.spot_start().map_err(|e| Error::Env(e.to_string()))?;
    client.wait_online(Duration::from_secs(15)).await.map_err(|e| Error::Env(format!("joinSign: spot not online: {e}")))?;
    let me_spot = client.target_id();
    let (sorted, by_moniker, me_idx) = build_party_ids(peers, &me_spot, "")?;
    let sid = sid_from_remote_key(remote_key).to_string();
    let me = sorted[me_idx].clone();
    let peer_map = build_peer_map(&sorted, &by_moniker, me_idx)?;

    let (out_tx, out_rx) = unbounded::<OutMsg>();
    let broker = Arc::new(WasmBroker { self_id: me.id.clone(), sid: sid.clone(), peers: peer_map, out: out_tx, inner: Mutex::new(Inner::default()) });

    let params = Parameters::new(sorted.clone(), &me, wallet.threshold.max(0) as usize, broker.clone() as Arc<dyn MessageBroker + Send + Sync>);
    let signing = key.new_signing(digest.to_vec(), params).map_err(|e| Error::Env(format!("joinSign: start signing: {e:?}")))?;
    let sig = run_ceremony(client.clone(), sid.clone(), broker.clone(), out_rx, || signing.try_result()).await?;
    if sig.signature.len() != 64 { return Err(Error::Env(format!("joinSign: expected 64-byte signature, got {}", sig.signature.len()))); }
    Ok(sig.signature)
}
