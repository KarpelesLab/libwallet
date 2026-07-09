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
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde_json::{json, Value};
use tsslib::frosttss::{Key as FrostKey, Resharing};
use tsslib::tss::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver, PartyId, ReSharingParameters};

use crate::sign::KeyDescription;
use crate::{Env, Error, Result};

/// Per-operation router: local (in-process) brokers + remote (Spot) wdrone
/// peers, keyed by tss `PartyId.id` (Go `tssHub`).
pub struct Hub {
    local: Mutex<HashMap<String, Arc<LocalBroker>>>,
    remote: Mutex<HashMap<String, Arc<WdronePeer>>>,
}

impl Hub {
    fn new() -> Arc<Hub> {
        Arc::new(Hub { local: Mutex::new(HashMap::new()), remote: Mutex::new(HashMap::new()) })
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
    /// selectPeer (ping the fleet) + the `walletsign/<sid>/init` handshake. Arms
    /// the inbound handler first so a wdrone that replies with a round-1 frame
    /// the instant it processes init finds a handler waiting.
    fn start(self: &Arc<Self>, base: &str, client_id: Option<&str>, info: &Value) -> Result<()> {
        // Arm inbound: the wdrone replies to our sender path <self>/<sid>/<party>,
        // so our client dispatches those on the first segment == sid.
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

        let peer = select_peer(base, client_id, &self.client)?;
        *self.peer.lock().unwrap() = peer.clone();

        let body = serde_json::to_vec(info).map_err(|e| Error::Env(e.to_string()))?;
        let target = format!("{peer}/walletsign/{}/init", self.sid);
        self.client
            .query(&target, &body, Duration::from_secs(15))
            .map_err(|e| Error::Env(format!("reshare: wdrone init failed: {e}")))?;
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

    let cx = setup_ceremony(env, &wallet, old_keys, new_keys, threshold, "ed25519", "frost")?;

    // Spawn resharing parties: new committee (input None) + local old committee
    // (input = decrypted old share). Each runs on its own thread.
    let mut handles: Vec<std::thread::JoinHandle<std::result::Result<Option<FrostKey>, String>>> = Vec::new();
    for p in &cx.new_sorted {
        let broker = cx.hub.local.lock().unwrap().get(&p.id).cloned().unwrap();
        let params = ReSharingParameters::new(cx.old_sorted.clone(), cx.new_sorted.clone(), threshold, threshold, p.clone(), broker as Arc<dyn MessageBroker + Send + Sync>);
        handles.push(std::thread::spawn(move || {
            Resharing::new(params, None).map_err(|e| format!("{e:?}"))?.wait().map_err(|e| format!("{e:?}"))
        }));
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
        handles.push(std::thread::spawn(move || {
            Resharing::new(params, Some(key)).map_err(|e| format!("{e:?}"))?.wait().map_err(|e| format!("{e:?}"))
        }));
    }

    let mut new_shares: HashMap<String, FrostKey> = HashMap::new();
    for (i, h) in handles.into_iter().enumerate() {
        let key = h.join().map_err(|_| Error::Env("reshare party thread panicked".into()))?.map_err(|e| Error::Env(format!("reshare failed: {e}")))?;
        if i < cx.new_sorted.len() {
            if let Some(k) = key {
                new_shares.insert(cx.new_sorted[i].id.clone(), k);
            }
        }
    }
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

    let cx = setup_ceremony(env, &wallet, old_keys, new_keys, threshold, "secp256k1", "dkls23")?;

    let mut handles: Vec<std::thread::JoinHandle<std::result::Result<Option<DklsKey>, String>>> = Vec::new();
    for p in &cx.new_sorted {
        let broker = cx.hub.local.lock().unwrap().get(&p.id).cloned().unwrap();
        let params = ReSharingParameters::new(cx.old_sorted.clone(), cx.new_sorted.clone(), threshold, threshold, p.clone(), broker as Arc<dyn MessageBroker + Send + Sync>);
        let pub_pt = old_ecdsa_pub.clone();
        handles.push(std::thread::spawn(move || {
            ResharingParty::new(params, pub_pt, None).map_err(|e| format!("{e:?}"))?.wait().map_err(|e| format!("{e:?}"))
        }));
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
        handles.push(std::thread::spawn(move || {
            ResharingParty::new(params, pub_pt, Some(key)).map_err(|e| format!("{e:?}"))?.wait().map_err(|e| format!("{e:?}"))
        }));
    }

    let mut new_shares: HashMap<String, DklsKey> = HashMap::new();
    for (i, h) in handles.into_iter().enumerate() {
        let key = h.join().map_err(|_| Error::Env("reshare party thread panicked".into()))?.map_err(|e| Error::Env(format!("reshare failed: {e}")))?;
        if i < cx.new_sorted.len() {
            if let Some(k) = key {
                new_shares.insert(cx.new_sorted[i].id.clone(), k);
            }
        }
    }
    crate::models::wallet::persist_reshared_dkls(env, &wallet, new_keys, &cx.new_wk_ids, &cx.new_parties, &new_shares)?;
    Ok(())
}

/// Open a locally-held (Plain/Password/StoreKey) FROST share to its JSON.
#[allow(clippy::ptr_arg)]
fn open_local_share(wk: &crate::models::wallet::WalletKey, material: &str) -> Result<String> {
    let xid: xuid::Xuid = wk.id.parse().map_err(|e| Error::Env(format!("bad walletkey id: {e}")))?;
    let uuid = xid.uuid().as_bytes().to_vec();
    let json = if wk.kind == "Plain" {
        crate::keystore::open(&wk.data, []).map_err(|e| Error::Env(e.to_string()))?
    } else {
        let k = crate::models::wallet::resolve_unlock_key(&wk.kind, material, &uuid)?;
        crate::keystore::open(&wk.data, [k]).map_err(|e| Error::Env(e.to_string()))?
    };
    String::from_utf8(json).map_err(|e| Error::Env(e.to_string()))
}
