//! WalletConnect v2 session manager — the session state machine over a
//! [`RelayTransport`] (port of wltwc `Manager`). Ties together the pairing store,
//! envelope crypto, relay protocol, inbound dispatch, and namespace/settle
//! builders. Transport-independent, so it drives a real relay in production and
//! a loopback/mock socket in tests. The persistent connection wiring into the
//! FFI `Env` (a background reader thread) is the deployment step on top of this.

use crate::models::wc_session;
use crate::walletconnect as wc;
use crate::{Env, Error, Result};

/// Seven days in seconds — the default WC v2 session lifetime.
const SESSION_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// How many inbound JSON-RPC request ids are remembered per topic for replay
/// detection (oldest forgotten first).
const SEEN_IDS_PER_TOPIC: usize = 1024;

/// A WalletConnect session manager driving one relay connection.
pub struct WcManager<T: wc::RelayTransport> {
    client: wc::RelayClient<T>,
    /// Pending `wc_sessionPropose` ids keyed by pairing topic (mirrors Go's
    /// `proposalsByPairing`) so `reject` can address the right proposal.
    pending_proposals: std::collections::HashMap<String, i64>,
    /// JSON-RPC ids of the peer requests already processed on each topic, so a
    /// frame replayed by the relay (or anyone who captured it) is not acted on
    /// twice. Bounded to [`SEEN_IDS_PER_TOPIC`] per topic; in-memory only.
    seen_ids: std::collections::HashMap<String, std::collections::VecDeque<i64>>,
}

impl<T: wc::RelayTransport> WcManager<T> {
    pub fn new(transport: T) -> Self {
        WcManager {
            client: wc::RelayClient::new(transport),
            pending_proposals: std::collections::HashMap::new(),
            seen_ids: std::collections::HashMap::new(),
        }
    }

    /// `WalletConnect:pair`: parse the pairing URI, generate the wallet's
    /// proposal keypair, persist the pairing session, and subscribe to its
    /// topic. Returns the pairing topic.
    pub fn pair(&mut self, env: &Env, uri: &str) -> Result<String> {
        let p = wc::parse_pairing_uri(uri)?;
        let (self_priv, self_pub) = wc::new_x25519_keypair();
        wc_session::create_pairing(
            env,
            &p.topic,
            &b64url(&p.sym_key),
            &b64url(&self_priv),
            &b64url(&self_pub),
        )?;
        self.client.subscribe(&p.topic)?;
        Ok(p.topic)
    }

    /// Poll one inbound relay frame, decrypt it under the owning session's keys,
    /// and classify it. Returns `(topic, message)` — the session topic the frame
    /// arrived on and the decoded WalletConnect message.
    pub fn pump(&mut self, env: &Env) -> Result<Option<(String, wc::WcInbound)>> {
        let frame = self.client.poll()?;
        let (topic, message) = match frame {
            Some(wc::RelayFrame::Subscription { topic, message, .. }) => (topic, message),
            _ => return Ok(None),
        };
        let s = wc_session::fetch_by_topic(env, &topic)?
            .ok_or_else(|| Error::Env(format!("inbound for unknown topic {topic}")))?;
        // Only a live row takes traffic: a disconnected (or consumed-pairing)
        // row's keys must not keep authenticating frames, and neither may a row
        // past its expiry — that one is torn down on the spot.
        if s.state != "pairing" && s.state != "active" {
            return Err(Error::Env(format!("inbound on {} session dropped", s.state)));
        }
        if s.is_expired(now_unix()) {
            wc_session::set_state(env, &s.id, "disconnected")?;
            self.pending_proposals.remove(&topic);
            self.seen_ids.remove(&topic);
            return Err(Error::Env("inbound on expired session dropped".into()));
        }
        let sym: [u8; 32] = b64url_decode(&s.sym_key)?
            .try_into()
            .map_err(|_| Error::Env("session symKey not 32 bytes".into()))?;
        // Only Type-0 (symmetric) envelopes are accepted, on every topic. Nothing
        // in the wallet-side Sign flow is Type-1: `wc_sessionPropose` arrives
        // Type-0 under the pairing symKey, and the wallet's proposal public key
        // is not disclosed to anyone until the approve response, after which all
        // traffic is Type-0 on the session topic. Offering the proposal private
        // key here would only let a frame bypass the pairing symKey (the sole
        // thing authenticating the dApp), so it is never offered.
        let active = s.state == "active";
        let inbound = wc::process_inbound(&sym, None, active, &message)?;
        // Replay protection: every peer request (anything but a reply to one of
        // ours) is processed at most once per topic. The id is only recorded
        // after the envelope authenticated, so garbage cannot poison the set.
        let request_id = match &inbound {
            wc::WcInbound::Response { .. } => None,
            wc::WcInbound::Propose { id, .. }
            | wc::WcInbound::Settle { id }
            | wc::WcInbound::Request { id, .. }
            | wc::WcInbound::Delete { id }
            | wc::WcInbound::Other { id, .. } => Some(*id),
        };
        if let Some(id) = request_id {
            if !self.first_sighting(&topic, id) {
                return Ok(None);
            }
        }
        match &inbound {
            // A proposal only makes sense on a pairing topic; track it so a
            // later reject can address it.
            wc::WcInbound::Propose { id, .. } => {
                if active {
                    return Err(Error::Env("wc_sessionPropose on a settled session dropped".into()));
                }
                self.pending_proposals.insert(topic.clone(), *id);
            }
            // Requests only exist inside a settled session.
            wc::WcInbound::Request { .. } if !active => {
                return Err(Error::Env("wc_sessionRequest on a pairing topic dropped".into()));
            }
            // …and only for the chains + methods that session approved. Anything
            // else is answered here with the WalletConnect error and never
            // reaches the host.
            wc::WcInbound::Request { id, method, chain_id, .. } => {
                if let Some((code, msg)) = wc::request_violation(&s.namespaces, chain_id, method) {
                    let rpc = wc::build_jsonrpc_error(*id, code, msg);
                    let env0 = wc::seal_type0(&sym, rpc.to_string().as_bytes());
                    self.client.publish(&topic, &env0, wc::TAG_SESSION_RESPONSE, 0)?;
                    return Ok(None);
                }
            }
            // The peer ended the session (Go `handleSessionDelete`): tear it
            // down locally so its keys stop being accepted.
            wc::WcInbound::Delete { .. } => {
                wc_session::set_state(env, &s.id, "disconnected")?;
                self.pending_proposals.remove(&topic);
                self.seen_ids.remove(&topic);
            }
            _ => {}
        }
        Ok(Some((topic, inbound)))
    }

    /// Record `id` as seen on `topic`; false when it was already there (a
    /// replay). Keeps the newest [`SEEN_IDS_PER_TOPIC`] ids per topic.
    fn first_sighting(&mut self, topic: &str, id: i64) -> bool {
        let seen = self.seen_ids.entry(topic.to_owned()).or_default();
        if seen.contains(&id) {
            return false;
        }
        if seen.len() >= SEEN_IDS_PER_TOPIC {
            seen.pop_front();
        }
        seen.push_back(id);
        true
    }

    /// `WalletConnect:approveSession`: settle a pending proposal. Derives the
    /// session key from the proposer's X25519 pubkey, subscribes + persists the
    /// active session, publishes `wc_sessionSettle` on the session topic, and the
    /// proposal response on the pairing topic. Returns the session topic.
    pub fn approve(
        &mut self,
        env: &Env,
        pairing_topic: &str,
        proposal_id: i64,
        proposal: &serde_json::Value,
        accounts: &[String],
        methods: &[String],
        events: &[String],
    ) -> Result<String> {
        let pairing = wc_session::fetch_by_topic(env, pairing_topic)?
            .ok_or_else(|| Error::Env("pairing session not found".into()))?;
        let now = now_unix();
        self.check_pairing_live(env, &pairing, now)?;
        let pairing_sym: [u8; 32] = b64url_decode(&pairing.sym_key)?
            .try_into()
            .map_err(|_| Error::Env("pairing symKey not 32 bytes".into()))?;
        let self_priv: [u8; 32] = b64url_decode(&pairing.self_priv)?
            .try_into()
            .map_err(|_| Error::Env("pairing selfPriv not 32 bytes".into()))?;
        let self_pub = wc::x25519_public(&self_priv);

        // Derive the session key from the proposer's X25519 public key.
        let peer_pub_str = proposal
            .get("proposer")
            .and_then(|p| p.get("publicKey"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Env("proposal missing proposer.publicKey".into()))?;
        let peer_pub = wc::decode_pubkey32(peer_pub_str)
            .ok_or_else(|| Error::Env("bad proposer publicKey".into()))?;
        // Fails for a small-order proposer key (all-zero shared secret), which
        // would otherwise settle the session under a publicly computable key.
        let session_sym = wc::derive_sym_key(&self_priv, &peer_pub)?;
        let session_topic = wc::derive_topic(&session_sym);

        let namespaces = wc::build_namespaces(proposal, accounts, methods, events);
        // WC v2 `expiry` is an ABSOLUTE Unix timestamp (seconds); the same value
        // is stored on the row and enforced on every inbound frame.
        let expiry = now + SESSION_TTL_SECS;
        self.client.subscribe(&session_topic)?;

        // Persist the active session.
        wc_session::create_active(
            env,
            &session_topic,
            pairing_topic,
            &b64url(&session_sym),
            &b64url(&self_priv),
            &b64url(&self_pub),
            &b64url(&peer_pub),
            &namespaces.to_string(),
            &crate::db::unix_to_rfc3339(expiry),
        )?;

        // wc_sessionSettle on the session topic (Type-0 under the session key).
        let settle = serde_json::json!({
            "id": proposal_id,
            "jsonrpc": "2.0",
            "method": "wc_sessionSettle",
            "params": {
                "relay": { "protocol": "irn" },
                "controller": {
                    "publicKey": wc::hex_lower(&self_pub),
                    "metadata": { "name": "libwallet", "description": "", "url": "", "icons": [] },
                },
                "namespaces": namespaces,
                "requiredNamespaces": proposal.get("requiredNamespaces"),
                "optionalNamespaces": proposal.get("optionalNamespaces"),
                "expiry": expiry,
            },
        });
        let settle_env = wc::seal_type0(&session_sym, settle.to_string().as_bytes());
        self.client.publish(&session_topic, &settle_env, wc::TAG_SESSION_SETTLE, 0)?;

        // The proposal response on the pairing topic (Type-0 under the pairing key).
        let response = serde_json::json!({
            "id": proposal_id,
            "jsonrpc": "2.0",
            "result": {
                "relay": { "protocol": "irn" },
                "responderPublicKey": wc::hex_lower(&self_pub),
            },
        });
        let resp_env = wc::seal_type0(&pairing_sym, response.to_string().as_bytes());
        self.client.publish(pairing_topic, &resp_env, wc::TAG_SESSION_SETTLE, 0)?;

        // The pairing has served its purpose: retire it so its symKey stops
        // authenticating further proposals.
        self.pending_proposals.remove(pairing_topic);
        self.seen_ids.remove(pairing_topic);
        wc_session::set_state(env, &pairing.id, "disconnected")?;
        Ok(session_topic)
    }

    /// `WalletConnect:rejectSession`: publish a JSON-RPC error for the pending
    /// proposal on `pairing_topic` (Go `RejectProposal`). Defaults: code 5000,
    /// message "User rejected".
    pub fn reject(&mut self, env: &Env, pairing_topic: &str, code: i64, message: &str) -> Result<()> {
        let proposal_id = self
            .pending_proposals
            .remove(pairing_topic)
            .ok_or_else(|| Error::Env("no pending proposal on that pairing topic".into()))?;
        let pairing = wc_session::fetch_by_topic(env, pairing_topic)?
            .ok_or_else(|| Error::Env("pairing session not found".into()))?;
        self.check_pairing_live(env, &pairing, now_unix())?;
        let sym: [u8; 32] = b64url_decode(&pairing.sym_key)?
            .try_into()
            .map_err(|_| Error::Env("pairing symKey not 32 bytes".into()))?;
        let code = if code == 0 { 5000 } else { code };
        let message = if message.is_empty() { "User rejected" } else { message };
        let rpc = wc::build_jsonrpc_error(proposal_id, code, message);
        let env0 = wc::seal_type0(&sym, rpc.to_string().as_bytes());
        // Retire the pairing whether or not the publish goes through — the
        // proposal is consumed either way.
        wc_session::set_state(env, &pairing.id, "disconnected")?;
        self.client.publish(pairing_topic, &env0, wc::TAG_SESSION_SETTLE, 0)?;
        Ok(())
    }

    /// A pairing row can only be approved/rejected while it is still in the
    /// `pairing` state and inside its TTL; an expired one is retired here.
    fn check_pairing_live(&mut self, env: &Env, pairing: &wc_session::WcSession, now: i64) -> Result<()> {
        if pairing.state != "pairing" {
            return Err(Error::Env(format!("pairing is no longer pending (state {})", pairing.state)));
        }
        if pairing.is_expired(now) {
            wc_session::set_state(env, &pairing.id, "disconnected")?;
            self.pending_proposals.remove(&pairing.topic);
            return Err(Error::Env("pairing expired".into()));
        }
        Ok(())
    }

    /// `WalletConnect:respondError`: publish a JSON-RPC error for a
    /// `wc_sessionRequest` (Go `RespondSessionError`). Default code 5000.
    pub fn respond_error(&mut self, env: &Env, topic: &str, id: i64, code: i64, message: &str) -> Result<()> {
        let sym = self.session_sym(env, topic)?;
        let code = if code == 0 { 5000 } else { code };
        let rpc = wc::build_jsonrpc_error(id, code, message);
        let env0 = wc::seal_type0(&sym, rpc.to_string().as_bytes());
        self.client.publish(topic, &env0, wc::TAG_SESSION_RESPONSE, 0)?;
        Ok(())
    }

    /// `WalletConnect:emitEvent`: publish `wc_sessionEvent` on a session (Go
    /// `EmitSessionEvent`) — used for chainChanged / accountsChanged pushes.
    pub fn emit_event(&mut self, env: &Env, topic: &str, name: &str, data: serde_json::Value, chain_id: &str) -> Result<()> {
        let sym = self.session_sym(env, topic)?;
        let rpc = serde_json::json!({
            "id": rpc_id(),
            "jsonrpc": "2.0",
            "method": "wc_sessionEvent",
            "params": { "event": { "name": name, "data": data }, "chainId": chain_id },
        });
        let env0 = wc::seal_type0(&sym, rpc.to_string().as_bytes());
        self.client.publish(topic, &env0, wc::TAG_SESSION_EVENT, 0)?;
        Ok(())
    }

    /// `WalletConnect:disconnect`: send `wc_sessionDelete` to the peer and mark
    /// the session disconnected locally (Go `Disconnect` + `handleSessionDelete`).
    pub fn disconnect(&mut self, env: &Env, topic: &str) -> Result<()> {
        let s = wc_session::fetch_by_topic(env, topic)?
            .ok_or_else(|| Error::Env("unknown topic".into()))?;
        let sym: [u8; 32] = b64url_decode(&s.sym_key)?
            .try_into()
            .map_err(|_| Error::Env("session symKey not 32 bytes".into()))?;
        let rpc = serde_json::json!({
            "id": rpc_id(),
            "jsonrpc": "2.0",
            "method": "wc_sessionDelete",
            "params": { "code": 6000, "message": "User disconnected" },
        });
        let env0 = wc::seal_type0(&sym, rpc.to_string().as_bytes());
        // Best-effort publish, then always tear down locally.
        let _ = self.client.publish(topic, &env0, wc::TAG_SESSION_DELETE, 0);
        self.seen_ids.remove(topic);
        wc_session::set_state(env, &s.id, "disconnected")?;
        Ok(())
    }

    /// Fetch an active session by topic and decode its 32-byte symmetric key.
    /// A row that is not `active` (pairing / disconnected) is "unknown topic",
    /// as in Go's `sessionByTopic`; one past its expiry is torn down.
    fn session_sym(&self, env: &Env, topic: &str) -> Result<[u8; 32]> {
        let s = wc_session::fetch_by_topic(env, topic)?
            .filter(|s| s.state == "active")
            .ok_or_else(|| Error::Env("unknown topic".into()))?;
        if s.is_expired(now_unix()) {
            wc_session::set_state(env, &s.id, "disconnected")?;
            return Err(Error::Env("session expired".into()));
        }
        b64url_decode(&s.sym_key)?
            .try_into()
            .map_err(|_| Error::Env("session symKey not 32 bytes".into()))
    }

    /// `WalletConnect:respond`: publish a JSON-RPC result for a `wc_sessionRequest`
    /// on an active session (Type-0 under the session key).
    pub fn respond(&mut self, env: &Env, topic: &str, id: i64, result: serde_json::Value) -> Result<()> {
        let sym = self.session_sym(env, topic)?;
        let rpc = wc::build_jsonrpc_result(id, result);
        let env0 = wc::seal_type0(&sym, rpc.to_string().as_bytes());
        self.client.publish(topic, &env0, wc::TAG_SESSION_RESPONSE, 0)?;
        Ok(())
    }

    /// Access the underlying transport (e.g. to read what was sent, in tests).
    pub fn transport(self) -> T {
        self.client.into_transport()
    }
}

/// Format an inbound WalletConnect message as a host event JSON (broadcast by
/// the relay reader thread so the host UI can react to proposals/requests).
///
/// Proposals and requests use the event names and flat shapes the Dart client
/// subscribes to (`wc_session_propose` → `WcSessionProposal`,
/// `wc_session_request` → `WcSessionRequest`); `peer_metadata` is the session's
/// stored dApp metadata, when there is any.
pub fn inbound_event_with(topic: &str, msg: &wc::WcInbound, peer_metadata: serde_json::Value) -> String {
    let (kind, data) = match msg {
        wc::WcInbound::Propose { id, params } => (
            "wc_session_propose",
            serde_json::json!({
                "pairingTopic": topic,
                "proposalId": id,
                "proposer": params.get("proposer").and_then(|p| p.get("metadata")).cloned().unwrap_or_else(|| serde_json::json!({})),
                "proposal": params,
            }),
        ),
        wc::WcInbound::Request { id, method, chain_id, params } => (
            "wc_session_request",
            serde_json::json!({
                "topic": topic,
                "id": id,
                "method": method,
                "chainId": chain_id,
                "params": params,
                "peerMetadata": peer_metadata,
            }),
        ),
        wc::WcInbound::Settle { id } => ("wc_sessionSettle", serde_json::json!({ "topic": topic, "payload": { "id": id } })),
        wc::WcInbound::Delete { id } => ("wc_sessionDelete", serde_json::json!({ "topic": topic, "payload": { "id": id } })),
        wc::WcInbound::Response { id, error } => ("wc_response", serde_json::json!({ "topic": topic, "payload": { "id": id, "error": error } })),
        wc::WcInbound::Other { id, method } => ("wc_other", serde_json::json!({ "topic": topic, "payload": { "id": id, "method": method } })),
    };
    crate::response::event(kind, data)
}

/// [`inbound_event_with`] without session metadata.
pub fn inbound_event(topic: &str, msg: &wc::WcInbound) -> String {
    inbound_event_with(topic, msg, serde_json::json!({}))
}

/// [`inbound_event_with`], taking the dApp metadata from the stored session.
pub fn inbound_event_for(env: &Env, topic: &str, msg: &wc::WcInbound) -> String {
    let meta = wc_session::fetch_by_topic(env, topic)
        .ok()
        .flatten()
        .and_then(|row| serde_json::from_str::<serde_json::Value>(&row.peer_metadata).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    inbound_event_with(topic, msg, meta)
}

/// The current Unix time in seconds (session / pairing expiry checks).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A JSON-RPC id for outbound notifications (Go uses `time.Now().UnixNano()`).
fn rpc_id() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn b64url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Env(format!("base64: {e}")))
}
