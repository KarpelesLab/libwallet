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

/// A WalletConnect session manager driving one relay connection.
pub struct WcManager<T: wc::RelayTransport> {
    client: wc::RelayClient<T>,
}

impl<T: wc::RelayTransport> WcManager<T> {
    pub fn new(transport: T) -> Self {
        WcManager { client: wc::RelayClient::new(transport) }
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
        let sym: [u8; 32] = b64url_decode(&s.sym_key)?
            .try_into()
            .map_err(|_| Error::Env("session symKey not 32 bytes".into()))?;
        // A settled session only accepts Type-0; before settle, offer the
        // proposal private key for the Type-1 sessionPropose.
        let active = s.state == "active";
        let self_priv: Option<[u8; 32]> = if active {
            None
        } else {
            b64url_decode(&s.self_priv).ok().and_then(|v| v.try_into().ok())
        };
        let inbound = wc::process_inbound(&sym, self_priv.as_ref(), active, &message)?;
        Ok(Some((topic, inbound)))
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
        let session_sym = wc::derive_sym_key(&self_priv, &peer_pub);
        let session_topic = wc::derive_topic(&session_sym);

        let namespaces = wc::build_namespaces(proposal, accounts, methods, events);
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
            "", // expiry timestamp (informational); the Unix expiry rides the settle payload
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
                "expiry": SESSION_TTL_SECS,
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

        Ok(session_topic)
    }

    /// `WalletConnect:respond`: publish a JSON-RPC result for a `wc_sessionRequest`
    /// on an active session (Type-0 under the session key).
    pub fn respond(&mut self, env: &Env, topic: &str, id: i64, result: serde_json::Value) -> Result<()> {
        let s = wc_session::fetch_by_topic(env, topic)?
            .ok_or_else(|| Error::Env("session not found".into()))?;
        let sym: [u8; 32] = b64url_decode(&s.sym_key)?
            .try_into()
            .map_err(|_| Error::Env("session symKey not 32 bytes".into()))?;
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
pub fn inbound_event(topic: &str, msg: &wc::WcInbound) -> String {
    let (kind, body) = match msg {
        wc::WcInbound::Propose { id, params } => ("wc_sessionPropose", serde_json::json!({ "id": id, "params": params })),
        wc::WcInbound::Request { id, method, params } => {
            ("wc_sessionRequest", serde_json::json!({ "id": id, "method": method, "params": params }))
        }
        wc::WcInbound::Settle { id } => ("wc_sessionSettle", serde_json::json!({ "id": id })),
        wc::WcInbound::Delete { id } => ("wc_sessionDelete", serde_json::json!({ "id": id })),
        wc::WcInbound::Response { id, error } => ("wc_response", serde_json::json!({ "id": id, "error": error })),
        wc::WcInbound::Other { id, method } => ("wc_other", serde_json::json!({ "id": id, "method": method })),
    };
    crate::response::event(kind, serde_json::json!({ "topic": topic, "payload": body }))
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
