//! Regression tests for the WalletConnect session-manager audit findings
//! (F1 envelope key agreement, F3 session state/expiry, F4 namespace
//! enforcement, F10 replay), over a mock relay.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use libwallet::models::wc_session;
use libwallet::walletconnect as wc;
use libwallet::wcmanager::WcManager;
use libwallet::Env;

#[derive(Default)]
struct Inner {
    sent: RefCell<Vec<serde_json::Value>>,
    inbox: RefCell<VecDeque<String>>,
}

#[derive(Clone, Default)]
struct MockRelay(Rc<Inner>);
impl MockRelay {
    /// Queue an `irn_subscription` delivering `message` on `topic`.
    fn deliver(&self, topic: &str, message: &str) {
        let frame = serde_json::json!({
            "id": 1, "method": "irn_subscription",
            "params": { "data": { "topic": topic, "message": message, "tag": 1108 } },
        });
        self.0.inbox.borrow_mut().push_back(frame.to_string());
    }
    /// Seal `rpc` Type-0 under `sym` and deliver it on `topic`.
    fn deliver_rpc(&self, topic: &str, sym: &[u8; 32], rpc: serde_json::Value) {
        self.deliver(topic, &wc::seal_type0(sym, rpc.to_string().as_bytes()));
    }
    /// Every `irn_publish` the manager sent on `topic`, decrypted under `sym`.
    #[allow(dead_code)]
    fn published(&self, topic: &str, sym: &[u8; 32]) -> Vec<serde_json::Value> {
        self.0
            .sent
            .borrow()
            .iter()
            .filter(|m| m["method"] == "irn_publish" && m["params"]["topic"] == topic)
            .map(|m| {
                let (pt, _) = wc::open_envelope(Some(sym), None, m["params"]["message"].as_str().unwrap()).unwrap();
                serde_json::from_slice(&pt).unwrap()
            })
            .collect()
    }
}
impl wc::RelayTransport for MockRelay {
    fn send_text(&mut self, text: &str) -> libwallet::Result<()> {
        self.0.sent.borrow_mut().push(serde_json::from_str(text).unwrap());
        Ok(())
    }
    fn recv_text(&mut self) -> libwallet::Result<Option<String>> {
        Ok(self.0.inbox.borrow_mut().pop_front())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn b64url_decode32(s: &str) -> [u8; 32] {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s).unwrap().try_into().unwrap()
}

struct Paired {
    env: Env,
    relay: MockRelay,
    mgr: WcManager<MockRelay>,
    /// Pairing symKey + topic.
    sym: [u8; 32],
    topic: String,
}

/// A fresh env with one pairing row (state "pairing").
fn paired(seed: u8) -> Paired {
    let env = Env::init_memory().unwrap();
    wc_session::init(&env).unwrap();
    let sym: [u8; 32] = (0..32).map(|i| seed.wrapping_add(i)).collect::<Vec<u8>>().try_into().unwrap();
    let topic = wc::derive_topic(&sym);
    let relay = MockRelay::default();
    let mut mgr = WcManager::new(relay.clone());
    mgr.pair(&env, &format!("wc:{topic}@2?relay-protocol=irn&symKey={}", hex(&sym))).unwrap();
    Paired { env, relay, mgr, sym, topic }
}

fn proposal(id: i64, proposer_pub: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "id": id, "jsonrpc": "2.0", "method": "wc_sessionPropose",
        "params": {
            "proposer": { "publicKey": hex(proposer_pub), "metadata": { "name": "dApp" } },
            "requiredNamespaces": { "eip155": {
                "chains": ["eip155:1"], "methods": ["personal_sign", "eth_sendTransaction"], "events": ["chainChanged"]
            }},
        }
    })
}

/// Audit F1: a Type-1 `wc_sessionPropose` forged under the constant key a
/// small-order senderPub produces must not be accepted on a pairing topic — and
/// neither must any other Type-1 frame (the pairing symKey is the only thing
/// authenticating the dApp).
#[test]
fn forged_type1_propose_on_pairing_topic_is_rejected() {
    let mut p = paired(1);
    let nonce = [9u8; 12];

    // (a) senderPub = the zero point: key = HKDF(0^32), computable by anyone.
    let mut key = [0u8; 32];
    purecrypto::kdf::hkdf::<purecrypto::hash::Sha256>(&[], &[0u8; 32], &[], &mut key);
    let aead = purecrypto::cipher::ChaCha20Poly1305::new(&key);
    let (_, attacker_pub) = wc::new_x25519_keypair();
    let mut ct = proposal(666, &attacker_pub).to_string().into_bytes();
    let tag = aead.encrypt(&nonce, &[], &mut ct);
    let mut raw = vec![0x01];
    raw.extend_from_slice(&[0u8; 32]);
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ct);
    raw.extend_from_slice(&tag);
    p.relay.deliver(&p.topic, &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw));
    assert!(p.mgr.pump(&p.env).is_err(), "forged low-order Type-1 propose was accepted");

    // (b) a well-formed Type-1 to the wallet's real proposal key is refused too:
    // pairing topics only speak Type-0.
    let row = wc_session::fetch_by_topic(&p.env, &p.topic).unwrap().unwrap();
    let wallet_pub = b64url_decode32(&row.self_pub);
    let (sender_priv, _) = wc::new_x25519_keypair();
    let (type1, _) =
        wc::seal_type1_with_nonce(&wallet_pub, &sender_priv, &nonce, proposal(667, &attacker_pub).to_string().as_bytes())
            .unwrap();
    p.relay.deliver(&p.topic, &type1);
    assert!(p.mgr.pump(&p.env).is_err(), "Type-1 frame accepted on a pairing topic");

    // Nothing was recorded as a pending proposal.
    assert!(p.mgr.reject(&p.env, &p.topic, 0, "").is_err());
}

/// Audit F1: approving a proposal whose proposer key is a small-order point
/// would settle the session under a publicly computable key.
#[test]
fn approve_rejects_small_order_proposer_key() {
    let mut p = paired(2);
    let low = [0u8; 32];
    p.relay.deliver_rpc(&p.topic, &p.sym, proposal(100, &low));
    let (_, inbound) = p.mgr.pump(&p.env).unwrap().unwrap();
    let wc::WcInbound::Propose { id, params } = inbound else { panic!("expected Propose") };
    let err = p
        .mgr
        .approve(&p.env, &p.topic, id, &params, &["eip155:1:0xabc".to_string()], &[], &[])
        .unwrap_err();
    assert!(format!("{err}").contains("small-order"), "got: {err}");
    assert!(wc_session::list_by_state(&p.env, "active").unwrap().is_empty(), "no session may be stored");
}

// ── F3: session state / expiry ───────────────────────────────────────────────

struct Session {
    p: Paired,
    /// Session topic + symKey (as the dApp derives them).
    topic: String,
    sym: [u8; 32],
}

/// Pair, propose, and approve a session for `eip155:1` with `personal_sign` +
/// `eth_sendTransaction`.
fn established(seed: u8) -> Session {
    let mut p = paired(seed);
    let (dapp_priv, dapp_pub) = wc::new_x25519_keypair();
    p.relay.deliver_rpc(&p.topic, &p.sym, proposal(100, &dapp_pub));
    let (_, inbound) = p.mgr.pump(&p.env).unwrap().unwrap();
    let wc::WcInbound::Propose { id, params } = inbound else { panic!("expected Propose") };
    let wallet_pub = b64url_decode32(&wc_session::fetch_by_topic(&p.env, &p.topic).unwrap().unwrap().self_pub);
    let topic = p.mgr.approve(&p.env, &p.topic, id, &params, &["eip155:1:0xabc".to_string()], &[], &[]).unwrap();
    let sym = wc::derive_sym_key(&dapp_priv, &wallet_pub).unwrap();
    Session { p, topic, sym }
}

fn session_request(id: i64, chain: &str, method: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "jsonrpc": "2.0", "method": "wc_sessionRequest",
        "params": { "request": { "method": method, "params": ["0xdeadbeef", "0xabc"] }, "chainId": chain },
    })
}

fn set_expiry(env: &Env, topic: &str, expiry: &str) {
    env.exec(
        r#"UPDATE "WalletConnect" SET "Expiry" = ?1 WHERE "Topic" = ?2"#,
        vec![libwallet::SqlValue::Text(expiry.into()), libwallet::SqlValue::Text(topic.into())],
    )
    .unwrap();
}

fn state_of(env: &Env, topic: &str) -> String {
    wc_session::fetch_by_topic(env, topic).unwrap().unwrap().state
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// The settle carries an ABSOLUTE Unix expiry (not the relative 604800), and the
/// same instant is stored on the session row.
#[test]
fn settle_expiry_is_absolute_and_stored() {
    let s = established(10);
    let settle = s
        .p
        .relay
        .published(&s.topic, &s.sym)
        .into_iter()
        .find(|m| m["method"] == "wc_sessionSettle")
        .expect("settle published");
    let expiry = settle["params"]["expiry"].as_i64().unwrap();
    let want = unix_now() + 7 * 24 * 60 * 60;
    assert!((expiry - want).abs() < 60, "expiry {expiry} is not ~now+7d ({want})");

    let row = wc_session::fetch_by_topic(&s.p.env, &s.topic).unwrap().unwrap();
    assert_eq!(row.expiry_unix(), Some(expiry));
}

/// A session the wallet disconnected no longer accepts frames, and can no longer
/// be answered on.
#[test]
fn frames_on_a_disconnected_session_are_dropped() {
    let mut s = established(11);
    s.p.relay.deliver_rpc(&s.topic, &s.sym, session_request(1, "eip155:1", "personal_sign"));
    assert!(matches!(s.p.mgr.pump(&s.p.env).unwrap(), Some((_, wc::WcInbound::Request { .. }))));

    s.p.mgr.disconnect(&s.p.env, &s.topic).unwrap();
    s.p.relay.deliver_rpc(&s.topic, &s.sym, session_request(2, "eip155:1", "personal_sign"));
    assert!(s.p.mgr.pump(&s.p.env).is_err(), "request accepted on a disconnected session");
    assert!(s.p.mgr.respond(&s.p.env, &s.topic, 2, serde_json::json!("0x")).is_err());
    assert!(s.p.mgr.respond_error(&s.p.env, &s.topic, 2, 0, "x").is_err());
}

/// An inbound `wc_sessionDelete` is applied: the row flips to disconnected and
/// the session stops taking requests.
#[test]
fn inbound_session_delete_disconnects() {
    let mut s = established(12);
    s.p.relay.deliver_rpc(
        &s.topic,
        &s.sym,
        serde_json::json!({ "id": 5, "jsonrpc": "2.0", "method": "wc_sessionDelete", "params": { "code": 6000, "message": "bye" } }),
    );
    assert!(matches!(s.p.mgr.pump(&s.p.env).unwrap(), Some((_, wc::WcInbound::Delete { id: 5 }))));
    assert_eq!(state_of(&s.p.env, &s.topic), "disconnected");

    s.p.relay.deliver_rpc(&s.topic, &s.sym, session_request(6, "eip155:1", "personal_sign"));
    assert!(s.p.mgr.pump(&s.p.env).is_err(), "request accepted after wc_sessionDelete");
}

/// A session past its stored expiry is torn down on the next frame.
#[test]
fn frames_past_session_expiry_are_rejected() {
    let mut s = established(13);
    set_expiry(&s.p.env, &s.topic, "2020-01-01T00:00:00Z");
    s.p.relay.deliver_rpc(&s.topic, &s.sym, session_request(1, "eip155:1", "personal_sign"));
    assert!(s.p.mgr.pump(&s.p.env).is_err(), "request accepted on an expired session");
    assert_eq!(state_of(&s.p.env, &s.topic), "disconnected");
}

/// A legacy active row with no recorded expiry keeps working.
#[test]
fn legacy_session_without_expiry_still_works() {
    let mut s = established(14);
    set_expiry(&s.p.env, &s.topic, "");
    s.p.relay.deliver_rpc(&s.topic, &s.sym, session_request(1, "eip155:1", "personal_sign"));
    assert!(matches!(s.p.mgr.pump(&s.p.env).unwrap(), Some((_, wc::WcInbound::Request { .. }))));
}

/// A pairing only lives for the 5-minute proposal TTL: after that the proposal
/// is dropped and cannot be approved.
#[test]
fn pairing_expires_after_ttl() {
    // Fresh pairing rows carry an expiry ~5 minutes out.
    let mut p = paired(15);
    let row = wc_session::fetch_by_topic(&p.env, &p.topic).unwrap().unwrap();
    let exp = row.expiry_unix().expect("pairing expiry recorded");
    assert!((exp - (unix_now() + 300)).abs() < 60, "pairing expiry {exp} is not ~now+5m");

    // Expired before the proposal arrives: the proposal is dropped.
    let (_, dapp_pub) = wc::new_x25519_keypair();
    set_expiry(&p.env, &p.topic, "2020-01-01T00:00:00Z");
    p.relay.deliver_rpc(&p.topic, &p.sym, proposal(100, &dapp_pub));
    assert!(p.mgr.pump(&p.env).is_err(), "proposal accepted on an expired pairing");
    assert_eq!(state_of(&p.env, &p.topic), "disconnected");

    // Expired between proposal and approval: the approval is refused.
    let mut p = paired(16);
    p.relay.deliver_rpc(&p.topic, &p.sym, proposal(100, &dapp_pub));
    let (_, inbound) = p.mgr.pump(&p.env).unwrap().unwrap();
    let wc::WcInbound::Propose { id, params } = inbound else { panic!("expected Propose") };
    set_expiry(&p.env, &p.topic, "2020-01-01T00:00:00Z");
    assert!(p.mgr.approve(&p.env, &p.topic, id, &params, &["eip155:1:0xabc".to_string()], &[], &[]).is_err());
    assert!(wc_session::list_by_state(&p.env, "active").unwrap().is_empty());

    // A legacy pairing row (no Expiry) ages out from its Created time.
    let mut p = paired(17);
    p.env
        .exec(
            r#"UPDATE "WalletConnect" SET "Expiry" = '', "Created" = '2020-01-01T00:00:00Z' WHERE "Topic" = ?1"#,
            vec![libwallet::SqlValue::Text(p.topic.clone())],
        )
        .unwrap();
    p.relay.deliver_rpc(&p.topic, &p.sym, proposal(100, &dapp_pub));
    assert!(p.mgr.pump(&p.env).is_err(), "proposal accepted on a stale legacy pairing");
}

/// Once approved (or rejected) the pairing is retired: its symKey no longer
/// authenticates further proposals, and it cannot be approved twice.
#[test]
fn pairing_is_retired_once_used() {
    let mut s = established(18);
    assert_eq!(state_of(&s.p.env, &s.p.topic), "disconnected");
    let (_, other_pub) = wc::new_x25519_keypair();
    s.p.relay.deliver_rpc(&s.p.topic, &s.p.sym, proposal(101, &other_pub));
    assert!(s.p.mgr.pump(&s.p.env).is_err(), "second proposal accepted on a used pairing");
    let params = proposal(101, &other_pub)["params"].clone();
    assert!(s.p.mgr.approve(&s.p.env, &s.p.topic, 101, &params, &["eip155:1:0xabc".to_string()], &[], &[]).is_err());

    // Rejected pairing.
    let mut p = paired(19);
    p.relay.deliver_rpc(&p.topic, &p.sym, proposal(100, &other_pub));
    p.mgr.pump(&p.env).unwrap().unwrap();
    p.mgr.reject(&p.env, &p.topic, 0, "").unwrap();
    assert_eq!(state_of(&p.env, &p.topic), "disconnected");
    p.relay.deliver_rpc(&p.topic, &p.sym, proposal(102, &other_pub));
    assert!(p.mgr.pump(&p.env).is_err(), "proposal accepted on a rejected pairing");
}

/// Frame kinds are tied to the row they belong on: no requests on a pairing
/// topic, no proposals on a settled session.
#[test]
fn frame_kind_must_match_row_state() {
    let mut p = paired(20);
    p.relay.deliver_rpc(&p.topic, &p.sym, session_request(1, "eip155:1", "personal_sign"));
    assert!(p.mgr.pump(&p.env).is_err(), "wc_sessionRequest accepted on a pairing topic");

    let mut s = established(21);
    let (_, other_pub) = wc::new_x25519_keypair();
    s.p.relay.deliver_rpc(&s.topic, &s.sym, proposal(7, &other_pub));
    assert!(s.p.mgr.pump(&s.p.env).is_err(), "wc_sessionPropose accepted on a settled session");
}
