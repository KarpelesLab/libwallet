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
