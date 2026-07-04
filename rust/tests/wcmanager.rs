//! Full WalletConnect v2 session handshake through the manager, over a mock
//! transport playing the relay + dApp: pair -> receive sessionPropose -> approve
//! -> the dApp decrypts the wallet's sessionSettle with the mutually-derived key.
//! (The real WebSocket transport is loopback-verified separately.)

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use libwallet::walletconnect as wc;
use libwallet::wcmanager::WcManager;
use libwallet::Env;

#[derive(Default)]
struct Inner {
    sent: RefCell<Vec<serde_json::Value>>,
    inbox: RefCell<VecDeque<String>>,
}

/// A shared-handle mock relay: the test keeps a clone to inject inbound frames
/// and inspect what the manager published.
#[derive(Clone, Default)]
struct MockRelay(Rc<Inner>);
impl MockRelay {
    fn push(&self, frame: &str) {
        self.0.inbox.borrow_mut().push_back(frame.to_owned());
    }
    fn sent(&self) -> Vec<serde_json::Value> {
        self.0.sent.borrow().clone()
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

#[test]
fn full_session_handshake() {
    let env = Env::init_memory().unwrap();
    libwallet::models::wc_session::init(&env).unwrap();

    // Pairing key from the URI, and the dApp's X25519 keypair.
    let sym: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
    let topic = wc::derive_topic(&sym);
    let uri = format!("wc:{topic}@2?relay-protocol=irn&symKey={}", hex(&sym));
    let (dapp_priv, dapp_pub) = wc::new_x25519_keypair();

    let relay = MockRelay::default();
    let mut mgr = WcManager::new(relay.clone());

    // 1. Pair — subscribes to the pairing topic and stores the pairing session.
    let pairing_topic = mgr.pair(&env, &uri).unwrap();
    assert_eq!(pairing_topic, topic);
    let pairing = libwallet::models::wc_session::fetch_by_topic(&env, &topic).unwrap().unwrap();
    assert_eq!(pairing.state, "pairing");
    // The wallet's proposal public key (for the dApp to ECDH against).
    let wallet_pub: [u8; 32] = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &pairing.self_pub,
    )
    .unwrap()
    .try_into()
    .unwrap();

    // 2. The dApp publishes wc_sessionPropose (Type-0 on the pairing topic).
    let propose = serde_json::json!({
        "id": 100, "jsonrpc": "2.0", "method": "wc_sessionPropose",
        "params": {
            "proposer": { "publicKey": hex(&dapp_pub), "metadata": { "name": "dApp" } },
            "requiredNamespaces": { "eip155": {
                "chains": ["eip155:1"], "methods": ["personal_sign"], "events": ["chainChanged"]
            }},
        }
    });
    let env0 = wc::seal_type0(&sym, propose.to_string().as_bytes());
    relay.push(
        &format!(r#"{{"id":1,"method":"irn_subscription","params":{{"data":{{"topic":"{topic}","message":"{env0}","tag":1100}}}}}}"#),
    );

    // 3. Pump — decrypt + classify the proposal.
    let (t, inbound) = mgr.pump(&env).unwrap().unwrap();
    assert_eq!(t, topic);
    let (id, params) = match inbound {
        wc::WcInbound::Propose { id, params } => (id, params),
        other => panic!("expected Propose, got {other:?}"),
    };
    assert_eq!(id, 100);

    // 4. Approve — derive the session key, publish settle + response, store session.
    let accounts = vec!["eip155:1:0xabc".to_string()];
    let session_topic = mgr
        .approve(&env, &topic, id, &params, &accounts, &["personal_sign".to_string()], &[])
        .unwrap();
    let active = libwallet::models::wc_session::fetch_by_topic(&env, &session_topic).unwrap().unwrap();
    assert_eq!(active.state, "active");

    // The dApp derives the SAME session key and decrypts the wallet's settle —
    // proving the X25519 + HKDF agreement is correct end to end.
    let session_sym = wc::derive_sym_key(&dapp_priv, &wallet_pub);
    assert_eq!(wc::derive_topic(&session_sym), session_topic);

    let sent = relay.sent();
    // Find the settle publish (on the session topic) and decrypt it.
    let settle_pub = sent
        .iter()
        .find(|m| m["method"] == "irn_publish" && m["params"]["topic"] == session_topic)
        .expect("settle published on session topic");
    let settle_env = settle_pub["params"]["message"].as_str().unwrap();
    let (pt, _) = wc::open_envelope(Some(&session_sym), None, settle_env).unwrap();
    let settle: serde_json::Value = serde_json::from_slice(&pt).unwrap();
    assert_eq!(settle["method"], "wc_sessionSettle");
    assert_eq!(settle["params"]["namespaces"]["eip155"]["accounts"][0], "eip155:1:0xabc");
    assert_eq!(settle["params"]["controller"]["publicKey"], hex(&wallet_pub));

    // Helper: decrypt the last publish on the session topic under the session key.
    let last_session_publish = |relay: &MockRelay| -> serde_json::Value {
        let m = relay
            .sent()
            .into_iter()
            .filter(|m| m["method"] == "irn_publish" && m["params"]["topic"] == session_topic)
            .next_back()
            .expect("a publish on the session topic");
        let env = m["params"]["message"].as_str().unwrap().to_owned();
        let (pt, _) = wc::open_envelope(Some(&session_sym), None, &env).unwrap();
        serde_json::from_slice(&pt).unwrap()
    };

    // 5. respondError — a JSON-RPC error for a session request.
    mgr.respond_error(&env, &session_topic, 100, 4001, "User rejected request").unwrap();
    let err = last_session_publish(&relay);
    assert_eq!(err["id"], 100);
    assert_eq!(err["error"]["code"], 4001);
    assert_eq!(err["error"]["message"], "User rejected request");

    // 6. emitEvent — wc_sessionEvent (chainChanged) on the session.
    mgr.emit_event(&env, &session_topic, "chainChanged", serde_json::json!("0x1"), "eip155:1").unwrap();
    let ev = last_session_publish(&relay);
    assert_eq!(ev["method"], "wc_sessionEvent");
    assert_eq!(ev["params"]["event"]["name"], "chainChanged");
    assert_eq!(ev["params"]["event"]["data"], "0x1");
    assert_eq!(ev["params"]["chainId"], "eip155:1");

    // 7. disconnect — wc_sessionDelete + local state flips to "disconnected".
    mgr.disconnect(&env, &session_topic).unwrap();
    let del = last_session_publish(&relay);
    assert_eq!(del["method"], "wc_sessionDelete");
    assert_eq!(del["params"]["code"], 6000);
    let gone = libwallet::models::wc_session::fetch_by_topic(&env, &session_topic).unwrap().unwrap();
    assert_eq!(gone.state, "disconnected");
}

/// A second pairing that the wallet rejects: the JSON-RPC error is published on
/// the pairing topic under the pairing key, addressing the pending proposal id.
#[test]
fn reject_pending_proposal() {
    let env = Env::init_memory().unwrap();
    libwallet::models::wc_session::init(&env).unwrap();

    let sym: [u8; 32] = (10u8..42).collect::<Vec<_>>().try_into().unwrap();
    let topic = wc::derive_topic(&sym);
    let uri = format!("wc:{topic}@2?relay-protocol=irn&symKey={}", hex(&sym));
    let (_dapp_priv, dapp_pub) = wc::new_x25519_keypair();

    let relay = MockRelay::default();
    let mut mgr = WcManager::new(relay.clone());
    mgr.pair(&env, &uri).unwrap();

    // Rejecting before any proposal arrives is an error.
    assert!(mgr.reject(&env, &topic, 0, "").is_err());

    // dApp sends a proposal; pump records it as pending.
    let propose = serde_json::json!({
        "id": 777, "jsonrpc": "2.0", "method": "wc_sessionPropose",
        "params": { "proposer": { "publicKey": hex(&dapp_pub) },
            "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign"], "events": [] } } }
    });
    let env0 = wc::seal_type0(&sym, propose.to_string().as_bytes());
    relay.push(&format!(r#"{{"id":1,"method":"irn_subscription","params":{{"data":{{"topic":"{topic}","message":"{env0}","tag":1100}}}}}}"#));
    mgr.pump(&env).unwrap().unwrap();

    // Reject with default code/message.
    mgr.reject(&env, &topic, 0, "").unwrap();
    let m = relay
        .sent()
        .into_iter()
        .filter(|m| m["method"] == "irn_publish" && m["params"]["topic"] == topic)
        .next_back()
        .expect("reject published on pairing topic");
    let env_msg = m["params"]["message"].as_str().unwrap().to_owned();
    let (pt, _) = wc::open_envelope(Some(&sym), None, &env_msg).unwrap();
    let reject: serde_json::Value = serde_json::from_slice(&pt).unwrap();
    assert_eq!(reject["id"], 777);
    assert_eq!(reject["error"]["code"], 5000);
    assert_eq!(reject["error"]["message"], "User rejected");

    // The proposal is consumed — a second reject fails.
    assert!(mgr.reject(&env, &topic, 0, "").is_err());
}
