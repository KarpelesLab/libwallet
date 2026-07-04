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
}
