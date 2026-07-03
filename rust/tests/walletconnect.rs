//! WalletConnect v2 envelope crypto + pairing URI. The Type-0 envelope and
//! topic vectors come from a Go reference (golang.org/x/crypto/chacha20poly1305
//! + crypto/sha256) over the same fixed symKey/nonce, proving byte-compat.

use libwallet::walletconnect as wc;

fn seq(base: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| base.wrapping_add(i as u8)).collect()
}

#[test]
fn topic_and_type0_match_go_reference() {
    let sym: [u8; 32] = seq(0, 32).try_into().unwrap();
    let nonce: [u8; 12] = seq(100, 12).try_into().unwrap();

    // topic = hex(sha256(symKey)).
    assert_eq!(
        wc::derive_topic(&sym),
        "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
    );

    // Type-0 envelope byte-identical to Go's chacha20poly1305 seal.
    let env = wc::seal_type0_with_nonce(&sym, &nonce, br#"{"id":1,"jsonrpc":"2.0"}"#);
    assert_eq!(env, "AGRlZmdoaWprbG1ub08z0q66n0d+2bRmEJz7qPBS/LAGsWDJ0J2V2HTNN6XyPgpTkFagC/w=");

    // Round-trips back to the plaintext.
    let (pt, sender) = wc::open_envelope(Some(&sym), None, &env).unwrap();
    assert_eq!(pt, br#"{"id":1,"jsonrpc":"2.0"}"#);
    assert!(sender.is_none());

    // A tampered envelope fails authentication.
    let mut bad = env.clone();
    bad.replace_range(20..21, "A");
    assert!(wc::open_envelope(Some(&sym), None, &bad).is_err());
}

#[test]
fn type1_asymmetric_roundtrip() {
    // Recipient (wallet proposal keypair) + sender (dapp ephemeral).
    let recipient_priv: [u8; 32] = seq(1, 32).try_into().unwrap();
    let recipient_pub = wc::x25519_public(&recipient_priv);
    let sender_priv: [u8; 32] = seq(200, 32).try_into().unwrap();
    let nonce: [u8; 12] = seq(7, 12).try_into().unwrap();

    let (env, sender_pub) =
        wc::seal_type1_with_nonce(&recipient_pub, &sender_priv, &nonce, b"session propose");
    assert_eq!(sender_pub, wc::x25519_public(&sender_priv));

    // Recipient decrypts with its private key and recovers the sender's pubkey.
    let (pt, got_sender) = wc::open_envelope(None, Some(&recipient_priv), &env).unwrap();
    assert_eq!(pt, b"session propose");
    assert_eq!(got_sender, Some(sender_pub));

    // Both sides derive the same per-message symKey (ECDH symmetry).
    assert_eq!(
        wc::derive_sym_key(&sender_priv, &recipient_pub),
        wc::derive_sym_key(&recipient_priv, &sender_pub)
    );
}

/// In-memory transport for the client-logic test.
struct MockTransport {
    sent: std::collections::VecDeque<String>,
    inbox: std::collections::VecDeque<String>,
}
impl wc::RelayTransport for MockTransport {
    fn send_text(&mut self, text: &str) -> libwallet::Result<()> {
        self.sent.push_back(text.to_owned());
        Ok(())
    }
    fn recv_text(&mut self) -> libwallet::Result<Option<String>> {
        Ok(self.inbox.pop_front())
    }
}

#[test]
fn relay_client_subscribe_publish_and_dispatch() {
    let mut client = wc::RelayClient::new(MockTransport {
        sent: Default::default(),
        inbox: Default::default(),
    });

    // subscribe + publish assign incrementing ids and emit the right frames.
    let sub_id = client.subscribe("topichex").unwrap();
    let pub_id = client.publish("topichex", "ENV", wc::TAG_SESSION_RESPONSE, 0).unwrap();
    assert_eq!((sub_id, pub_id), (1, 2));

    // A pre-seeded inbox tests poll + auto-ack deterministically.
    let mut inbox = std::collections::VecDeque::new();
    inbox.push_back(
        r#"{"id":9,"method":"irn_subscription","params":{"data":{"topic":"t","message":"m","tag":1108}}}"#.to_string(),
    );
    let mut client = wc::RelayClient::new(MockTransport { sent: Default::default(), inbox });
    let frame = client.poll().unwrap().unwrap();
    assert_eq!(frame, wc::RelayFrame::Subscription { ack_id: 9, topic: "t".into(), message: "m".into(), tag: 1108 });
    // The client auto-acked id 9.
    let t = client.into_transport();
    assert_eq!(t.sent.len(), 1);
    assert_eq!(t.sent[0], wc::build_ack(9).to_string());
}

#[test]
fn relay_client_over_real_websocket_loopback() {
    use std::net::{TcpListener, TcpStream};
    // A local WS server: accepts one connection, echoes the wallet's subscribe
    // as a fact, then pushes an irn_subscription and reads the ack.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut ws = tungstenite::accept(stream).unwrap();
        // Read the subscribe frame the client sends.
        let msg = ws.read().unwrap();
        let text = msg.into_text().unwrap();
        assert!(text.contains("irn_subscribe"), "got {text}");
        assert!(text.contains("mytopic"));
        // Push an inbound subscription event to the wallet.
        ws.send(tungstenite::Message::Text(
            r#"{"id":42,"method":"irn_subscription","params":{"data":{"topic":"mytopic","message":"CIPHER","tag":1108}}}"#.into(),
        ))
        .unwrap();
        // Read the wallet's ack.
        let ack = ws.read().unwrap().into_text().unwrap();
        assert!(ack.contains("\"id\":42"), "ack: {ack}");
        assert!(ack.contains("\"result\":true"));
    });

    let stream = TcpStream::connect(addr).unwrap();
    let (socket, _resp) = tungstenite::client(format!("ws://{addr}/"), stream).unwrap();
    let mut client = wc::RelayClient::new(wc::WsTransport::new(socket));

    client.subscribe("mytopic").unwrap();
    // Poll for the server's pushed subscription (real bytes over the socket).
    let frame = loop {
        if let Some(f) = client.poll().unwrap() {
            break f;
        }
    };
    assert_eq!(
        frame,
        wc::RelayFrame::Subscription { ack_id: 42, topic: "mytopic".into(), message: "CIPHER".into(), tag: 1108 }
    );
    server.join().unwrap();
}

#[test]
fn process_inbound_classifies_and_guards() {
    let sym: [u8; 32] = seq(0, 32).try_into().unwrap();
    let nonce: [u8; 12] = seq(60, 12).try_into().unwrap();

    // A wc_sessionRequest carrying personal_sign.
    let req = br#"{"id":11,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":["0xdeadbeef","0xacct"]}}}"#;
    let env = wc::seal_type0_with_nonce(&sym, &nonce, req);
    let got = wc::process_inbound(&sym, None, true, &env).unwrap();
    assert_eq!(
        got,
        wc::WcInbound::Request {
            id: 11,
            method: "personal_sign".into(),
            params: serde_json::json!(["0xdeadbeef", "0xacct"]),
        }
    );

    // wc_sessionDelete and a reply classify correctly.
    let del = wc::seal_type0_with_nonce(&sym, &nonce, br#"{"id":12,"method":"wc_sessionDelete","params":{}}"#);
    assert_eq!(wc::process_inbound(&sym, None, true, &del).unwrap(), wc::WcInbound::Delete { id: 12 });
    let reply = wc::seal_type0_with_nonce(&sym, &nonce, br#"{"id":13,"jsonrpc":"2.0","result":true}"#);
    assert_eq!(
        wc::process_inbound(&sym, None, true, &reply).unwrap(),
        wc::WcInbound::Response { id: 13, error: None }
    );

    // Envelope type-confusion guard: an active session (self_priv withheld)
    // must reject a Type-1 (asymmetric) envelope.
    let recipient_priv: [u8; 32] = seq(1, 32).try_into().unwrap();
    let recipient_pub = wc::x25519_public(&recipient_priv);
    let sender_priv: [u8; 32] = seq(200, 32).try_into().unwrap();
    let (type1, _) = wc::seal_type1_with_nonce(&recipient_pub, &sender_priv, &nonce, req);
    // Active: no private key -> rejected.
    assert!(wc::process_inbound(&sym, Some(&recipient_priv), true, &type1).is_err());
    // Pre-settle: private key supplied -> opens (it's a propose-time path).
    assert!(wc::process_inbound(&sym, Some(&recipient_priv), false, &type1).is_ok());
}

#[test]
fn jsonrpc_response_builders() {
    assert_eq!(
        wc::build_jsonrpc_result(5, serde_json::json!("0xsig")),
        serde_json::json!({"id":5,"jsonrpc":"2.0","result":"0xsig"})
    );
    assert_eq!(
        wc::build_jsonrpc_error(6, 5000, "user rejected"),
        serde_json::json!({"id":6,"jsonrpc":"2.0","error":{"code":5000,"message":"user rejected"}})
    );
}

#[test]
fn relay_message_builders() {
    // irn_subscribe.
    let sub = wc::build_subscribe(1, "topichex");
    assert_eq!(sub["method"], "irn_subscribe");
    assert_eq!(sub["jsonrpc"], "2.0");
    assert_eq!(sub["params"]["topic"], "topichex");

    // irn_publish: default TTL, prompt=true for sessionRequest.
    let pub_req = wc::build_publish(2, "t", "envelopeb64", wc::TAG_SESSION_REQUEST, 0);
    assert_eq!(pub_req["method"], "irn_publish");
    assert_eq!(pub_req["params"]["ttl"], wc::IRN_DEFAULT_TTL);
    assert_eq!(pub_req["params"]["tag"], wc::TAG_SESSION_REQUEST);
    assert_eq!(pub_req["params"]["prompt"], true);
    // A settle publish does not prompt, and honors an explicit ttl.
    let settle = wc::build_publish(3, "t", "e", wc::TAG_SESSION_SETTLE, 60);
    assert_eq!(settle["params"]["prompt"], false);
    assert_eq!(settle["params"]["ttl"], 60);

    // ack shape.
    let ack = wc::build_ack(42);
    assert_eq!(ack, serde_json::json!({"id":42,"jsonrpc":"2.0","result":true}));
}

#[test]
fn parse_relay_frames() {
    // A relay reply.
    let resp = wc::parse_relay_frame(br#"{"id":7,"jsonrpc":"2.0","result":"subid"}"#).unwrap();
    assert_eq!(resp, wc::RelayFrame::Response { id: 7, error: None });
    // An error reply.
    let err = wc::parse_relay_frame(br#"{"id":8,"error":{"code":-1,"message":"boom"}}"#).unwrap();
    assert_eq!(err, wc::RelayFrame::Response { id: 8, error: Some("boom".into()) });
    // An inbound subscription.
    let note = wc::parse_relay_frame(
        br#"{"id":9,"method":"irn_subscription","params":{"id":"sub","data":{"topic":"abc","message":"ENV","tag":1108}}}"#,
    )
    .unwrap();
    assert_eq!(
        note,
        wc::RelayFrame::Subscription { ack_id: 9, topic: "abc".into(), message: "ENV".into(), tag: 1108 }
    );
}

#[test]
fn end_to_end_frame_to_plaintext() {
    // A dapp seals a request to the pairing symKey and the relay wraps it in an
    // irn_subscription frame; the wallet parses the frame and decrypts it.
    let sym: [u8; 32] = seq(0, 32).try_into().unwrap();
    let nonce: [u8; 12] = seq(50, 12).try_into().unwrap();
    let payload = br#"{"id":1,"jsonrpc":"2.0","method":"personal_sign","params":[]}"#;
    let envelope = wc::seal_type0_with_nonce(&sym, &nonce, payload);
    let topic = wc::derive_topic(&sym);

    let frame = format!(
        r#"{{"id":5,"method":"irn_subscription","params":{{"id":"s","data":{{"topic":"{topic}","message":"{envelope}","tag":1108}}}}}}"#
    );
    let parsed = wc::parse_relay_frame(frame.as_bytes()).unwrap();
    match parsed {
        wc::RelayFrame::Subscription { ack_id, message, tag, .. } => {
            assert_eq!(ack_id, 5);
            assert_eq!(tag, wc::TAG_SESSION_REQUEST);
            let (pt, _) = wc::open_envelope(Some(&sym), None, &message).unwrap();
            assert_eq!(pt, payload);
        }
        other => panic!("expected subscription, got {other:?}"),
    }
}

#[test]
fn build_namespaces_filters_and_intersects() {
    let proposal = serde_json::json!({
        "requiredNamespaces": {
            "eip155": {
                "chains": ["eip155:1", "eip155:137"],
                "methods": ["eth_sendTransaction", "personal_sign", "eth_secretMethod"],
                "events": ["chainChanged", "accountsChanged"]
            }
        },
        "optionalNamespaces": {
            "solana": {
                "chains": ["solana:mainnet"],
                "methods": ["solana_signTransaction"],
                "events": []
            }
        }
    });
    let accounts = vec![
        "eip155:1:0xabc".to_string(),
        "eip155:137:0xabc".to_string(),
        "solana:mainnet:SoLaddr".to_string(),
    ];
    // Wallet allows a subset of methods; empty events allow-list echoes all.
    let methods = vec!["eth_sendTransaction".to_string(), "personal_sign".to_string(), "solana_signTransaction".to_string()];
    let events: Vec<String> = vec![];

    let ns = libwallet::walletconnect::build_namespaces(&proposal, &accounts, &methods, &events);

    // eip155: accounts filtered to eip155:*, methods intersected (secretMethod
    // dropped), events echoed (empty allow-list).
    let eip = &ns["eip155"];
    assert_eq!(eip["accounts"], serde_json::json!(["eip155:1:0xabc", "eip155:137:0xabc"]));
    assert_eq!(eip["methods"], serde_json::json!(["eth_sendTransaction", "personal_sign"]));
    assert_eq!(eip["events"], serde_json::json!(["chainChanged", "accountsChanged"]));
    assert_eq!(eip["chains"], serde_json::json!(["eip155:1", "eip155:137"]));

    // solana from optionalNamespaces: only its account, its method.
    let sol = &ns["solana"];
    assert_eq!(sol["accounts"], serde_json::json!(["solana:mainnet:SoLaddr"]));
    assert_eq!(sol["methods"], serde_json::json!(["solana_signTransaction"]));
}

#[test]
fn parse_pairing_uri_validates() {
    let sym: [u8; 32] = seq(0, 32).try_into().unwrap();
    let topic = wc::derive_topic(&sym);
    let sym_hex: String = sym.iter().map(|b| format!("{b:02x}")).collect();
    let uri = format!("wc:{topic}@2?relay-protocol=irn&symKey={sym_hex}");

    let p = wc::parse_pairing_uri(&uri).unwrap();
    assert_eq!(p.topic, topic);
    assert_eq!(p.version, "2");
    assert_eq!(p.protocol, "irn");
    assert_eq!(p.sym_key, sym);

    // Rejections: wrong scheme, v1, topic/symKey mismatch, missing symKey.
    assert!(wc::parse_pairing_uri("https://example.com").is_err());
    assert!(wc::parse_pairing_uri(&format!("wc:{topic}@1?symKey={sym_hex}")).is_err());
    assert!(wc::parse_pairing_uri(&format!("wc:deadbeef@2?symKey={sym_hex}")).is_err());
    assert!(wc::parse_pairing_uri(&format!("wc:{topic}@2?relay-protocol=irn")).is_err());
}
