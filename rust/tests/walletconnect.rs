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
