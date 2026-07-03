//! KLB REST request signing — byte-compat with Go `rest.ApiKey`.
//!
//! The expected signature and encoded query come from a Go reference program
//! (crypto/ed25519 + net/url) run over the same fixed seed and params. Matching
//! them proves our signing string, query encoding, and Ed25519 signature are
//! byte-for-byte compatible with the platform's auth.

use std::collections::BTreeMap;

use libwallet::rest::{encode_query, ApiKey};

#[test]
fn sign_query_matches_go_reference() {
    // Fixed seed: bytes 1..=32.
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let key = ApiKey::from_seed("test-key-id", seed);

    let mut q = BTreeMap::new();
    q.insert("_".to_string(), r#"{"chainIndex":"1","amount":"1000"}"#.to_string());
    q.insert("_key".to_string(), "test-key-id".to_string());
    q.insert("_time".to_string(), "1700000000".to_string());
    q.insert("_nonce".to_string(), "fixed-nonce-123".to_string());

    // Query encoding matches Go url.Values.Encode() (sorted keys, %XX escapes).
    assert_eq!(
        encode_query(&q),
        "_=%7B%22chainIndex%22%3A%221%22%2C%22amount%22%3A%221000%22%7D&_key=test-key-id&_nonce=fixed-nonce-123&_time=1700000000"
    );

    // Ed25519 signature over the canonical signing string (GET, empty body).
    let sig = key.sign_query("GET", "Crypto/Okx:quote", &q, b"");
    assert_eq!(sig, "3aFQFyj3ekkm9-BdiFCVQP617Icavgg_YdBWHy5Gn3Li-96JlaN81oqnIpMSF1XTPT6l9c9-r4SHsmbP7Aw0Bg");
}

#[test]
fn query_escape_space_becomes_plus() {
    // Go query-component escaping: space -> '+', unreserved passes through.
    let mut q = BTreeMap::new();
    q.insert("k".to_string(), "a b~c.d".to_string());
    assert_eq!(encode_query(&q), "k=a+b~c.d");
}

#[test]
fn from_secret_b64_takes_seed_prefix() {
    // A 64-byte secret (seed ‖ pubkey) and its 32-byte seed sign identically.
    let mut seed = [7u8; 32];
    seed[0] = 9;
    let full = {
        // seed ‖ arbitrary 32 bytes — only the seed prefix is used.
        let mut v = seed.to_vec();
        v.extend_from_slice(&[0xabu8; 32]);
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, v)
    };
    let k1 = ApiKey::from_seed("id", seed);
    let k2 = ApiKey::from_secret_b64("id", &full).unwrap();
    let mut q = BTreeMap::new();
    q.insert("_key".to_string(), "id".to_string());
    assert_eq!(
        k1.sign_query("GET", "X:y", &q, b""),
        k2.sign_query("GET", "X:y", &q, b"")
    );
}
