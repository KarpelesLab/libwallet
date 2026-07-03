//! Round-trip of the key-share storage crypto: a payload sealed to a
//! password-derived Ed25519 key must decrypt only with the same key.

use libwallet::keystore;

#[test]
fn password_seal_open_roundtrip() {
    let salt = b"walletkey-uuid-bytes"; // stand-in for the WalletKey UUID
    let key = keystore::password_to_ed25519("correct horse", salt).unwrap();
    let recipient = key.public();

    let payload = b"encrypted TSS share bytes";
    let sealed = keystore::seal(payload, &[recipient]).unwrap();
    assert!(!sealed.is_empty());
    // The plaintext must not appear in the CBOR bottle.
    assert!(!sealed.windows(payload.len()).any(|w| w == payload));

    // Re-derive the same key and open.
    let key_again = keystore::password_to_ed25519("correct horse", salt).unwrap();
    let recovered = keystore::open(&sealed, [key_again]).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn wrong_password_cannot_open() {
    let salt = b"walletkey-uuid-bytes";
    let key = keystore::password_to_ed25519("correct horse", salt).unwrap();
    let sealed = keystore::seal(b"secret", &[key.public()]).unwrap();

    let wrong = keystore::password_to_ed25519("wrong horse", salt).unwrap();
    assert!(keystore::open(&sealed, [wrong]).is_err());
}

#[test]
fn short_password_rejected() {
    assert!(keystore::password_to_ed25519("abc", b"salt").is_err());
}

#[test]
fn seed_key_roundtrip() {
    // StoreKey path: a raw 32-byte seed.
    let seed = [7u8; 32];
    let key = keystore::ed25519_from_seed(seed);
    let sealed = keystore::seal(b"share", &[key.public()]).unwrap();
    let recovered = keystore::open(&sealed, [keystore::ed25519_from_seed(seed)]).unwrap();
    assert_eq!(recovered, b"share");
}
