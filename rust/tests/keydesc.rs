//! KeyDescription resolution: each scheme resolves to the recipient a share is
//! sealed to, and a StoreKey/Password share round-trips (seal -> open).

use libwallet::keystore;
use libwallet::sign::{KeyDescription, Recipient};

#[test]
fn store_key_resolves_and_roundtrips() {
    // A device holds an Ed25519 keypair; its PKIX public key (base64url) is the
    // StoreKey descriptor.
    let device = keystore::ed25519_from_seed([3u8; 32]);
    let pkix_b64 = keystore::public_key_to_pkix_b64(&device.public()).unwrap();

    let kd = KeyDescription { kind: "StoreKey".into(), key: pkix_b64, id: String::new() };
    let recipient = match kd.resolve(b"walletkey-id").unwrap() {
        Recipient::Encrypt(pk) => pk,
        _ => panic!("StoreKey should encrypt"),
    };

    let share = b"frost key share json";
    let sealed = keystore::seal(share, &[recipient]).unwrap();
    // Only the device key opens it.
    let opened = keystore::open(&sealed, [keystore::ed25519_from_seed([3u8; 32])]).unwrap();
    assert_eq!(opened, share);
}

#[test]
fn password_resolves_and_roundtrips() {
    let salt = b"walletkey-uuid";
    let kd = KeyDescription { kind: "Password".into(), key: "hunter2hunter".into(), id: String::new() };
    let recipient = match kd.resolve(salt).unwrap() {
        Recipient::Encrypt(pk) => pk,
        _ => panic!("Password should encrypt"),
    };
    let sealed = keystore::seal(b"share", &[recipient]).unwrap();

    // The same password+salt re-derives the opening key.
    let unlock = keystore::password_to_ed25519("hunter2hunter", salt).unwrap();
    assert_eq!(keystore::open(&sealed, [unlock]).unwrap(), b"share");
}

#[test]
fn plain_and_remote_and_unknown() {
    assert!(matches!(
        KeyDescription { kind: "Plain".into(), ..Default::default() }.resolve(b"s").unwrap(),
        Recipient::Plain
    ));
    assert!(matches!(
        KeyDescription { kind: "RemoteKey".into(), ..Default::default() }.resolve(b"s").unwrap(),
        Recipient::Remote
    ));
    assert!(KeyDescription { kind: "Bogus".into(), ..Default::default() }.resolve(b"s").is_err());
}

#[test]
fn key_description_json_matches_go_keys() {
    // Parses from the Wallet:create params shape.
    let kd: KeyDescription =
        serde_json::from_str(r#"{"Type":"StoreKey","Key":"AAAA","Id":"x"}"#).unwrap();
    assert_eq!(kd.kind, "StoreKey");
    assert_eq!(kd.key, "AAAA");
    assert_eq!(kd.id, "x");
}
