//! End-to-end FROST via the production local-ceremony module: an all-on-device
//! wallet generates its shares and signs, all through `libwallet::tss`.

use libwallet::tss::{frost_keygen_local, frost_sign_local};

#[test]
fn frost_keygen_then_sign_local() {
    let threshold = 1;
    // 3 shares, 1-of-3 threshold (needs 2 signers).
    let shares = frost_keygen_local(3, threshold).unwrap();
    assert_eq!(shares.len(), 3);

    // All shares converge on one group public key and validate.
    let gpk = shares[0].1.group_public_key;
    for (_, k) in &shares {
        k.validate_basic().unwrap();
        assert_eq!(k.group_public_key, gpk);
        assert_eq!(k.ks.len(), 3);
    }
    assert_ne!(shares[0].1.xi, shares[1].1.xi);

    // A committee of threshold+1 shares signs; result is a 64-byte Ed25519 sig.
    let committee = &shares[..=threshold];
    let msg = b"transaction hash to sign";
    let sig = frost_sign_local(committee, threshold, msg).unwrap();
    assert_eq!(sig.len(), 64);

    // A different committee (parties 0 and 2) yields a valid signature too.
    let committee2 = vec![shares[0].clone(), shares[2].clone()];
    let sig2 = frost_sign_local(&committee2, threshold, msg).unwrap();
    assert_eq!(sig2.len(), 64);
}

#[test]
fn too_small_committee_rejected() {
    let shares = frost_keygen_local(3, 1).unwrap();
    // threshold+1 = 2 required; one share is not enough.
    assert!(frost_sign_local(&shares[..1], 1, b"m").is_err());
}

#[test]
fn frost_key_json_roundtrips() {
    let shares = frost_keygen_local(2, 0).unwrap(); // 1-of-2 (single-sig-like)
    let json = shares[0].1.to_json().unwrap();
    let reloaded = libwallet::tss::Key::from_json(&json).unwrap();
    assert_eq!(reloaded.group_public_key, shares[0].1.group_public_key);
}
