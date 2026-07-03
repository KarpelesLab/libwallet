//! End-to-end FROST via the production local-ceremony module: an all-on-device
//! wallet generates its shares and signs, all through `libwallet::tss`.

use libwallet::tss::{
    ed25519_verify, frost_group_pubkey, frost_keygen_local, frost_keygen_with_parties,
    frost_sign_local,
};

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
fn keygen_with_uuid_party_keys_signs() {
    // Production wallets key parties by WalletKey UUID bytes (16 bytes each).
    let uuids: Vec<Vec<u8>> = vec![
        vec![0x11; 16],
        vec![0x22; 16],
        vec![0x33; 16],
    ];
    let shares = frost_keygen_with_parties(uuids, 1).unwrap();
    assert_eq!(shares.len(), 3);
    let gpk = shares[0].1.group_public_key;
    for (_, k) in &shares {
        k.validate_basic().unwrap();
        assert_eq!(k.group_public_key, gpk);
    }
    // A committee formed from these UUID-keyed shares signs.
    let sig = frost_sign_local(&shares[..2], 1, b"msg").unwrap();
    assert_eq!(sig.len(), 64);
}

#[test]
fn frost_signature_verifies_as_standard_ed25519() {
    // The gold-standard proof: a FROST aggregate signature must verify under the
    // compressed group key exactly like any Ed25519 signature. This also proves
    // frost_group_pubkey derives the right Wallet.Pubkey bytes.
    let shares = frost_keygen_local(3, 1).unwrap();
    let pubkey = frost_group_pubkey(&shares[0].1);
    // All shares agree on the group pubkey.
    assert_eq!(frost_group_pubkey(&shares[1].1), pubkey);

    let msg = b"a real transaction hash";
    let sig = frost_sign_local(&shares[..2], 1, msg).unwrap();
    let sig64: [u8; 64] = sig.try_into().unwrap();

    assert!(ed25519_verify(&pubkey, msg, &sig64), "FROST sig must verify under group key");
    assert!(!ed25519_verify(&pubkey, b"tampered", &sig64), "wrong message must fail");
}

#[test]
fn dkls_keygen_then_sign() {
    // DKLs23 (secp256k1 / ECDSA), party-keyed by UUIDs.
    let uuids: Vec<Vec<u8>> = vec![vec![0x11; 16], vec![0x22; 16], vec![0x33; 16]];
    let shares = libwallet::tss::dkls_keygen_local(uuids, 1).unwrap();
    assert_eq!(shares.len(), 3);
    // 33-byte compressed group pubkey.
    let pk = libwallet::tss::dkls_group_pubkey(&shares[0].1).unwrap();
    assert_eq!(pk.len(), 33);
    assert!(pk[0] == 0x02 || pk[0] == 0x03);

    let keys: Vec<_> = shares.iter().map(|(_, k)| k.clone()).collect();
    let hash = [0x9au8; 32]; // a 32-byte message digest
    let (r, s, v) = libwallet::tss::dkls_sign_local(&keys, 1, &hash).unwrap();
    assert_eq!(r.len(), 32);
    assert_eq!(s.len(), 32);
    assert!(v <= 1);
}

#[test]
fn too_small_committee_rejected() {
    let shares = frost_keygen_local(3, 1).unwrap();
    // threshold+1 = 2 required; one share is not enough.
    assert!(frost_sign_local(&shares[..1], 1, b"m").is_err());
}

#[test]
fn frost_import_key_derives_group_pubkey() {
    use libwallet::tss::{frost_group_pubkey, frost_import_key};
    // Import a raw Ed25519 secret as a 1-of-1 FROST key. Its group public key is
    // the imported scalar times G (frosttss import_key sets group_public_key =
    // pub_key). validate_basic confirms the share is well-formed.
    let priv_be: Vec<u8> = (1..=32u8).collect();
    let (_party, key) = frost_import_key(&priv_be, &[9]).unwrap();
    key.validate_basic().unwrap();
    let gpk = frost_group_pubkey(&key);
    assert_eq!(gpk.len(), 32);

    // Import is deterministic: same secret + party -> same group key + share.
    let (_, key2) = frost_import_key(&priv_be, &[9]).unwrap();
    assert_eq!(frost_group_pubkey(&key2), gpk);
    assert_eq!(key2.xi, key.xi);

    // A different secret yields a different group key.
    let other: Vec<u8> = (2..=33u8).collect();
    assert_ne!(frost_group_pubkey(&frost_import_key(&other, &[9]).unwrap().1), gpk);
    // A zero scalar is rejected.
    assert!(frost_import_key(&[0u8; 32], &[9]).is_err());
    // (A 1-of-1 FROST *sign* over LocalHub deadlocks — the single party waits on
    // peers that don't exist — so signing is exercised by the multi-party tests;
    // here we verify the import's key derivation.)
}

#[test]
fn dkls_import_key_produces_valid_group_pubkey() {
    use libwallet::tss::{dkls_group_pubkey, dkls_import_key, dkls_sign_local};
    // A 32-byte secp secret below the curve order.
    let mut priv_be = [0x11u8; 32];
    priv_be[0] = 0x0a;
    let (_, key) = dkls_import_key(&priv_be, &[7]).unwrap();
    let pk = dkls_group_pubkey(&key).unwrap();
    assert_eq!(pk.len(), 33);
    assert!(pk[0] == 0x02 || pk[0] == 0x03, "compressed sec1 prefix");

    // Deterministic.
    let (_, key2) = dkls_import_key(&priv_be, &[7]).unwrap();
    assert_eq!(dkls_group_pubkey(&key2).unwrap(), pk);

    // A 1-of-1 imported key signs a digest (r,s,v well-formed).
    let (r, s, v) = dkls_sign_local(&[key], 0, &[0x5au8; 32]).unwrap();
    assert_eq!((r.len(), s.len()), (32, 32));
    assert!(v <= 1);
}

#[test]
fn frost_key_json_roundtrips() {
    let shares = frost_keygen_local(2, 0).unwrap(); // 1-of-2 (single-sig-like)
    let json = shares[0].1.to_json().unwrap();
    let reloaded = libwallet::tss::Key::from_json(&json).unwrap();
    assert_eq!(reloaded.group_public_key, shares[0].1.group_public_key);
}
