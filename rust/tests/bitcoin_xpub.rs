//! Bitcoin xpub serialization — byte-compat with BIP-32.
//!
//! Go `Account.Xpub` (ecckd.FromPublicKey) emits a depth-0, zero-fingerprint,
//! zero-child-number extended public key — exactly the shape of a BIP-32 master
//! xpub. So BIP-32 test vector 1's master pubkey + chain code must serialize to
//! its published xpub string, proving our encoding matches byte-for-byte.

use libwallet::bitcoin::build_xpub;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn build_xpub_matches_bip32_vector1_master() {
    // BIP-32 test vector 1, master (m):
    let pubkey = unhex("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
    let chaincode = unhex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    let pk: [u8; 33] = pubkey.try_into().unwrap();
    let cc: [u8; 32] = chaincode.try_into().unwrap();

    // Matches secp256k1/ecckd testVec1MasterPubKey exactly (the value Go emits).
    let xpub = build_xpub(&pk, &cc);
    assert_eq!(
        xpub,
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    );
    assert!(xpub.starts_with("xpub"));
    assert_eq!(xpub.len(), 111);
}
