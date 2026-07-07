//! BIP-39 mnemonic decode + seed + master, against canonical test vectors.

use libwallet::bip39::{entropy_to_mnemonic, master_from_seed, mnemonic_to_entropy, mnemonic_to_seed};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn trezor_vector_entropy_and_seed() {
    // The canonical all-"abandon" 12-word mnemonic (Trezor vector, entropy 0).
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert_eq!(hex(&mnemonic_to_entropy(m).unwrap()), "00000000000000000000000000000000");
    // entropy_to_mnemonic is the exact inverse (round-trips both ways).
    assert_eq!(entropy_to_mnemonic(&[0u8; 16]).unwrap(), m);
    let ent = unhex("f30f8c1da665478f49b001d94c5fc452");
    assert_eq!(mnemonic_to_entropy(&entropy_to_mnemonic(&ent).unwrap()).unwrap(), ent);

    // Seed with passphrase "TREZOR".
    let seed = mnemonic_to_seed(m, "TREZOR");
    assert_eq!(
        hex(&seed),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );

    // A tampered mnemonic fails the checksum.
    let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(mnemonic_to_entropy(bad).is_err());
    // An out-of-list word is rejected.
    assert!(mnemonic_to_entropy("zzzz abandon about").is_err());
}

#[test]
fn bip32_master_from_seed_vector1() {
    // BIP-32 test vector 1: seed 000102...0f -> master private key + chain code.
    let seed = unhex("000102030405060708090a0b0c0d0e0f");
    let (master, cc) = master_from_seed(&seed, "secp256k1").unwrap();
    assert_eq!(hex(&master), "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    assert_eq!(hex(&cc), "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");

    // ed25519 (SLIP-0010) uses the "ed25519 seed" HMAC key — different master.
    let (ed_master, _) = master_from_seed(&seed, "ed25519").unwrap();
    assert_ne!(hex(&ed_master), hex(&master));
    // SLIP-0010 vector 1 (ed25519) master: 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
    assert_eq!(hex(&ed_master), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
}
