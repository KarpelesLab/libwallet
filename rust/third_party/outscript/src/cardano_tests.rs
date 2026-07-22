//! Tests for Cardano addresses and transactions, ported from `cardano_test.go`
//! and `cardanotx_test.go`.

use crate::cardano::{
    cardano_base_address, cardano_enterprise_address, cardano_key_hash, cardano_reward_address,
    parse_cardano_address,
};
use crate::cardano_derive::{
    CardanoExtendedKey, cardano_harden as harden, cardano_icarus_master_key,
};
use crate::cardanotx::{CardanoAsset, CardanoInput, CardanoOutput, CardanoSigner, CardanoTx};
use crate::cbor::split_array_items;
use crate::crypto::ed25519;
use crate::hash::blake2b_256;
use crate::script::Script;

// Raw 32-byte Ed25519 public keys decoded from the CIP-19 reference bech32 keys
// addr_vk1w0l2sr2... and stake_vk1px4j0r2...
const CIP19_ADDR_VK: &str = "73fea80d424276ad0978d4fe5310e8bc2d485f5f6bb3bf87612989f112ad5a7d";
const CIP19_STAKE_VK: &str = "09ab278d49b7b86a055185c474c4942281ddfa05a54684c7e8a6f230625aee57";

fn payment_hash() -> [u8; 28] {
    cardano_key_hash(&hex::decode(CIP19_ADDR_VK).unwrap())
}
fn stake_hash() -> [u8; 28] {
    cardano_key_hash(&hex::decode(CIP19_STAKE_VK).unwrap())
}

#[test]
fn cip19_address_vectors() {
    let p = payment_hash();
    let s = stake_hash();

    assert_eq!(
        cardano_base_address(&p, &s, "cardano").unwrap(),
        "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
    );
    assert_eq!(
        cardano_enterprise_address(&p, "cardano").unwrap(),
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
    );
    assert_eq!(
        cardano_reward_address(&s, "cardano").unwrap(),
        "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
    );
    assert_eq!(
        cardano_base_address(&p, &s, "cardano-testnet").unwrap(),
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"
    );
    assert_eq!(
        cardano_reward_address(&s, "cardano-testnet").unwrap(),
        "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"
    );
}

#[test]
fn cardano_from_pubkey() {
    let payment_key = hex::decode(CIP19_ADDR_VK).unwrap();
    let s = Script::new(crate::pubkey::PubKey::Ed25519(
        payment_key.clone().try_into().unwrap(),
    ));

    // default (mainnet) enterprise address via the format
    assert_eq!(
        s.address("cardano", &[]).unwrap(),
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
    );

    // testnet enterprise: validate via parse round-trip (same payment hash, net 0)
    let got_test = s.address("cardano", &["cardano-testnet"]).unwrap();
    let out = parse_cardano_address(&got_test).unwrap();
    assert_eq!(
        hex::encode(out.hash().unwrap()),
        "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
    );
}

#[test]
fn cardano_parse_round_trip() {
    let addrs = [
        "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
        "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw",
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae",
        "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn",
    ];
    for a in addrs {
        let out = parse_cardano_address(a).unwrap();
        assert_eq!(out.address(&[]).unwrap(), a, "round-trip mismatch for {a}");
    }
}

#[test]
fn cardano_real_tx_body_hash() {
    // A Cardano transaction id is blake2b-256 of the body's exact CBOR bytes.
    // Mainnet tx b94c3185280a4217d5ab922619f74d768e0a7189f653c644c4f2aaccc7498217.
    const WANT_TXID: &str = "b94c3185280a4217d5ab922619f74d768e0a7189f653c644c4f2aaccc7498217";
    let raw = include_str!("../testdata/cardano_mainnet_tx.hex");
    let buf = hex::decode(raw.trim()).unwrap();
    let arr = split_array_items(&buf).unwrap();
    assert_eq!(arr.len(), 4);
    assert_eq!(hex::encode(blake2b_256(&arr[0])), WANT_TXID);
}

fn addr_bytes(addr: &str) -> Vec<u8> {
    parse_cardano_address(addr).unwrap().bytes().to_vec()
}

fn sample_tx() -> CardanoTx {
    let txid =
        hex::decode("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376").unwrap();
    CardanoTx {
        inputs: vec![CardanoInput { txid, index: 0 }],
        outputs: vec![
            CardanoOutput {
                address: addr_bytes("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
                amount: 1_000_000,
                assets: vec![],
            },
            CardanoOutput {
                address: addr_bytes(
                    "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
                ),
                amount: 8_500_000,
                assets: vec![],
            },
        ],
        fee: 170_000,
        ttl: 41_000_000,
        witnesses: vec![],
    }
}

#[test]
fn cardano_tx_sign_and_verify() {
    let mut tx = sample_tx();
    let seed = [0x42u8; 32];
    let pub_key = ed25519::public_from_seed(&seed);

    let digest = tx.sign_bytes().unwrap();
    assert_eq!(digest.len(), 32);

    tx.sign(&[seed]).unwrap();
    assert_eq!(tx.witnesses.len(), 1);
    let w = &tx.witnesses[0];
    assert_eq!(w.vkey, pub_key.to_vec());
    assert!(ed25519::verify(
        &pub_key,
        &digest,
        &w.signature.clone().try_into().unwrap()
    ));
    tx.verify().unwrap();

    // Hash() must equal the signing digest (the transaction id).
    assert_eq!(tx.hash().unwrap(), digest);
}

#[test]
fn cardano_tx_round_trip() {
    let mut tx = sample_tx();
    tx.sign(&[[0x07u8; 32]]).unwrap();

    let enc = tx.to_bytes().unwrap();
    let arr = split_array_items(&enc).unwrap();
    assert_eq!(arr.len(), 4);
    // txid must be blake2b-256 of the embedded body bytes
    assert_eq!(blake2b_256(&arr[0]), tx.hash().unwrap());

    let decoded = CardanoTx::from_bytes(&enc).unwrap();
    assert_eq!(decoded.fee, tx.fee);
    assert_eq!(decoded.ttl, tx.ttl);
    assert_eq!(decoded.inputs.len(), tx.inputs.len());
    assert_eq!(decoded.outputs.len(), tx.outputs.len());
    for (a, b) in decoded.inputs.iter().zip(&tx.inputs) {
        assert_eq!(a.txid, b.txid);
        assert_eq!(a.index, b.index);
    }
    for (a, b) in decoded.outputs.iter().zip(&tx.outputs) {
        assert_eq!(a.address, b.address);
        assert_eq!(a.amount, b.amount);
    }
    assert_eq!(decoded.witnesses.len(), 1);
    assert_eq!(decoded.witnesses[0].signature, tx.witnesses[0].signature);

    // re-marshaling the decoded transaction must be byte-identical (deterministic)
    assert_eq!(decoded.to_bytes().unwrap(), enc);
}

#[test]
fn cardano_tx_multiasset() {
    let txid =
        hex::decode("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376").unwrap();
    let policy = hex::decode("00000000000000000000000000000000000000000000000000000000").unwrap();
    let tx = CardanoTx {
        inputs: vec![CardanoInput { txid, index: 1 }],
        outputs: vec![CardanoOutput {
            address: addr_bytes("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
            amount: 2_000_000,
            assets: vec![CardanoAsset {
                policy_id: policy.clone(),
                asset_name: b"TOKEN".to_vec(),
                amount: 42,
            }],
        }],
        fee: 180_000,
        ttl: 0,
        witnesses: vec![],
    };
    let enc = tx.to_bytes().unwrap();
    let decoded = CardanoTx::from_bytes(&enc).unwrap();
    assert_eq!(decoded.outputs.len(), 1);
    assert_eq!(decoded.outputs[0].assets.len(), 1);
    let a = &decoded.outputs[0].assets[0];
    assert_eq!(a.policy_id, policy);
    assert_eq!(a.asset_name, b"TOKEN");
    assert_eq!(a.amount, 42);
    assert_eq!(decoded.outputs[0].amount, 2_000_000);
}

#[test]
fn cardano_asset_amount_overflow() {
    // Aggregating two duplicate (policy, asset name) entries whose amounts
    // overflow u64 must error rather than silently wrapping.
    let txid =
        hex::decode("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376").unwrap();
    let policy = hex::decode("00000000000000000000000000000000000000000000000000000000").unwrap();
    let tx = CardanoTx {
        inputs: vec![CardanoInput { txid, index: 1 }],
        outputs: vec![CardanoOutput {
            address: addr_bytes("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
            amount: 2_000_000,
            assets: vec![
                CardanoAsset {
                    policy_id: policy.clone(),
                    asset_name: b"TOKEN".to_vec(),
                    amount: u64::MAX,
                },
                CardanoAsset {
                    policy_id: policy,
                    asset_name: b"TOKEN".to_vec(),
                    amount: 1,
                },
            ],
        }],
        fee: 180_000,
        ttl: 0,
        witnesses: vec![],
    };
    assert!(tx.to_bytes().is_err());
    assert!(tx.body_bytes().is_err());
}

#[test]
fn cardano_parse_hrp_mismatch() {
    // checksum-valid addresses whose HRP disagrees with the header byte must be
    // rejected (network confusion).
    let bad = [
        // "stake" HRP wrapping an enterprise (payment) header (0x61)
        "stake1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzersuzp9l4",
        // "addr" (mainnet) HRP with a testnet enterprise header (0x60)
        "addr1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers6g8jlq",
        // "addr" (mainnet) HRP with a testnet base header (0x00)
        "addr1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n9a3vl7ljgpcrf6e0p5lrzxyq034l8e5d3gemafc3ey5q9syj92",
    ];
    for a in bad {
        assert!(
            parse_cardano_address(a).is_err(),
            "expected {a} to be rejected"
        );
    }

    // all four legitimate prefixes must still parse
    let good = [
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae",
        "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw",
        "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn",
    ];
    for a in good {
        assert!(parse_cardano_address(a).is_ok(), "expected {a} to parse");
    }
}

// --- BIP32-Ed25519 / CIP-1852 HD derivation ---

/// Mimics standard Ed25519 secret-key expansion (RFC 8032): SHA-512 of the seed,
/// lower half clamped into the scalar, upper half the nonce.
fn expand_seed(seed: &[u8; 32]) -> [u8; 64] {
    let mut h = purecrypto::hash::sha512(seed);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    h
}

#[test]
fn cardano_extended_key_matches_stdlib() {
    // For a key expanded from a seed the standard way, both public key and
    // signatures are byte-identical to standard Ed25519.
    for i in 0u8..8 {
        let seed = [i + 1; 32];
        let std_pub = ed25519::public_from_seed(&seed);

        let ek = CardanoExtendedKey::new(&expand_seed(&seed)).unwrap();
        assert_eq!(ek.public_key(), std_pub, "seed {i}: public key mismatch");

        for msg in [&b""[..], &b"cardano"[..], &[0xABu8; 32][..]] {
            let got = ek.sign(msg);
            assert_eq!(
                got,
                ed25519::sign(&seed, msg),
                "seed {i}: signature mismatch"
            );
            assert!(ed25519::verify(&std_pub, msg, &got));
        }
    }
}

#[test]
fn cardano_extended_key_derived_scalar() {
    // A scalar not in freshly-clamped form (as after child derivation) still
    // produces a valid Ed25519 signature.
    let mut secret = expand_seed(&[0x11; 32]);
    let mut carry = 0i32;
    for (i, b) in secret.iter_mut().enumerate().take(28) {
        let v = *b as i32 + (((8 * 0x1234) >> ((i % 4) * 8)) & 0xff) + carry;
        *b = (v & 0xff) as u8;
        carry = v >> 8;
    }
    secret[0] &= 248;
    secret[31] &= 63;
    secret[31] |= 64;

    let ek = CardanoExtendedKey::new(&secret).unwrap();
    let pub_key = ek.public_key();
    let msg = b"derived-key transaction body hash";
    let sig = ek.sign(msg);
    assert!(ed25519::verify(&pub_key, msg, &sig));
}

#[test]
fn cardano_extended_key_bad_length() {
    assert!(CardanoExtendedKey::new(&[0u8; 63]).is_err());
}

#[test]
fn cardano_tx_sign_with_extended_key() {
    let mut tx = sample_tx();
    let ek = CardanoExtendedKey::new(&expand_seed(&[0x55; 32])).unwrap();

    let digest = tx.sign_bytes().unwrap();
    tx.sign_with(&[&ek]).unwrap();
    assert_eq!(tx.witnesses.len(), 1);
    let w = &tx.witnesses[0];
    assert_eq!(w.vkey, ek.cardano_public_key());
    assert!(ed25519::verify(
        &ek.public_key(),
        &digest,
        &w.signature.clone().try_into().unwrap()
    ));

    let enc = tx.to_bytes().unwrap();
    let decoded = CardanoTx::from_bytes(&enc).unwrap();
    assert_eq!(decoded.witnesses.len(), 1);
    assert_eq!(decoded.witnesses[0].signature, w.signature);
}

// Authoritative V2 derivation vectors from typed-io/rust-ed25519-bip32 (used by
// cardano-serialization-lib): parent key D1, its hardened child at 0x80000000
// (D1_H0), and D1_H0's signature over "Hello World".
const D1: &str = "f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fadea15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d";
const D1_H0: &str = "60d399da83ef80d8d4f8d223239efdc2b8fef387e1b5219137ffb4e8fbdea15adc9366b7d003af37c11396de9a83734e30e05e851efa32745c9cd7b42712c890608763770eddf77248ab652984b21b849760d1da74a6f5bd633ce41adceef07a";
const D1_H0_SIG: &str = "90194d57cde4fdadd01eb7cf161780c277e129fc7135b97779a3268837e4cd2e9444b9bb91c0e84d23bba870df3c4bda91a110ef735638fa7a34ea2046d4be04";

#[test]
fn cardano_derive_hardened_vector() {
    let parent = CardanoExtendedKey::new(&hex::decode(D1).unwrap()).unwrap();
    let child = parent.derive_child(0x8000_0000).unwrap();
    assert_eq!(hex::encode(child.bytes()), D1_H0);
}

#[test]
fn cardano_derived_key_signs_vector() {
    let ek = CardanoExtendedKey::new(&hex::decode(D1_H0).unwrap()[..64]).unwrap();
    let sig = ek.sign(b"Hello World");
    assert_eq!(hex::encode(sig), D1_H0_SIG);
}

#[test]
fn cardano_icarus_end_to_end() {
    // cardano-serialization-lib vectors for the recovery phrase "test walk nut
    // penalty hip pave soap entry language right filter choice".
    let entropy = hex::decode("df9ed25ed146bf43336a5d7cf7395994").unwrap();
    let master = cardano_icarus_master_key(&entropy, &[]).unwrap();

    let spend = master
        .derive_path(&[harden(1852), harden(1815), harden(0), 0, 0])
        .unwrap();
    let stake = master
        .derive_path(&[harden(1852), harden(1815), harden(0), 2, 0])
        .unwrap();

    let spend_hash = cardano_key_hash(&spend.public_key());
    let stake_hash = cardano_key_hash(&stake.public_key());

    // the spend key is the same one used in the CIP-19 address tests
    assert_eq!(
        hex::encode(spend_hash),
        "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
    );

    assert_eq!(
        cardano_enterprise_address(&spend_hash, "cardano").unwrap(),
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
    );
    assert_eq!(
        cardano_enterprise_address(&spend_hash, "cardano-testnet").unwrap(),
        "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"
    );
    assert_eq!(
        cardano_base_address(&spend_hash, &stake_hash, "cardano").unwrap(),
        "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwqfjkjv7"
    );
    assert_eq!(
        cardano_base_address(&spend_hash, &stake_hash, "cardano-testnet").unwrap(),
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
    );
}

#[test]
fn cardano_public_derivation_matches_private() {
    let entropy = hex::decode("df9ed25ed146bf43336a5d7cf7395994").unwrap();
    let master = cardano_icarus_master_key(&entropy, &[]).unwrap();

    // account/role level (m/1852'/1815'/0'/0), still private so we hold an xpub
    let role = master
        .derive_path(&[harden(1852), harden(1815), harden(0), 0])
        .unwrap();
    let xpub = role.extended_public_key().unwrap();

    for idx in [0u32, 1, 5, 100] {
        let priv_child = role.derive_child(idx).unwrap();
        let pub_child = xpub.derive_child(idx).unwrap();
        assert_eq!(
            priv_child.public_key(),
            pub_child.public_key(),
            "index {idx}: public-path pubkey != private-path pubkey"
        );
    }

    // hardened public derivation must be rejected
    assert!(xpub.derive_child(harden(0)).is_err());
}
