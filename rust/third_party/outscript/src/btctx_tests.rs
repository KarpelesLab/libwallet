//! Ported known-answer tests from `btctx_test.go` and `p2tr_test.go`.

use crate::btctx::{BtcTx, BtcTxInput, BtcTxOutput, BtcTxSign};
use crate::crypto::secp256k1::{SecpPrivateKey, bip340_sign, bip340_verify, taproot_tweak};
use crate::script::Script;

fn key(hex_s: &str) -> SecpPrivateKey {
    let mut s = [0u8; 32];
    s.copy_from_slice(&hex::decode(hex_s).unwrap());
    SecpPrivateKey::from_bytes(&s).unwrap()
}

fn parse(hex_s: &str) -> BtcTx {
    BtcTx::from_bytes(&hex::decode(hex_s).unwrap()).unwrap()
}

#[test]
fn parse_txid() {
    let tx = parse(
        "0100000003362c10b042d48378b428d60c5c98d8b8aca7a03e1a2ca1048bfd469934bbda95010000008b483045022046c8bc9fb0e063e2fc8c6b1084afe6370461c16cbf67987d97df87827917d42d022100c807fa0ab95945a6e74c59838cc5f9e850714d8850cec4db1e7f3bcf71d5f5ef0141044450af01b4cc0d45207bddfb47911744d01f768d23686e9ac784162a5b3a15bc01e6653310bdd695d8c35d22e9bb457563f8de116ecafea27a0ec831e4a3e9feffffffffc19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace5444388331c4813000000008b48304502201738185959373f04cc73dbbb1d061623d51dc40aac0220df56dabb9b80b72f49022100a7f76bde06369917c214ee2179e583fefb63c95bf876eb54d05dfdf0721ed772014104e6aa2cf108e1c650e12d8dd7ec0a36e478dad5a5d180585d25c30eb7c88c3df0c6f5fd41b3e70b019b777abd02d319bf724de184001b3d014cb740cb83ed21a6ffffffffbaae89b5d2e3ca78fd3f13cf0058784e7c089fb56e1e596d70adcfa486603967010000008b483045022055efbaddb4c67c1f1a46464c8f770aab03d6b513779ad48735d16d4c5b9907c2022100f469d50a5e5556fc2c932645f6927ac416aa65bc83d58b888b82c3220e1f0b73014104194b3f8aa08b96cae19b14bd6c32a92364bea3051cb9f018b03e3f09a57208ff058f4b41ebf96b9911066aef3be22391ac59175257af0984d1432acb8f2aefcaffffffff0340420f00000000001976a914c0fbb13eb10b57daa78b47660a4ffb79c29e2e6b88ac204e0000000000001976a9142cae94ffdc05f8214ccb2b697861c9c07e3948ee88ac1c2e0100000000001976a9146e03561cd4d6033456cc9036d409d2bf82721e9888ac00000000",
    );
    assert_eq!(
        hex::encode(tx.hash()),
        "38d4cfeb57d6685753b7a3b3534c3cb576c34ca7344cd4582f9613ebf0c2b02a"
    );
}

#[test]
fn parse_witness_txid() {
    let tx = parse(
        "0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030cafb3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e21125f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841b9874d913c430048c78a7b18baebdbea440588ac8096980000000000160014e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd8250f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c276b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a83999738db0f7a6b91b2ec64f00db080000",
    );
    assert_eq!(
        hex::encode(tx.hash()),
        "99e7484eafb6e01622c395c8cae7cb9f8822aab6ba993696b39df8b60b0f4b11"
    );
}

const BIP143_TX: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

#[test]
fn p2pk_and_p2wpkh_bip143() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");

    // script generation checks
    let s0 = Script::new(key0.public_key()).generate("p2pk").unwrap();
    assert_eq!(
        hex::encode(&s0),
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
    );
    let s1 = Script::new(key1.public_key()).generate("p2wpkh").unwrap();
    assert_eq!(
        hex::encode(&s1),
        "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
    );

    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wpkh").amount(600000000),
    ])
    .unwrap();

    assert_eq!(
        hex::encode(&tx.inputs[0].script),
        "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01"
    );
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[0]),
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
    );

    let signed = "0100000000010".to_string()
        + "2fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01210"
        + "25476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    assert_eq!(hex::encode(tx.bytes()), signed);
}

#[test]
fn p2sh_p2wpkh() {
    let k = key("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
    let mut tx = parse(
        "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000",
    );
    tx.sign(&[BtcTxSign::new(&k, "p2sh:p2wpkh").amount(1000000000)])
        .unwrap();
    let expected = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000";
    assert_eq!(hex::encode(tx.bytes()), expected);
}

#[test]
fn p2wsh_p2pkh_matches_p2wpkh_sig() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wsh:p2pkh").amount(600000000),
    ])
    .unwrap();
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[0]),
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
    );
    assert_eq!(tx.inputs[1].witnesses.len(), 3);
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[1]),
        "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
    );
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[2]),
        "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
    );
    assert!(tx.inputs[1].script.is_empty());
}

#[test]
fn p2wsh_p2pk() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wsh:p2pk").amount(600000000),
    ])
    .unwrap();
    assert_eq!(tx.inputs[1].witnesses.len(), 2);
    let expected_ws = Script::new(key1.public_key()).generate("p2pk").unwrap();
    assert_eq!(tx.inputs[1].witnesses[1], expected_ws);
}

#[test]
fn p2wsh_autodetect() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.inputs[1].script = Script::new(key1.public_key())
        .generate("p2wsh:p2pkh")
        .unwrap();
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wsh").amount(600000000),
    ])
    .unwrap();
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[0]),
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
    );
    assert_eq!(tx.inputs[1].witnesses.len(), 3);
    assert!(tx.inputs[1].script.is_empty());
}

#[test]
fn compute_size_prefill_ge_signed() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    for scheme in [
        "p2wsh",
        "p2wsh:p2pk",
        "p2wsh:p2pkh",
        "p2wsh:p2puk",
        "p2wsh:p2pukh",
    ] {
        let mut est = parse(BIP143_TX);
        est.inputs[0].prefill("p2pk").unwrap();
        est.inputs[1].prefill(scheme).unwrap();
        let estimated = est.compute_size();

        let mut sig_tx = parse(BIP143_TX);
        let sign_scheme = if scheme == "p2wsh" {
            "p2wsh:p2pkh"
        } else {
            scheme
        };
        sig_tx
            .sign(&[
                BtcTxSign::new(&key0, "p2pk"),
                BtcTxSign::new(&key1, sign_scheme).amount(600000000),
            ])
            .unwrap();
        assert!(estimated >= sig_tx.compute_size(), "scheme {scheme}");
    }
}

#[test]
fn btc_output_json() {
    let v = BtcTxOutput {
        amount: crate::BtcAmount(123_456_700),
        n: 0,
        script: Vec::new(),
    };
    let j = serde_json::to_string(&v).unwrap();
    assert!(j.starts_with("{\"value\":1.23456700,"), "got {j}");

    let parsed: BtcTxOutput = serde_json::from_str("{\"value\":\"2.424242\"}").unwrap();
    assert_eq!(parsed.amount.0, 242_424_200);
}

#[test]
fn btc_tx_json_roundtrip() {
    let tx = parse(BIP143_TX);
    let j = serde_json::to_string(&tx).unwrap();
    let tx2: BtcTx = serde_json::from_str(&j).unwrap();
    assert_eq!(tx.bytes(), tx2.bytes());
}

// --- taproot ---

fn arr32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn bip341_tweak_vector() {
    let internal = arr32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
    let (tweaked, _) = taproot_tweak(&internal).unwrap();
    assert_eq!(
        hex::encode(tweaked),
        "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    );
}

#[test]
fn p2tr_generate_and_address() {
    let k = key("0101010101010101010101010101010101010101010101010101010101010101");
    let s = Script::new(k.public_key());
    let script = s.generate("p2tr").unwrap();
    assert_eq!(script.len(), 34);
    assert_eq!(&script[..2], &[0x51, 0x20]);
    let addr = s.address("p2tr", &["bitcoin"]).unwrap();
    assert!(addr.starts_with("bc1p"));
    let out = crate::parse_bitcoin_based_address("bitcoin", &addr).unwrap();
    assert_eq!(out.bytes(), &script[..]);
}

#[test]
fn p2tr_sign_produces_valid_sig() {
    let k = key("0101010101010101010101010101010101010101010101010101010101010101");
    let s = Script::new(k.public_key());
    let script_pubkey = s.generate("p2tr").unwrap();

    let mut tx = BtcTx {
        version: 2,
        inputs: vec![BtcTxInput {
            sequence: 0xffffffff,
            ..Default::default()
        }],
        outputs: vec![BtcTxOutput {
            amount: crate::BtcAmount(90000),
            n: 0,
            script: script_pubkey.clone(),
        }],
        locktime: 0,
    };
    tx.sign(&[BtcTxSign::new(&k, "p2tr")
        .amount(100000)
        .prev_script(script_pubkey.clone())])
        .unwrap();

    assert_eq!(tx.inputs[0].witnesses.len(), 1);
    assert_eq!(tx.inputs[0].witnesses[0].len(), 64);

    let keys = [BtcTxSign {
        key: None,
        scheme: String::new(),
        amount: crate::BtcAmount(100000),
        sighash: 0,
        prev_script: script_pubkey.clone(),
    }];
    let digest = tx.taproot_sighash(&keys, 0).unwrap();
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&script_pubkey[2..]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&tx.inputs[0].witnesses[0]);
    assert!(bip340_verify(&xonly, &digest, &sig));
}

#[test]
fn p2tr_external_signer() {
    // Simulate a TSS/HSM that holds the already-tweaked key.
    use crate::btctx::Signer;
    use crate::crypto::secp256k1::SecpPublicKey;

    let internal = key("0202020202020202020202020202020202020202020202020202020202020202");
    let pub_comp = internal.public_key().serialize_compressed();
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&pub_comp[1..]);
    let (tweaked_x, _) = taproot_tweak(&x_only).unwrap();

    // External signer that already knows its tweaked scalar.
    struct Ext {
        tweaked_secret: [u8; 32],
    }
    impl Signer for Ext {
        fn ecdsa_public_key(&self) -> Option<SecpPublicKey> {
            None
        }
        fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], String> {
            bip340_sign(&self.tweaked_secret, sighash, &[0u8; 32]).map_err(|e| e.to_string())
        }
    }

    // Compute the tweaked secret the way the library would internally.
    let tweaked_secret = compute_tweaked_secret(&internal);
    let signer = Ext { tweaked_secret };

    let mut script_pubkey = vec![0x51, 0x20];
    script_pubkey.extend_from_slice(&tweaked_x);

    let mut tx = BtcTx {
        version: 2,
        inputs: vec![BtcTxInput {
            sequence: 0xffffffff,
            ..Default::default()
        }],
        outputs: vec![BtcTxOutput {
            amount: crate::BtcAmount(90000),
            n: 0,
            script: script_pubkey.clone(),
        }],
        locktime: 0,
    };
    tx.sign(&[BtcTxSign::new(&signer, "p2tr")
        .amount(100000)
        .prev_script(script_pubkey.clone())])
        .unwrap();

    let keys = [BtcTxSign {
        key: None,
        scheme: String::new(),
        amount: crate::BtcAmount(100000),
        sighash: 0,
        prev_script: script_pubkey.clone(),
    }];
    let digest = tx.taproot_sighash(&keys, 0).unwrap();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&tx.inputs[0].witnesses[0]);
    assert!(bip340_verify(&tweaked_x, &digest, &sig));
}

#[test]
fn extract_and_verify_p2wpkh() {
    use crate::btctxparse::extract_btc_input_sig;
    use crate::crypto::secp256k1::parse_der_signature;

    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wpkh").amount(600000000),
    ])
    .unwrap();

    let sigs = extract_btc_input_sig(&tx.inputs[1].script, &tx.inputs[1].witnesses).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].scheme, "p2wpkh");
    assert_eq!(sigs[0].sighash_flag, 1);

    let digest = tx
        .input_sighash(1, &sigs[0], &[], crate::BtcAmount(600000000))
        .unwrap();

    let der = &tx.inputs[1].witnesses[0];
    let (r, s) = parse_der_signature(&der[..der.len() - 1]).unwrap();
    assert!(key1.public_key().verify(&digest, &r, &s));
}

#[test]
fn extract_and_verify_p2pkh() {
    use crate::btctxparse::extract_btc_input_sig;
    use crate::crypto::secp256k1::parse_der_signature;

    let k = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let prev_script = Script::new(k.public_key()).generate("p2pkh").unwrap();

    let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000001000000000 0ffffffff01a0860100000000001976a91400112233445566778899aabbccddeeff0011223388ac00000000"
        .replace(' ', "");
    let mut tx = parse(&tx_hex);
    tx.sign(&[BtcTxSign::new(&k, "p2pkh")]).unwrap();

    let sigs = extract_btc_input_sig(&tx.inputs[0].script, &tx.inputs[0].witnesses).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].scheme, "p2pkh");

    let digest = tx
        .input_sighash(0, &sigs[0], &prev_script, crate::BtcAmount(0))
        .unwrap();
    let der = &{
        let (s, n) = crate::parse_push_bytes(&tx.inputs[0].script).unwrap();
        let _ = n;
        s.to_vec()
    };
    let (r, s) = parse_der_signature(&der[..der.len() - 1]).unwrap();
    assert!(k.public_key().verify(&digest, &r, &s));
}

// Helper mirroring the internal taproot scalar tweak, for the external-signer test.
fn compute_tweaked_secret(k: &SecpPrivateKey) -> [u8; 32] {
    use crate::crypto::secp256k1::tagged_hash;
    use num_bigint::BigUint;
    use num_traits::Num;

    let n = BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let pub_comp = k.public_key().serialize_compressed();
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&pub_comp[1..]);
    let (_, parity) = taproot_tweak(&x_only).unwrap();

    // We don't have direct scalar access; recompute d from the known test key bytes.
    let d_bytes = arr32("0202020202020202020202020202020202020202020202020202020202020202");
    let mut d = BigUint::from_bytes_be(&d_bytes);
    if pub_comp[0] == 0x03 {
        d = (&n - (&d % &n)) % &n;
    }
    let t = BigUint::from_bytes_be(&tagged_hash("TapTweak", &[&x_only]));
    d = (&d + &t) % &n;
    if parity == 1 {
        d = (&n - (&d % &n)) % &n;
    }
    let db = d.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - db.len()..].copy_from_slice(&db);
    out
}
