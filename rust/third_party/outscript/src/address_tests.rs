//! Ported known-answer tests from the Go `address_test.go`, `massa_test.go`,
//! covering address generation and round-trip parsing.

use crate::crypto::ed25519::public_from_seed;
use crate::crypto::secp256k1::SecpPrivateKey;
use crate::pubkey::PubKey;
use crate::script::Script;
use crate::{parse_bitcoin_based_address, parse_evm_address, parse_massa_address};

fn arr32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn secp_script() -> Script {
    let sk = SecpPrivateKey::from_bytes(&arr32(
        "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
    ))
    .unwrap();
    Script::new(sk.public_key())
}

#[test]
fn addresses_generate_and_roundtrip() {
    let s = secp_script();
    // (format, network, expected address)
    let cases: &[(&str, &str, &str)] = &[
        (
            "eth",
            "ethereum",
            "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7",
        ),
        ("p2pkh", "bitcoin", "1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi"),
        (
            "p2pkh",
            "bitcoincash",
            "bitcoincash:qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm",
        ),
        ("p2pkh", "litecoin", "LWFvvfLCSpdSXzXgb6wUfwkfv6QDipAzJc"),
        (
            "p2pkh",
            "electraproto",
            "PKd9pRRDR5saG2WHm3Gi4pfBKdCpm1YfY3",
        ),
        (
            "p2sh:p2pkh",
            "litecoin",
            "MNBNbudWqRT5MhorGVnpk7DDuMX5XCxKnR",
        ),
        (
            "p2wpkh",
            "bitcoin",
            "bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m",
        ),
        (
            "p2wpkh",
            "litecoin",
            "ltc1q0yy3juscd3zfavw76g4h3eqdqzda7qyfsmekdt",
        ),
        (
            "p2wpkh",
            "electraproto",
            "ep1q0yy3juscd3zfavw76g4h3eqdqzda7qyf4r3klt",
        ),
        (
            "p2wsh:p2wpkh",
            "bitcoin",
            "bc1qwg7r0yn6t7ctfaplxuwvlu2yk8q6fd3xsvr3lkq5ud4ylsecczzqgq9ste",
        ),
    ];

    for (fmt, net, want) in cases {
        let sout = s.out(fmt).unwrap_or_else(|e| panic!("generate {fmt}: {e}"));
        let addr = sout
            .address(&[net])
            .unwrap_or_else(|e| panic!("addr {fmt}: {e}"));
        assert_eq!(&addr, want, "format {fmt} net {net}");

        // re-parse and compare scripts
        let out = if want.starts_with("0x") {
            parse_evm_address(want).unwrap()
        } else if *net != "electraproto" {
            parse_bitcoin_based_address("auto", want).unwrap()
        } else {
            parse_bitcoin_based_address(net, want).unwrap()
        };
        assert_eq!(out.script, sout.script, "script mismatch for {want}");
    }
}

#[test]
fn taproot_parse_roundtrip() {
    // We can't generate taproot from this key path test, but parsing must work.
    let a = "bc1pgf6m46mr8c55veujxg3qvqxfektwmmpfrt5mhwtvwrzeacmm7xaqdndj5l";
    let addr = parse_bitcoin_based_address("bitcoin", a).unwrap();
    let b = addr.address(&[]).unwrap();
    assert_eq!(b, a);
}

#[test]
fn massa_address() {
    let seed = arr32("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88");
    let pk = public_from_seed(&seed);
    let s = Script::new(PubKey::Ed25519(pk));
    let sout = s.out("massa").unwrap();
    let addr = sout.address(&["massa"]).unwrap();
    assert_eq!(addr, "AU16f3K8uWS8cSJaXb7oDzKUZRqt7392eFPtq2bBBop9PVbyXkMs");

    let out = parse_massa_address(&addr).unwrap();
    assert_eq!(out.script, sout.script);
}

#[test]
fn short_base58_address_is_rejected() {
    // OOB / malformed-payload guards: short or wrong-length base58 must not panic
    // and must not parse to a non-standard script.
    for a in ["1", "111", "1111111111"] {
        assert!(parse_bitcoin_based_address("auto", a).is_err());
    }
}

#[test]
fn unknown_network_p2pkh_errors() {
    // Out::address must reject an unrecognized network rather than silently
    // emitting a Bitcoin-mainnet address.
    let out = parse_bitcoin_based_address("bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
    assert!(out.address(&["bitcoin"]).is_ok());
    assert!(out.address(&["nonsense-network"]).is_err());
}

#[test]
fn evm_lowercase_and_checksum() {
    let checksummed = "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7";
    assert!(parse_evm_address(checksummed).is_ok());
    assert!(parse_evm_address(&checksummed.to_lowercase()).is_ok());
    // a bad checksum (flip a letter case) must fail
    let bad = "0x2aEb8ADD8337360E088B7D9ce4e857b9BE60f3a7";
    assert!(parse_evm_address(bad).is_err());
}
