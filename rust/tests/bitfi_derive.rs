//! Bitfi derivation, against vectors generated separately from the published
//! algorithm with @noble/hashes, @noble/curves and @scure/bip32. They check this
//! code against other implementations of that algorithm; they are not output from
//! Bitfi's own software. The secrets are made up.

use libwallet::bitfi::{addresses, coin, coin_index, master, Family};

struct Case {
    coin: &'static str,
    position: u32,
    key: &'static str,
    /// Expected addresses as (kind, address), lowercase for Ethereum.
    addresses: &'static [(&'static str, &'static str)],
    wif_legacy: Option<&'static str>,
    wif_segwit: Option<&'static str>,
}

const VECTORS: &[(&str, &str, &[Case])] = &[
    ("test-salt-0001", "correct horse battery staple is thirty+ chars", &[
        Case { coin: "btc", position: 0, key: "b26380102ee5993e9543678098c0cdf6832e01674adb4cd97c87debc06570c1d", addresses: &[("legacy", "1Mc4Z8TwSqat46oEmpSub6xWjukaPpwCCf"), ("segwit", "bc1q6hrmt9kpq75vaadk82nwdhtuvw7pw92wvs7y2w")], wif_legacy: Some("5KArHEeEM2wmw13AV5xbS4tG4St3g5Q27udbV3yWt8iqcbVYcsm"), wif_segwit: Some("L3CUWfDKuRamKMAYrxtNye9FUDEJoUQbwVJXCp8Sth5fZnM8RTMs") },
        Case { coin: "btc", position: 1, key: "abc5d471b3d665452a9c3eb2c5c79ffef229588ab1628b60df34790b9aaa54ae", addresses: &[("legacy", "17T2SFMtkaX1joxyntCU9vjnhAgSvjKNmQ"), ("segwit", "bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4")], wif_legacy: Some("5K7wHZsMFaeiCjr6tKC4HpU8w9ZwbMYNtxAS1oohiTJikKJXjeX"), wif_segwit: Some("L2ycc85EPMXSrp7iyVHoXEWn1zpPxdfVeJUdQZb8hy7DFtdNgB6d") },
        Case { coin: "ltc", position: 0, key: "d9bea0a1d6803307418c02989e7be4573b6eae5e5a694ca3c6190cdf3ce72cfa", addresses: &[("legacy", "Lf46VKdzbkh5YL9ZEqtLWaVxX1gUN1VLqA"), ("segwit", "ltc1q4zcw0d3v6kcnjf88kxwwsxamvu0s3gmg8zha4q")], wif_legacy: Some("6vmv3Veo3HAALV2SBDuyDBX75P69jemZps19TeZizy4j1m31jee"), wif_segwit: Some("TAMF81TpD4KSCzhL87zo6mRspLVjZFhhtFheLcoSNrTSSADY7Yda") },
        Case { coin: "ltc", position: 1, key: "d4f83d7987b933ec70469c119f84192e090ca090a94fd70c0c78ddd095e058bd", addresses: &[("legacy", "LedMh3fzwX1fkARCsq2NNr1hAKBh8aLAD2"), ("segwit", "ltc1q9h8zz9l6c4el0upxs676xursl8fj5w0k85c0g3")], wif_legacy: Some("6vjp5FaDG8gtWWgakPFHhXc6qSnf6UAD2cPsze5BJVi62RXZA49"), wif_segwit: Some("TABxmmKb7nw4MG1hxVC4ht5vkppX98se67Dz5QdSUDiMBAhbptH4") },
        Case { coin: "doge", position: 0, key: "fe84555021cad118397dabff6ac2b9acd6896e88e57df4983d870fe7e8e79cae", addresses: &[("legacy", "DEaGuzizNNhwnsdYur8yw1WK5oxf4LqLmK")], wif_legacy: Some("6L4iAeZjDJeN9MwG7FfWKjwm2nsWJk3Kntgga39RRpTvxo9ZzEJ"), wif_segwit: None },
        Case { coin: "doge", position: 1, key: "8bcd4163d774bb4348e91e781ab9d09795209e9b8c4f5c61bc96ed14e7eb9e36", addresses: &[("legacy", "DJtFzcEGr73unEKkyqfdmaG8ANog12MMCM")], wif_legacy: Some("6KCBvU7iSV1nn4PERjGUG2gJWoKUzsizjogQLZaP5GokbLEC7Un"), wif_segwit: None },
        Case { coin: "bch", position: 0, key: "0f2767366149dd96a109d89df34b0481e61deb302e0c7010b59aafef98d7c979", addresses: &[], wif_legacy: Some("5HvxfhUqRE5GUmFKUBkapo39Wa1zKBsXTuYhnPe4gffLAhM2k1H"), wif_segwit: None },
        Case { coin: "bch", position: 1, key: "c6c31c32a26f6cc241fb23d34a52408b62e4398b1a9889c3cf2acfa2577a1753", addresses: &[], wif_legacy: Some("5KKphCKvxXFiXqvY1D4mQaY1geZR1Dw9ykVQyZJWg818tmPCstW"), wif_segwit: None },
        Case { coin: "mona", position: 0, key: "d4262faa1e934c42ac466b8815d26226e5c6d56ae701f7834f44929d9d764f90", addresses: &[("legacy", "MFkTuWGRCdwJfhF2as8GkdpTqBXcciJE9d"), ("segwit", "mona1qh2us8a689nuc6r88st3s59uyrt5rf8kwfmx4zr")], wif_legacy: Some("6vjT7cwhDKXKV6uH1gYzhEYobY2H8YcB5kZ7BNNdBWo9Wd94Qe9"), wif_segwit: Some("TAANGDeQVNkpb33jg1aDeaoNfRveCJWFVyEiGmLShQWgZRbDUQFB") },
        Case { coin: "mona", position: 1, key: "9e7f03cfd3d54f5a75ada26be98975dc21cacf20491564bd980937aac1d9ec67", addresses: &[("legacy", "MMV2Yq91K2MaFRXkHhNcKVhpUArYp1gyPA"), ("segwit", "mona1qp36jtvre4lxy8g4pfwa9fvdc7wfu9fj8cxnyz9")], wif_legacy: Some("6vKpcxSWJJ272mfDrf17G5XeiYREWPtDXEphyTKzTg9dvGj9ZMg"), wif_segwit: Some("T8N5BhhaKL7scp7hkAjUdYzHUMfxck14GU1ZrBCpcjo7wyn5k2Fn") },
        Case { coin: "eth", position: 0, key: "32db692c762b7b50879ad9e0e250b7ded26b4e61f58ae6369662073754b9d22a", addresses: &[("ethereum", "0x37ea7fda970f84b8f34f746a3254c186e23a5a52")], wif_legacy: None, wif_segwit: None },
        Case { coin: "eth", position: 1, key: "b09f8ab0c942bdaee2a47d9c32ce70d53ddd46ee007473de4b0c823aa3a938c0", addresses: &[("ethereum", "0xf45a414dbc4eef65d7ea540db0aa6fa0fa6f9b3f")], wif_legacy: None, wif_segwit: None },
        Case { coin: "xmr", position: 0, key: "83008b4e32002290fa28300389981660fc092ffdb42db799a3a5fd4468e9e3f2", addresses: &[("monero", "4AqBdb3UydfBxBEMQvYrubgTQTh6HKWo2hKeMhd6iF1k9sjXDhdfwqCDUASuQWfF5o3pnJn51ZDx43PRHzgSzuApM1mmiw3")], wif_legacy: None, wif_segwit: None },
        Case { coin: "xmr", position: 1, key: "c0d0538943f69c8e5c6a11e12b9e7be968ae7894acc94dde64abde12095f6b35", addresses: &[("monero", "43JB5gfgppb9TcFx11puGB4ncWtK6b5C1ADWTH4PGKkz757J5YCGWjn9p264FQgZqJHKfeWANJUAUUievo5PWnWpQjfKLzb")], wif_legacy: None, wif_segwit: None },
    ]),
    ("+15550100000", "Made Up Phrase, With Spaces & CASE: not a real wallet!", &[
        Case { coin: "btc", position: 1, key: "c95011a369b2230ca628b62d59f6cb869890c427ddfd97c74567e74eefa31ade", addresses: &[("legacy", "17Kw1ArKCYYosjkVVgYZ98gKsFVYnkryN3"), ("segwit", "bc1qer28m5mgev209qqfgxjxzzqfxteqvr3kqe6qrj")], wif_legacy: Some("5KLwr2DhNTVCmKKWgLfk5tm1YMRzyExiYPq3MUxRc6ng5dsd6ZQ"), wif_segwit: Some("L3y35NP3BhuUvbrhzdp1AbTFPPBLsEcvMZm3PQPdbvYbV3m5Ewkx") },
        Case { coin: "ltc", position: 1, key: "da4e658cac63224fe271cfff62b8007dff28001ce81731808f717442772387cd", addresses: &[("legacy", "LaGToDxHzWKaPZRyXTiqt7BkAZceFG9ksQ"), ("segwit", "ltc1qnrm0k05t0tuyaysc2fz0dhk3kxlachnsm8eaay")], wif_legacy: Some("6vnAPXAuPEf1CEgRE1sz2eLPazfv67TNekChGuhFX2a786L91iU"), wif_segwit: Some("TANLSQAiD9GjrbNyvSt2iFnah3YmKZVQZbgcmDaf5Xw822vAMPku") },
        Case { coin: "doge", position: 1, key: "830a65eb6b5a85c9194f4813dbc8b471bead517cca71820738261ccefca85dbd", addresses: &[("legacy", "DLoDhbUxuFkamxgfhGGVMFRQfKbHaifJ2L")], wif_legacy: Some("6K8L8XTw7AaUgMitfEpRnVC5Kj4tKvD4fWhtmGu3UChY2Rc7XH6"), wif_segwit: None },
        Case { coin: "bch", position: 1, key: "75684ddea1ae884b30a7d8e19da3b02e7736415d8bdf16a8dcdcf6dd2942389c", addresses: &[], wif_legacy: Some("5JhzbaMv9jZY1P5sMypbiopdzkrZXKAYYQZ8nwVWuu5p38Svdvy"), wif_segwit: None },
        Case { coin: "mona", position: 1, key: "cf41cf9277301120d9cf839467d5b6d44595d5d54b7644c85641d17d96cfdf81", addresses: &[("legacy", "MWfmyWSsjWXNCE88G2HidbLrdjcV7zuwNz"), ("segwit", "mona1qg0s54npaeqt4345ehty5vfr5cd7tutw2da0j94")], wif_legacy: Some("6vhJ9q6Swfr9KsZZN8mkytUQCwdJq2XASP6AGSA4raoYqbQXneE"), wif_segwit: Some("T9zrhyH3WJTukJAhrHJZ86BwRi7Fgyi8f2Vmu8321rCTX339SBEa") },
        Case { coin: "eth", position: 1, key: "1a46c128045ca3c52f7d04ec1a388a3c6c789324e38aeb16a684de4e36a6f6f1", addresses: &[("ethereum", "0x0bb3e0924122e40ccde526d0d5e01bef7e82da8d")], wif_legacy: None, wif_segwit: None },
        Case { coin: "xmr", position: 1, key: "04ec50a316cacb3ef3b952420ea801f8d3f945ac68b57e1b13beef232333b2cd", addresses: &[("monero", "47NAN78ssFWLbvFQZugqHT2Ryja5hwN6yepDfXnDtLqKRLDb2nBBZ7AcFjQQzfYMp9L4rAnuvKqcz3Pjw7ZxLjrd8RA6ypM")], wif_legacy: None, wif_segwit: None },
    ]),
];

const SALT: &str = "test-salt-0001";
const SECRET: &str = "correct horse battery staple is thirty+ chars";
const MONERO_SPEND: &str = "f9547272f4cc6586d9932af88fb0deaa68ae7894acc94dde64abde12095f6b05";
const MONERO_VIEW: &str = "efa1b34a91b04b708e8592d64012fa1c20fad5506f6b64f21ece91b230b1fb00";
/// RIPEMD-160(SHA-256(uncompressed key)) of the Bitcoin Cash key at position 1.
const BCH_HASH160: &str = "b6eef9f32b1eac77e817d02105b5a8d0bb45d83a";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn matches_the_reference_vectors() {
    let mut checked = 0;
    for (salt, secret, cases) in VECTORS {
        let node = master(salt, secret).unwrap();
        for case in *cases {
            let c = coin(case.coin).unwrap();
            let key = node.derive(case.coin, case.position).unwrap();
            assert_eq!(key.to_hex(), case.key, "{} {}", case.coin, case.position);
            let got = addresses(c, &key).unwrap();
            for (kind, expected) in case.addresses {
                let found = got.iter().find(|a| a.kind == *kind).unwrap_or_else(|| panic!("no {kind} for {}", case.coin));
                let address = if *kind == "ethereum" { found.address.to_lowercase() } else { found.address.clone() };
                assert_eq!(address, *expected, "{} {} {kind}", case.coin, case.position);
                checked += 1;
            }
            if let Family::Bitcoin { wif, .. } = c.family {
                assert_eq!(Some(key.to_wif(wif, false).as_str()), case.wif_legacy, "{}", case.coin);
                if let Some(expected) = case.wif_segwit {
                    assert_eq!(key.to_wif(wif, true), expected, "{}", case.coin);
                }
            }
        }
    }
    assert!(checked > 20, "only {checked} addresses checked");
}

#[test]
fn monero_keys_match() {
    let keys = master(SALT, SECRET).unwrap().derive("xmr", 1).unwrap().monero();
    assert_eq!(hex(&keys.spend), MONERO_SPEND);
    assert_eq!(hex(&keys.view), MONERO_VIEW);
    assert_eq!(keys.address().len(), 95);
}

/// A Bitcoin Cash address is a CashAddr of the uncompressed key's hash.
#[test]
fn bitcoin_cash_uses_the_uncompressed_key_hash() {
    let key = master(SALT, SECRET).unwrap().derive("bch", 1).unwrap();
    let got = addresses(coin("bch").unwrap(), &key).unwrap();
    assert_eq!(got.len(), 1, "no SegWit on Bitcoin Cash");
    let (_, hash) = outscript::bech32::cashaddr_decode("bitcoincash", &got[0].address).expect("valid CashAddr");
    assert_eq!(hex(&hash), BCH_HASH160, "{}", got[0].address);
}

#[test]
fn coin_indexes_join_the_letter_positions() {
    assert_eq!(coin_index("btc"), 2203);
    assert_eq!(coin_index("eth"), 5208);
    assert_eq!(coin_index("doge"), 41575);
    assert_eq!(coin_index("xmr"), 241318);
}

#[test]
fn refuses_non_ascii_rather_than_guessing() {
    assert!(master("salé-1234", "a secret phrase of plain characters").is_err());
    assert!(master("salt-1234", "phrase ’ with a curly quote").is_err());
    assert!(master("", "a secret").is_err());
}

/// Input is used exactly as typed: no trimming, no case folding.
#[test]
fn whitespace_and_case_change_the_key() {
    let base = master("salt-1234", "a secret").unwrap().derive("btc", 1).unwrap().to_hex();
    for (salt, secret) in [("salt-1234 ", "a secret"), ("SALT-1234", "a secret"), ("salt-1234", "A secret"), ("salt-1234", "a secret ")] {
        assert_ne!(master(salt, secret).unwrap().derive("btc", 1).unwrap().to_hex(), base, "{salt:?} {secret:?}");
    }
}

#[test]
fn amounts_format_without_trailing_zeros() {
    use libwallet::bitfi::format_units;
    assert_eq!(format_units("50000000", 8), "0.5");
    assert_eq!(format_units("150000000", 8), "1.5");
    assert_eq!(format_units("5", 8), "0.00000005");
    assert_eq!(format_units("0", 8), "0");
    assert_eq!(format_units("20000000000000000000", 18), "20");
}
