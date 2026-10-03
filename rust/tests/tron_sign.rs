//! Tron accounts: TronLink-compatible addresses for imported mnemonics, and
//! transactions signed by the wallet (DKLs committee or mnemonic) that recover
//! to the account — `tron::sign_tx` refuses to return a signature that doesn't,
//! so a successful sign is the recovery proof; the tests re-check it from the
//! serialized bytes anyway.

use libwallet::models::{account, network, wallet};
use libwallet::sign::KeyDescription;
use libwallet::tron::{self, RefBlock, Transfer};
use libwallet::Env;
use outscript::trontx::TronTx;

const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

fn block() -> RefBlock {
    let mut id = [0x5cu8; 32];
    id[..8].copy_from_slice(&86_777_507u64.to_be_bytes());
    RefBlock { height: 86_777_507, id, timestamp: 1_791_005_153_610 }
}

/// Split a signed `Transaction` message back into its raw data and signature
/// and return the address the signature recovers to.
fn recovered_signer(signed: &[u8]) -> String {
    // field 1 (raw_data) and field 2 (signature), both length-delimited with
    // single-byte tags; lengths are varints.
    fn field(b: &[u8], at: usize) -> (usize, usize) {
        let (mut len, mut shift, mut i) = (0usize, 0, at + 1);
        loop {
            len |= ((b[i] & 0x7f) as usize) << shift;
            shift += 7;
            i += 1;
            if b[i - 1] & 0x80 == 0 {
                break;
            }
        }
        (i, len)
    }
    assert_eq!(signed[0], 0x0a);
    let (start, len) = field(signed, 0);
    let raw = &signed[start..start + len];
    let at = start + len;
    assert_eq!(signed[at], 0x12);
    let (sstart, slen) = field(signed, at);
    assert_eq!(slen, 65);
    let sig: [u8; 65] = signed[sstart..sstart + 65].try_into().unwrap();
    let tx = TronTx::parse(raw).unwrap();
    outscript::tron::address_to_string(&tx.signer(&sig).unwrap()).unwrap()
}

#[test]
fn dkls_tron_accounts_sign_trx_and_trc20() {
    let env = env();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "TSS", "secp256k1", &kds).unwrap();
    let unlock: Vec<(String, String)> = vec![
        (w.keys[0].id.clone(), "passwordone".into()),
        (w.keys[1].id.clone(), "passwordtwo".into()),
        (w.keys[2].id.clone(), "passwordthree".into()),
    ];

    let eth = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let a0 = account::create(&env, &w.id, "", "tron", 0).unwrap();
    let a1 = account::create(&env, &w.id, "", "tron", 1).unwrap();
    assert_eq!(a0.curve, "secp256k1");
    assert!(a0.address.starts_with('T') && a0.address.len() == 34);
    assert_eq!(a0.uri, format!("tron:{}", a0.address));
    assert_eq!(a1.path, "m/44/195/0/1");
    assert_ne!(a0.address, a1.address);
    // Index 0 is the group key itself — the same key hash as the EVM account.
    let raw0 = tron::parse_address(&a0.address).unwrap();
    assert_eq!(
        raw0[1..].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        eth.address[2..].to_ascii_lowercase()
    );

    for a in [&a0, &a1] {
        let trx = Transfer::Trx { to: USDT.into(), amount: 1_000_000 };
        let (_, signed) = tron::sign_transfer(&env, a, &unlock, &trx, &block()).unwrap();
        assert_eq!(recovered_signer(&signed), a.address);

        let trc20 = Transfer::Trc20 { contract: USDT.into(), to: a0.address.clone(), amount: 1_315_764, fee_limit: tron::DEFAULT_TRC20_FEE_LIMIT };
        let (txid, signed) = tron::sign_transfer(&env, a, &unlock, &trc20, &block()).unwrap();
        assert_eq!(recovered_signer(&signed), a.address);

        // Offline path: the same raw data, handed back as hex, signs to the same id.
        let calldata = outscript::trontx::trc20_transfer_data(&raw0, 1_315_764);
        let raw_hex = {
            let tx = TronTx {
                timestamp: block().timestamp,
                expiration: block().timestamp + 10 * 60 * 1000,
                fee_limit: tron::DEFAULT_TRC20_FEE_LIMIT,
                ..TronTx::new(outscript::trontx::TronContract::TriggerSmartContract(
                    outscript::trontx::TronTriggerSmartContract::new(
                        tron::parse_address(&a.address).unwrap(),
                        tron::parse_address(USDT).unwrap(),
                        &calldata,
                    ),
                ))
            }
            .with_ref_block(block().height, &block().id);
            tx.raw_data().iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        let (txid2, _) = tron::sign_raw_data(&env, a, &unlock, &raw_hex).unwrap();
        assert_eq!(txid, txid2);
    }

    // Raw data owned by someone else is refused, not signed.
    let foreign = TronTx::new(outscript::trontx::TronContract::Transfer(outscript::trontx::TronTransfer {
        owner: tron::parse_address(USDT).unwrap(),
        to: raw0,
        amount: 1,
    }))
    .with_ref_block(block().height, &block().id);
    let hex: String = foreign.raw_data().iter().map(|b| format!("{b:02x}")).collect();
    let err = tron::sign_raw_data(&env, &a0, &unlock, &hex).unwrap_err().to_string();
    assert!(err.contains("not owned"), "{err}");
}

#[test]
fn mnemonic_tron_account_is_tronlinks_and_signs() {
    let env = env();
    let kd = pw("seal-password");
    let w = wallet::import_mnemonic(&env, "seed", "secp256k1", M, "", &kd).unwrap();
    let unlock = vec![(w.keys[0].id.clone(), "seal-password".to_string())];

    let a0 = account::create_with_unlock(&env, &w.id, "", "tron", 0, &unlock).unwrap();
    assert_eq!(a0.path, "m/44'/195'/0'/0/0");
    assert_eq!(a0.address, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
    let a1 = account::create_with_unlock(&env, &w.id, "", "tron", 1, &unlock).unwrap();
    assert_eq!(a1.path, "m/44'/195'/0'/0/1");

    for a in [&a0, &a1] {
        let trx = Transfer::Trx { to: USDT.into(), amount: 1 };
        let (_, signed) = tron::sign_transfer(&env, a, &unlock, &trx, &block()).unwrap();
        assert_eq!(recovered_signer(&signed), a.address);
    }
}

#[test]
fn view_account_normalizes_tron_address() {
    let env = env();
    let hex = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";
    let a = account::create_view(&env, "", "tron", hex).unwrap();
    assert_eq!(a.address, USDT);
    assert!(account::create_view(&env, "", "tron", "0xdead").is_err());
}

#[test]
fn tron_mainnet_is_seeded_with_its_defaults() {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    let n = network::fetch(&env, &network::network_id_for("tron", "mainnet")).unwrap().unwrap();
    assert_eq!((n.name.as_str(), n.currency_symbol.as_str(), n.native_decimals()), ("Tron", "TRX", 6));
    assert!(n.resolved_rpc().unwrap().ends_with("/tron/rest"));
    assert_eq!(n.transaction_url("ab"), "https://tronscan.org/#/transaction/ab");
    assert!(!n.testnet);

    let mut nile = network::Network { kind: "tron".into(), chain_id: "nile".into(), ..Default::default() };
    nile.check().unwrap();
    assert!(nile.testnet);
    assert_eq!(nile.resolved_rpc().unwrap(), "https://nile.trongrid.io");
    let mut bad = network::Network { kind: "tron".into(), chain_id: "nope".into(), ..Default::default() };
    assert!(bad.check().is_err());
}
