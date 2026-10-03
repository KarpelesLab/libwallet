//! Imported-mnemonic wallets: accounts must live at the standard single-key
//! paths (MetaMask m/44'/60'/0'/0/i, BIP-84 m/84'/0'/i', Phantom
//! m/44'/501'/i'/0') — the addresses the import UI shows and where the user's
//! funds are — not at the BIP-32/SLIP-10 master the wallet row records. And
//! signing for those accounts must verify under the account's own key.
//!
//! Regression: index-0 accounts were null-derivation (= the master key), so an
//! imported Solana/Ethereum account showed a zero native balance at an address
//! nobody funds.

use base64::Engine;
use libwallet::evm::{recover_sender, sign_tx, EvmTxRequest};
use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::tss::ed25519_verify;
use libwallet::Env;

// Canonical all-zero-entropy phrase; its standard-path addresses are public
// test vectors (and what walletcore::derive_addresses — the import UI — shows).
const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PW: &str = "seal-password";

fn pw() -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: PW.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

fn unlock(w: &wallet::Wallet) -> Vec<(String, String)> {
    vec![(w.keys[0].id.clone(), PW.to_string())]
}

#[test]
fn mnemonic_accounts_land_on_the_standard_addresses() {
    let env = env();
    let ui = libwallet::walletcore::derive_addresses(M, "").unwrap();

    let ws = wallet::import_mnemonic(&env, "seed", "secp256k1", M, "", &pw()).unwrap();
    let we = wallet::import_mnemonic(&env, "seed", "ed25519", M, "", &pw()).unwrap();

    // Without Keys a mnemonic wallet can't derive: refuse loudly rather than
    // silently handing back the master-key address.
    let err = account::create_with_unlock(&env, &ws.id, "", "ethereum", 0, &[]).unwrap_err().to_string();
    assert!(err.contains("Keys"), "{err}");

    let eth = account::create_with_unlock(&env, &ws.id, "", "ethereum", 0, &unlock(&ws)).unwrap();
    let btc = account::create_with_unlock(&env, &ws.id, "", "bitcoin", 0, &unlock(&ws)).unwrap();
    let sol = account::create_with_unlock(&env, &we.id, "", "solana", 0, &unlock(&we)).unwrap();

    assert_eq!(eth.path, "m/44'/60'/0'/0/0");
    assert_eq!(eth.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "MetaMask vector");
    assert_eq!(eth.address, ui.evm, "must match what the import UI displayed");
    assert!(eth.il.is_null());

    assert_eq!(btc.path, "m/84'/0'/0'");
    // No bitcoin network selected → the BIP-84 first receive key as mainnet P2PKH;
    // its SegWit form is the BIP-84 vector and what the UI shows.
    let formats = libwallet::bitcoin::address_formats(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&btc.pubkey).unwrap().try_into().unwrap(),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&btc.chaincode).unwrap().try_into().unwrap(),
        "bitcoin",
    )
    .unwrap();
    assert_eq!(formats[0].address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "BIP-84 vector");
    assert_eq!(formats[0].address, ui.bitcoin);
    // The account xpub is the real BIP-84 account xpub (own chaincode recorded).
    assert_ne!(btc.chaincode, ws.chaincode);
    assert!(btc.xpub().unwrap().starts_with("xpub"));

    assert_eq!(sol.path, "m/44'/501'/0'/0'");
    assert_eq!(sol.address, ui.solana, "Phantom path, as shown by the import UI");
    assert!(sol.il.is_null());

    // None of them is the master key the wallet row records.
    let master_secp = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&ws.pubkey).unwrap();
    assert_ne!(eth.address, libwallet::hdderive::evm_address(&master_secp).unwrap());
    assert_ne!(sol.pubkey, we.pubkey);

    // Further indexes are distinct and follow the same conventions.
    let eth1 = account::create_with_unlock(&env, &ws.id, "", "ethereum", 1, &unlock(&ws)).unwrap();
    let sol1 = account::create_with_unlock(&env, &we.id, "", "solana", 1, &unlock(&we)).unwrap();
    assert_eq!(eth1.path, "m/44'/60'/0'/0/1");
    assert_eq!(sol1.path, "m/44'/501'/1'/0'");
    assert_ne!(eth1.address, eth.address);
    assert_ne!(sol1.address, sol.address);
}

#[test]
fn mnemonic_accounts_sign_under_their_own_keys() {
    let env = env();
    let ws = wallet::import_mnemonic(&env, "seed", "secp256k1", M, "", &pw()).unwrap();
    let we = wallet::import_mnemonic(&env, "seed", "ed25519", M, "", &pw()).unwrap();
    let eth = account::create_with_unlock(&env, &ws.id, "", "ethereum", 0, &unlock(&ws)).unwrap();
    let eth1 = account::create_with_unlock(&env, &ws.id, "", "ethereum", 1, &unlock(&ws)).unwrap();
    let btc = account::create_with_unlock(&env, &ws.id, "", "bitcoin", 0, &unlock(&ws)).unwrap();
    let sol = account::create_with_unlock(&env, &we.id, "", "solana", 0, &unlock(&we)).unwrap();
    let sol1 = account::create_with_unlock(&env, &we.id, "", "solana", 1, &unlock(&we)).unwrap();

    // EVM: a signed tx must ecrecover to the hardened-path account address.
    for a in [&eth, &eth1] {
        let req = EvmTxRequest {
            nonce: 0,
            gas: 21000,
            max_fee: "20000000000".into(),
            max_priority: "0".into(),
            to: "0x000000000000000000000000000000000000dEaD".into(),
            value: "1".into(),
            data: vec![],
            chain_id: 1,
            eip1559: false,
        };
        let raw = sign_tx(&env, &a.id, &unlock(&ws), &req).unwrap();
        assert_eq!(recover_sender(&raw).unwrap().to_lowercase(), a.address.to_lowercase(), "{}", a.path);
    }

    // Bitcoin: sign_message brute-forces the recovery id against the account's
    // pubkey, so Ok() means the signature is the account key's.
    let compact = libwallet::bitcoin::sign_message(&env, &btc.id, &unlock(&ws), "bitcoin", b"hello").unwrap();
    assert_eq!(compact.len(), 65);

    // Solana: verifies under the account pubkey, not under the master key.
    let master: [u8; 32] =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&we.pubkey).unwrap().try_into().unwrap();
    for a in [&sol, &sol1] {
        let pk: [u8; 32] =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&a.pubkey).unwrap().try_into().unwrap();
        let msg = format!("solana {}", a.path).into_bytes();
        let sig: [u8; 64] = wallet::sign_ed25519_for_account(&env, a, &unlock(&we), &msg).unwrap().try_into().unwrap();
        assert!(ed25519_verify(&pk, &msg, &sig), "must verify under {}", a.path);
        assert!(!ed25519_verify(&master, &msg, &sig), "must not be a master-key signature");
    }
}

#[test]
fn derived_tss_solana_account_signs_under_its_own_key() {
    // The TSS counterpart: an index>0 Solana account on a FROST wallet is an IL
    // tweak of the group key, and sign_ed25519_for_account must apply it (the
    // plain sign_frost_local would sign for the group key instead).
    let env = env();
    let kds: Vec<KeyDescription> = ["passwordone", "passwordtwo", "passwordthree"]
        .iter()
        .map(|p| KeyDescription { kind: "Password".into(), key: (*p).into(), id: String::new() })
        .collect();
    let w = wallet::create(&env, "W", "ed25519", &kds).unwrap();
    let unlock = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
    ];
    let group: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&w.pubkey).unwrap().try_into().unwrap();

    let a0 = account::create(&env, &w.id, "", "solana", 0).unwrap();
    let a1 = account::create(&env, &w.id, "", "solana", 1).unwrap();
    let msg = b"tweaked frost";
    let s0: [u8; 64] = wallet::sign_ed25519_for_account(&env, &a0, &unlock, msg).unwrap().try_into().unwrap();
    assert!(ed25519_verify(&group, msg, &s0), "index 0 is the group key");

    let pk1: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&a1.pubkey).unwrap().try_into().unwrap();
    let s1: [u8; 64] = wallet::sign_ed25519_for_account(&env, &a1, &unlock, msg).unwrap().try_into().unwrap();
    assert!(ed25519_verify(&pk1, msg, &s1), "index 1 must verify under its derived key");
    assert!(!ed25519_verify(&group, msg, &s1));
}
