//! Gold-standard EVM signing proof: a DKLs-signed legacy transaction, built for
//! a derived ethereum account, must recover (ecrecover) to that account's own
//! address. This verifies the whole chain — BIP32 tweak derivation, DKLs
//! sign_with_tweak, low-s normalization, EIP-155 v, and RLP assembly.

use libwallet::evm::{recover_sender, sign_legacy_tx, LegacyTxRequest};
use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::Env;

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

#[test]
fn evm_tx_signature_recovers_to_account() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();

    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();

    // DKLs signing needs ALL shares unlocked.
    let unlock: Vec<(String, String)> = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
        (w.keys[2].id.clone(), "passwordthree".to_string()),
    ];
    let req = LegacyTxRequest {
        nonce: 0,
        gas: 21000,
        gas_price: "20000000000".to_string(),
        to: "0x000000000000000000000000000000000000dEaD".to_string(),
        value: "1000000000000000000".to_string(),
        data: vec![],
        chain_id: 1,
    };

    let raw = sign_legacy_tx(&env, &a.id, &unlock, &req).unwrap();
    assert!(!raw.is_empty());

    let sender = recover_sender(&raw).unwrap();
    assert_eq!(
        sender.to_lowercase(),
        a.address.to_lowercase(),
        "the DKLs-signed tx must recover to the account address"
    );
}
