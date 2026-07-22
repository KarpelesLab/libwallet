//! SPL transfer message signing: build a TransferChecked message with derived
//! ATAs, sign it with the FROST wallet, verify under the account key, and confirm
//! the sender owner is the required signer at slot 0 (so the on-wire tx the send
//! path assembles would pass Solana's signature-verification).

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::solana::{assemble_tx, find_signer_slot, pubkey_from_b64url};
use libwallet::solana_spl::{
    build_spl_transfer_message, derive_ata, program_id, SPL_DEFAULT_CU_LIMIT, SPL_TOKEN_PROGRAM_B58,
};
use libwallet::tss::ed25519_verify;
use libwallet::Env;

fn pw(p: &str) -> KeyDescription {
    KeyDescription {
        kind: "Password".into(),
        key: p.into(),
        id: String::new(),
    }
}

fn b58_32(s: &str) -> [u8; 32] {
    bs58::decode(s).into_vec().unwrap().try_into().unwrap()
}

#[test]
fn spl_transfer_message_signs_and_verifies() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();

    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "SOL", "ed25519", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "solana", 0).unwrap();

    let sender_owner = pubkey_from_b64url(&a.pubkey).expect("account pubkey");
    let recipient_owner = [7u8; 32];
    let mint = b58_32("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"); // USDC
    let tp = program_id(SPL_TOKEN_PROGRAM_B58);
    let sender_ata = derive_ata(&sender_owner, &mint, &tp).unwrap();
    let recipient_ata = derive_ata(&recipient_owner, &mint, &tp).unwrap();
    let blockhash = [9u8; 32];

    let msg = build_spl_transfer_message(
        &sender_owner,
        &recipient_owner,
        &mint,
        &sender_ata,
        &recipient_ata,
        &tp,
        1_315_764, // 1.315764 USDC @ 6 decimals
        6,
        &blockhash,
        SPL_DEFAULT_CU_LIMIT,
        0,
    );

    // The sender owner must be the required signer at slot 0 — otherwise the
    // broadcast tx fails Solana signature verification.
    assert_eq!(find_signer_slot(&msg, &sender_owner), Some(0));

    let unlock = vec![
        (w.keys[0].id.clone(), "passwordone".to_string()),
        (w.keys[1].id.clone(), "passwordtwo".to_string()),
    ];
    let sig = wallet::sign_frost_local(&env, &w.id, &unlock, &msg).unwrap();
    assert_eq!(sig.len(), 64);
    let sig64: [u8; 64] = sig.clone().try_into().unwrap();
    assert!(
        ed25519_verify(&sender_owner, &msg, &sig64),
        "SPL tx must verify under the account key"
    );

    let tx = assemble_tx(&msg, &sig);
    assert_eq!(tx[0], 1);
    assert_eq!(tx.len(), 1 + 64 + msg.len());
}
