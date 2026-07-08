//! A mnemonic-keep (Schema="mnemonic") secp256k1 wallet must sign an EVM tx that
//! ecrecovers to its derived account — proving Rust can *use* a Go-format
//! mnemonic wallet by importing its master scalar at sign time.

use base64::Engine as _;
use libwallet::{Env, SqlValue};
use xuid::Xuid;

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[test]
fn mnemonic_wallet_signs_evm_tx_recovering_to_account() {
    let env = Env::init_memory().unwrap();
    libwallet::models::wallet::init(&env).unwrap();
    libwallet::models::account::init(&env).unwrap();

    // The canonical "abandon … about" mnemonic (all-zero 16-byte entropy).
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = libwallet::bip39::mnemonic_to_seed(mnemonic, "");
    // Wallet master = the seed's BIP32 master (secp256k1); accounts derive
    // non-hardened from its pubkey, exactly like a TSS wallet.
    let master_pub = libwallet::hdderive::derive_pubkey_for_path(&seed, "secp256k1", "").unwrap();
    let (_master, chaincode) = libwallet::bip39::master_from_seed(&seed, "secp256k1").unwrap();

    // Encrypt the MnemonicKeyShare to a Password-derived key.
    let wk_id = Xuid::new("wkey").to_string();
    let xid: Xuid = wk_id.parse().unwrap();
    let uuid = xid.uuid().as_bytes().to_vec();
    let priv_key = libwallet::keystore::password_to_ed25519("password1", &uuid).unwrap();
    let pkix = libwallet::keystore::public_key_to_pkix_b64(&priv_key.public()).unwrap();
    let entropy_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    let share = format!(r#"{{"curve":"secp256k1","entropy":"{entropy_b64}","language":"english","passphrase":""}}"#);
    let sealed = libwallet::keystore::seal(share.as_bytes(), &[priv_key.public()]).unwrap();

    let wallet_id = Xuid::new("wlt").to_string();
    env.exec(
        r#"INSERT INTO "Wallet" ("Id","Name","Curve","Protocol","Threshold","Gen","Pubkey","Chaincode","Created","Modified") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
        vec![
            SqlValue::Text(wallet_id.clone()), SqlValue::Text("Seed".into()), SqlValue::Text("secp256k1".into()),
            SqlValue::Text("mnemonic".into()), SqlValue::Int(0), SqlValue::Int(1),
            SqlValue::Text(b64url(&master_pub)), SqlValue::Text(b64url(&chaincode)),
            SqlValue::Text(libwallet::now_rfc3339()), SqlValue::Text(libwallet::now_rfc3339()),
        ],
    ).unwrap();
    env.exec(
        r#"INSERT INTO "WalletKey" ("Id","Wallet","Type","Schema","Key","Data","Gen") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
        vec![
            SqlValue::Text(wk_id.clone()), SqlValue::Text(wallet_id.clone()), SqlValue::Text("Password".into()),
            SqlValue::Text("mnemonic".into()), SqlValue::Text(pkix), SqlValue::Blob(sealed), SqlValue::Int(1),
        ],
    ).unwrap();

    // Derive an ethereum account (m/44/60/0/0 non-hardened from the master).
    let account = libwallet::models::account::create(&env, &wallet_id, "acct", "ethereum", 0).unwrap();
    assert!(account.address.starts_with("0x"));

    // Sign a legacy EVM transaction with the mnemonic-derived key.
    let unlock = vec![(wk_id.clone(), "password1".to_string())];
    let req = libwallet::evm::EvmTxRequest {
        nonce: 0,
        gas: 21000,
        max_fee: "20000000000".into(),
        max_priority: "0".into(),
        to: "0x000000000000000000000000000000000000dEaD".into(),
        value: "1000000000000000000".into(),
        data: Vec::new(),
        chain_id: 1,
        eip1559: false,
    };
    let raw = libwallet::evm::sign_tx(&env, &account.id, &unlock, &req).unwrap();

    // The signed tx must ecrecover to the account that mnemonic-derived it.
    let recovered = libwallet::evm::recover_sender(&raw).unwrap();
    assert_eq!(recovered.to_lowercase(), account.address.to_lowercase());
}

#[test]
fn mnemonic_wallet_signs_solana_message_verifying_under_account() {
    let env = Env::init_memory().unwrap();
    libwallet::models::wallet::init(&env).unwrap();
    libwallet::models::account::init(&env).unwrap();

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = libwallet::bip39::mnemonic_to_seed(mnemonic, "");
    // ed25519 wallet master pubkey = SLIP-0010 master as an ed25519 seed.
    let master_pub = libwallet::hdderive::master_pubkey(&seed, "ed25519").unwrap();

    let wk_id = Xuid::new("wkey").to_string();
    let xid: Xuid = wk_id.parse().unwrap();
    let uuid = xid.uuid().as_bytes().to_vec();
    let priv_key = libwallet::keystore::password_to_ed25519("password1", &uuid).unwrap();
    let pkix = libwallet::keystore::public_key_to_pkix_b64(&priv_key.public()).unwrap();
    let entropy_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    let share = format!(r#"{{"curve":"ed25519","entropy":"{entropy_b64}","language":"english","passphrase":""}}"#);
    let sealed = libwallet::keystore::seal(share.as_bytes(), &[priv_key.public()]).unwrap();

    let wallet_id = Xuid::new("wlt").to_string();
    env.exec(
        r#"INSERT INTO "Wallet" ("Id","Name","Curve","Protocol","Threshold","Gen","Pubkey","Chaincode","Created","Modified") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
        vec![
            SqlValue::Text(wallet_id.clone()), SqlValue::Text("Seed".into()), SqlValue::Text("ed25519".into()),
            SqlValue::Text("mnemonic".into()), SqlValue::Int(0), SqlValue::Int(1),
            SqlValue::Text(b64url(&master_pub)), SqlValue::Text(b64url(&[0u8; 32])),
            SqlValue::Text(libwallet::now_rfc3339()), SqlValue::Text(libwallet::now_rfc3339()),
        ],
    ).unwrap();
    env.exec(
        r#"INSERT INTO "WalletKey" ("Id","Wallet","Type","Schema","Key","Data","Gen") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
        vec![
            SqlValue::Text(wk_id.clone()), SqlValue::Text(wallet_id.clone()), SqlValue::Text("Password".into()),
            SqlValue::Text("mnemonic".into()), SqlValue::Text(pkix), SqlValue::Blob(sealed), SqlValue::Int(1),
        ],
    ).unwrap();

    // Solana account = the wallet master pubkey (path "m"), base58.
    let account = libwallet::models::account::create(&env, &wallet_id, "acct", "solana", 0).unwrap();

    // Sign a message directly with the mnemonic-derived ed25519 master key.
    let unlock = vec![(wk_id.clone(), "password1".to_string())];
    let msg = b"hello solana";
    let sig = libwallet::models::wallet::sign_frost_local(&env, &wallet_id, &unlock, msg).unwrap();
    assert_eq!(sig.len(), 64);

    // Verify under the account's pubkey (== the master pubkey).
    let pk: [u8; 32] = master_pub.clone().try_into().unwrap();
    let sig64: [u8; 64] = sig.try_into().unwrap();
    assert!(libwallet::tss::ed25519_verify(&pk, msg, &sig64), "sig must verify under the account key");
    // The account's stored pubkey matches the signing key.
    assert_eq!(account.pubkey, b64url(&master_pub));
}
