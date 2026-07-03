//! The all-local wallet crypto lifecycle, end to end: generate threshold key
//! shares, encrypt each into the WalletKey.Data form (a bottlers bottle over the
//! FROST Key JSON), then later decrypt a committee and produce a signature.
//! This is the crypto heart of Wallet:create + Account:signAndSend for wallets
//! whose shares all live on the device.

use libwallet::keystore;
use libwallet::tss::{frost_keygen_local, frost_sign_local, Key};

#[test]
fn local_wallet_generate_encrypt_then_sign() {
    let threshold = 1; // 1-of-3: any 2 shares sign
    let password = "correct horse battery";

    // 1. Keygen: generate the shares (Wallet:create).
    let shares = frost_keygen_local(3, threshold).unwrap();
    let group_key = shares[0].1.group_public_key; // -> Wallet.Pubkey

    // 2. Encrypt each share to a per-share password-derived key (WalletKey.Data).
    //    Salt is the WalletKey id; here we stand in with the share index.
    let stored: Vec<(_, Vec<u8>)> = shares
        .iter()
        .enumerate()
        .map(|(i, (pid, key))| {
            let salt = [i as u8; 16];
            let recipient = keystore::password_to_ed25519(password, &salt).unwrap();
            let json = key.to_json().unwrap();
            let data = keystore::seal(json.as_bytes(), &[recipient.public()]).unwrap();
            // The plaintext share must not survive in the stored blob.
            assert!(!data.windows(json.len()).any(|w| w == json.as_bytes()));
            (pid.clone(), data)
        })
        .collect();

    // 3. Sign: decrypt a committee of threshold+1 shares and run the ceremony.
    let committee: Vec<(_, Key)> = stored
        .iter()
        .take(threshold + 1)
        .enumerate()
        .map(|(i, (pid, data))| {
            let salt = [i as u8; 16];
            let unlock = keystore::password_to_ed25519(password, &salt).unwrap();
            let json = keystore::open(data, [unlock]).unwrap();
            let key = Key::from_json(std::str::from_utf8(&json).unwrap()).unwrap();
            assert_eq!(key.group_public_key, group_key); // decrypted the right share
            (pid.clone(), key)
        })
        .collect();

    let sig = frost_sign_local(&committee, threshold, b"transaction hash").unwrap();
    assert_eq!(sig.len(), 64, "64-byte Ed25519 signature");
}

#[test]
fn wrong_password_cannot_unlock_a_share() {
    let shares = frost_keygen_local(2, 0).unwrap();
    let salt = [9u8; 16];
    let recipient = keystore::password_to_ed25519("the password", &salt).unwrap();
    let json = shares[0].1.to_json().unwrap();
    let data = keystore::seal(json.as_bytes(), &[recipient.public()]).unwrap();

    let wrong = keystore::password_to_ed25519("wrong password", &salt).unwrap();
    assert!(keystore::open(&data, [wrong]).is_err());
}
