//! Key-share storage crypto — the Rust side of the Go wltwallet encrypt/decrypt
//! pipeline (walletkey.go). A share is wrapped in a `bottlers` Bottle,
//! encrypted to one or more recipient public keys, and CBOR-encoded into
//! `WalletKey.Data`. `bottlers` is byte-compatible with the Go cryptutil/gobottle
//! format, so shares written by the Go build open here and vice versa.
//!
//! This module ports the crypto envelope only. Which recipients/keys apply
//! (StoreKey pubkey, Password-derived key, RemoteKey session, Plain) is the
//! WalletKey layer's concern and lands with the TSS work; the two schemes that
//! reduce to a local keypair — StoreKey and Password — are supported here.

use base64::Engine;
use bottlers::{Bottle, Keychain, Opener, PrivateKey, PublicKey};
use purecrypto::ec::Ed25519PrivateKey;

#[derive(Debug)]
pub enum KeystoreError {
    PasswordTooShort,
    Decode(String),
    Bottle(bottlers::BottleError),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::PasswordTooShort => write!(f, "password is too short"),
            KeystoreError::Decode(s) => write!(f, "decode error: {s}"),
            KeystoreError::Bottle(e) => write!(f, "bottle error: {e:?}"),
        }
    }
}

impl std::error::Error for KeystoreError {}

impl From<bottlers::BottleError> for KeystoreError {
    fn from(e: bottlers::BottleError) -> Self {
        KeystoreError::Bottle(e)
    }
}

/// Wrap a raw 32-byte Ed25519 seed as a private key (the StoreKey path stores
/// the matching public key; the seed is provided by the caller/keystore).
pub fn ed25519_from_seed(seed: [u8; 32]) -> PrivateKey {
    PrivateKey::Ed25519(Ed25519PrivateKey::from_bytes(seed))
}

/// base64url (no-pad) encoding of a 32-byte seed — the StoreKey unlock material
/// a host passes at sign time.
pub fn seed_to_b64url(seed: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed)
}

/// Derive an Ed25519 key from a password + salt via PBKDF2-HMAC-SHA256, 4096
/// iterations, 32-byte output — matching Go wltwallet `passwordToEd25519`
/// (salt is the WalletKey UUID bytes).
pub fn password_to_ed25519(password: &str, salt: &[u8]) -> Result<PrivateKey, KeystoreError> {
    if password.len() < 6 {
        return Err(KeystoreError::PasswordTooShort);
    }
    let mut seed = [0u8; 32];
    purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha256>(password.as_bytes(), salt, 4096, &mut seed);
    Ok(ed25519_from_seed(seed))
}

/// Parse a StoreKey recipient: a base64url (no-pad) PKIX/DER SubjectPublicKeyInfo
/// (as Go stores in `WalletKey.Key`) into a bottlers public key.
pub fn public_key_from_pkix_b64(b64: &str) -> Result<PublicKey, KeystoreError> {
    let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| KeystoreError::Decode(e.to_string()))?;
    bottlers::pkix::parse_public_key(&der).map_err(KeystoreError::Bottle)
}

/// The base64url (no-pad) PKIX encoding of a public key — the value stored in
/// `WalletKey.Key` for StoreKey/Password shares.
pub fn public_key_to_pkix_b64(key: &PublicKey) -> Result<String, KeystoreError> {
    let der = bottlers::pkix::marshal_public_key(key).map_err(KeystoreError::Bottle)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der))
}

/// Encrypt `payload` to `recipients` and CBOR-encode it (the WalletKey.Data
/// wire format).
pub fn seal(payload: &[u8], recipients: &[PublicKey]) -> Result<Vec<u8>, KeystoreError> {
    let mut bottle = Bottle::new(payload.to_vec());
    bottle.encrypt(recipients)?;
    Ok(bottle.to_cbor()?)
}

/// Wrap `payload` in an unencrypted CBOR bottle (the Plain scheme: the share is
/// stored as-is, matching Go's Type=="Plain" path).
pub fn wrap_plain(payload: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let bottle = Bottle::new(payload.to_vec());
    Ok(bottle.to_cbor()?)
}

/// Open a CBOR-encoded Bottle (encrypted or plain) with the given private keys,
/// returning the payload.
pub fn open(
    cbor: &[u8],
    keys: impl IntoIterator<Item = PrivateKey>,
) -> Result<Vec<u8>, KeystoreError> {
    let keychain = Keychain::from_keys(keys)?;
    let opener = Opener::new(keychain);
    let (data, _result) = opener.open_cbor(cbor)?;
    Ok(data)
}
