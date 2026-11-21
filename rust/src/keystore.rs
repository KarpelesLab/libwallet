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
use purecrypto::zeroize::Zeroizing;

#[derive(Debug)]
pub enum KeystoreError {
    PasswordTooShort,
    Decode(String),
    /// A vault reference could not be resolved (locked, cancelled, expired).
    Vault(String),
    Bottle(bottlers::BottleError),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::PasswordTooShort => write!(f, "password is too short"),
            KeystoreError::Decode(s) => write!(f, "decode error: {s}"),
            KeystoreError::Vault(s) => write!(f, "{s}"),
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

/// base64url (no-pad) of a 64-byte store key.
pub fn seed_to_b64url_64(store: &[u8; 64]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(store)
}

/// Generate a fresh 64-byte store key (base64url) and the Ed25519 PKIX public
/// key it derives to (Go `StoreKey:create`).
pub fn create_store_key() -> Result<(String, String), KeystoreError> {
    use purecrypto::rng::RngCore;
    let mut raw = [0u8; 64];
    purecrypto::rng::OsRng.fill_bytes(&mut raw);
    let store_b64 = seed_to_b64url_64(&raw);
    let pk = store_key_to_ed25519(&store_b64)?;
    let pub_b64 = public_key_to_pkix_b64(&pk.public())?;
    Ok((store_b64, pub_b64))
}

/// Derive the Ed25519 key a StoreKey resolves to (Go `storeKeyToEd25519`): the
/// 64-byte base64url store key is split, then
/// `PBKDF2-HMAC-SHA256(store[:32], salt = store[32:], 4096, 32)` gives the seed.
/// This is the StoreKey scheme's unlock derivation and the input to
/// `StoreKey:create`'s public key.
///
/// `store_key_b64url` may also be a vault reference (see [`crate::vault`]):
/// the entry's 64 bytes are then unsealed here, used, and wiped.
pub fn store_key_to_ed25519(store_key_b64url: &str) -> Result<PrivateKey, KeystoreError> {
    if let Some(secret) = crate::vault::session::secret_for_token(store_key_b64url) {
        let secret = secret.map_err(|e| KeystoreError::Vault(e.to_string()))?;
        return store_key_bytes_to_ed25519(&secret);
    }
    let k = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(store_key_b64url)
            .map_err(|e| KeystoreError::Decode(e.to_string()))?,
    );
    store_key_bytes_to_ed25519(&k)
}

/// [`store_key_to_ed25519`] on the raw 64 bytes.
pub fn store_key_bytes_to_ed25519(k: &[u8]) -> Result<PrivateKey, KeystoreError> {
    if k.len() != 64 {
        return Err(KeystoreError::Decode(format!("storeKey must be 64 bytes, got {}", k.len())));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha256>(&k[..32], &k[32..], 4096, &mut *seed);
    Ok(ed25519_from_seed(*seed))
}

/// Shortest password a NEW Password share may be sealed to. Shares sealed
/// before 0.5.11 accepted 6 characters and still open with them.
pub const MIN_SEAL_PASSWORD_LEN: usize = 8;
/// Shortest password the legacy (PBKDF2) derivation accepts.
const MIN_LEGACY_PASSWORD_LEN: usize = 6;

/// Argon2id cost for Password shares: the same as the vault's password backend
/// (64 MiB, 3 passes, 1 lane), about a second in a browser.
const PW_SHARE_M_KIB: u32 = 64 * 1024;
const PW_SHARE_T: u32 = 3;
/// Domain separation for the share KDF (Argon2 associated data).
const PW_SHARE_AD: &[u8] = b"libwallet:password-share:v2";

/// Which KDF a Password share's key was derived with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordKdf {
    /// PBKDF2-HMAC-SHA256, 4096 iterations: every share sealed before 0.5.11
    /// (and by Go wltwallet).
    Pbkdf2,
    /// Argon2id, 64 MiB × 3: every share sealed since 0.5.11.
    Argon2id,
}

impl PasswordKdf {
    pub fn as_str(self) -> &'static str {
        match self {
            PasswordKdf::Pbkdf2 => "pbkdf2",
            PasswordKdf::Argon2id => "argon2id",
        }
    }
}

/// The key a NEW Password share is sealed to: Argon2id over the password, salt
/// = the WalletKey UUID bytes. Refuses passwords shorter than
/// [`MIN_SEAL_PASSWORD_LEN`].
///
/// `password` may also be a vault reference to a password entry.
pub fn password_to_ed25519(password: &str, salt: &[u8]) -> Result<PrivateKey, KeystoreError> {
    let bytes = password_bytes(password)?;
    if bytes.len() < MIN_SEAL_PASSWORD_LEN {
        return Err(KeystoreError::PasswordTooShort);
    }
    password_argon2_to_ed25519(&bytes, salt)
}

/// The key that opens an existing Password share sealed to `sealed_to` (the
/// share's base64url PKIX public key, `WalletKey.Key`). The legacy PBKDF2 key
/// is derived first (it is cheap) and used when its public key matches;
/// otherwise the Argon2id key is returned. A wrong password yields a key that
/// simply fails to open the share. An empty `sealed_to` (no recorded
/// recipient) means the legacy derivation, as before.
///
/// A vault reference is unsealed once, whichever derivation is used.
pub fn password_unlock_key(password: &str, salt: &[u8], sealed_to: &str) -> Result<(PrivateKey, PasswordKdf), KeystoreError> {
    let bytes = password_bytes(password)?;
    if bytes.len() < MIN_LEGACY_PASSWORD_LEN {
        return Err(KeystoreError::PasswordTooShort);
    }
    let legacy = password_pbkdf2_to_ed25519(&bytes, salt);
    if sealed_to.is_empty() || public_key_to_pkix_b64(&legacy.public()).ok().as_deref() == Some(sealed_to) {
        return Ok((legacy, PasswordKdf::Pbkdf2));
    }
    if bytes.len() < MIN_SEAL_PASSWORD_LEN {
        // No Argon2id share was ever sealed to a password this short: it's
        // the wrong password, and the legacy key will fail to open the share.
        return Ok((legacy, PasswordKdf::Pbkdf2));
    }
    Ok((password_argon2_to_ed25519(&bytes, salt)?, PasswordKdf::Argon2id))
}

/// The legacy (pre-0.5.11, Go wltwallet) Password-share key. Only for opening
/// and testing old shares: never seal a new share to it.
pub fn password_to_ed25519_legacy(password: &str, salt: &[u8]) -> Result<PrivateKey, KeystoreError> {
    let bytes = password_bytes(password)?;
    if bytes.len() < MIN_LEGACY_PASSWORD_LEN {
        return Err(KeystoreError::PasswordTooShort);
    }
    Ok(password_pbkdf2_to_ed25519(&bytes, salt))
}

/// The password's bytes, unsealing a vault reference.
fn password_bytes(password: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    if let Some(secret) = crate::vault::session::secret_for_token(password) {
        let secret = secret.map_err(|e| KeystoreError::Vault(e.to_string()))?;
        return Ok(secret);
    }
    Ok(Zeroizing::new(password.as_bytes().to_vec()))
}

/// Legacy derivation: PBKDF2-HMAC-SHA256, 4096 iterations, 32-byte output —
/// matching Go wltwallet `passwordToEd25519` (salt is the WalletKey UUID bytes).
fn password_pbkdf2_to_ed25519(password: &[u8], salt: &[u8]) -> PrivateKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha256>(password, salt, 4096, &mut *seed);
    ed25519_from_seed(*seed)
}

fn password_argon2_to_ed25519(password: &[u8], salt: &[u8]) -> Result<PrivateKey, KeystoreError> {
    use purecrypto::kdf::argon2::{argon2, Argon2Params, Argon2Type};
    let params = Argon2Params {
        t_cost: PW_SHARE_T,
        m_cost_kib: PW_SHARE_M_KIB,
        parallelism: 1,
        variant: Argon2Type::Argon2id,
        version: 0x13,
    };
    let mut seed = Zeroizing::new([0u8; 32]);
    argon2(&params, password, salt, &[], PW_SHARE_AD, &mut *seed).map_err(|e| KeystoreError::Decode(format!("argon2: {e:?}")))?;
    Ok(ed25519_from_seed(*seed))
}

/// Parse a StoreKey recipient: a base64url (no-pad) PKIX/DER SubjectPublicKeyInfo
/// (as Go stores in `WalletKey.Key`) into a bottlers public key.
///
/// `b64` may also be a vault reference to a StoreKey entry, which resolves to
/// the entry's public key without unsealing it.
pub fn public_key_from_pkix_b64(b64: &str) -> Result<PublicKey, KeystoreError> {
    if let Some(public) = crate::vault::session::public_for_token(b64) {
        let public = public.map_err(|e| KeystoreError::Vault(e.to_string()))?;
        return public_key_from_pkix_b64(&public);
    }
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

/// Like [`seal`] but stamps the `ct="json"` content-type header, matching Go
/// `cryptutil.MarshalJson(share)` → Bottle → Encrypt. The WalletSign backend's
/// `loadShare` reads this header to know the sealed payload is a JSON-encoded
/// TSS share (so a RemoteKey upload round-trips wdrone-side).
pub fn seal_json(payload: &[u8], recipients: &[PublicKey]) -> Result<Vec<u8>, KeystoreError> {
    let mut bottle =
        Bottle::new(payload.to_vec()).with_header("ct", bottlers::HeaderValue::Text("json".into()));
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
