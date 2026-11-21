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

/// Cleartext header on a sealed Password share naming the KDF its key was
/// derived with, e.g. `argon2id$v=19$m=65536,t=3,p=1`. It sits on the outer
/// (encrypted) bottle so it can be read before the key is derived. It is not
/// authenticated, and doesn't need to be: altered parameters derive a key that
/// fails to open the share.
pub const KDF_HEADER: &str = "kdf";

/// Domain separation for the Argon2id share KDF (Argon2 associated data).
const PW_SHARE_AD: &[u8] = b"libwallet:password-share:v2";

/// How a Password share's key is derived from the password (salt: the
/// WalletKey UUID bytes).
///
/// Compatibility is incremental: every share sealed since 0.5.12 records its
/// parameters in the [`KDF_HEADER`], so the cost can be raised later without
/// breaking older shares, and a share that names a scheme this version doesn't
/// know fails with a clear "update libwallet" error. A share without the header
/// predates it: PBKDF2 (before 0.5.11) or Argon2id at [`PasswordKdf::V0_5_11`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordKdf {
    /// PBKDF2-HMAC-SHA256 (Go wltwallet `passwordToEd25519`, 4096 iterations).
    Pbkdf2 { iterations: u32 },
    /// Argon2id v1.3, with [`PW_SHARE_AD`] as associated data.
    Argon2id { m_kib: u32, t: u32, p: u32 },
}

impl PasswordKdf {
    /// What libwallet before 0.5.11 (and Go wltwallet) sealed with.
    pub const LEGACY: PasswordKdf = PasswordKdf::Pbkdf2 { iterations: 4096 };
    /// What 0.5.11 sealed with, without recording it.
    pub const V0_5_11: PasswordKdf = PasswordKdf::Argon2id { m_kib: 64 * 1024, t: 3, p: 1 };
    /// What new shares are sealed with: the vault password backend's cost
    /// (64 MiB, 3 passes), about 0.1 s natively and up to a second in a browser.
    pub const CURRENT: PasswordKdf = PasswordKdf::Argon2id { m_kib: 64 * 1024, t: 3, p: 1 };

    /// The scheme name: `pbkdf2` or `argon2id`.
    pub fn name(self) -> &'static str {
        match self {
            PasswordKdf::Pbkdf2 { .. } => "pbkdf2",
            PasswordKdf::Argon2id { .. } => "argon2id",
        }
    }

    /// The [`KDF_HEADER`] value.
    pub fn to_header(self) -> String {
        match self {
            PasswordKdf::Pbkdf2 { iterations } => format!("pbkdf2-sha256$i={iterations}"),
            PasswordKdf::Argon2id { m_kib, t, p } => format!("argon2id$v=19$m={m_kib},t={t},p={p}"),
        }
    }

    /// Parse a [`KDF_HEADER`] value. The header comes from the share blob, which
    /// may come from an untrusted backup, so the costs are bounded before any
    /// memory is spent on them.
    pub fn parse(header: &str) -> Result<PasswordKdf, KeystoreError> {
        let unsupported = || {
            KeystoreError::Decode(format!(
                "this password share was sealed with a KDF this libwallet doesn't support ({header:?}): update libwallet"
            ))
        };
        let params = |s: &str| -> Result<std::collections::BTreeMap<String, u32>, KeystoreError> {
            let mut m = std::collections::BTreeMap::new();
            for kv in s.split(',') {
                let (k, v) = kv.split_once('=').ok_or_else(unsupported)?;
                let v: u32 = v.parse().map_err(|_| unsupported())?;
                if m.insert(k.to_owned(), v).is_some() {
                    return Err(unsupported());
                }
            }
            Ok(m)
        };
        let parts: Vec<&str> = header.split('$').collect();
        let kdf = match parts.as_slice() {
            ["argon2id", "v=19", p] => {
                let m = params(p)?;
                if m.len() != 3 {
                    return Err(unsupported());
                }
                let get = |k: &str| m.get(k).copied().ok_or_else(unsupported);
                PasswordKdf::Argon2id { m_kib: get("m")?, t: get("t")?, p: get("p")? }
            }
            ["pbkdf2-sha256", p] => {
                let m = params(p)?;
                match (m.len(), m.get("i")) {
                    (1, Some(&iterations)) => PasswordKdf::Pbkdf2 { iterations },
                    _ => return Err(unsupported()),
                }
            }
            _ => return Err(unsupported()),
        };
        kdf.check()?;
        Ok(kdf)
    }

    /// Bounds a share's parameters must sit in (the same Argon2 bounds as a
    /// vault blob).
    fn check(self) -> Result<(), KeystoreError> {
        let bad = |what: &str| Err(KeystoreError::Decode(format!("password share: unsupported {what}")));
        match self {
            PasswordKdf::Pbkdf2 { iterations } if !(1..=10_000_000).contains(&iterations) => bad("PBKDF2 iteration count"),
            PasswordKdf::Argon2id { p, t, .. } if !(1..=8).contains(&p) || !(1..=16).contains(&t) => bad("Argon2 parameters"),
            PasswordKdf::Argon2id { m_kib, p, .. } if m_kib < 8 * p || m_kib > 1024 * 1024 => bad("Argon2 memory cost"),
            _ => Ok(()),
        }
    }

    /// The share key for `password` (raw bytes; a vault reference isn't
    /// resolved here) and `salt` under these parameters.
    pub fn derive(self, password: &[u8], salt: &[u8]) -> Result<PrivateKey, KeystoreError> {
        self.check()?;
        let mut seed = Zeroizing::new([0u8; 32]);
        match self {
            PasswordKdf::Pbkdf2 { iterations } => {
                purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha256>(password, salt, iterations, &mut *seed);
            }
            PasswordKdf::Argon2id { m_kib, t, p } => {
                use purecrypto::kdf::argon2::{argon2, Argon2Params, Argon2Type};
                let params = Argon2Params { t_cost: t, m_cost_kib: m_kib, parallelism: p, variant: Argon2Type::Argon2id, version: 0x13 };
                argon2(&params, password, salt, &[], PW_SHARE_AD, &mut *seed)
                    .map_err(|e| KeystoreError::Decode(format!("argon2: {e:?}")))?;
            }
        }
        Ok(ed25519_from_seed(*seed))
    }
}

/// The key a NEW Password share is sealed to, with [`PasswordKdf::CURRENT`].
/// Refuses passwords shorter than [`MIN_SEAL_PASSWORD_LEN`]. Seal the share
/// with [`seal_to`] and the returned KDF so the share records it.
///
/// `password` may also be a vault reference to a password entry.
pub fn password_to_ed25519(password: &str, salt: &[u8]) -> Result<PrivateKey, KeystoreError> {
    let bytes = password_bytes(password)?;
    if bytes.len() < MIN_SEAL_PASSWORD_LEN {
        return Err(KeystoreError::PasswordTooShort);
    }
    PasswordKdf::CURRENT.derive(&bytes, salt)
}

/// The KDF a sealed share records in its [`KDF_HEADER`]: `None` for a share
/// without one (sealed before 0.5.12, or not a Password share).
pub fn share_kdf(sealed: &[u8]) -> Result<Option<PasswordKdf>, KeystoreError> {
    let bottle = Bottle::from_cbor(sealed)?;
    match bottle.header.get(KDF_HEADER) {
        None => Ok(None),
        Some(bottlers::HeaderValue::Text(h)) => PasswordKdf::parse(h).map(Some),
        Some(_) => Err(KeystoreError::Decode("password share: malformed kdf header".into())),
    }
}

/// The key that opens an existing Password share. `sealed` is the share blob
/// (`WalletKey.Data`) and `sealed_to` its recorded recipient (`WalletKey.Key`).
///
/// A share that records its KDF is opened with exactly that. One that doesn't
/// predates the header: if the legacy PBKDF2 key matches `sealed_to` it is
/// that, otherwise it was sealed by 0.5.11 ([`PasswordKdf::V0_5_11`]). An empty
/// `sealed_to` means legacy, as before. A wrong password yields a key that
/// fails to open the share.
///
/// A vault reference is unsealed once, whichever derivation is used.
pub fn password_unlock_key(
    password: &str,
    salt: &[u8],
    sealed_to: &str,
    sealed: &[u8],
) -> Result<(PrivateKey, PasswordKdf), KeystoreError> {
    let recorded = share_kdf(sealed)?;
    let bytes = password_bytes(password)?;
    if bytes.len() < MIN_LEGACY_PASSWORD_LEN {
        return Err(KeystoreError::PasswordTooShort);
    }
    if let Some(kdf) = recorded {
        return Ok((kdf.derive(&bytes, salt)?, kdf));
    }
    let legacy = PasswordKdf::LEGACY.derive(&bytes, salt)?;
    if sealed_to.is_empty() || bytes.len() < MIN_SEAL_PASSWORD_LEN
        || public_key_to_pkix_b64(&legacy.public()).ok().as_deref() == Some(sealed_to)
    {
        // (0.5.11 never sealed to a password under 8 characters: with one this
        // short it's legacy or the wrong password.)
        return Ok((legacy, PasswordKdf::LEGACY));
    }
    Ok((PasswordKdf::V0_5_11.derive(&bytes, salt)?, PasswordKdf::V0_5_11))
}

/// The legacy (pre-0.5.11, Go wltwallet) Password-share key. Only for opening
/// and testing old shares: never seal a new share to it.
pub fn password_to_ed25519_legacy(password: &str, salt: &[u8]) -> Result<PrivateKey, KeystoreError> {
    let bytes = password_bytes(password)?;
    if bytes.len() < MIN_LEGACY_PASSWORD_LEN {
        return Err(KeystoreError::PasswordTooShort);
    }
    PasswordKdf::LEGACY.derive(&bytes, salt)
}

/// The password's bytes, unsealing a vault reference.
fn password_bytes(password: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    if let Some(secret) = crate::vault::session::secret_for_token(password) {
        return secret.map_err(|e| KeystoreError::Vault(e.to_string()));
    }
    Ok(Zeroizing::new(password.as_bytes().to_vec()))
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

/// [`seal`] to one recipient, recording `kdf` (a Password share's KDF) in the
/// outer bottle's [`KDF_HEADER`].
pub fn seal_to(payload: &[u8], recipient: &PublicKey, kdf: Option<PasswordKdf>) -> Result<Vec<u8>, KeystoreError> {
    let mut bottle = Bottle::new(payload.to_vec());
    bottle.encrypt(std::slice::from_ref(recipient))?;
    if let Some(kdf) = kdf {
        bottle.header.insert(KDF_HEADER.into(), bottlers::HeaderValue::Text(kdf.to_header()));
    }
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
