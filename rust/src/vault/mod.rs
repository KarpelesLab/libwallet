//! Vault — secrets libwallet holds on the host's behalf, so the host never has
//! to.
//!
//! An entry is a secret (a StoreKey, a wallet password, or opaque data) sealed
//! by one of two backends:
//!
//! * `secure` — a per-entry key in the platform's secure storage (Secure
//!   Enclave or Keychain on Apple, Keystore on Android) releases the entry's
//!   data key, behind Face ID / Touch ID / fingerprint / passcode when the
//!   policy asks for user presence;
//! * `password` — Argon2id of a user password; the envelope is a portable blob
//!   (for a browser extension or any host without secure storage).
//!
//! Entries are used by reference: wherever a request takes `Keys`, a
//! KeyDescription `{"Type":"Vault","Key":"<entry id>"}` stands for the entry's
//! secret. The dispatcher swaps it for a request-scoped token
//! ([`session::bind_params`]) and the keystore resolves the token at the point
//! of use, so the secret is unsealed inside Rust, used, and wiped — it never
//! crosses the FFI boundary unless the entry is `Exportable` and the host asks
//! for it with `Vault:export`.

pub mod blob;
pub mod platform;
pub mod session;

use base64::Engine;
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Env, Error, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Vault" ("Id" text, "Label" text, "Kind" text, "Backend" text, "Provider" text, "Public" text, "Policy" text, "Data" blob, "Created" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Label", "Kind", "Backend", "Provider", "Public", "Policy", "Data", "Created""#;

/// Largest secret an entry holds (opaque `data` entries).
const MAX_SECRET: usize = 64 * 1024;

/// What an entry's secret is, which decides how it can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A 64-byte StoreKey: unlocks `StoreKey` wallet keys.
    StoreKey,
    /// A password: unlocks `Password` wallet keys.
    Password,
    /// Opaque bytes, only ever read back with `Vault:export`.
    Data,
}

impl Kind {
    pub fn parse(s: &str) -> Result<Kind> {
        match s {
            "storekey" => Ok(Kind::StoreKey),
            "password" => Ok(Kind::Password),
            "data" => Ok(Kind::Data),
            other => Err(Error::Env(format!("unknown vault entry kind {other:?} (storekey, password, data)"))),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::StoreKey => "storekey",
            Kind::Password => "password",
            Kind::Data => "data",
        }
    }
    /// The WalletKey type a `Type:"Vault"` KeyDescription becomes.
    pub fn key_type(self) -> Option<&'static str> {
        match self {
            Kind::StoreKey => Some("StoreKey"),
            Kind::Password => Some("Password"),
            Kind::Data => None,
        }
    }
}

/// How an entry may be used. Bound into the envelope's authenticated data, so
/// editing the stored policy makes the entry unopenable rather than weaker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Require Face ID / Touch ID / fingerprint / passcode for every release
    /// (secure backend; enforced by the OS).
    #[serde(rename = "UserPresence", default = "yes")]
    pub user_presence: bool,
    /// How long an unsealed secret may stay in memory for reuse: 0 = unseal on
    /// every use (default), N = N seconds, -1 = until `Vault:lock` or the app
    /// goes to background.
    #[serde(rename = "CacheSeconds", default)]
    pub cache_seconds: i64,
    /// Allow `Vault:export` to hand the secret to the host. Off by default.
    #[serde(rename = "Exportable", default)]
    pub exportable: bool,
}

fn yes() -> bool {
    true
}

impl Default for Policy {
    fn default() -> Self {
        Policy { user_presence: true, cache_seconds: 0, exportable: false }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: String,
    pub label: String,
    pub kind: Kind,
    /// "secure" | "password"
    pub backend: String,
    /// The concrete store ("apple-se", "android-keystore", "argon2id", …).
    pub provider: String,
    /// StoreKey entries: the base64url PKIX Ed25519 public key a wallet key is
    /// sealed to. Empty otherwise.
    pub public: String,
    pub policy: Policy,
    pub data: Vec<u8>,
    pub created: String,
}

impl Entry {
    /// The host-facing view. Never includes the sealed data; `Vault:blob`
    /// returns that for password entries.
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "Id": self.id,
            "Label": self.label,
            "Kind": self.kind.as_str(),
            "Backend": self.backend,
            "Provider": self.provider,
            "Policy": self.policy,
            "Created": self.created,
        });
        if !self.public.is_empty() {
            v["Public"] = json!(self.public);
        }
        v
    }

    /// Everything the envelope authenticates besides the secret. The password
    /// blob carries this in its cleartext header; the secure envelope binds it
    /// as associated data.
    fn meta(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "Id": self.id,
            "Label": self.label,
            "Kind": self.kind.as_str(),
            "Public": self.public,
            "Policy": self.policy,
            "Created": self.created,
        }))
        .unwrap()
    }

    /// Whether authenticated metadata (a password blob's header, a secure
    /// envelope's associated data) describes this row. The row itself is not
    /// authenticated, so this is what stops a swapped kind, public key or
    /// policy in the database. Compared field by field, not byte for byte, so
    /// envelopes keep opening when the metadata later gains fields.
    fn matches_meta(&self, meta: &[u8]) -> bool {
        let Ok(m) = serde_json::from_slice::<Value>(meta) else { return false };
        let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("");
        let policy: Option<Policy> = m.get("Policy").and_then(|p| serde_json::from_value(p.clone()).ok());
        s("Id") == self.id && s("Kind") == self.kind.as_str() && s("Public") == self.public && policy.as_ref() == Some(&self.policy)
    }

    /// Whether this row agrees with the metadata its own envelope
    /// authenticates (see [`Entry::matches_meta`]).
    pub(crate) fn matches_envelope(&self) -> bool {
        let meta = match self.backend.as_str() {
            "password" => blob::password_meta(&self.data).ok(),
            "secure" => blob::secure_parts(&self.data).ok().map(|(aad, _, _)| aad),
            _ => None,
        };
        meta.is_some_and(|m| self.matches_meta(m))
    }
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

fn row_to_entry(row: &[SqlValue]) -> Result<Entry> {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    Ok(Entry {
        id: text(0),
        label: text(1),
        kind: Kind::parse(&text(2))?,
        backend: text(3),
        provider: text(4),
        public: text(5),
        policy: serde_json::from_str(&text(6)).unwrap_or_default(),
        data: row.get(7).and_then(|v| v.as_blob()).unwrap_or_default().to_vec(),
        created: text(8),
    })
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Entry>> {
    let rows = env.query(&format!(r#"SELECT {COLS} FROM "Vault" WHERE "Id" = ?1"#), vec![SqlValue::Text(id.to_owned())])?;
    rows.first().map(|r| row_to_entry(r)).transpose()
}

pub fn list(env: &Env) -> Result<Vec<Entry>> {
    let rows = env.query(&format!(r#"SELECT {COLS} FROM "Vault" ORDER BY "Created""#), vec![])?;
    rows.iter().map(|r| row_to_entry(r)).collect()
}

fn store(env: &Env, e: &Entry) -> Result<()> {
    env.exec(r#"DELETE FROM "Vault" WHERE "Id" = ?1"#, vec![SqlValue::Text(e.id.clone())])?;
    insert(env, e)
}

/// Add a row; fails (primary key) rather than replace an entry with that id.
fn insert(env: &Env, e: &Entry) -> Result<()> {
    env.exec(
        &format!(r#"INSERT INTO "Vault" ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"#),
        vec![
            SqlValue::Text(e.id.clone()),
            SqlValue::Text(e.label.clone()),
            SqlValue::Text(e.kind.as_str().into()),
            SqlValue::Text(e.backend.clone()),
            SqlValue::Text(e.provider.clone()),
            SqlValue::Text(e.public.clone()),
            SqlValue::Text(serde_json::to_string(&e.policy).unwrap()),
            SqlValue::Blob(e.data.clone()),
            SqlValue::Text(e.created.clone()),
        ],
    )?;
    Ok(())
}

/// Remove an entry: its platform key is destroyed and any cached copy wiped.
pub fn delete(env: &Env, id: &str) -> Result<bool> {
    let Some(e) = fetch(env, id)? else { return Ok(false) };
    if e.backend == "secure" {
        if let Ok(b) = platform::backend_for(&e.provider) {
            b.delete_key(&e.id).map_err(Error::Env)?;
        }
    }
    session::forget_everywhere(&e.id);
    env.exec(r#"DELETE FROM "Vault" WHERE "Id" = ?1"#, vec![SqlValue::Text(e.id)])?;
    Ok(true)
}

/// A fresh secret of `kind`: 64 random bytes for a StoreKey, a 256-bit random
/// password (base64url) for a Password, 32 random bytes for data.
fn generate(kind: Kind) -> Zeroizing<Vec<u8>> {
    match kind {
        Kind::StoreKey => {
            let mut b = Zeroizing::new(vec![0u8; 64]);
            OsRng.fill_bytes(&mut b);
            b
        }
        Kind::Password => {
            let mut raw = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *raw);
            Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*raw).into_bytes())
        }
        Kind::Data => {
            let mut b = Zeroizing::new(vec![0u8; 32]);
            OsRng.fill_bytes(&mut b);
            b
        }
    }
}

fn check_secret(kind: Kind, secret: &[u8]) -> Result<()> {
    match kind {
        Kind::StoreKey if secret.len() != 64 => Err(Error::Env(format!("a storekey secret is 64 bytes, got {}", secret.len()))),
        Kind::Password if std::str::from_utf8(secret).is_err() => Err(Error::Env("a password secret must be UTF-8".into())),
        Kind::Password if secret.len() < 6 => Err(Error::Env("password is too short".into())),
        Kind::Data if secret.is_empty() || secret.len() > MAX_SECRET => Err(Error::Env(format!("a data secret is 1..={MAX_SECRET} bytes"))),
        _ => Ok(()),
    }
}

/// The StoreKey public key for a raw 64-byte store key (see
/// [`crate::keystore::store_key_bytes_to_ed25519`]).
fn storekey_public(secret: &[u8]) -> Result<String> {
    let k = crate::keystore::store_key_bytes_to_ed25519(secret).map_err(|e| Error::Env(e.to_string()))?;
    crate::keystore::public_key_to_pkix_b64(&k.public()).map_err(|e| Error::Env(e.to_string()))
}

/// Parameters for [`create`].
pub struct NewEntry<'a> {
    pub label: &'a str,
    pub kind: Kind,
    /// "secure" or "password".
    pub backend: &'a str,
    pub policy: Policy,
    /// The password backend's password.
    pub password: Option<&'a str>,
    /// The secret to store (`Vault:import`); None generates one in Rust.
    pub secret: Option<Zeroizing<Vec<u8>>>,
    /// Argon2id cost for the password backend (tests use a cheap one).
    pub kdf: blob::Kdf,
}

/// Create an entry, generating its secret inside Rust unless one is imported.
pub fn create(env: &Env, n: NewEntry<'_>) -> Result<Entry> {
    let secret = match n.secret {
        Some(s) => s,
        None => generate(n.kind),
    };
    check_secret(n.kind, &secret)?;
    let mut e = Entry {
        id: xuid::Xuid::new("vlt").to_string(),
        label: n.label.to_owned(),
        kind: n.kind,
        backend: n.backend.to_owned(),
        provider: String::new(),
        public: if n.kind == Kind::StoreKey { storekey_public(&secret)? } else { String::new() },
        policy: n.policy,
        data: Vec::new(),
        created: crate::db::now_rfc3339(),
    };
    match n.backend {
        "password" => {
            let pw = n.password.filter(|p| !p.is_empty()).ok_or_else(|| Error::Env("the password backend needs a Password".into()))?;
            if pw.len() < 8 {
                return Err(Error::Env("vault password must be at least 8 characters".into()));
            }
            // User presence is a platform notion; a password entry's presence
            // check is the password itself.
            e.policy.user_presence = false;
            e.provider = "argon2id".into();
            e.data = blob::seal_password(&e.meta(), pw.as_bytes(), &secret, n.kdf).map_err(Error::Env)?;
        }
        "secure" => {
            let caps = platform::capabilities();
            let b = platform::backend().filter(|_| caps.secure).ok_or_else(|| Error::Env(format!("secure storage unavailable: {}", caps.reason)))?;
            e.provider = b.provider().to_owned();
            let (dek, wrapped) = b.seal_key(&e.id, &e.policy).map_err(Error::Env)?;
            e.data = blob::seal_secure(&e.meta(), &e.provider, &wrapped, &dek, &secret).map_err(Error::Env)?;
        }
        other => return Err(Error::Env(format!("unknown vault backend {other:?} (secure, password)"))),
    }
    store(env, &e)?;
    Ok(e)
}

/// Register a password blob produced by this library (`Vault:blob`), e.g. the
/// one a browser extension kept on disk. The password is not needed until the
/// entry is used.
///
/// Loading never replaces an entry: the id comes from the blob's cleartext
/// header, so a crafted blob could otherwise swap a different envelope (and
/// policy) in under an id the host already trusts. Loading the very blob an
/// entry already holds is a no-op, which is what a host re-loading its saved
/// blob at startup does.
pub fn load_blob(env: &Env, blob_bytes: &[u8]) -> Result<Entry> {
    let meta: Value = serde_json::from_slice(blob::password_meta(blob_bytes).map_err(Error::Env)?)
        .map_err(|_| Error::Env("vault blob: bad header".into()))?;
    let s = |k: &str| meta.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let id = s("Id");
    if !id.starts_with("vlt-") {
        return Err(Error::Env("vault blob: bad entry id".into()));
    }
    let e = Entry {
        id,
        label: s("Label"),
        kind: Kind::parse(&s("Kind"))?,
        backend: "password".into(),
        provider: "argon2id".into(),
        public: s("Public"),
        policy: meta.get("Policy").and_then(|p| serde_json::from_value(p.clone()).ok()).unwrap_or_default(),
        data: blob_bytes.to_vec(),
        created: s("Created"),
    };
    if let Some(existing) = fetch(env, &e.id)? {
        if existing.backend == "password" && existing.data == e.data {
            return Ok(existing);
        }
        return Err(Error::Env(format!(
            "vault entry {} already exists with different contents; delete it before loading this blob",
            e.id
        )));
    }
    insert(env, &e)?;
    Ok(e)
}

/// Unseal an entry's secret (no cache — see [`session::secret`]). `password`
/// is the password backend's password; `reason` is shown in the OS prompt.
pub(crate) fn unseal(e: &Entry, password: Option<&str>, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
    match e.backend.as_str() {
        "password" => {
            let pw = password.ok_or_else(|| Error::Env(format!("vault entry {} is locked: unlock it with its password", e.id)))?;
            if !e.matches_meta(blob::password_meta(&e.data).map_err(Error::Env)?) {
                return Err(Error::Env("vault entry does not match its sealed metadata".into()));
            }
            blob::open_password(&e.data, pw.as_bytes()).map_err(Error::Env)
        }
        "secure" => {
            let (aad, provider, wrapped) = blob::secure_parts(&e.data).map_err(Error::Env)?;
            if !e.matches_meta(aad) {
                return Err(Error::Env("vault entry does not match its sealed metadata".into()));
            }
            let dek = platform::backend_for(provider).map_err(Error::Env)?.open_key(&e.id, wrapped, reason).map_err(Error::Env)?;
            blob::open_secure(&e.data, &dek).map_err(Error::Env)
        }
        other => Err(Error::Env(format!("unknown vault backend {other}"))),
    }
}

/// Re-seal a password entry under a new password (same id, same secret).
pub fn change_password(env: &Env, id: &str, old: &str, new: &str, kdf: blob::Kdf) -> Result<Entry> {
    let mut e = fetch(env, id)?.ok_or_else(|| Error::Env("vault entry not found".into()))?;
    if e.backend != "password" {
        return Err(Error::Env("only password entries have a password".into()));
    }
    if new.len() < 8 {
        return Err(Error::Env("vault password must be at least 8 characters".into()));
    }
    let secret = unseal(&e, Some(old), "")?;
    e.data = blob::seal_password(&e.meta(), new.as_bytes(), &secret, kdf).map_err(Error::Env)?;
    store(env, &e)?;
    Ok(e)
}

/// The secret as the host would pass it before vaults existed: StoreKey =
/// base64url of the 64 bytes (`StoreKey:create`'s `private`), Password =
/// itself, data = base64url.
pub fn encode_secret(kind: Kind, secret: &[u8]) -> Zeroizing<String> {
    match kind {
        Kind::Password => Zeroizing::new(String::from_utf8_lossy(secret).into_owned()),
        _ => Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret)),
    }
}

/// Inverse of [`encode_secret`] for `Vault:import`. `encoding` overrides the
/// kind's default ("utf8", "base64", "base64url", "hex").
pub fn decode_secret(kind: Kind, secret: &str, encoding: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let enc = encoding.unwrap_or(if kind == Kind::Password { "utf8" } else { "base64url" });
    let s = secret.trim();
    let bytes = match enc {
        "utf8" => secret.as_bytes().to_vec(),
        "base64url" => URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|e| Error::Env(format!("Secret is not base64url: {e}")))?,
        "base64" => STANDARD.decode(s).map_err(|e| Error::Env(format!("Secret is not base64: {e}")))?,
        "hex" => (0..s.len() / 2)
            .map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2).unwrap_or("zz"), 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .ok()
            .filter(|_| s.len() % 2 == 0)
            .ok_or_else(|| Error::Env("Secret is not hex".into()))?,
        other => return Err(Error::Env(format!("unknown Encoding {other:?}"))),
    };
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests;
