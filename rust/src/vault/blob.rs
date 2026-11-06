//! The two sealed formats a vault entry's secret is stored in. Both are
//! versioned binary envelopes; the symmetric crypto is XChaCha20-Poly1305 with
//! everything outside the ciphertext (magic, version, entry metadata, KDF
//! parameters / platform-wrapped key) bound in as associated data, so a
//! tampered policy, kind or id makes the open fail rather than change meaning.
//!
//! * **Password** (`LWVP`): the key is Argon2id(password, salt). The envelope
//!   is self-describing — its cleartext header carries the entry metadata —
//!   so it doubles as the portable blob a browser extension keeps on disk and
//!   hands back to `Vault:load`.
//! * **Secure** (`LWVS`): the key is a data-encryption key released by the
//!   platform backend (Secure Enclave / Keychain / Android Keystore), which
//!   stores its own wrapped form of it here.

use purecrypto::cipher::XChaCha20Poly1305;
use purecrypto::kdf::argon2::{argon2, Argon2Params, Argon2Type};
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::zeroize::Zeroizing;

const MAGIC_PASSWORD: &[u8; 4] = b"LWVP";
const MAGIC_SECURE: &[u8; 4] = b"LWVS";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Argon2id cost. The default is RFC 9106's second recommended option
/// (64 MiB, 3 passes) with one lane, so it costs the same in a single-threaded
/// browser as on a phone (≈0.3–1 s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u8,
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf { m_kib: 64 * 1024, t: 3, p: 1 }
    }
}

impl Kdf {
    /// Bounds a blob's parameters must sit in before we spend memory on them:
    /// the blob is attacker-supplied input to `Vault:load`.
    fn check(&self) -> Result<(), String> {
        if !(1..=8).contains(&self.p) || self.t == 0 || self.t > 16 {
            return Err("vault blob: unsupported Argon2 parameters".into());
        }
        if self.m_kib < 8 * self.p as u32 || self.m_kib > 1024 * 1024 {
            return Err("vault blob: unsupported Argon2 memory cost".into());
        }
        Ok(())
    }

    fn derive(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        self.check()?;
        let params = Argon2Params {
            t_cost: self.t,
            m_cost_kib: self.m_kib,
            parallelism: self.p as u32,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        let mut key = Zeroizing::new([0u8; 32]);
        argon2(&params, password, salt, &[], &[], &mut *key).map_err(|e| format!("argon2: {e:?}"))?;
        Ok(key)
    }
}

fn put_u16_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), String> {
    let n = u16::try_from(b.len()).map_err(|_| "vault blob: field too long".to_string())?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

/// A tiny cursor over an envelope; every read is bounds-checked.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("vault blob: truncated")?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u16_bytes(&mut self) -> Result<&'a [u8], String> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        self.take(n)
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// AEAD-seal `secret` under `key`, appending `nonce || ct || tag` to `out`,
/// whose current contents are the associated data.
fn seal_tail(out: &mut Vec<u8>, key: &[u8; 32], secret: &[u8]) {
    let nonce: [u8; NONCE_LEN] = random();
    let aad = out.clone();
    out.extend_from_slice(&nonce);
    let start = out.len();
    out.extend_from_slice(secret);
    let tag = XChaCha20Poly1305::new(key).encrypt(&nonce, &aad, &mut out[start..]);
    out.extend_from_slice(&tag);
}

/// Inverse of [`seal_tail`]: `blob[..at]` is the associated data.
fn open_tail(blob: &[u8], at: usize, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, String> {
    let rest = &blob[at..];
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err("vault blob: truncated".into());
    }
    let nonce: [u8; NONCE_LEN] = rest[..NONCE_LEN].try_into().unwrap();
    let (ct, tag) = rest[NONCE_LEN..].split_at(rest.len() - NONCE_LEN - TAG_LEN);
    let tag: [u8; TAG_LEN] = tag.try_into().unwrap();
    let mut buf = Zeroizing::new(ct.to_vec());
    XChaCha20Poly1305::new(key)
        .decrypt(&nonce, &blob[..at], &mut buf, &tag)
        .map_err(|_| "wrong password or damaged vault data".to_string())?;
    Ok(buf)
}

/// Seal `secret` under `password`. `meta` (the entry's id/label/kind/policy/
/// public, as JSON) rides in the clear header so `Vault:load` can register the
/// entry without the password — and is authenticated, so it cannot be edited.
pub fn seal_password(meta: &[u8], password: &[u8], secret: &[u8], kdf: Kdf) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT_LEN] = random();
    let key = kdf.derive(password, &salt)?;
    let mut out = Vec::with_capacity(64 + meta.len() + secret.len());
    out.extend_from_slice(MAGIC_PASSWORD);
    out.push(VERSION);
    put_u16_bytes(&mut out, meta)?;
    out.extend_from_slice(&kdf.m_kib.to_be_bytes());
    out.extend_from_slice(&kdf.t.to_be_bytes());
    out.push(kdf.p);
    out.extend_from_slice(&salt);
    seal_tail(&mut out, &key, secret);
    Ok(out)
}

/// A password envelope's cleartext header, read without the password.
pub fn password_meta(blob: &[u8]) -> Result<&[u8], String> {
    let mut r = Reader { b: blob, at: 0 };
    if r.take(4)? != MAGIC_PASSWORD {
        return Err("not a libwallet vault blob".into());
    }
    if r.u8()? != VERSION {
        return Err("unsupported vault blob version".into());
    }
    r.u16_bytes()
}

/// Open a password envelope.
pub fn open_password(blob: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut r = Reader { b: blob, at: 0 };
    password_meta(blob)?;
    r.take(4 + 1)?;
    r.u16_bytes()?;
    let kdf = Kdf { m_kib: r.u32()?, t: r.u32()?, p: r.u8()? };
    let salt = r.take(SALT_LEN)?;
    let key = kdf.derive(password, salt)?;
    open_tail(blob, r.at, &key)
}

/// Seal `secret` under a platform-released `dek`. `provider` names the backend
/// and `wrapped` is its own wrapped form of the dek; `aad` binds the entry's
/// id, kind and policy.
pub fn seal_secure(aad: &[u8], provider: &str, wrapped: &[u8], dek: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64 + wrapped.len() + secret.len());
    out.extend_from_slice(MAGIC_SECURE);
    out.push(VERSION);
    put_u16_bytes(&mut out, aad)?;
    put_u16_bytes(&mut out, provider.as_bytes())?;
    put_u16_bytes(&mut out, wrapped)?;
    seal_tail(&mut out, dek, secret);
    Ok(out)
}

/// The parts of a secure envelope needed to ask the platform for the dek:
/// `(aad, provider, wrapped)`.
pub fn secure_parts(blob: &[u8]) -> Result<(&[u8], &str, &[u8]), String> {
    let mut r = Reader { b: blob, at: 0 };
    if r.take(4)? != MAGIC_SECURE {
        return Err("not a secure vault envelope".into());
    }
    if r.u8()? != VERSION {
        return Err("unsupported vault envelope version".into());
    }
    let aad = r.u16_bytes()?;
    let provider = std::str::from_utf8(r.u16_bytes()?).map_err(|_| "vault envelope: bad provider")?;
    Ok((aad, provider, r.u16_bytes()?))
}

/// Open a secure envelope with the dek the platform released.
pub fn open_secure(blob: &[u8], dek: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, String> {
    let (_, _, wrapped) = secure_parts(blob)?;
    let at = wrapped.as_ptr() as usize - blob.as_ptr() as usize + wrapped.len();
    open_tail(blob, at, dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Kdf = Kdf { m_kib: 64, t: 1, p: 1 };

    #[test]
    fn password_roundtrip_and_tamper() {
        let meta = br#"{"Id":"vlt-1","Kind":"password"}"#;
        let blob = seal_password(meta, b"hunter22", b"s3cret", FAST).unwrap();
        assert_eq!(password_meta(&blob).unwrap(), meta);
        assert_eq!(&*open_password(&blob, b"hunter22").unwrap(), b"s3cret");
        assert!(open_password(&blob, b"hunter23").is_err());
        // Flipping any header byte (here: the metadata) breaks the open.
        let mut bad = blob.clone();
        bad[10] ^= 1;
        assert!(open_password(&bad, b"hunter22").is_err());
        // Truncation is an error, not a panic.
        for n in 0..blob.len() {
            assert!(open_password(&blob[..n], b"hunter22").is_err());
        }
    }

    #[test]
    fn hostile_kdf_parameters_are_refused_before_allocating() {
        let mut blob = seal_password(b"{}", b"pw", b"x", FAST).unwrap();
        // m_kib sits right after magic(4)+ver(1)+len(2)+meta(2).
        blob[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(open_password(&blob, b"pw").unwrap_err().contains("memory"));
    }

    #[test]
    fn secure_roundtrip() {
        let dek = [7u8; 32];
        let blob = seal_secure(b"aad", "test", b"wrapped-dek", &dek, b"payload").unwrap();
        let (aad, provider, wrapped) = secure_parts(&blob).unwrap();
        assert_eq!((aad, provider, wrapped), (&b"aad"[..], "test", &b"wrapped-dek"[..]));
        assert_eq!(&*open_secure(&blob, &dek).unwrap(), b"payload");
        assert!(open_secure(&blob, &[8u8; 32]).is_err());
    }
}
