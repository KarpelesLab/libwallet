//! secp256k1 keys, ECDSA (RFC6979 deterministic, low-S, DER + recoverable) and
//! BIP-340 Schnorr / BIP-341 taproot, built on `purecrypto`'s hazmat secp256k1
//! scalar/point arithmetic.
//!
//! The ECDSA path uses the standard RFC6979 deterministic nonce, low-S
//! normalization, and recovery-code semantics, so signatures are reproducible
//! and interoperable with other conforming implementations.

use num_bigint::BigUint;
use num_traits::Num;
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::{HmacSha256, sha256};

/// secp256k1 group order n.
fn n_biguint() -> BigUint {
    BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
}

/// secp256k1 field prime p.
fn p_biguint() -> BigUint {
    BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .unwrap()
}

/// (n-1)/2, the low-S threshold (big-endian 32 bytes).
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn is_over_half_order(s_be: &[u8; 32]) -> bool {
    // Equal-length big-endian comparison is numeric comparison.
    s_be[..] > HALF_ORDER[..]
}

/// Errors from secp256k1 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A secret key, scalar or coordinate was out of range.
    InvalidKey,
    /// A point or encoding was malformed.
    Malformed,
    /// Public-key recovery failed.
    Recovery,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidKey => f.write_str("invalid secp256k1 key"),
            Error::Malformed => f.write_str("malformed secp256k1 data"),
            Error::Recovery => f.write_str("secp256k1 public-key recovery failed"),
        }
    }
}
impl core::error::Error for Error {}

// ---------------------------------------------------------------------------
// HMAC-SHA256 helper
// ---------------------------------------------------------------------------

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut data = Vec::new();
    for p in parts {
        data.extend_from_slice(p);
    }
    HmacSha256::mac(key, &data)
}

/// RFC6979 deterministic nonce generation (HMAC-SHA256), matching
/// `KarpelesLab/secp256k1`'s `NonceRFC6979` with `extra`/`version` unset.
/// `extra_iterations` selects the (extra_iterations+1)-th valid candidate.
fn generate_k(priv_be: &[u8; 32], hash: &[u8; 32], extra_iterations: u32) -> Scalar {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(priv_be);
    key.extend_from_slice(hash);

    let mut v = [1u8; 32];
    let mut k = [0u8; 32];

    k = hmac(&k, &[&v, &[0x00], &key]);
    v = hmac(&k, &[&v]);
    k = hmac(&k, &[&v, &[0x01], &key]);
    v = hmac(&k, &[&v]);

    let mut generated: u32 = 0;
    loop {
        v = hmac(&k, &[&v]);
        if let Ok(cand) = Scalar::from_bytes_be(&v)
            && !bool::from(cand.is_zero())
        {
            generated += 1;
            if generated > extra_iterations {
                return cand;
            }
        }
        k = hmac(&k, &[&v, &[0x00]]);
        v = hmac(&k, &[&v]);
    }
}

// ---------------------------------------------------------------------------
// Public key
// ---------------------------------------------------------------------------

/// A secp256k1 public key.
#[derive(Clone)]
pub struct SecpPublicKey {
    point: AffinePoint,
}

impl SecpPublicKey {
    /// Parses a SEC1-encoded public key (compressed 0x02/0x03 or uncompressed 0x04).
    pub fn from_sec1(bytes: &[u8]) -> Result<SecpPublicKey, Error> {
        let point = AffinePoint::from_sec1(bytes).map_err(|_| Error::Malformed)?;
        Ok(SecpPublicKey { point })
    }

    /// Returns the 33-byte compressed SEC1 encoding.
    pub fn serialize_compressed(&self) -> [u8; 33] {
        self.point.to_sec1_compressed()
    }

    /// Returns the 65-byte uncompressed SEC1 encoding.
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.point.to_sec1_uncompressed()
    }

    /// Returns the 32-byte x-only public key (compressed key without prefix).
    pub fn x_only(&self) -> [u8; 32] {
        self.point.x_bytes()
    }

    /// Verifies a low-level ECDSA signature `(r, s)` over `hash`.
    pub fn verify(&self, hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
        let r = match Scalar::from_bytes_be(r) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let s = match Scalar::from_bytes_be(s) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
            return false;
        }
        let e = Scalar::from_bytes_be_reduce(hash);
        let w = s.invert();
        let u1 = e.mul(&w);
        let u2 = r.mul(&w);
        let big_r = ProjectivePoint::mul_generator(&u1).add(&self.point.to_projective().mul(&u2));
        let big_r = match big_r.to_affine() {
            Some(p) => p,
            None => return false,
        };
        // r' = R.x mod n
        let x = big_r.x_bytes();
        let r_prime = match Scalar::from_bytes_be(&x) {
            Ok(v) => v,
            Err(_) => Scalar::from_bytes_be_reduce(&x),
        };
        bool::from(r_prime.ct_eq(&r))
    }
}

// ---------------------------------------------------------------------------
// Private key
// ---------------------------------------------------------------------------

/// A secp256k1 private key.
#[derive(Clone)]
pub struct SecpPrivateKey {
    d: Scalar,
    d_be: [u8; 32],
}

impl SecpPrivateKey {
    /// Creates a private key from a 32-byte big-endian secret scalar. Returns
    /// an error if the scalar is zero or >= n.
    pub fn from_bytes(secret: &[u8; 32]) -> Result<SecpPrivateKey, Error> {
        let d = Scalar::from_bytes_be(secret).map_err(|_| Error::InvalidKey)?;
        if bool::from(d.is_zero()) {
            return Err(Error::InvalidKey);
        }
        Ok(SecpPrivateKey { d, d_be: *secret })
    }

    /// Derives the public key.
    pub fn public_key(&self) -> SecpPublicKey {
        let point = ProjectivePoint::mul_generator(&self.d)
            .to_affine()
            .expect("d in [1,n-1] so d*G is not identity");
        SecpPublicKey { point }
    }

    /// Low-level RFC6979 ECDSA signing of a 32-byte digest. Returns
    /// `(r, s, recovery_id)` with `s` in low-S form and `recovery_id` in 0..=3.
    pub fn sign_recoverable(&self, hash: &[u8; 32]) -> ([u8; 32], [u8; 32], u8) {
        for iteration in 0u32.. {
            let k = generate_k(&self.d_be, hash, iteration);
            let big_r = ProjectivePoint::mul_generator(&k)
                .to_affine()
                .expect("k != 0 so k*G is not identity");
            let x = big_r.x_bytes();
            let (r, overflow) = match Scalar::from_bytes_be(&x) {
                Ok(v) => (v, 0u8),
                Err(_) => (Scalar::from_bytes_be_reduce(&x), 1u8),
            };
            if bool::from(r.is_zero()) {
                continue;
            }
            let y_odd = big_r.y_bytes()[31] & 1;
            let mut recid = (overflow << 1) | y_odd;

            let e = Scalar::from_bytes_be_reduce(hash);
            let kinv = k.invert();
            let mut s = self.d.mul(&r).add(&e).mul(&kinv);
            if bool::from(s.is_zero()) {
                continue;
            }
            let s_be = s.to_bytes_be();
            if is_over_half_order(&s_be) {
                s = s.negate();
                recid ^= 1;
            }
            return (r.to_bytes_be(), s.to_bytes_be(), recid);
        }
        unreachable!()
    }

    /// RFC6979 ECDSA signing of a 32-byte digest, returning a DER-encoded
    /// signature with low-S (as used for Bitcoin).
    pub fn sign_der(&self, hash: &[u8; 32]) -> Vec<u8> {
        let (r, s, _) = self.sign_recoverable(hash);
        der_encode(&r, &s)
    }

    /// BIP-341 key-path taproot signing: applies the taproot tweak to this key
    /// (empty merkle root) and produces a 64-byte BIP-340 Schnorr signature
    /// over `sighash`. Uses deterministic (zero) auxiliary randomness.
    pub fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], Error> {
        let pub_bytes = self.public_key().serialize_compressed();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&pub_bytes[1..]);
        let (_, parity, tweak) = taproot_tweak_full(&x_only)?;

        // d' = d if internal P.y even else n-d
        let mut d = if pub_bytes[0] == 0x03 {
            self.d.negate()
        } else {
            self.d.clone()
        };
        let t = Scalar::from_bytes_be(&tweak).map_err(|_| Error::InvalidKey)?;
        d = d.add(&t);
        if parity == 1 {
            d = d.negate();
        }
        bip340_sign_scalar(&d, sighash, &[0u8; 32])
    }
}

// ---------------------------------------------------------------------------
// DER encoding
// ---------------------------------------------------------------------------

fn canon_int(value_be: &[u8; 32]) -> Vec<u8> {
    // Prepend a 0x00 then strip leading 0x00 bytes while the next byte's high
    // bit is clear (keeps the DER integer positive and minimally encoded).
    let mut buf = [0u8; 33];
    buf[1..].copy_from_slice(value_be);
    let mut start = 0;
    while start < 32 && buf[start] == 0x00 && buf[start + 1] & 0x80 == 0 {
        start += 1;
    }
    buf[start..].to_vec()
}

fn der_encode(r_be: &[u8; 32], s_be: &[u8; 32]) -> Vec<u8> {
    let r = canon_int(r_be);
    let s = canon_int(s_be);
    // total length of the whole signature (mirrors Go: 6 + len(r) + len(s)).
    let total = 6 + r.len() + s.len();
    let mut out = Vec::with_capacity(total);
    out.push(0x30);
    out.push((total - 2) as u8);
    out.push(0x02);
    out.push(r.len() as u8);
    out.extend_from_slice(&r);
    out.push(0x02);
    out.push(s.len() as u8);
    out.extend_from_slice(&s);
    out
}

/// Parses a DER-encoded ECDSA signature into 32-byte big-endian `(r, s)`.
pub fn parse_der_signature(sig: &[u8]) -> Result<([u8; 32], [u8; 32]), Error> {
    if sig.len() < 8 || sig.len() > 72 {
        return Err(Error::Malformed);
    }
    if sig[0] != 0x30 {
        return Err(Error::Malformed);
    }
    if sig[1] as usize != sig.len() - 2 {
        return Err(Error::Malformed);
    }
    if sig[2] != 0x02 {
        return Err(Error::Malformed);
    }
    let r_len = sig[3] as usize;
    let s_type_off = 4 + r_len;
    if s_type_off + 1 >= sig.len() || sig[s_type_off] != 0x02 {
        return Err(Error::Malformed);
    }
    let s_len = sig[s_type_off + 1] as usize;
    let s_off = s_type_off + 2;
    if s_off + s_len != sig.len() {
        return Err(Error::Malformed);
    }
    let r = normalize_32(&sig[4..4 + r_len])?;
    let s = normalize_32(&sig[s_off..s_off + s_len])?;
    Ok((r, s))
}

fn normalize_32(b: &[u8]) -> Result<[u8; 32], Error> {
    let mut start = 0;
    while start < b.len() && b[start] == 0x00 {
        start += 1;
    }
    let trimmed = &b[start..];
    if trimmed.len() > 32 {
        return Err(Error::Malformed);
    }
    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Recovers the public key from an ECDSA signature `(r, s)`, recovery id, and
/// 32-byte message digest.
pub fn recover_public_key(
    r_be: &[u8; 32],
    s_be: &[u8; 32],
    recid: u8,
    hash: &[u8; 32],
) -> Result<SecpPublicKey, Error> {
    if recid > 3 {
        return Err(Error::Recovery);
    }
    let r = Scalar::from_bytes_be(r_be).map_err(|_| Error::Recovery)?;
    let s = Scalar::from_bytes_be(s_be).map_err(|_| Error::Recovery)?;
    if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
        return Err(Error::Recovery);
    }

    // Determine the x coordinate of R (possibly r + n).
    let n = n_biguint();
    let p = p_biguint();
    let r_int = BigUint::from_bytes_be(r_be);
    let x_int = if recid & 0x02 != 0 {
        let x = &r_int + &n;
        if x >= p {
            return Err(Error::Recovery);
        }
        x
    } else {
        r_int
    };
    let mut x_bytes = [0u8; 32];
    let xb = x_int.to_bytes_be();
    if xb.len() > 32 {
        return Err(Error::Recovery);
    }
    x_bytes[32 - xb.len()..].copy_from_slice(&xb);

    // Lift x to a point with the requested y parity using SEC1 decompression.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02 | (recid & 1);
    compressed[1..].copy_from_slice(&x_bytes);
    let big_x = AffinePoint::from_sec1(&compressed).map_err(|_| Error::Recovery)?;

    let e = Scalar::from_bytes_be_reduce(hash);
    let w = r.invert();
    let u1 = e.mul(&w).negate();
    let u2 = s.mul(&w);
    let q = ProjectivePoint::mul_generator(&u1).add(&big_x.to_projective().mul(&u2));
    if bool::from(q.is_identity()) {
        return Err(Error::Recovery);
    }
    let point = q.to_affine().ok_or(Error::Recovery)?;
    Ok(SecpPublicKey { point })
}

// ---------------------------------------------------------------------------
// BIP-340 Schnorr / BIP-341 taproot
// ---------------------------------------------------------------------------

/// Computes a BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let th = sha256(tag.as_bytes());
    let mut data = Vec::with_capacity(64 + parts.iter().map(|p| p.len()).sum::<usize>());
    data.extend_from_slice(&th);
    data.extend_from_slice(&th);
    for p in parts {
        data.extend_from_slice(p);
    }
    sha256(&data)
}

fn taproot_tweak_full(internal_xonly: &[u8; 32]) -> Result<([u8; 32], u8, [u8; 32]), Error> {
    // lift_x: even-Y point with this x coordinate.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(internal_xonly);
    let p_point = AffinePoint::from_sec1(&compressed).map_err(|_| Error::Malformed)?;

    let t_bytes = tagged_hash("TapTweak", &[internal_xonly]);
    let t = Scalar::from_bytes_be(&t_bytes).map_err(|_| Error::InvalidKey)?;

    let q = p_point
        .to_projective()
        .add(&ProjectivePoint::mul_generator(&t));
    let qa = q.to_affine().ok_or(Error::Malformed)?;
    let tweaked = qa.x_bytes();
    let parity = qa.y_bytes()[31] & 1;
    Ok((tweaked, parity, t_bytes))
}

/// Applies the BIP-341 key-path-only taproot tweak (empty merkle root) to a
/// 32-byte x-only internal public key, returning the tweaked x-only output key
/// and the parity (0 if Q.y even, 1 if odd).
pub fn taproot_tweak(internal_xonly: &[u8; 32]) -> Result<([u8; 32], u8), Error> {
    let (xonly, parity, _) = taproot_tweak_full(internal_xonly)?;
    Ok((xonly, parity))
}

fn bip340_sign_scalar(d0: &Scalar, msg: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], Error> {
    if bool::from(d0.is_zero()) {
        return Err(Error::InvalidKey);
    }
    // P = d0*G; if P.y odd, d = n - d0.
    let p_point = ProjectivePoint::mul_generator(d0)
        .to_affine()
        .ok_or(Error::InvalidKey)?;
    let p_y_odd = p_point.y_bytes()[31] & 1 == 1;
    let d = if p_y_odd { d0.negate() } else { d0.clone() };
    let px = p_point.x_bytes();

    // t = d XOR tagged_hash("BIP0340/aux", aux)
    let aux_hash = tagged_hash("BIP0340/aux", &[aux]);
    let d_bytes = d.to_bytes_be();
    let mut t = [0u8; 32];
    for i in 0..32 {
        t[i] = d_bytes[i] ^ aux_hash[i];
    }

    // rand = tagged_hash("BIP0340/nonce", t || P.x || msg)
    let rand = tagged_hash("BIP0340/nonce", &[&t, &px, msg]);
    let mut k = Scalar::from_bytes_be_reduce(&rand);
    if bool::from(k.is_zero()) {
        return Err(Error::InvalidKey);
    }

    // R = k*G; if R.y odd, k = n - k.
    let big_r = ProjectivePoint::mul_generator(&k)
        .to_affine()
        .ok_or(Error::InvalidKey)?;
    if big_r.y_bytes()[31] & 1 == 1 {
        k = k.negate();
    }
    let rx = big_r.x_bytes();

    // e = int(tagged_hash("BIP0340/challenge", R.x || P.x || msg)) mod n
    let e_bytes = tagged_hash("BIP0340/challenge", &[&rx, &px, msg]);
    let e = Scalar::from_bytes_be_reduce(&e_bytes);

    // s = k + e*d
    let s = k.add(&e.mul(&d));
    let s_bytes = s.to_bytes_be();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx);
    sig[32..].copy_from_slice(&s_bytes);
    Ok(sig)
}

/// BIP-340 Schnorr signature over a 32-byte message using a 32-byte secret key,
/// with the given 32-byte auxiliary randomness (pass zeros for deterministic).
pub fn bip340_sign(secret: &[u8; 32], msg: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], Error> {
    let d0 = Scalar::from_bytes_be(secret).map_err(|_| Error::InvalidKey)?;
    bip340_sign_scalar(&d0, msg, aux)
}

/// Verifies a 64-byte BIP-340 Schnorr signature over `msg` against a 32-byte
/// x-only public key.
pub fn bip340_verify(xonly_pub: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    // P = lift_x(xonly_pub) (even Y).
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(xonly_pub);
    let p_point = match AffinePoint::from_sec1(&compressed) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let mut rx = [0u8; 32];
    rx.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let s = match Scalar::from_bytes_be(&s_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // e = tagged_hash("BIP0340/challenge", rx || P.x || msg) mod n
    let e_bytes = tagged_hash("BIP0340/challenge", &[&rx, xonly_pub, msg]);
    let e = Scalar::from_bytes_be_reduce(&e_bytes);

    // R = s*G - e*P
    let r_point = ProjectivePoint::mul_generator(&s).add(&p_point.to_projective().mul(&e.negate()));
    let r_affine = match r_point.to_affine() {
        Some(p) => p,
        None => return false,
    };
    // R.y must be even and R.x == rx.
    if r_affine.y_bytes()[31] & 1 != 0 {
        return false;
    }
    r_affine.x_bytes() == rx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn arr32(s: &str) -> [u8; 32] {
        let v = h(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn pubkey_compressed_uncompressed() {
        // From the Go outscript address test (priv eb696a...).
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
        ))
        .unwrap();
        let pk = sk.public_key();
        let comp = hex::encode(pk.serialize_compressed());
        // Must start with 02/03 and be 33 bytes.
        assert_eq!(comp.len(), 66);
        assert!(comp.starts_with("02") || comp.starts_with("03"));
        // Uncompressed begins with 04.
        assert!(hex::encode(pk.serialize_uncompressed()).starts_with("04"));
    }

    #[test]
    fn ecdsa_rfc6979_deterministic_and_verify() {
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ))
        .unwrap();
        let msg = super::sha256(b"Satoshi Nakamoto");
        let (r1, s1, _) = sk.sign_recoverable(&msg);
        let (r2, s2, _) = sk.sign_recoverable(&msg);
        assert_eq!(r1, r2);
        assert_eq!(s1, s2);
        assert!(sk.public_key().verify(&msg, &r1, &s1));
        // low-S
        assert!(!is_over_half_order(&s1));
    }

    #[test]
    fn ecdsa_recovery_roundtrip() {
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
        ))
        .unwrap();
        let msg = super::sha256(b"recover me");
        let (r, s, recid) = sk.sign_recoverable(&msg);
        let rec = recover_public_key(&r, &s, recid, &msg).unwrap();
        assert_eq!(
            rec.serialize_compressed(),
            sk.public_key().serialize_compressed()
        );
    }

    #[test]
    fn der_roundtrip() {
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ))
        .unwrap();
        let msg = super::sha256(b"der");
        let der = sk.sign_der(&msg);
        let (r, s) = parse_der_signature(&der).unwrap();
        assert!(sk.public_key().verify(&msg, &r, &s));
    }

    #[test]
    fn rfc6979_known_nonce() {
        // Canonical secp256k1 + SHA-256 RFC6979 vector (message "sample").
        let d = arr32("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let hash = super::sha256(b"sample");
        let k = generate_k(&d, &hash, 0);
        assert_eq!(
            hex::encode(k.to_bytes_be()),
            "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60"
        );
    }

    #[test]
    fn bip340_test_vector_0() {
        // BIP-340 test vector index 0.
        let secret = arr32("0000000000000000000000000000000000000000000000000000000000000003");
        let msg = arr32("0000000000000000000000000000000000000000000000000000000000000000");
        let aux = arr32("0000000000000000000000000000000000000000000000000000000000000000");
        let sig = bip340_sign(&secret, &msg, &aux).unwrap();
        let expected = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
        assert_eq!(hex::encode(sig).to_uppercase(), expected);
    }
}
