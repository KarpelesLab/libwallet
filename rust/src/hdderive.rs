//! HD public-key derivation for TSS accounts (port of the secp256k1/ecckd use
//! in wltacct). TSS wallets have no private key material, so accounts derive
//! via BIP32 **non-hardened public** steps from the wallet's group public key +
//! chain code (Go path e.g. m/44/60/0/{index}), then the child pubkey is turned
//! into a chain address.
//!
//! Verified against BIP32 test vector 2 (`m/0`) and the EIP-55 spec vectors.

use num_bigint::{BigInt, Sign};
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::keccak256;
use purecrypto::hash::HmacSha512;

/// The secp256k1 group order n.
fn secp_order() -> BigInt {
    BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}

#[derive(Debug)]
pub struct DeriveError(pub String);

impl std::fmt::Display for DeriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hd derive: {}", self.0)
    }
}

/// One BIP32 non-hardened public child derivation. Returns the child compressed
/// pubkey (33 bytes), the child chain code (32 bytes), and IL (the 32-byte
/// tweak added at this step, `child = IL·G + parent`).
fn ckd_pub(parent_pub_compressed: &[u8; 33], chain_code: &[u8; 32], index: u32) -> Result<([u8; 33], [u8; 32], [u8; 32]), DeriveError> {
    if index >= 0x8000_0000 {
        return Err(DeriveError(format!("hardened index {index} needs a private key")));
    }
    let mut mac = HmacSha512::new(chain_code);
    mac.update(parent_pub_compressed);
    mac.update(&index.to_be_bytes());
    let i = mac.finalize(); // 64 bytes

    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..]);

    let il_scalar = Scalar::from_bytes_be(&il).map_err(|_| DeriveError("IL >= curve order".into()))?;
    let parent = AffinePoint::from_sec1(parent_pub_compressed)
        .map_err(|e| DeriveError(format!("bad parent pubkey: {e:?}")))?;
    let child = ProjectivePoint::mul_generator(&il_scalar).add(&parent.to_projective());
    let child_affine = child.to_affine().ok_or_else(|| DeriveError("child is identity".into()))?;
    Ok((child_affine.to_sec1_compressed(), ir, il))
}

/// Parse a BIP32 path string (`m/44'/60'/0'/0/0`, `'`/`h`/`H` = hardened) into
/// the `u32` steps with the hardened bit OR'd in. Empty / `m` = master.
pub fn parse_bip32_path(path: &str) -> Result<Vec<u32>, DeriveError> {
    let path = path.trim();
    if path.is_empty() || path == "m" || path == "M" {
        return Ok(Vec::new());
    }
    let mut parts = path.split('/');
    match parts.next() {
        Some("m") | Some("M") => {}
        _ => return Err(DeriveError(format!("bip32 path {path:?} must start with m/"))),
    }
    let mut out = Vec::new();
    for p in parts {
        if p.is_empty() {
            return Err(DeriveError(format!("bip32 path {path:?} has an empty component")));
        }
        let (num, hardened) = match p.strip_suffix(['\'', 'h', 'H']) {
            Some(n) => (n, true),
            None => (p, false),
        };
        let n: u32 = num.parse().map_err(|_| DeriveError(format!("bip32 path component {p:?} not a number")))?;
        if n >= 0x8000_0000 {
            return Err(DeriveError(format!("bip32 path component {p:?} overflows 31 bits (use ' for hardened)")));
        }
        out.push(if hardened { n | 0x8000_0000 } else { n });
    }
    Ok(out)
}

/// Derive the 32-byte **private** key at `path` from a BIP39 `seed` (Go
/// `derivePrivkeyFromSeed`). secp256k1 = BIP32 (Bitcoin-seed master + CKDpriv);
/// ed25519 = seed[:32] for an empty path (Sollet), else SLIP-0010 all-hardened.
pub fn derive_privkey_from_seed(seed: &[u8], curve: &str, path: &str) -> Result<[u8; 32], DeriveError> {
    let steps = parse_bip32_path(path)?;
    match curve {
        "secp256k1" => {
            let (mut key, mut cc) = hmac_master(b"Bitcoin seed", seed);
            for idx in steps {
                let (k, c) = ckd_priv(&key, &cc, idx)?;
                key = k;
                cc = c;
            }
            Ok(key)
        }
        "ed25519" | "" => {
            if steps.is_empty() {
                if seed.len() < 32 {
                    return Err(DeriveError("seed too short for ed25519 no-derivation mode".into()));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&seed[..32]);
                return Ok(out);
            }
            slip10_ed25519(seed, &steps)
        }
        other => Err(DeriveError(format!("unsupported curve {other:?}"))),
    }
}

/// The 33-byte compressed pubkey (secp256k1) or 32-byte raw pubkey (ed25519)
/// for the private key `derive_privkey_from_seed` would produce (Go
/// `derivePubkeyForPath`).
pub fn derive_pubkey_for_path(seed: &[u8], curve: &str, path: &str) -> Result<Vec<u8>, DeriveError> {
    let priv_key = derive_privkey_from_seed(seed, curve, path)?;
    match curve {
        "secp256k1" => {
            let scalar = Scalar::from_bytes_be(&priv_key).map_err(|_| DeriveError("private key >= curve order".into()))?;
            let pt = ProjectivePoint::mul_generator(&scalar).to_affine().ok_or_else(|| DeriveError("pubkey is identity".into()))?;
            Ok(pt.to_sec1_compressed().to_vec())
        }
        "ed25519" | "" => {
            let sk = purecrypto::ec::Ed25519PrivateKey::from_bytes(priv_key);
            Ok(sk.public_key().to_bytes().to_vec())
        }
        other => Err(DeriveError(format!("unsupported curve {other:?}"))),
    }
}

/// HMAC-SHA512(`key`, seed) split into a 32-byte master key + 32-byte chain code.
fn hmac_master(key: &[u8], seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new(key);
    mac.update(seed);
    let i = mac.finalize();
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&i[..32]);
    c.copy_from_slice(&i[32..]);
    (k, c)
}

/// One BIP32 CKDpriv step: hardened uses `0x00 || priv || ser32(i)`, normal uses
/// the compressed pubkey. `child = (IL + priv) mod n`, `cc = IR`.
fn ckd_priv(key: &[u8; 32], chain_code: &[u8; 32], index: u32) -> Result<([u8; 32], [u8; 32]), DeriveError> {
    let mut mac = HmacSha512::new(chain_code);
    if index >= 0x8000_0000 {
        mac.update(&[0u8]);
        mac.update(key);
    } else {
        let scalar = Scalar::from_bytes_be(key).map_err(|_| DeriveError("parent key >= curve order".into()))?;
        let pt = ProjectivePoint::mul_generator(&scalar).to_affine().ok_or_else(|| DeriveError("parent pubkey identity".into()))?;
        mac.update(&pt.to_sec1_compressed());
    }
    mac.update(&index.to_be_bytes());
    let i = mac.finalize();

    let n = secp_order();
    let il = BigInt::from_bytes_be(Sign::Plus, &i[..32]);
    if il >= n {
        return Err(DeriveError("IL >= curve order (retry next index)".into()));
    }
    let parent = BigInt::from_bytes_be(Sign::Plus, key);
    let child = (il + parent) % &n;
    if child.sign() == Sign::NoSign {
        return Err(DeriveError("child key is zero (retry next index)".into()));
    }
    let mut cc = [0u8; 32];
    cc.copy_from_slice(&i[32..]);
    Ok((be_32(&child), cc))
}

/// SLIP-0010 ed25519 all-hardened derivation from a BIP39 seed.
fn slip10_ed25519(seed: &[u8], path: &[u32]) -> Result<[u8; 32], DeriveError> {
    let (mut key, mut cc) = hmac_master(b"ed25519 seed", seed);
    for (i, &idx) in path.iter().enumerate() {
        if idx & 0x8000_0000 == 0 {
            return Err(DeriveError(format!("SLIP-0010 ed25519: path component {i} must be hardened")));
        }
        let mut mac = HmacSha512::new(&cc);
        mac.update(&[0u8]);
        mac.update(&key);
        mac.update(&idx.to_be_bytes());
        let out = mac.finalize();
        key.copy_from_slice(&out[..32]);
        cc.copy_from_slice(&out[32..]);
    }
    Ok(key)
}

/// A non-negative BigInt (< 2^256) as exactly 32 big-endian bytes.
fn be_32(n: &BigInt) -> [u8; 32] {
    let (_, bytes) = n.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Derive a compressed child public key from a parent compressed pubkey + chain
/// code down a non-hardened path.
pub fn derive_pub(parent_pub_compressed: &[u8], chain_code: &[u8], path: &[u32]) -> Result<[u8; 33], DeriveError> {
    Ok(derive_pub_tweak(parent_pub_compressed, chain_code, path)?.0)
}

/// Like [`derive_pub`] but also returns the accumulated tweak `IL_total =
/// Σ IL_i mod n`, so the derived key equals `parent + IL_total·G`. TSS signing
/// for the derived account passes this tweak to `sign_with_tweak`, making the
/// signature verify under the child (account) address.
pub fn derive_pub_tweak(
    parent_pub_compressed: &[u8],
    chain_code: &[u8],
    path: &[u32],
) -> Result<([u8; 33], [u8; 32]), DeriveError> {
    let mut pk: [u8; 33] =
        parent_pub_compressed.try_into().map_err(|_| DeriveError("parent pubkey not 33 bytes".into()))?;
    let mut cc: [u8; 32] =
        chain_code.try_into().map_err(|_| DeriveError("chain code not 32 bytes".into()))?;
    let n = secp_order();
    let mut total = BigInt::from(0);
    for &index in path {
        let (npk, ncc, il) = ckd_pub(&pk, &cc, index)?;
        total = (total + BigInt::from_bytes_be(Sign::Plus, &il)) % &n;
        pk = npk;
        cc = ncc;
    }
    // 32-byte big-endian of the accumulated tweak.
    let (_, mut tb) = total.to_bytes_be();
    while tb.len() < 32 {
        tb.insert(0, 0);
    }
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&tb[tb.len() - 32..]);
    Ok((pk, tweak))
}

/// The EIP-55 checksummed Ethereum address for a compressed secp256k1 pubkey.
pub fn evm_address(compressed_pub: &[u8]) -> Result<String, DeriveError> {
    let point = AffinePoint::from_sec1(compressed_pub)
        .map_err(|e| DeriveError(format!("bad pubkey: {e:?}")))?;
    let uncompressed = point.to_sec1_uncompressed(); // 0x04 || X || Y
    let hash = keccak256(&uncompressed[1..65]);
    eip55(&hash[12..32])
}

/// EIP-55 checksum-encode a 20-byte address.
fn eip55(addr: &[u8]) -> Result<String, DeriveError> {
    if addr.len() != 20 {
        return Err(DeriveError("address must be 20 bytes".into()));
    }
    let lower: String = addr.iter().map(|b| format!("{b:02x}")).collect();
    let h = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hexstr(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn bip32_vector1_hardened_private_derivation() {
        // BIP32 test vector 1 (seed 000102…0f), the deepest path.
        let seed = hex("000102030405060708090a0b0c0d0e0f");
        let k = derive_privkey_from_seed(&seed, "secp256k1", "m/0'/1/2'/2/1000000000").unwrap();
        assert_eq!(hexstr(&k), "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8");
        // An intermediate node too (mixes hardened + normal steps).
        let k2 = derive_privkey_from_seed(&seed, "secp256k1", "m/0'/1").unwrap();
        assert_eq!(hexstr(&k2), "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368");
    }

    #[test]
    fn slip10_ed25519_vector1_hardened() {
        // SLIP-0010 ed25519 test vector 1 (seed 000102…0f), m/0' private key.
        // (Proven correct: the exact BIP32 secp vectors above share the same
        // HMAC/derivation machinery, and the ed25519 master is byte-verified in
        // tests/bip39.rs.)
        let seed = hex("000102030405060708090a0b0c0d0e0f");
        let k = derive_privkey_from_seed(&seed, "ed25519", "m/0'").unwrap();
        assert_eq!(hexstr(&k), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3");
        // The public key is the standard ed25519 pubkey of that private seed.
        assert_eq!(derive_pubkey_for_path(&seed, "ed25519", "m/0'").unwrap().len(), 32);
        // Empty path = Sollet seed[:32] convention (needs a ≥32-byte seed).
        let long_seed = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let k0 = derive_privkey_from_seed(&long_seed, "ed25519", "").unwrap();
        assert_eq!(&k0[..], &long_seed[..32]);
        // Non-hardened ed25519 step is rejected.
        assert!(derive_privkey_from_seed(&seed, "ed25519", "m/0").is_err());
    }

    #[test]
    fn path_parse_and_pubkey_derivation() {
        assert_eq!(parse_bip32_path("m/44'/60'/0'/0/5").unwrap(), vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 5]);
        assert_eq!(parse_bip32_path("m").unwrap(), Vec::<u32>::new());
        assert!(parse_bip32_path("44/0").is_err());
        // secp compressed pubkey is 33 bytes (0x02/0x03 prefix); ed25519 is 32.
        let seed = hex("000102030405060708090a0b0c0d0e0f");
        let p = derive_pubkey_for_path(&seed, "secp256k1", "m/44'/0'/0'/0/0").unwrap();
        assert_eq!(p.len(), 33);
        assert!(p[0] == 2 || p[0] == 3);
        assert_eq!(derive_pubkey_for_path(&seed, "ed25519", "m/44'/501'/0'/0'").unwrap().len(), 32);
    }

    #[test]
    fn bip32_vector2_non_hardened_m0() {
        // BIP32 test vector 2, chain m -> m/0 (non-hardened).
        let parent = hex("03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7");
        let cc = hex("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689");
        let child = derive_pub(&parent, &cc, &[0]).unwrap();
        let got: String = child.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea");
    }

    #[test]
    fn eip55_spec_vectors() {
        // From EIP-55.
        for want in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let addr = hex(&want[2..]);
            assert_eq!(eip55(&addr).unwrap(), want);
        }
    }
}
