//! HD public-key derivation for TSS accounts (port of the secp256k1/ecckd use
//! in wltacct). TSS wallets have no private key material, so accounts derive
//! via BIP32 **non-hardened public** steps from the wallet's group public key +
//! chain code (Go path e.g. m/44/60/0/{index}), then the child pubkey is turned
//! into a chain address.
//!
//! Verified against BIP32 test vector 2 (`m/0`) and the EIP-55 spec vectors.

use hmac::{Hmac, Mac};
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::keccak256;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug)]
pub struct DeriveError(pub String);

impl std::fmt::Display for DeriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hd derive: {}", self.0)
    }
}

/// One BIP32 non-hardened public child derivation. `index` must be < 2^31
/// (non-hardened). Returns the child compressed pubkey (33 bytes) and chain
/// code (32 bytes).
fn ckd_pub(parent_pub_compressed: &[u8; 33], chain_code: &[u8; 32], index: u32) -> Result<([u8; 33], [u8; 32]), DeriveError> {
    if index >= 0x8000_0000 {
        return Err(DeriveError(format!("hardened index {index} needs a private key")));
    }
    let mut mac = HmacSha512::new_from_slice(chain_code).map_err(|e| DeriveError(e.to_string()))?;
    mac.update(parent_pub_compressed);
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes(); // 64 bytes

    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..]);

    // child = IL·G + parent. from_bytes_be rejects IL >= curve order (BIP32
    // says derive with the next index then; astronomically rare, so we surface
    // it as an error rather than loop).
    let il_scalar = Scalar::from_bytes_be(&il).map_err(|_| DeriveError("IL >= curve order".into()))?;
    let parent = AffinePoint::from_sec1(parent_pub_compressed)
        .map_err(|e| DeriveError(format!("bad parent pubkey: {e:?}")))?;
    let child = ProjectivePoint::mul_generator(&il_scalar).add(&parent.to_projective());
    let child_affine = child.to_affine().ok_or_else(|| DeriveError("child is identity".into()))?;
    Ok((child_affine.to_sec1_compressed(), ir))
}

/// Derive a compressed child public key from a parent compressed pubkey +
/// chain code down a non-hardened path.
pub fn derive_pub(parent_pub_compressed: &[u8], chain_code: &[u8], path: &[u32]) -> Result<[u8; 33], DeriveError> {
    let mut pk: [u8; 33] =
        parent_pub_compressed.try_into().map_err(|_| DeriveError("parent pubkey not 33 bytes".into()))?;
    let mut cc: [u8; 32] =
        chain_code.try_into().map_err(|_| DeriveError("chain code not 32 bytes".into()))?;
    for &index in path {
        let (npk, ncc) = ckd_pub(&pk, &cc, index)?;
        pk = npk;
        cc = ncc;
    }
    Ok(pk)
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
