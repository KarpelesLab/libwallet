//! Hashing helpers built on `purecrypto::hash`.
//!
//! Supports chained hashing, where a sequence of hash functions is applied so
//! that each function consumes the output of the previous one (e.g.
//! HASH160 = RIPEMD160(SHA256(x))).

use purecrypto::hash::{Blake2bMac, Blake3, blake2b256, keccak256, ripemd160, sha256};

/// A single hash step usable in a [`hash_chain`]: maps input bytes to output
/// bytes.
///
/// This is a plain function pointer, not an enum, so adding a hash needs no
/// change here — any `fn(&[u8]) -> Vec<u8>` works, whether one of the chainable
/// helpers below ([`sha256_vec`], [`ripemd160_vec`], …) or a user-defined one.
pub type HashFn = fn(&[u8]) -> Vec<u8>;

/// SHA-256, as a chainable [`HashFn`].
pub fn sha256_vec(data: &[u8]) -> Vec<u8> {
    sha256(data).to_vec()
}
/// RIPEMD-160, as a chainable [`HashFn`].
pub fn ripemd160_vec(data: &[u8]) -> Vec<u8> {
    ripemd160(data).to_vec()
}
/// Keccak-256 (Ethereum legacy keccak, not SHA3-256), as a chainable [`HashFn`].
pub fn keccak256_vec(data: &[u8]) -> Vec<u8> {
    keccak256(data).to_vec()
}
/// BLAKE3 with 32-byte output (used for Massa), as a chainable [`HashFn`].
pub fn blake3_vec(data: &[u8]) -> Vec<u8> {
    Blake3::hash(data).to_vec()
}
/// BLAKE2b-224 (used for Cardano key credentials), as a chainable [`HashFn`].
pub fn blake2b224_vec(data: &[u8]) -> Vec<u8> {
    blake2b224(data).to_vec()
}
/// The Ethereum public-key hash (keccak-256 over the body with the SEC1 prefix
/// byte stripped, last 20 bytes), as a chainable [`HashFn`]. Terminal in a chain.
pub fn ether_hash_vec(data: &[u8]) -> Vec<u8> {
    ether_hash(data).to_vec()
}

/// Applies a sequence of hash functions, chaining the output of one into the
/// input of the next.
pub fn hash_chain(data: &[u8], fns: &[HashFn]) -> Vec<u8> {
    let mut cur = data.to_vec();
    for f in fns {
        cur = f(&cur);
    }
    cur
}

/// SHA-256 one-shot.
pub fn sha256_once(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// Double SHA-256: SHA256(SHA256(data)).
pub fn dsha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// HASH160: RIPEMD160(SHA256(data)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// Keccak-256 (legacy keccak, as used by Ethereum).
pub fn keccak256_once(data: &[u8]) -> [u8; 32] {
    keccak256(data)
}

/// BLAKE3 with 32-byte output (used for Massa addresses).
pub fn blake3_256(data: &[u8]) -> [u8; 32] {
    Blake3::hash(data)
}

/// BLAKE2b with a 224-bit (28-byte) digest, used to derive Cardano key
/// credentials from public keys.
pub fn blake2b224(data: &[u8]) -> [u8; 28] {
    let mut h = Blake2bMac::new_unkeyed(28);
    h.update(data);
    let mut out = [0u8; 28];
    h.finalize_into(&mut out);
    out
}

/// BLAKE2b with a 256-bit (32-byte) digest, used as the Cardano transaction id
/// and signing digest.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    blake2b256(data)
}

/// The Ethereum public-key hash used by the `eth` format.
///
/// Keccak-256 over the public key bytes with the leading byte (the SEC1 `0x04`
/// uncompressed prefix) stripped, returning the last 20 bytes of the digest.
pub fn ether_hash(uncompressed_pubkey: &[u8]) -> [u8; 20] {
    let body = if uncompressed_pubkey.is_empty() {
        uncompressed_pubkey
    } else {
        &uncompressed_pubkey[1..]
    };
    let h = keccak256(body);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash160() {
        // HASH160 of empty string.
        let h = hash160(b"");
        assert_eq!(hex::encode(h), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    }

    #[test]
    fn test_dsha256() {
        let h = dsha256(b"hello");
        assert_eq!(
            hex::encode(h),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
    }

    #[test]
    fn test_hash_chain_matches_helpers() {
        let data = b"the quick brown fox";
        assert_eq!(
            hash_chain(data, &[sha256_vec, sha256_vec]),
            dsha256(data).to_vec()
        );
        assert_eq!(
            hash_chain(data, &[sha256_vec, ripemd160_vec]),
            hash160(data).to_vec()
        );
    }
}
