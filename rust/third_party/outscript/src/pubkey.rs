//! Public-key abstraction used by [`crate::script::Script`].
//!
//! A small enum over the key types outscript understands, used to extract the
//! raw bytes for a requested public-key format.

use crate::crypto::secp256k1::SecpPublicKey;

/// A public key understood by outscript: either secp256k1 or Ed25519.
///
/// Non-exhaustive: more key/curve types may be added as new chains are
/// supported.
#[derive(Clone)]
#[non_exhaustive]
pub enum PubKey {
    /// A secp256k1 public key (Bitcoin, EVM, ...).
    Secp256k1(SecpPublicKey),
    /// A raw 32-byte Ed25519 public key (Solana, Massa).
    Ed25519([u8; 32]),
}

impl PubKey {
    /// Returns the public-key bytes for the requested internal format name
    /// (`pubkey:comp`, `pubkey:uncomp`, `pubkey:ed25519`).
    pub fn bytes_for(&self, typ: &str) -> Result<Vec<u8>, String> {
        match (typ, self) {
            ("pubkey:ed25519", PubKey::Ed25519(k)) => Ok(k.to_vec()),
            ("pubkey:comp", PubKey::Secp256k1(k)) => Ok(k.serialize_compressed().to_vec()),
            ("pubkey:uncomp", PubKey::Secp256k1(k)) => Ok(k.serialize_uncompressed().to_vec()),
            ("pubkey:ed25519" | "pubkey:comp" | "pubkey:uncomp", _) => {
                Err(format!("public key does not support {typ} export"))
            }
            _ => Err(format!("unknown public key format {typ}")),
        }
    }
}

impl From<SecpPublicKey> for PubKey {
    fn from(k: SecpPublicKey) -> Self {
        PubKey::Secp256k1(k)
    }
}
