//! Cardano BIP32-Ed25519 (CIP-1852) hierarchical key derivation and
//! extended-key signing.
//!
//! A [`CardanoExtendedKey`] is the form used by Cardano HD wallets: a standard
//! Ed25519 key is a 32-byte seed expanded with SHA-512 (and clamped) at signing
//! time, but an extended key stores the already-expanded 64-byte secret directly
//! — a 32-byte scalar followed by a 32-byte nonce — so it cannot be consumed by
//! a standard Ed25519 implementation. The scalar is not re-clamped, which is
//! what lets it represent keys produced by BIP32-Ed25519 child derivation. The
//! signatures it produces are ordinary Ed25519 signatures.
//!
//! Derivation follows BIP32-Ed25519 scheme V2 (little-endian indices), as used
//! by cardano-serialization-lib, with the [`cardano_icarus_master_key`] root
//! from BIP-39 entropy (CIP-3).
//!
//! Port of `cardano_extkey.go` and `cardano_derive.go`.

use purecrypto::hash::{HmacSha512, Sha512, sha512};
use purecrypto::kdf::pbkdf2;

use crate::cardanotx::CardanoSigner;
use crate::crypto::ed25519;

/// The offset that marks a BIP32 derivation index as hardened. A hardened child
/// can only be derived from a private key.
pub const CARDANO_HARDENED: u32 = 0x8000_0000;

/// Returns the hardened form of a derivation index (`index | 2^31`).
pub fn cardano_harden(index: u32) -> u32 {
    index | CARDANO_HARDENED
}

/// A BIP32-Ed25519 (CIP-1852) extended Ed25519 signing key.
///
/// See the [module documentation](self) for the representation. Create one from
/// an xprv with [`CardanoExtendedKey::new`], or derive a root from entropy with
/// [`cardano_icarus_master_key`].
#[derive(Clone)]
pub struct CardanoExtendedKey {
    scalar: [u8; 32],     // kL: the (clamped or derived) signing scalar
    nonce: [u8; 32],      // kR: the signing nonce / prefix
    pub_key: [u8; 32],    // cached public key A = (kL mod L)·B
    chain_code: [u8; 32], // chain code (only meaningful when has_chain)
    has_chain: bool,      // whether chain_code is present (required for derivation)
}

impl CardanoExtendedKey {
    /// Builds an extended key from a Cardano xprv. The input is either the
    /// 64-byte expanded secret (32-byte scalar followed by 32-byte nonce) for
    /// signing only, or the full 96-byte xprv (secret followed by a 32-byte
    /// chain code), which additionally enables BIP32-Ed25519 child derivation —
    /// the form exported by `cardano-address` / cardano-serialization-lib.
    pub fn new(xprv: &[u8]) -> Result<CardanoExtendedKey, String> {
        if xprv.len() != 64 && xprv.len() != 96 {
            return Err(format!(
                "cardano xprv must be 64 or 96 bytes, got {}",
                xprv.len()
            ));
        }
        let mut scalar = [0u8; 32];
        let mut nonce = [0u8; 32];
        scalar.copy_from_slice(&xprv[..32]);
        nonce.copy_from_slice(&xprv[32..64]);
        let mut chain_code = [0u8; 32];
        let has_chain = xprv.len() == 96;
        if has_chain {
            chain_code.copy_from_slice(&xprv[64..96]);
        }
        let pub_key = ed25519::scalar_mul_base(&scalar);
        Ok(CardanoExtendedKey {
            scalar,
            nonce,
            pub_key,
            chain_code,
            has_chain,
        })
    }

    /// Returns the 32-byte chain code, or `None` if this key was created without
    /// one (and therefore cannot derive children).
    pub fn chain_code(&self) -> Option<[u8; 32]> {
        self.has_chain.then_some(self.chain_code)
    }

    /// Returns the 32-byte Ed25519 public key for this extended key.
    pub fn public_key(&self) -> [u8; 32] {
        self.pub_key
    }

    /// Returns the xprv: the 64-byte expanded secret (scalar followed by nonce),
    /// plus the 32-byte chain code when present (96 bytes total).
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&self.scalar);
        out.extend_from_slice(&self.nonce);
        if self.has_chain {
            out.extend_from_slice(&self.chain_code);
        }
        out
    }

    /// Signs `message` (the 32-byte transaction body hash) and returns a standard
    /// 64-byte Ed25519 signature, using the stored scalar and nonce instead of
    /// expanding a seed:
    ///
    /// ```text
    /// a    = scalar mod L
    /// r    = SHA-512(nonce || message) mod L
    /// R    = r·B
    /// hram = SHA-512(R || A || message) mod L
    /// S    = (hram·a + r) mod L
    /// sig  = R || S
    /// ```
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let a = ed25519::scalar_reduce_wide(&extend64(&self.scalar));

        let mut r_input = Vec::with_capacity(32 + message.len());
        r_input.extend_from_slice(&self.nonce);
        r_input.extend_from_slice(message);
        let r = ed25519::scalar_reduce_wide(&sha512(&r_input));
        let r_point = ed25519::scalar_mul_base(&r);

        let mut k_input = Vec::with_capacity(64 + message.len());
        k_input.extend_from_slice(&r_point);
        k_input.extend_from_slice(&self.pub_key);
        k_input.extend_from_slice(message);
        let hram = ed25519::scalar_reduce_wide(&sha512(&k_input));

        let s = ed25519::scalar_mul_add(&hram, &a, &r);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_point);
        sig[32..].copy_from_slice(&s);
        sig
    }

    /// Derives the BIP32-Ed25519 (scheme V2) child of this key at `index`.
    /// Indices `>= `[`CARDANO_HARDENED`] derive a hardened child. The key must
    /// carry a chain code.
    pub fn derive_child(&self, index: u32) -> Result<CardanoExtendedKey, String> {
        if !self.has_chain {
            return Err("cardano: extended key has no chain code; cannot derive".into());
        }
        let seri = le32(index);
        let (zout, iout) = if index >= CARDANO_HARDENED {
            // hardened: HMAC over 0x00/0x01 || kL || kR || ser32(i)
            (
                hmac_sha512(
                    &self.chain_code,
                    &[&[0x00], &self.scalar[..], &self.nonce[..], &seri],
                ),
                hmac_sha512(
                    &self.chain_code,
                    &[&[0x01], &self.scalar[..], &self.nonce[..], &seri],
                ),
            )
        } else {
            // soft: HMAC over 0x02/0x03 || A || ser32(i)
            (
                hmac_sha512(&self.chain_code, &[&[0x02], &self.pub_key[..], &seri]),
                hmac_sha512(&self.chain_code, &[&[0x03], &self.pub_key[..], &seri]),
            )
        };

        let mut zl = [0u8; 32];
        let mut zr = [0u8; 32];
        zl.copy_from_slice(&zout[..32]);
        zr.copy_from_slice(&zout[32..64]);

        let scalar = add28_mul8(&self.scalar, &zl); // kL_child = kL + 8·trunc28(zl)
        let nonce = add256(&self.nonce, &zr); // kR_child = kR + zr (mod 2^256)
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&iout[32..64]);
        let pub_key = ed25519::scalar_mul_base(&scalar);
        Ok(CardanoExtendedKey {
            scalar,
            nonce,
            pub_key,
            chain_code,
            has_chain: true,
        })
    }

    /// Derives a chain of children in sequence, e.g. the CIP-1852 payment-key
    /// path `[harden(1852), harden(1815), harden(0), 0, 0]`.
    pub fn derive_path(&self, indices: &[u32]) -> Result<CardanoExtendedKey, String> {
        let mut cur = self.clone();
        for (i, &idx) in indices.iter().enumerate() {
            cur = cur
                .derive_child(idx)
                .map_err(|e| format!("cardano: deriving index {idx} (step {i}): {e}"))?;
        }
        Ok(cur)
    }

    /// Returns the extended public key (public key + chain code) for watch-only
    /// soft derivation, or `None` if this key has no chain code.
    pub fn extended_public_key(&self) -> Option<CardanoExtendedPubKey> {
        if !self.has_chain {
            return None;
        }
        Some(CardanoExtendedPubKey {
            pub_key: self.pub_key,
            chain_code: self.chain_code,
        })
    }
}

impl CardanoSigner for CardanoExtendedKey {
    fn cardano_public_key(&self) -> Vec<u8> {
        self.pub_key.to_vec()
    }
    fn sign_cardano(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.sign(message).to_vec())
    }
}

/// A BIP32-Ed25519 extended public key (a 32-byte public key plus a 32-byte
/// chain code). Supports watch-only derivation of soft (non-hardened) children
/// without access to the private key.
#[derive(Clone)]
pub struct CardanoExtendedPubKey {
    pub_key: [u8; 32],
    chain_code: [u8; 32],
}

impl CardanoExtendedPubKey {
    /// Builds an extended public key from a 32-byte public key and 32-byte chain
    /// code.
    pub fn new(pub_key: &[u8], chain_code: &[u8]) -> Result<CardanoExtendedPubKey, String> {
        if pub_key.len() != 32 {
            return Err(format!(
                "cardano public key must be 32 bytes, got {}",
                pub_key.len()
            ));
        }
        if chain_code.len() != 32 {
            return Err(format!(
                "cardano chain code must be 32 bytes, got {}",
                chain_code.len()
            ));
        }
        let mut pk = [0u8; 32];
        let mut cc = [0u8; 32];
        pk.copy_from_slice(pub_key);
        cc.copy_from_slice(chain_code);
        Ok(CardanoExtendedPubKey {
            pub_key: pk,
            chain_code: cc,
        })
    }

    /// Returns the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.pub_key
    }

    /// Returns the 32-byte chain code.
    pub fn chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    /// Derives a soft (non-hardened) child extended public key. Hardened
    /// derivation is impossible without the private key and returns an error.
    pub fn derive_child(&self, index: u32) -> Result<CardanoExtendedPubKey, String> {
        if index >= CARDANO_HARDENED {
            return Err("cardano: cannot derive a hardened child from a public key".into());
        }
        let seri = le32(index);
        let zout = hmac_sha512(&self.chain_code, &[&[0x02], &self.pub_key[..], &seri]);
        let iout = hmac_sha512(&self.chain_code, &[&[0x03], &self.pub_key[..], &seri]);

        let mut zl = [0u8; 32];
        zl.copy_from_slice(&zout[..32]);
        // child public point = A + (8·trunc28(zl))·B
        let tweak = add28_mul8(&[0u8; 32], &zl);
        let pub_key = ed25519::point_add_base(&self.pub_key, &tweak)
            .ok_or("cardano: invalid parent public key point")?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&iout[32..64]);
        Ok(CardanoExtendedPubKey {
            pub_key,
            chain_code,
        })
    }

    /// Derives a chain of soft children in sequence.
    pub fn derive_path(&self, indices: &[u32]) -> Result<CardanoExtendedPubKey, String> {
        let mut cur = self.clone();
        for (i, &idx) in indices.iter().enumerate() {
            cur = cur
                .derive_child(idx)
                .map_err(|e| format!("cardano: deriving index {idx} (step {i}): {e}"))?;
        }
        Ok(cur)
    }
}

/// Derives a root extended key from BIP-39 entropy using the Icarus master-key
/// scheme (CIP-3): the 96-byte xprv is `PBKDF2(HMAC-SHA512, password, entropy,
/// 4096 iterations)`, with the resulting scalar bit-tweaked. `password` is the
/// optional spending passphrase (empty for none); `entropy` is the decoded
/// BIP-39 entropy, not the mnemonic seed.
pub fn cardano_icarus_master_key(
    entropy: &[u8],
    password: &[u8],
) -> Result<CardanoExtendedKey, String> {
    if entropy.is_empty() {
        return Err("cardano: empty entropy".into());
    }
    let mut xprv = [0u8; 96];
    pbkdf2::<Sha512>(password, entropy, 4096, &mut xprv);
    // CIP-3 force-3rd clamp: clear the low 3 bits and the two highest bits, set
    // bit 254.
    xprv[0] &= 0b1111_1000;
    xprv[31] &= 0b0001_1111;
    xprv[31] |= 0b0100_0000;
    CardanoExtendedKey::new(&xprv)
}

// --- byte-level helpers ---

/// Zero-extends a 32-byte little-endian value to 64 bytes for wide reduction.
fn extend64(bytes: &[u8; 32]) -> [u8; 64] {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes);
    wide
}

/// Serializes a derivation index as little-endian (BIP32-Ed25519 V2).
fn le32(i: u32) -> [u8; 4] {
    i.to_le_bytes()
}

/// HMAC-SHA512 of the concatenation of `parts`, keyed by `key`.
fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = HmacSha512::new(key);
    for p in parts {
        mac.update(p);
    }
    mac.finalize()
}

/// Computes `x + 8·y` over the low 28 bytes of `y`, propagating the carry through
/// bytes 28..31 of `x`. This is the V2 scalar tweak for child keys.
fn add28_mul8(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..28 {
        let r = x[i] as u16 + ((y[i] as u16) << 3) + carry;
        out[i] = r as u8;
        carry = r >> 8;
    }
    for i in 28..32 {
        let r = x[i] as u16 + carry;
        out[i] = r as u8;
        carry = r >> 8;
    }
    out
}

/// Computes `x + y` modulo 2^256 (32-byte little-endian addition).
fn add256(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let r = x[i] as u16 + y[i] as u16 + carry;
        out[i] = r as u8;
        carry = r >> 8;
    }
    out
}
