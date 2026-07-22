//! Composable `Insertable` operations that define how an output script is
//! derived from a public key.

use crate::hash::{HashFn, hash_chain, ripemd160_vec, sha256_vec};
use crate::pushbytes::push_bytes;
use crate::script::Script;

/// A component that produces bytes for inclusion in an output script.
///
/// Non-exhaustive: more script-building primitives may be added as new output
/// formats are supported.
#[derive(Clone)]
#[non_exhaustive]
pub enum Insertable {
    /// A fixed byte sequence.
    Bytes(Vec<u8>),
    /// A reference to another named format, resolved via [`Script::generate`].
    Lookup(&'static str),
    /// PUSHDATA-encodes the output of the inner insertable.
    PushBytes(Box<Insertable>),
    /// Hashes the output of the inner insertable through a chain of functions.
    Hash(Box<Insertable>, Vec<HashFn>),
    /// Applies the BIP-341 key-path taproot tweak to a 33-byte compressed
    /// secp256k1 pubkey, emitting the 32-byte tweaked x-only output key.
    TaprootTweak(Box<Insertable>),
}

/// A format is a sequence of insertables concatenated together.
pub type Format = Vec<Insertable>;

impl Insertable {
    /// Evaluates this insertable against `script`, producing its bytes.
    pub fn bytes(&self, script: &Script) -> Result<Vec<u8>, String> {
        match self {
            Insertable::Bytes(b) => Ok(b.clone()),
            Insertable::Lookup(name) => script.generate(name),
            Insertable::PushBytes(inner) => {
                let v = inner.bytes(script)?;
                Ok(push_bytes(&v))
            }
            Insertable::Hash(inner, fns) => {
                let v = inner.bytes(script)?;
                Ok(hash_chain(&v, fns))
            }
            Insertable::TaprootTweak(inner) => {
                let v = inner.bytes(script)?;
                if v.len() != 33 {
                    return Err(format!(
                        "taproot tweak expects 33-byte compressed pubkey, got {}",
                        v.len()
                    ));
                }
                let mut x_only = [0u8; 32];
                x_only.copy_from_slice(&v[1..]);
                let (tweaked, _) =
                    crate::crypto::secp256k1::taproot_tweak(&x_only).map_err(|e| e.to_string())?;
                Ok(tweaked.to_vec())
            }
        }
    }
}

// --- concise constructors for the built-in formats ---

pub(crate) fn b(bytes: &[u8]) -> Insertable {
    Insertable::Bytes(bytes.to_vec())
}
pub(crate) fn lookup(name: &'static str) -> Insertable {
    Insertable::Lookup(name)
}
pub(crate) fn push(inner: Insertable) -> Insertable {
    Insertable::PushBytes(Box::new(inner))
}
pub(crate) fn ihash(inner: Insertable, fns: &[HashFn]) -> Insertable {
    Insertable::Hash(Box::new(inner), fns.to_vec())
}
pub(crate) fn ihash160(inner: Insertable) -> Insertable {
    ihash(inner, &[sha256_vec, ripemd160_vec])
}
pub(crate) fn ttweak(inner: Insertable) -> Insertable {
    Insertable::TaprootTweak(Box::new(inner))
}
