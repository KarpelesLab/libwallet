//! The [`Script`] engine: holds a public key and generates output scripts for
//! various named formats, caching results.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::hash::{blake2b224_vec, blake3_vec, ether_hash_vec, sha256_vec};
use crate::insertable::{Format, b, ihash, ihash160, lookup, push, ttweak};
use crate::out::Out;
use crate::pubkey::PubKey;

/// Returns the format definition for a name.
pub fn format_def(name: &str) -> Option<Format> {
    let f = match name {
        "p2pkh" => vec![
            b(&[0x76, 0xa9]),
            push(ihash160(lookup("pubkey:comp"))),
            b(&[0x88, 0xac]),
        ],
        "p2pukh" => vec![
            b(&[0x76, 0xa9]),
            push(ihash160(lookup("pubkey:uncomp"))),
            b(&[0x88, 0xac]),
        ],
        "p2pk" => vec![push(lookup("pubkey:comp")), b(&[0xac])],
        "p2puk" => vec![push(lookup("pubkey:uncomp")), b(&[0xac])],
        "p2wpkh" => vec![b(&[0x00]), push(ihash160(lookup("pubkey:comp")))],
        "p2tr" => vec![b(&[0x51]), push(ttweak(lookup("pubkey:comp")))],
        "p2sh:p2pkh" => vec![b(&[0xa9]), push(ihash160(lookup("p2pkh"))), b(&[0x87])],
        "p2sh:p2pukh" => vec![b(&[0xa9]), push(ihash160(lookup("p2pukh"))), b(&[0x87])],
        "p2sh:p2pk" => vec![b(&[0xa9]), push(ihash160(lookup("p2pk"))), b(&[0x87])],
        "p2sh:p2puk" => vec![b(&[0xa9]), push(ihash160(lookup("p2puk"))), b(&[0x87])],
        "p2sh:p2wpkh" => vec![b(&[0xa9]), push(ihash160(lookup("p2wpkh"))), b(&[0x87])],
        "p2wsh:p2pkh" => vec![b(&[0x00]), push(ihash(lookup("p2pkh"), &[sha256_vec]))],
        "p2wsh:p2pukh" => vec![b(&[0x00]), push(ihash(lookup("p2pukh"), &[sha256_vec]))],
        "p2wsh:p2pk" => vec![b(&[0x00]), push(ihash(lookup("p2pk"), &[sha256_vec]))],
        "p2wsh:p2puk" => vec![b(&[0x00]), push(ihash(lookup("p2puk"), &[sha256_vec]))],
        "p2wsh:p2wpkh" => vec![b(&[0x00]), push(ihash(lookup("p2wpkh"), &[sha256_vec]))],
        "eth" => vec![ihash(lookup("pubkey:uncomp"), &[ether_hash_vec])],
        "massa_pubkey" => vec![b(&[0x00]), lookup("pubkey:ed25519")],
        "massa" => vec![
            b(&[0x00, 0x00]),
            ihash(lookup("massa_pubkey"), &[blake3_vec]),
        ],
        "solana" => vec![lookup("pubkey:ed25519")],
        // cardano: type-6 enterprise address payload (mainnet header 0x61) followed
        // by the blake2b-224 payment key hash. Out::address adjusts the network nibble.
        "cardano" => vec![
            b(&[0x61]),
            ihash(lookup("pubkey:ed25519"), &[blake2b224_vec]),
        ],
        _ => return None,
    };
    Some(f)
}

/// All known format names (used by [`crate::out::get_outs`]).
pub const ALL_FORMATS: &[&str] = &[
    "p2pkh",
    "p2pukh",
    "p2pk",
    "p2puk",
    "p2wpkh",
    "p2tr",
    "p2sh:p2pkh",
    "p2sh:p2pukh",
    "p2sh:p2pk",
    "p2sh:p2puk",
    "p2sh:p2wpkh",
    "p2wsh:p2pkh",
    "p2wsh:p2pukh",
    "p2wsh:p2pk",
    "p2wsh:p2puk",
    "p2wsh:p2wpkh",
    "eth",
    "massa_pubkey",
    "massa",
    "solana",
    "cardano",
];

/// Typical formats available for each network (port of `FormatsPerNetwork`).
pub fn formats_per_network(network: &str) -> Option<&'static [&'static str]> {
    Some(match network {
        "bitcoin" => &[
            "p2tr",
            "p2wpkh",
            "p2sh:p2wpkh",
            "p2puk",
            "p2pk",
            "p2pukh",
            "p2pkh",
        ],
        "bitcoin-cash" => &["p2puk", "p2pk", "p2pukh", "p2pkh"],
        "litecoin" => &["p2wpkh", "p2sh:p2wpkh", "p2puk", "p2pk", "p2pukh", "p2pkh"],
        "dogecoin" => &["p2puk", "p2pk", "p2pukh", "p2pkh"],
        "evm" => &["eth"],
        "massa" => &["massa"],
        "solana" => &["solana"],
        "cardano" => &["cardano"],
        _ => return None,
    })
}

/// Holds a public key and caches generated output scripts for various formats.
pub struct Script {
    pubkey: PubKey,
    cache: RefCell<HashMap<String, Vec<u8>>>,
}

impl Script {
    /// Creates a new [`Script`] for the given public key.
    pub fn new(pubkey: impl Into<PubKey>) -> Script {
        Script {
            pubkey: pubkey.into(),
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// The underlying public key.
    pub fn pubkey(&self) -> &PubKey {
        &self.pubkey
    }

    /// Returns the byte value for the specified format name, generating and
    /// caching it as needed.
    pub fn generate(&self, name: &str) -> Result<Vec<u8>, String> {
        if let Some(v) = self.cache.borrow().get(name) {
            return Ok(v.clone());
        }

        // Special-case direct public-key access.
        if matches!(
            name,
            "pubkey:pkix" | "pubkey:ed25519" | "pubkey:comp" | "pubkey:uncomp"
        ) {
            let res = self.pubkey.bytes_for(name)?;
            self.cache
                .borrow_mut()
                .insert(name.to_string(), res.clone());
            return Ok(res);
        }

        let format = format_def(name).ok_or_else(|| format!("unsupported format {name}"))?;
        let mut out = Vec::new();
        for piece in &format {
            out.extend_from_slice(&piece.bytes(self)?);
        }
        self.cache
            .borrow_mut()
            .insert(name.to_string(), out.clone());
        Ok(out)
    }

    /// Returns an [`Out`] for the requested format.
    pub fn out(&self, name: &str) -> Result<Out, String> {
        let buf = self.generate(name)?;
        Ok(Out::make(name, buf, &[]))
    }

    /// Formats the key as an address using the given format and optional network
    /// hints.
    pub fn address(&self, script: &str, flags: &[&str]) -> Result<String, String> {
        let out = self.out(script)?;
        out.address(flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::SecpPrivateKey;

    fn key() -> SecpPrivateKey {
        let mut s = [0u8; 32];
        s.copy_from_slice(
            &hex::decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap(),
        );
        SecpPrivateKey::from_bytes(&s).unwrap()
    }

    #[test]
    fn generates_p2pkh_script() {
        let s = Script::new(key().public_key());
        let script = s.generate("p2pkh").unwrap();
        // OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(script.len(), 25);
        assert_eq!(&script[..3], &[0x76, 0xa9, 0x14]);
        assert_eq!(&script[23..], &[0x88, 0xac]);
    }

    #[test]
    fn generates_p2wpkh_and_p2tr() {
        let s = Script::new(key().public_key());
        let wpkh = s.generate("p2wpkh").unwrap();
        assert_eq!(wpkh.len(), 22);
        assert_eq!(&wpkh[..2], &[0x00, 0x14]);
        let tr = s.generate("p2tr").unwrap();
        assert_eq!(tr.len(), 34);
        assert_eq!(&tr[..2], &[0x51, 0x20]);
    }

    #[test]
    fn caching_is_consistent() {
        let s = Script::new(key().public_key());
        assert_eq!(
            s.generate("p2sh:p2wpkh").unwrap(),
            s.generate("p2sh:p2wpkh").unwrap()
        );
    }
}
