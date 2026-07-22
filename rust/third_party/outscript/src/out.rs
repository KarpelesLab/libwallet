//! The [`Out`] type: a generated output script with format name and network
//! flags, plus script-recognition helpers (`guess_out`, `get_outs`).

use serde::Serialize;

use crate::hash::hash160;
use crate::pubkey::PubKey;
use crate::pushbytes::{parse_push_bytes, push_bytes};
use crate::script::{ALL_FORMATS, Script};

/// A generated output script with its format name, hex-encoded script and
/// optional network flags.
#[derive(Debug, Clone, Serialize)]
pub struct Out {
    /// Format name, e.g. "p2pkh", "p2sh", "eth".
    pub name: String,
    /// Hex-encoded output script.
    pub script: String,
    /// Optional network flags / hints.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub flags: Vec<String>,
    #[serde(skip)]
    pub(crate) raw: Vec<u8>,
}

impl Out {
    /// Builds an [`Out`] from a format name, raw script bytes, and flags.
    pub fn make(name: &str, script: Vec<u8>, flags: &[&str]) -> Out {
        Out {
            name: name.to_string(),
            script: hex::encode(&script),
            flags: flags.iter().map(|s| s.to_string()).collect(),
            raw: script,
        }
    }

    /// The raw output script bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The base format name (the part before any ':').
    pub fn base_name(&self) -> &str {
        match self.name.split_once(':') {
            Some((base, _)) => base,
            None => &self.name,
        }
    }

    /// Extracts the hash part of the output, or `None` if there is no known hash.
    pub fn hash(&self) -> Option<Vec<u8>> {
        match self.name.as_str() {
            "p2wpkh" | "p2tr" => self
                .raw
                .get(1..)
                .and_then(parse_push_bytes)
                .map(|(d, _)| d.to_vec()),
            "p2pkh" | "p2pukh" => self
                .raw
                .get(2..)
                .and_then(parse_push_bytes)
                .map(|(d, _)| d.to_vec()),
            "p2pk" | "p2puk" => parse_push_bytes(&self.raw).map(|(pub_, _)| hash160(pub_).to_vec()),
            "p2sh" => self
                .raw
                .get(1..)
                .and_then(parse_push_bytes)
                .map(|(d, _)| d.to_vec()),
            "eth" | "massa" | "solana" => Some(self.raw.clone()),
            // raw is "header byte + credential(s)"; return the payment/stake credential
            "cardano" if self.raw.len() >= 29 => Some(self.raw[1..29].to_vec()),
            _ => None,
        }
    }
}

impl core::fmt::Display for Out {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.name, self.script)
    }
}

/// Attempts to identify the output-script type of `script`, optionally using a
/// public-key hint to distinguish compressed/uncompressed variants.
pub fn guess_out(script: &[u8], pubkey_hint: Option<&PubKey>) -> Out {
    if script.is_empty() {
        return Out::make("empty", script.to_vec(), &["invalid"]);
    }

    if script[0] == 0 {
        // segwit
        return match script.len() {
            22 => Out::make("p2wpkh", script.to_vec(), &[]),
            34 => Out::make("p2wsh", script.to_vec(), &[]),
            _ => Out::make("invalid", script.to_vec(), &[]),
        };
    }
    if script[0] == 0x51 {
        // OP_1 (p2tr)
        if script.len() == 34 {
            return Out::make("p2tr", script.to_vec(), &[]);
        }
        return Out::make("invalid", script.to_vec(), &[]);
    }
    if script[0] == 0x6a {
        // OP_RETURN
        return Out::make("op_return", script.to_vec(), &[]);
    }

    let last = script[script.len() - 1];
    if last == 0xac {
        // OP_CHECKSIG
        if script.len() == 25
            && script.starts_with(&[0x76, 0xa9, 0x14])
            && script.ends_with(&[0x88, 0xac])
        {
            // pay-to-keyhash
            if let Some(hint) = pubkey_hint {
                let s = Script::new(hint.clone());
                for e in ["p2pkh", "p2pukh"] {
                    if let Ok(buf) = s.generate(e)
                        && buf == script
                    {
                        return Out::make(e, script.to_vec(), &[]);
                    }
                }
            }
            return Out::make("p2pkh", script.to_vec(), &[]);
        }
        if let Some((v, _)) = parse_push_bytes(script) {
            let mut rebuilt = push_bytes(v);
            rebuilt.push(0xac);
            if rebuilt == script {
                match v.len() {
                    33 => return Out::make("p2pk", script.to_vec(), &[]),
                    65 => return Out::make("p2puk", script.to_vec(), &[]),
                    _ => {}
                }
            }
        }
    } else if last == 0x87 {
        // OP_EQUAL (likely P2SH)
        if let Some((v, _)) = parse_push_bytes(&script[1..]) {
            let mut rebuilt = vec![0xa9];
            rebuilt.extend_from_slice(&push_bytes(v));
            rebuilt.push(0x87);
            if rebuilt == script {
                if let Some(hint) = pubkey_hint {
                    let s = Script::new(hint.clone());
                    for e in [
                        "p2sh:p2pk",
                        "p2sh:p2pkh",
                        "p2sh:p2puk",
                        "p2sh:p2pukh",
                        "p2sh:p2wpkh",
                    ] {
                        if let Ok(buf) = s.generate(e)
                            && buf == script
                        {
                            return Out::make(e, script.to_vec(), &[]);
                        }
                    }
                }
                return Out::make("p2sh", script.to_vec(), &[]);
            }
        }
    }

    Out::make("invalid", script.to_vec(), &[])
}

/// Returns the potential outputs that could in theory be opened with the given
/// public key.
pub fn get_outs(pubkey: impl Into<PubKey>) -> Vec<Out> {
    let s = Script::new(pubkey);
    let mut outs = Vec::new();
    for name in ALL_FORMATS {
        if let Ok(out) = s.out(name) {
            outs.push(out);
        }
    }
    outs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_returns_none_on_short_raw() {
        // raw shorter than the format's fixed prefix must yield None, not panic.
        assert_eq!(Out::make("p2wpkh", vec![], &[]).hash(), None);
        assert_eq!(Out::make("p2pkh", vec![0x76], &[]).hash(), None);
        assert_eq!(Out::make("p2sh", vec![], &[]).hash(), None);
        assert_eq!(Out::make("cardano", vec![0x01], &[]).hash(), None);
    }
}
