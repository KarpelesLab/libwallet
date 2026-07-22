//! Base58 encoding using the Bitcoin alphabet.
//!
//! Port of the parts of `github.com/KarpelesLab/base58` used by outscript
//! (`base58.Bitcoin.Encode` / `Decode`).

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encodes bytes to a base58 string (Bitcoin alphabet).
pub fn encode(input: &[u8]) -> String {
    // Count leading zero bytes; each becomes a leading '1'.
    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Convert base-256 to base-58 via repeated division.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Error returned when a base58 string contains an invalid character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub char);

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid base58 character: {:?}", self.0)
    }
}

impl core::error::Error for DecodeError {}

fn char_value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

/// Decodes a base58 string (Bitcoin alphabet) to bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = input.as_bytes();
    let zeros = bytes.iter().take_while(|&&b| b == b'1').count();

    let mut result: Vec<u8> = Vec::with_capacity(input.len());
    for &c in &bytes[zeros..] {
        let mut carry = char_value(c).ok_or(DecodeError(c as char))? as u32;
        for b in result.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            result.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = Vec::with_capacity(zeros + result.len());
    out.resize(zeros, 0u8);
    out.extend(result.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cases: &[&str] = &[
            "",
            "61",
            "626262",
            "516b6fcd0f",
            "00000000",
            "00010966776006953d5567439e5e39f86a0d273beed61967f6",
        ];
        for c in cases {
            let raw = hex::decode(c).unwrap();
            let enc = encode(&raw);
            let dec = decode(&enc).unwrap();
            assert_eq!(dec, raw, "roundtrip failed for {c}");
        }
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(&[0x00, 0x00, 0x01]), "112");
        assert_eq!(encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(decode("StV1DL6CwTryKyV").unwrap(), b"hello world");
    }

    #[test]
    fn invalid_char() {
        assert!(decode("0OIl").is_err());
    }
}
