//! RLP (Recursive Length Prefix) encoding/decoding.
//!
//! Port of `github.com/KarpelesLab/rlp` (the subset used by the EVM transaction
//! code), including its canonical-form decode checks.

use num_bigint::{BigInt, Sign};

/// An RLP item: either a byte string (leaf) or a list of items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpItem {
    /// A byte string.
    Bytes(Vec<u8>),
    /// A list of items.
    List(Vec<RlpItem>),
}

/// Errors from RLP operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Unexpected end of input.
    UnexpectedEof,
    /// A length was encoded in non-canonical (long) form when short would do,
    /// or with leading zeros.
    NonCanonicalSize,
    /// A single byte <= 0x7f was encoded with a length prefix.
    NonCanonicalValue,
    /// A negative integer cannot be RLP-encoded.
    NegativeValue,
    /// A string value lacked the required `0x` prefix.
    StringPrefix,
    /// Generic message.
    Other(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnexpectedEof => f.write_str("unexpected EOF"),
            Error::NonCanonicalSize => f.write_str("non-canonical size"),
            Error::NonCanonicalValue => f.write_str("non-canonical value"),
            Error::NegativeValue => f.write_str("cannot encode negative value"),
            Error::StringPrefix => f.write_str("string must start with 0x"),
            Error::Other(s) => f.write_str(s),
        }
    }
}
impl core::error::Error for Error {}

fn trim_left_zeros(mut b: &[u8]) -> &[u8] {
    while !b.is_empty() && b[0] == 0 {
        b = &b[1..];
    }
    b
}

/// Decodes a trimmed big-endian byte slice (max 8 bytes) into a u64.
///
/// # Panics
/// Panics if `buf` is longer than 8 bytes. Use [`decode_uint64_checked`] for
/// attacker-controlled input.
pub fn decode_uint64(buf: &[u8]) -> u64 {
    assert!(buf.len() <= 8, "decode_uint64 input longer than 8 bytes");
    let mut tmp = [0u8; 8];
    tmp[8 - buf.len()..].copy_from_slice(buf);
    u64::from_be_bytes(tmp)
}

/// Like [`decode_uint64`] but returns an error instead of panicking when `buf`
/// exceeds 8 bytes. Use this when decoding fields from untrusted transactions.
pub fn decode_uint64_checked(buf: &[u8]) -> Result<u64, Error> {
    if buf.len() > 8 {
        return Err(Error::Other(format!(
            "invalid uint64 field: length {} exceeds 8 bytes",
            buf.len()
        )));
    }
    Ok(decode_uint64(buf))
}

fn encode_len(ln: usize, is_array: bool) -> Vec<u8> {
    let array_flag: u8 = if is_array { 0x40 } else { 0 };
    if ln <= 55 {
        vec![(0x80 + ln as u8) | array_flag]
    } else {
        let be = (ln as u64).to_be_bytes();
        let trimmed = trim_left_zeros(&be);
        let mut out = vec![(0xb7 | array_flag) + trimmed.len() as u8];
        out.extend_from_slice(trimmed);
        out
    }
}

impl RlpItem {
    /// Encodes a u64 as a trimmed big-endian byte string.
    pub fn uint(v: u64) -> RlpItem {
        RlpItem::Bytes(trim_left_zeros(&v.to_be_bytes()).to_vec())
    }

    /// Encodes a non-negative BigInt as a trimmed big-endian byte string.
    pub fn bigint(v: &BigInt) -> Result<RlpItem, Error> {
        match v.sign() {
            Sign::Minus => Err(Error::NegativeValue),
            Sign::NoSign => Ok(RlpItem::Bytes(Vec::new())),
            Sign::Plus => {
                let (_, bytes) = v.to_bytes_be();
                Ok(RlpItem::Bytes(trim_left_zeros(&bytes).to_vec()))
            }
        }
    }

    /// Decodes a `0x`-prefixed hex string into a byte string item.
    pub fn hex_str(s: &str) -> Result<RlpItem, Error> {
        let body = s.strip_prefix("0x").ok_or(Error::StringPrefix)?;
        if body.is_empty() {
            return Ok(RlpItem::Bytes(Vec::new()));
        }
        let padded;
        let body = if body.len() % 2 == 1 {
            padded = format!("0{body}");
            padded.as_str()
        } else {
            body
        };
        let buf = hex::decode(body).map_err(|e| Error::Other(e.to_string()))?;
        Ok(RlpItem::Bytes(buf))
    }

    /// Serializes this item to RLP bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RlpItem::Bytes(b) => {
                if b.len() == 1 && b[0] <= 0x7f {
                    vec![b[0]]
                } else {
                    let mut out = encode_len(b.len(), false);
                    out.extend_from_slice(b);
                    out
                }
            }
            RlpItem::List(items) => encode_list(items),
        }
    }

    /// Returns the byte string if this is a leaf, else None.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            RlpItem::Bytes(b) => Some(b),
            RlpItem::List(_) => None,
        }
    }

    /// Returns the list items if this is a list, else None.
    pub fn as_list(&self) -> Option<&[RlpItem]> {
        match self {
            RlpItem::List(l) => Some(l),
            RlpItem::Bytes(_) => None,
        }
    }
}

/// Decodes one RLP item from the front of `buf`, returning the item and the
/// remaining bytes.
pub fn decode_one(buf: &[u8]) -> Result<(RlpItem, &[u8]), Error> {
    if buf.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    let c = buf[0];
    let mut buf = &buf[1..];

    if c <= 0x7f {
        return Ok((RlpItem::Bytes(vec![c]), buf));
    }

    let is_array = c & 0x40 == 0x40;
    let mut ln = (c & 0x3f) as u64;

    if (buf.len() as u64) < ln {
        return Err(Error::UnexpectedEof);
    }

    if ln > 55 {
        let ln_len = (ln - 55) as usize;
        if buf[0] == 0 {
            return Err(Error::NonCanonicalSize);
        }
        ln = decode_uint64(&buf[..ln_len]);
        buf = &buf[ln_len..];
        if ln <= 55 {
            return Err(Error::NonCanonicalSize);
        }
        if (buf.len() as u64) < ln {
            return Err(Error::UnexpectedEof);
        }
    }

    let ln = ln as usize;
    let v = &buf[..ln];
    let rest = &buf[ln..];

    if is_array {
        let items = decode(v)?;
        return Ok((RlpItem::List(items), rest));
    }

    if v.len() == 1 && v[0] <= 0x7f {
        return Err(Error::NonCanonicalValue);
    }

    Ok((RlpItem::Bytes(v.to_vec()), rest))
}

/// Decodes a sequence of RLP items from `buf`.
pub fn decode(buf: &[u8]) -> Result<Vec<RlpItem>, Error> {
    let mut res = Vec::new();
    let mut buf = buf;
    while !buf.is_empty() {
        let (item, rest) = decode_one(buf)?;
        res.push(item);
        buf = rest;
    }
    Ok(res)
}

/// Encodes a list of items as a single RLP list (length prefix + concatenated
/// item encodings).
pub fn encode_list(items: &[RlpItem]) -> Vec<u8> {
    let mut body = Vec::new();
    for it in items {
        body.extend_from_slice(&it.encode());
    }
    let mut out = encode_len(body.len(), true);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: Vec<RlpItem>) -> RlpItem {
        RlpItem::List(items)
    }
    fn b(v: &[u8]) -> RlpItem {
        RlpItem::Bytes(v.to_vec())
    }

    #[test]
    fn encode_vectors() {
        // []any{42, int32(123456789), 21000, "0x...", []byte{...}}
        let item = list(vec![
            RlpItem::uint(42),
            RlpItem::uint(123_456_789),
            RlpItem::uint(21000),
            RlpItem::hex_str("0xabdef0123456789abcdef0123456789012345789").unwrap(),
            b(&[1, 2, 3, 4, 5, 6]),
        ]);
        assert_eq!(
            hex::encode(item.encode()),
            "e52a84075bcd1582520894abdef0123456789abcdef012345678901234578986010203040506"
        );
    }

    #[test]
    fn empty_list_and_string() {
        assert_eq!(hex::encode(list(vec![]).encode()), "c0");
        assert_eq!(hex::encode(b(&[]).encode()), "80");
        assert_eq!(hex::encode(b(&[0x42]).encode()), "42");
        assert_eq!(hex::encode(b(&[0x80]).encode()), "8180");
        assert_eq!(hex::encode(b(&[0x00]).encode()), "00");
        assert_eq!(hex::encode(b(&[0x04, 0x00]).encode()), "820400");
    }

    #[test]
    fn bigint_zero() {
        assert_eq!(
            hex::encode(RlpItem::bigint(&BigInt::from(0)).unwrap().encode()),
            "80"
        );
    }

    #[test]
    fn nested() {
        let three = list(vec![
            list(vec![]),
            list(vec![list(vec![])]),
            list(vec![list(vec![]), list(vec![list(vec![])])]),
        ]);
        assert_eq!(hex::encode(three.encode()), "c7c0c1c0c3c0c1c0");
    }

    #[test]
    fn decode_roundtrip() {
        let item = list(vec![b(b"cat"), b(b"dog")]);
        let enc = item.encode();
        let dec = decode(&enc).unwrap();
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0], item);
    }

    #[test]
    fn decode_non_canonical() {
        assert_eq!(decode(&[0x81, 0x42]), Err(Error::NonCanonicalValue));
        let mut buf = vec![0u8; 2 + 55];
        buf[0] = 0xb8;
        buf[1] = 0x37;
        assert_eq!(decode(&buf), Err(Error::NonCanonicalSize));
    }
}
