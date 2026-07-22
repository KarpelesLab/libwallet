//! A minimal, self-contained CBOR codec sufficient for Cardano transaction
//! serialization.
//!
//! Encoding follows the canonical rules required by the Cardano ledger
//! (RFC 7049 canonical form): definite-length items, shortest-form integers,
//! and map keys sorted length-first then lexicographically by their encoded
//! bytes.
//!
//! The decoder parses the subset produced by [`Cbor::encode`] into [`Cbor`]
//! values, and additionally provides [`scan_item`], which measures one complete
//! data item — including indefinite-length strings/arrays/maps and tags — so
//! real on-chain transactions can be split into their raw top-level elements.

/// A CBOR data item, limited to the variants outscript needs to build and parse
/// Cardano transactions.
///
/// Non-exhaustive: this is a deliberate, growing subset of the CBOR model (tags,
/// text strings, negative integers and floats may be added).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cbor {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// Definite-length array (major type 4).
    Array(Vec<Cbor>),
    /// Definite-length map (major type 5). Entries are sorted canonically at
    /// encode time, so insertion order does not affect the output.
    Map(Vec<(Cbor, Cbor)>),
    /// Boolean (major type 7, simple values 20/21).
    Bool(bool),
    /// Null (major type 7, simple value 22).
    Null,
    /// Pre-encoded CBOR bytes inserted verbatim. Used to embed the exact
    /// transaction-body bytes that were hashed for signing.
    Raw(Vec<u8>),
}

fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let mt = major << 5;
    if value < 24 {
        out.push(mt | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

impl Cbor {
    /// Encodes this value as canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Uint(v) => write_head(out, 0, *v),
            Cbor::Bytes(b) => {
                write_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Cbor::Array(items) => {
                write_head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            Cbor::Map(entries) => {
                // Canonical (RFC 7049) ordering: sort by the encoded key,
                // shorter encodings first, ties broken lexicographically.
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (k.encode(), v.encode()))
                    .collect();
                encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
                write_head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
            Cbor::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Cbor::Null => out.push(0xf6),
            Cbor::Raw(bytes) => out.extend_from_slice(bytes),
        }
    }

    /// Decodes a single CBOR value from `data`, returning it and the number of
    /// bytes consumed. Only the subset emitted by [`Cbor::encode`] is supported
    /// (unsigned ints, byte strings, arrays, maps, bool and null); other types
    /// produce an error.
    pub fn decode(data: &[u8]) -> Result<(Cbor, usize), String> {
        let mut pos = 0;
        let v = decode_value(data, &mut pos)?;
        Ok((v, pos))
    }

    /// Returns the inner bytes if this is a [`Cbor::Bytes`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the value if this is a [`Cbor::Uint`].
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Cbor::Uint(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the elements if this is a [`Cbor::Array`].
    pub fn as_array(&self) -> Option<&[Cbor]> {
        match self {
            Cbor::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the entries if this is a [`Cbor::Map`].
    pub fn as_map(&self) -> Option<&[(Cbor, Cbor)]> {
        match self {
            Cbor::Map(entries) => Some(entries),
            _ => None,
        }
    }
}

/// Reads the major type and argument of a CBOR head, advancing `pos`.
fn read_head(data: &[u8], pos: &mut usize) -> Result<(u8, u64, bool), String> {
    if *pos >= data.len() {
        return Err("unexpected end of CBOR data".into());
    }
    let ib = data[*pos];
    *pos += 1;
    let major = ib >> 5;
    let info = ib & 0x1f;
    let (arg, indefinite) = match info {
        0..=23 => (info as u64, false),
        24 => (read_uint(data, pos, 1)?, false),
        25 => (read_uint(data, pos, 2)?, false),
        26 => (read_uint(data, pos, 4)?, false),
        27 => (read_uint(data, pos, 8)?, false),
        31 => (0, true),
        _ => return Err(format!("reserved CBOR additional info {info}")),
    };
    Ok((major, arg, indefinite))
}

fn read_uint(data: &[u8], pos: &mut usize, n: usize) -> Result<u64, String> {
    if *pos + n > data.len() {
        return Err("unexpected end of CBOR data".into());
    }
    let mut v = 0u64;
    for &b in &data[*pos..*pos + n] {
        v = (v << 8) | b as u64;
    }
    *pos += n;
    Ok(v)
}

fn decode_value(data: &[u8], pos: &mut usize) -> Result<Cbor, String> {
    let (major, arg, indefinite) = read_head(data, pos)?;
    match major {
        0 => {
            if indefinite {
                return Err("integers cannot be indefinite-length".into());
            }
            Ok(Cbor::Uint(arg))
        }
        2 => {
            if indefinite {
                return Err("indefinite-length byte strings are not supported".into());
            }
            let n = arg as usize;
            if *pos + n > data.len() {
                return Err("unexpected end of CBOR byte string".into());
            }
            let b = data[*pos..*pos + n].to_vec();
            *pos += n;
            Ok(Cbor::Bytes(b))
        }
        4 => {
            if indefinite {
                return Err("indefinite-length arrays are not supported here".into());
            }
            let mut items = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                items.push(decode_value(data, pos)?);
            }
            Ok(Cbor::Array(items))
        }
        5 => {
            if indefinite {
                return Err("indefinite-length maps are not supported here".into());
            }
            let mut entries = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                let k = decode_value(data, pos)?;
                let v = decode_value(data, pos)?;
                entries.push((k, v));
            }
            Ok(Cbor::Map(entries))
        }
        7 => match arg {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 | 23 => Ok(Cbor::Null),
            _ => Err(format!("unsupported CBOR simple/float value {arg}")),
        },
        _ => Err(format!("unsupported CBOR major type {major}")),
    }
}

/// Advances `pos` past one complete CBOR data item, supporting every major type
/// including tags and indefinite-length strings, arrays and maps. Used to carve
/// real transactions into their raw top-level elements without fully decoding
/// the (Plutus-laden) contents.
pub fn scan_item(data: &[u8], pos: &mut usize) -> Result<(), String> {
    if *pos >= data.len() {
        return Err("unexpected end of CBOR data".into());
    }
    let ib = data[*pos];
    let major = ib >> 5;
    let info = ib & 0x1f;
    let (_, arg, indefinite) = read_head(data, pos)?;

    match major {
        0 | 1 => Ok(()), // integers: head already consumed
        2 | 3 => {
            // byte / text string
            if indefinite {
                // sequence of definite-length chunks of the same major type
                scan_indefinite_chunks(data, pos, major)
            } else {
                let n = arg as usize;
                if *pos + n > data.len() {
                    return Err("unexpected end of CBOR string".into());
                }
                *pos += n;
                Ok(())
            }
        }
        4 => {
            // array
            if indefinite {
                scan_until_break(data, pos, 1)
            } else {
                for _ in 0..arg {
                    scan_item(data, pos)?;
                }
                Ok(())
            }
        }
        5 => {
            // map
            if indefinite {
                scan_until_break(data, pos, 2)
            } else {
                for _ in 0..arg {
                    scan_item(data, pos)?; // key
                    scan_item(data, pos)?; // value
                }
                Ok(())
            }
        }
        6 => scan_item(data, pos), // tag: one tagged item follows
        7 => {
            // simple values / floats; floats carry payload in the head argument,
            // which read_head already consumed. info 24 (simple) also consumed.
            if info == 31 {
                return Err("unexpected CBOR break".into());
            }
            Ok(())
        }
        _ => Err(format!("invalid CBOR major type {major}")),
    }
}

/// Scans the definite-length chunks of an indefinite-length string until the
/// break code (0xff). `major` is the expected chunk major type (2 or 3).
fn scan_indefinite_chunks(data: &[u8], pos: &mut usize, major: u8) -> Result<(), String> {
    loop {
        if *pos >= data.len() {
            return Err("unexpected end of indefinite CBOR string".into());
        }
        if data[*pos] == 0xff {
            *pos += 1;
            return Ok(());
        }
        let (m, arg, indef) = read_head(data, pos)?;
        if m != major || indef {
            return Err("invalid chunk in indefinite-length string".into());
        }
        let n = arg as usize;
        if *pos + n > data.len() {
            return Err("unexpected end of CBOR string chunk".into());
        }
        *pos += n;
    }
}

/// Scans items until a break code, where each logical entry consumes
/// `items_per_entry` data items (1 for arrays, 2 for maps).
fn scan_until_break(data: &[u8], pos: &mut usize, items_per_entry: usize) -> Result<(), String> {
    loop {
        if *pos >= data.len() {
            return Err("unexpected end of indefinite CBOR container".into());
        }
        if data[*pos] == 0xff {
            *pos += 1;
            return Ok(());
        }
        for _ in 0..items_per_entry {
            scan_item(data, pos)?;
        }
    }
}

/// Splits a top-level CBOR array into the raw byte slices of its elements.
/// Errors if `data` is not a definite-length array.
pub fn split_array_items(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut pos = 0;
    let (major, arg, indefinite) = read_head(data, &mut pos)?;
    if major != 4 || indefinite {
        return Err("expected a definite-length CBOR array".into());
    }
    let mut items = Vec::with_capacity(arg as usize);
    for _ in 0..arg {
        let start = pos;
        scan_item(data, &mut pos)?;
        items.push(data[start..pos].to_vec());
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_shortest_uint() {
        assert_eq!(Cbor::Uint(0).encode(), vec![0x00]);
        assert_eq!(Cbor::Uint(23).encode(), vec![0x17]);
        assert_eq!(Cbor::Uint(24).encode(), vec![0x18, 0x18]);
        assert_eq!(Cbor::Uint(255).encode(), vec![0x18, 0xff]);
        assert_eq!(Cbor::Uint(256).encode(), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            Cbor::Uint(1_000_000).encode(),
            vec![0x1a, 0x00, 0x0f, 0x42, 0x40]
        );
    }

    #[test]
    fn map_is_canonically_sorted() {
        // length-first: 1-byte key before 2-byte key regardless of insertion order
        let m = Cbor::Map(vec![
            (Cbor::Bytes(vec![0, 0]), Cbor::Uint(2)),
            (Cbor::Bytes(vec![9]), Cbor::Uint(1)),
        ]);
        let enc = m.encode();
        // a2 (map of 2) 41 09 01 (1-byte key first) 42 00 00 02
        assert_eq!(enc, vec![0xa2, 0x41, 0x09, 0x01, 0x42, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn roundtrip_decode() {
        let v = Cbor::Array(vec![
            Cbor::Bytes(vec![1, 2, 3]),
            Cbor::Uint(42),
            Cbor::Bool(true),
            Cbor::Null,
        ]);
        let enc = v.encode();
        let (dec, n) = Cbor::decode(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(dec, v);
    }

    #[test]
    fn scan_handles_indefinite_and_tags() {
        // [_ 1, 2] indefinite array inside a definite array: [ 9f 01 02 ff ]
        let data = vec![0x81, 0x9f, 0x01, 0x02, 0xff];
        let items = split_array_items(&data).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], vec![0x9f, 0x01, 0x02, 0xff]);

        // tagged item d8 18 43 010203 (tag 24 wrapping a 3-byte string)
        let tagged = vec![0x81, 0xd8, 0x18, 0x43, 0x01, 0x02, 0x03];
        let items = split_array_items(&tagged).unwrap();
        assert_eq!(items[0], vec![0xd8, 0x18, 0x43, 0x01, 0x02, 0x03]);
    }
}
