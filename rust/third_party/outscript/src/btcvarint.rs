//! Bitcoin variable-length integer (CompactSize).

use std::io::{self, Read, Write};

/// A Bitcoin variable-length integer as defined in the Bitcoin protocol.
/// Values 0-0xfc are a single byte; larger values use a prefix byte (0xfd,
/// 0xfe, 0xff) followed by 2, 4, or 8 little-endian bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtcVarInt(pub u64);

impl BtcVarInt {
    /// Returns the encoded variable-length integer.
    pub fn bytes(self) -> Vec<u8> {
        let v = self.0;
        if v <= 0xfc {
            vec![v as u8]
        } else if v <= 0xffff {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(v as u16).to_le_bytes());
            out
        } else if v <= 0xffff_ffff {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(v as u32).to_le_bytes());
            out
        } else {
            let mut out = vec![0xff];
            out.extend_from_slice(&v.to_le_bytes());
            out
        }
    }

    /// Returns the number of bytes needed to encode this value (always >= 1).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        let v = self.0;
        if v <= 0xfc {
            1
        } else if v <= 0xffff {
            3
        } else if v <= 0xffff_ffff {
            5
        } else {
            9
        }
    }

    /// Reads a variable-length integer from `r`, returning the value and the
    /// number of bytes consumed.
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<(BtcVarInt, u64)> {
        let mut first = [0u8; 1];
        r.read_exact(&mut first)?;
        let t = first[0];
        if t <= 0xfc {
            return Ok((BtcVarInt(t as u64), 1));
        }
        match t {
            0xfd => {
                let mut b = [0u8; 2];
                r.read_exact(&mut b)?;
                Ok((BtcVarInt(u16::from_le_bytes(b) as u64), 3))
            }
            0xfe => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b)?;
                Ok((BtcVarInt(u32::from_le_bytes(b) as u64), 5))
            }
            _ => {
                let mut b = [0u8; 8];
                r.read_exact(&mut b)?;
                Ok((BtcVarInt(u64::from_le_bytes(b)), 9))
            }
        }
    }

    /// Writes the encoded variable-length integer to `w`, returning the number
    /// of bytes written.
    pub fn write_to<W: Write>(self, w: &mut W) -> io::Result<u64> {
        let b = self.bytes();
        w.write_all(&b)?;
        Ok(b.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: u64, expected_len: usize, prefix: Option<u8>) {
        let bi = BtcVarInt(v);
        let b = bi.bytes();
        assert_eq!(b.len(), expected_len);
        assert_eq!(bi.len(), expected_len);
        if let Some(p) = prefix {
            assert_eq!(b[0], p);
        }
        let (got, n) = BtcVarInt::read_from(&mut &b[..]).unwrap();
        assert_eq!(got.0, v);
        assert_eq!(n as usize, expected_len);
    }

    #[test]
    fn sizes() {
        roundtrip(42, 1, None);
        roundtrip(0xfc, 1, None);
        roundtrip(0xfd, 3, Some(0xfd));
        roundtrip(0xffff, 3, None);
        roundtrip(0x10000, 5, Some(0xfe));
        roundtrip(0x1_0000_0000, 9, Some(0xff));
    }

    #[test]
    fn write_to_roundtrip() {
        let mut buf = Vec::new();
        let n = BtcVarInt(300).write_to(&mut buf).unwrap();
        assert_eq!(n, 3);
        let (got, _) = BtcVarInt::read_from(&mut &buf[..]).unwrap();
        assert_eq!(got.0, 300);
    }
}
