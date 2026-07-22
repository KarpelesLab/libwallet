//! Bech32 / Bech32m segwit addresses (BIP-173 / BIP-350) and Bitcoin Cash
//! CashAddr encoding.
//!
//! Port of the parts of `github.com/KarpelesLab/bech32m` used by outscript:
//! `SegwitAddrEncode`/`SegwitAddrDecode` and `CashAddrEncode`/`CashAddrDecode`.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Encoding constant distinguishing bech32 (segwit v0) from bech32m (v1+).
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Error type for bech32/cashaddr operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}
impl core::error::Error for Error {}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

fn charset_rev(c: u8) -> Option<u8> {
    CHARSET.iter().position(|&x| x == c).map(|p| p as u8)
}

// ----- bech32 core -----

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut v = Vec::with_capacity(bytes.len() * 2 + 1);
    for &c in bytes {
        v.push(c >> 5);
    }
    v.push(0);
    for &c in bytes {
        v.push(c & 31);
    }
    v
}

fn create_checksum(hrp: &str, data: &[u8], spec: u32) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = bech32_polymod(&values) ^ spec;
    (0..6)
        .map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

fn bech32_encode(hrp: &str, data: &[u8], spec: u32) -> String {
    let checksum = create_checksum(hrp, data, spec);
    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &d in data.iter().chain(checksum.iter()) {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

/// Decodes a bech32/bech32m string into (hrp, 5-bit data, spec constant).
fn bech32_decode(s: &str) -> Result<(String, Vec<u8>, u32), Error> {
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return err("mixed case bech32 string");
    }
    let s = s.to_ascii_lowercase();
    let pos = match s.rfind('1') {
        Some(p) => p,
        None => return err("missing separator '1'"),
    };
    if pos == 0 || pos + 7 > s.len() {
        return err("invalid separator position");
    }
    let hrp = s[..pos].to_string();
    let mut data = Vec::with_capacity(s.len() - pos - 1);
    for c in s[pos + 1..].bytes() {
        match charset_rev(c) {
            Some(v) => data.push(v),
            None => return err("invalid bech32 data character"),
        }
    }
    // Determine spec by which constant validates the checksum.
    let mut values = hrp_expand(&hrp);
    values.extend_from_slice(&data);
    let polymod = bech32_polymod(&values);
    let spec = if polymod == BECH32_CONST {
        BECH32_CONST
    } else if polymod == BECH32M_CONST {
        BECH32M_CONST
    } else {
        return err("invalid bech32 checksum");
    };
    data.truncate(data.len() - 6);
    Ok((hrp, data, spec))
}

/// Converts between bit groups. `pad` controls whether trailing bits are padded.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;
    let mut out = Vec::new();
    for &value in data {
        let v = value as u32;
        if (v >> from) != 0 {
            return None;
        }
        acc = ((acc << from) | v) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

// ----- segwit -----

/// Encodes a segwit address for the given human-readable part, witness version
/// (0..=16) and witness program.
pub fn segwit_addr_encode(hrp: &str, version: u8, program: &[u8]) -> Result<String, Error> {
    if version > 16 {
        return err("invalid witness version");
    }
    if program.len() < 2 || program.len() > 40 {
        return err("invalid witness program length");
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return err("invalid witness program length for v0");
    }
    let mut data = vec![version];
    let conv =
        convert_bits(program, 8, 5, true).ok_or_else(|| Error("convert_bits failed".into()))?;
    data.extend_from_slice(&conv);
    let spec = if version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    Ok(bech32_encode(hrp, &data, spec))
}

/// Decodes a segwit address, verifying it uses the expected human-readable part.
/// Returns the witness version and program.
pub fn segwit_addr_decode(hrp: &str, addr: &str) -> Result<(u8, Vec<u8>), Error> {
    let (got_hrp, data, spec) = bech32_decode(addr)?;
    if got_hrp != hrp {
        return err(format!("expected hrp {hrp}, got {got_hrp}"));
    }
    if data.is_empty() {
        return err("empty data");
    }
    let version = data[0];
    if version > 16 {
        return err("invalid witness version");
    }
    let program =
        convert_bits(&data[1..], 5, 8, false).ok_or_else(|| Error("convert_bits failed".into()))?;
    if program.len() < 2 || program.len() > 40 {
        return err("invalid witness program length");
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return err("invalid witness program length for v0");
    }
    let expected = if version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    if spec != expected {
        return err("wrong bech32 variant for witness version");
    }
    Ok((version, program))
}

// ----- CashAddr (Bitcoin Cash) -----

// The CashAddr polymod generator constants are 40-bit values defined by the
// Bitcoin Cash spec; their natural grouping is not byte-aligned.
#[allow(clippy::unusual_byte_groupings)]
fn cashaddr_polymod(values: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for &d in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07_ffff_ffff) << 5) ^ (d as u64);
        if c0 & 0x01 != 0 {
            c ^= 0x98f2_bc8e_61;
        }
        if c0 & 0x02 != 0 {
            c ^= 0x79b7_6d99_e2;
        }
        if c0 & 0x04 != 0 {
            c ^= 0xf33e_5fb3_c4;
        }
        if c0 & 0x08 != 0 {
            c ^= 0xae2e_abe2_a8;
        }
        if c0 & 0x10 != 0 {
            c ^= 0x1e4f_43e4_70;
        }
    }
    c ^ 1
}

fn cashaddr_prefix(prefix: &str) -> &str {
    prefix.strip_suffix(':').unwrap_or(prefix)
}

fn cashaddr_expand_prefix(prefix: &str) -> Vec<u8> {
    let mut v: Vec<u8> = prefix.bytes().map(|c| c & 0x1f).collect();
    v.push(0);
    v
}

fn size_bits(len: usize) -> Option<u8> {
    match len {
        20 => Some(0),
        24 => Some(1),
        28 => Some(2),
        32 => Some(3),
        40 => Some(4),
        48 => Some(5),
        56 => Some(6),
        64 => Some(7),
        _ => None,
    }
}

fn size_from_bits(bits: u8) -> usize {
    match bits {
        0 => 20,
        1 => 24,
        2 => 28,
        3 => 32,
        4 => 40,
        5 => 48,
        6 => 56,
        _ => 64,
    }
}

/// Encodes a Bitcoin Cash CashAddr. `prefix` may include a trailing colon
/// (e.g. "bitcoincash:"); the returned string is `prefix:payload`.
pub fn cashaddr_encode(prefix: &str, version_type: u8, hash: &[u8]) -> Result<String, Error> {
    let p = cashaddr_prefix(prefix);
    let size = size_bits(hash.len()).ok_or_else(|| Error("invalid cashaddr hash length".into()))?;
    let version_byte = (version_type << 3) | size;

    let mut payload = Vec::with_capacity(1 + hash.len());
    payload.push(version_byte);
    payload.extend_from_slice(hash);
    let payload5 =
        convert_bits(&payload, 8, 5, true).ok_or_else(|| Error("convert_bits failed".into()))?;

    let mut checksum_input = cashaddr_expand_prefix(p);
    checksum_input.extend_from_slice(&payload5);
    checksum_input.extend_from_slice(&[0u8; 8]);
    let polymod = cashaddr_polymod(&checksum_input);
    let checksum: Vec<u8> = (0..8)
        .map(|i| ((polymod >> (5 * (7 - i))) & 0x1f) as u8)
        .collect();

    let mut out = String::new();
    out.push_str(p);
    out.push(':');
    for &d in payload5.iter().chain(checksum.iter()) {
        out.push(CHARSET[d as usize] as char);
    }
    Ok(out)
}

/// Decodes a Bitcoin Cash CashAddr, verifying the expected prefix. Returns the
/// (type, hash) pair where type 0 is P2PKH and type 1 is P2SH.
pub fn cashaddr_decode(prefix: &str, addr: &str) -> Result<(u8, Vec<u8>), Error> {
    let p = cashaddr_prefix(prefix);
    let lower = addr.to_ascii_lowercase();
    let body = match lower.split_once(':') {
        Some((pre, rest)) => {
            if pre != p {
                return err(format!("expected cashaddr prefix {p}, got {pre}"));
            }
            rest.to_string()
        }
        None => lower,
    };

    let mut data = Vec::with_capacity(body.len());
    for c in body.bytes() {
        match charset_rev(c) {
            Some(v) => data.push(v),
            None => return err("invalid cashaddr character"),
        }
    }

    let mut checksum_input = cashaddr_expand_prefix(p);
    checksum_input.extend_from_slice(&data);
    if cashaddr_polymod(&checksum_input) != 0 {
        return err("invalid cashaddr checksum");
    }

    let payload5 = &data[..data.len() - 8];
    let payload =
        convert_bits(payload5, 5, 8, false).ok_or_else(|| Error("convert_bits failed".into()))?;
    if payload.is_empty() {
        return err("empty cashaddr payload");
    }
    let version_byte = payload[0];
    if version_byte & 0x80 != 0 {
        return err("invalid cashaddr version byte");
    }
    let typ = (version_byte >> 3) & 0x0f;
    let expected_len = size_from_bits(version_byte & 0x07);
    let hash = &payload[1..];
    if hash.len() != expected_len {
        return err("cashaddr hash length mismatch");
    }
    Ok((typ, hash.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segwit_v0_roundtrip() {
        // BIP-173 test vector.
        let prog = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = segwit_addr_encode("bc", 0, &prog).unwrap();
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let (v, p) = segwit_addr_decode("bc", &addr).unwrap();
        assert_eq!(v, 0);
        assert_eq!(p, prog);
    }

    #[test]
    fn segwit_v1_taproot_roundtrip() {
        let prog = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let addr = segwit_addr_encode("bc", 1, &prog).unwrap();
        let (v, p) = segwit_addr_decode("bc", &addr).unwrap();
        assert_eq!(v, 1);
        assert_eq!(p, prog);
    }

    #[test]
    fn cashaddr_roundtrip() {
        // From the outscript address test vector:
        // p2pkh bitcoincash:qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm
        let addr = "bitcoincash:qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm";
        let (typ, hash) = cashaddr_decode("bitcoincash:", addr).unwrap();
        assert_eq!(typ, 0);
        let re = cashaddr_encode("bitcoincash:", 0, &hash).unwrap();
        assert_eq!(re, addr);
    }
}
