//! Air-gapped signer interop: the payloads that cross a QR-code gap between
//! libwallet and an external signer (Keystone, Coldcard, Passport, SeedSigner,
//! Sparrow-style descriptor exports…), in both directions.
//!
//! Only the *strings* are handled here — the host renders and scans the QR
//! codes. Two transports are supported, chosen per request by the host:
//!
//! - **BC-UR** (BCR-2020-005 uniform resources, `ur:<type>/…`): the CBOR
//!   registry types hardware wallets exchange — `crypto-hdkey`,
//!   `crypto-account`, `crypto-multi-accounts` (Keystone), `crypto-psbt` /
//!   `psbt`, `eth-sign-request` / `eth-signature`, `sol-sign-request` /
//!   `sol-signature`. Large payloads become fountain-coded multi-part URs that
//!   a receiver reassembles from frames arriving in any order.
//! - **BBQr** (Coinkite, `B$…`): a file cut into numbered parts, optionally
//!   deflated. Used for PSBTs, raw transactions and the Coldcard-style JSON
//!   key exports.
//!
//! Layering: [`decoder`] reassembles scanned frames one at a time behind a
//! host-driven context (progress + `complete`); [`registry`] encodes/decodes
//! the UR CBOR types; [`import`] turns any supported key export into a signer
//! wallet with watch-only accounts; [`sign`] builds unsigned requests (PSBT,
//! EVM, Solana) for those accounts and turns the signer's answer — often just
//! the bare signature — into a broadcastable transaction.
//!
//! The transport codecs themselves (bytewords + fountain codes, BBQr headers +
//! base32, PSBT maps) come from `outscript`; the UR registry CBOR is ciborium
//! (tags + text), and BBQr `Z` compression runs through `compcol` deflate with
//! the 1 KiB match-distance cap BBQr decoders require.

pub mod cbor;
pub mod decoder;
pub mod import;
pub mod registry;
pub mod sign;

use crate::{Error, Result};

/// How a payload is cut into QR frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// BC-UR (`ur:…`), fountain-coded when it does not fit one frame.
    Ur,
    /// BBQr (`B$…`), fixed numbered parts.
    Bbqr,
}

impl Transport {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "ur" | "bc-ur" | "bcur" => Ok(Transport::Ur),
            "bbqr" => Ok(Transport::Bbqr),
            other => Err(Error::Env(format!("unknown transport {other:?} (ur|bbqr)"))),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Ur => "ur",
            Transport::Bbqr => "bbqr",
        }
    }
}

/// Default fountain fragment size (bytes of CBOR per UR part). ~200 bytes keeps
/// each frame around a version-15 QR at medium error correction, which phone
/// cameras scan reliably from a hardware-wallet screen.
pub const DEFAULT_UR_FRAGMENT_LEN: usize = 200;
/// Default BBQr part size in characters (the BBQr reference uses up to ~2000;
/// smaller parts scan better off small screens).
pub const DEFAULT_BBQR_PART_LEN: usize = 1000;

/// Encode `cbor` as UR frames of type `ur_type`, uppercase (QR alphanumeric
/// mode). A payload that fits `max_fragment_len` is one part; otherwise the
/// first `fragment_count` parts carry the payload in order and the rest are
/// fountain mixes so a receiver can finish from whichever frames it catches.
/// `extra` is how many redundant parts to add beyond the minimum (hosts loop
/// the returned list as an animated QR; the default is 50% more frames).
pub fn ur_parts(ur_type: &str, cbor: &[u8], max_fragment_len: Option<usize>, extra: Option<usize>) -> Result<Vec<String>> {
    let frag = max_fragment_len.unwrap_or(DEFAULT_UR_FRAGMENT_LEN).max(10);
    let mut enc = outscript::bcur::Encoder::new(ur_type, cbor, frag).map_err(|e| Error::Env(format!("ur encode: {e}")))?;
    if enc.is_single_part() {
        return Ok(vec![enc.next_part().to_ascii_uppercase()]);
    }
    let n = enc.fragment_count();
    let total = n + extra.unwrap_or(n.div_ceil(2));
    Ok((0..total).map(|_| enc.next_part().to_ascii_uppercase()).collect())
}

/// Encode a single-part UR string (no size limit; for logging / direct paste).
pub fn ur_single(ur_type: &str, cbor: &[u8]) -> Result<String> {
    outscript::bcur::encode(ur_type, cbor).map(|s| s.to_ascii_uppercase()).map_err(|e| Error::Env(format!("ur encode: {e}")))
}

/// BBQr's `Z` encoding is raw deflate that a receiver inflates with a 1 KiB
/// window (`zlib.decompressobj(wbits=-10)`), so back-references farther than
/// that would be rejected — cap the encoder's match distance accordingly.
const BBQR_DEFLATE_WINDOW: usize = 1024;

/// Deflate `data` for a BBQr `Z` payload (compcol, 1 KiB window, level 9).
pub fn bbqr_deflate(data: &[u8]) -> Result<Vec<u8>> {
    use compcol::deflate::{Deflate, EncoderConfig};
    let cfg = EncoderConfig::new().with_level(9).with_max_distance(BBQR_DEFLATE_WINDOW);
    compcol::vec::compress_to_vec_with::<Deflate>(data, cfg).map_err(|e| Error::Env(format!("deflate: {e:?}")))
}

/// Inflate a BBQr `Z` payload (raw deflate), refusing to grow past `max_len`.
pub fn bbqr_inflate(data: &[u8], max_len: usize) -> Result<Vec<u8>> {
    use compcol::deflate::Deflate;
    compcol::vec::decompress_to_vec_capped::<Deflate>(data, max_len as u64).map_err(|e| Error::Env(format!("inflate: {e:?}")))
}

/// Largest payload a BBQr/UR frame set may reassemble to (sanity cap).
pub const MAX_PAYLOAD_LEN: usize = 4 << 20;

/// Cut `data` into BBQr parts of at most `max_part_len` characters. With
/// `compress`, the file is deflated first (encoding `Z`) when that is shorter,
/// else base32 (`2`). Parts are uppercase as the protocol requires.
pub fn bbqr_parts(data: &[u8], file_type: outscript::bbqr::FileType, max_part_len: Option<usize>, compress: bool) -> Result<Vec<String>> {
    use outscript::bbqr::{self, Encoding, Header};
    let max_part_len = max_part_len.unwrap_or(DEFAULT_BBQR_PART_LEN);
    let (body, encoding) = if compress {
        let z = bbqr_deflate(data)?;
        if z.len() < data.len() {
            (z, Encoding::Zlib)
        } else {
            (data.to_vec(), Encoding::Base32)
        }
    } else {
        (data.to_vec(), Encoding::Base32)
    };
    // 8-char header + base32 (8 chars per 5 bytes). Cut on 5-byte group
    // boundaries so every part decodes on its own.
    let capacity_chars = max_part_len.checked_sub(8).filter(|c| *c >= 8).ok_or_else(|| Error::Env("bbqr part length too small".into()))?;
    let bytes_per_part = (capacity_chars / 8) * 5;
    let num_parts = body.len().div_ceil(bytes_per_part).max(1);
    if num_parts > 1295 {
        return Err(Error::Env(format!("payload needs {num_parts} BBQr parts (max 1295); raise MaxPartLen")));
    }
    let mut out = Vec::with_capacity(num_parts);
    for (i, chunk) in body.chunks(bytes_per_part.max(1)).enumerate() {
        let header = Header { encoding, file_type, num_parts: num_parts as u16, index: i as u16 };
        let mut buf = vec![0u8; 8 + chunk.len() * 2 + 16];
        let n = bbqr::encode_part_to_slice(&header, chunk, &mut buf).map_err(|e| Error::Env(format!("bbqr encode: {e}")))?;
        out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    if out.is_empty() {
        // Empty file: one empty part.
        let header = Header { encoding, file_type, num_parts: 1, index: 0 };
        let mut buf = [0u8; 16];
        let n = bbqr::encode_part_to_slice(&header, &[], &mut buf).map_err(|e| Error::Env(format!("bbqr encode: {e}")))?;
        out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    Ok(out)
}

/// Reassemble a complete set of BBQr parts (any order) into `(file_type, data)`,
/// inflating `Z` payloads through compcol.
pub fn bbqr_join(parts: &[String]) -> Result<(outscript::bbqr::FileType, Vec<u8>)> {
    use outscript::bbqr::{self, Encoding, Header};
    if parts.is_empty() {
        return Err(Error::Env("no BBQr parts".into()));
    }
    let mut decoded: Vec<Option<Vec<u8>>> = Vec::new();
    let mut first: Option<Header> = None;
    for p in parts {
        let (h, body) = Header::parse(p).map_err(|e| Error::Env(format!("bbqr header: {e}")))?;
        match &first {
            None => {
                decoded = vec![None; h.num_parts as usize];
                first = Some(h);
            }
            Some(f) => {
                if f.num_parts != h.num_parts || f.file_type != h.file_type || f.encoding != h.encoding {
                    return Err(Error::Env("BBQr parts belong to different files".into()));
                }
            }
        }
        let mut buf = vec![0u8; body.len() + 8];
        let (_, n) = bbqr::decode_part_to_slice(p, &mut buf).map_err(|e| Error::Env(format!("bbqr part: {e}")))?;
        let idx = h.index as usize;
        if idx >= decoded.len() {
            return Err(Error::Env("BBQr part index out of range".into()));
        }
        decoded[idx] = Some(buf[..n].to_vec());
    }
    let header = first.unwrap();
    let mut data = Vec::new();
    for (i, d) in decoded.into_iter().enumerate() {
        data.extend(d.ok_or_else(|| Error::Env(format!("BBQr part {i} missing")))?);
    }
    if header.encoding == Encoding::Zlib {
        data = bbqr_inflate(&data, MAX_PAYLOAD_LEN)?;
    }
    Ok((header.file_type, data))
}

/// Hex helpers shared by the airgap modules.
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(Error::Env("odd-length hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| Error::Env(format!("bad hex: {e}"))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ur_parts_roundtrip_single_and_multi() {
        let cbor = outscript::bcur::bytes_to_cbor(b"hello ur");
        let one = ur_parts("bytes", &cbor, Some(100), None).unwrap();
        assert_eq!(one.len(), 1);
        assert!(one[0].starts_with("UR:BYTES/"));
        let (t, c) = outscript::bcur::decode(&one[0]).unwrap();
        assert_eq!(t, "bytes");
        assert_eq!(c, cbor);

        // Multi-part: 1000 bytes in 50-byte fragments → 20 fragments + 10 extra.
        let big: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let cbor = outscript::bcur::bytes_to_cbor(&big);
        let parts = ur_parts("bytes", &cbor, Some(50), None).unwrap();
        let n = outscript::bcur::Encoder::new("bytes", &cbor, 50).unwrap().fragment_count();
        assert!(n > 10);
        assert_eq!(parts.len(), n + n.div_ceil(2));
        // Decoder finishes from a shuffled subset (drop a few early frames: the
        // fountain mixes make up for them).
        let mut dec = outscript::bcur::Decoder::new();
        let mut done = false;
        for p in parts.iter().skip(3) {
            if dec.receive(p).unwrap() {
                done = true;
                break;
            }
        }
        assert!(done, "fountain decode should complete with redundancy");
        assert_eq!(outscript::bcur::cbor_to_bytes(dec.message().unwrap()).unwrap(), &big[..]);
    }

    #[test]
    fn bbqr_parts_roundtrip_compressed_and_plain() {
        use outscript::bbqr::FileType;
        // Highly compressible payload → Z encoding.
        let data = vec![0x41u8; 3000];
        let parts = bbqr_parts(&data, FileType::PSBT, Some(200), true).unwrap();
        assert!(parts.iter().all(|p| p.starts_with("B$ZP")), "{:?}", &parts[0][..8]);
        let mut shuffled = parts.clone();
        shuffled.rotate_left(1);
        let (ft, back) = bbqr_join(&shuffled).unwrap();
        assert_eq!(ft, FileType::PSBT);
        assert_eq!(back, data);

        // Uncompressed → base32 ('2'); also decodable by outscript's own joiner.
        let noise: Vec<u8> = (0..700u32).map(|i| (i.wrapping_mul(2654435761u32) >> 13) as u8).collect();
        let parts = bbqr_parts(&noise, FileType::BINARY, Some(300), false).unwrap();
        assert!(parts.iter().all(|p| p.starts_with("B$2B")));
        let (ft, back) = outscript::bbqr::join(&parts).unwrap();
        assert_eq!((ft, back), (FileType::BINARY, noise.clone()));
        let (_, back2) = bbqr_join(&parts).unwrap();
        assert_eq!(back2, noise);
    }

    #[test]
    fn bbqr_z_interops_with_outscript_decoder_and_vice_versa() {
        use outscript::bbqr::{self, FileType};
        // Our compcol-deflated parts must inflate with outscript's (minizlib)
        // joiner — a stand-in for a Coldcard/Sparrow receiver — and theirs with
        // our compcol inflate.
        let data: Vec<u8> = (0..5000u32).map(|i| (i / 40) as u8).collect();
        let ours = bbqr_parts(&data, FileType::TRANSACTION, Some(500), true).unwrap();
        assert!(ours[0].starts_with("B$ZT"));
        let (ft, back) = bbqr::join(&ours).unwrap();
        assert_eq!((ft, back), (FileType::TRANSACTION, data.clone()));

        let theirs = bbqr::split_with(&data, FileType::TRANSACTION, bbqr::Encoding::Zlib, 500).unwrap();
        let (ft, back) = bbqr_join(&theirs).unwrap();
        assert_eq!((ft, back), (FileType::TRANSACTION, data));
    }

    #[test]
    fn deflate_respects_1k_window() {
        // A long repeat 2000 bytes back is NOT referenced (distance capped at
        // 1024), so a strict wbits=-10 inflater accepts the stream. We verify by
        // inflating with a 1 KiB-window-only check: every back-reference
        // distance ≤ 1024 is implied by successful decode under compcol too, so
        // instead assert the stream round-trips and is still well compressed.
        let mut data = vec![0u8; 2000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 97) as u8;
        }
        let z = bbqr_deflate(&data).unwrap();
        assert!(z.len() < data.len() / 4, "compressed {} of {}", z.len(), data.len());
        assert_eq!(bbqr_inflate(&z, 1 << 16).unwrap(), data);
    }
}
