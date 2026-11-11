//! The Ledger Tron app, which `lsdk` has no client for: three APDUs, as
//! Ledger's own `hw-app-trx` sends them.
//!
//! - `GET ADDRESS` (`E0 02`): `LV(uncompressed key) ‖ LV(ascii address)`.
//! - `SIGN` (`E0 04`): the path, then the transaction's protobuf `raw_data`,
//!   in chunks that never split a top-level protobuf field (the app parses
//!   them as they arrive). Answers the 65-byte signature `r ‖ s ‖ v`.
//! - `SIGN PERSONAL MESSAGE` (`E0 08`): the path, the length, the message.
//!
//! The app shows a TRX transfer in full. A TRC-20 transfer it shows as a
//! token transfer only for the tokens it knows (their signed descriptors are
//! not sent from here); any other contract call needs "Allow custom
//! contracts" switched on in the app's settings, and is then shown as such.

use lsdk::apdu::Apdu;
use lsdk::path::DerivationPath;
use lsdk::{Device, Error, Result, Transport};

const CLA: u8 = 0xe0;
const INS_ADDRESS: u8 = 0x02;
const INS_SIGN: u8 = 0x04;
const INS_SIGN_MESSAGE: u8 = 0x08;
/// The most bytes one APDU carries.
const CHUNK: usize = 250;

pub struct TronApp<'d, T: Transport> {
    device: &'d Device<T>,
}

/// `count(1) ‖ u32be…`
fn encode_path(path: &DerivationPath) -> Vec<u8> {
    let mut out = vec![path.0.len() as u8];
    for c in &path.0 {
        out.extend_from_slice(&c.to_be_bytes());
    }
    out
}

/// A protobuf varint at the start of `b`: `(value, bytes read)`.
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, byte) in b.iter().enumerate().take(10) {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// The length of the top-level protobuf field at the start of `raw`.
fn field_len(raw: &[u8]) -> Option<usize> {
    let (tag, n) = varint(raw)?;
    let (value, m) = varint(raw.get(n..)?)?;
    let len = match tag & 7 {
        0 => n + m,
        2 => n + m + usize::try_from(value).ok()?,
        _ => return None,
    };
    (len <= raw.len()).then_some(len)
}

/// `path ‖ raw_data`, cut into APDU payloads between top-level fields.
pub(super) fn sign_chunks(path: &DerivationPath, raw_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let bad = || Error::InvalidInput("the Tron transaction cannot be sent to the device (a field is malformed or too long)".into());
    let mut chunks = Vec::new();
    let mut current = encode_path(path);
    let mut rest = raw_data;
    while !rest.is_empty() {
        let len = field_len(rest).ok_or_else(bad)?;
        if len > CHUNK {
            return Err(bad());
        }
        if current.len() + len > CHUNK {
            chunks.push(std::mem::take(&mut current));
        }
        current.extend_from_slice(&rest[..len]);
        rest = &rest[len..];
    }
    chunks.push(current);
    Ok(chunks)
}

impl<'d, T: Transport> TronApp<'d, T> {
    pub fn new(device: &'d Device<T>) -> Self {
        TronApp { device }
    }

    /// `(uncompressed public key, T… address)` at `path`; with `display`,
    /// the device shows the address and waits for the owner to confirm it.
    pub async fn get_address(&self, path: &DerivationPath, display: bool) -> Result<(Vec<u8>, String)> {
        let resp = self.device.send(&Apdu::with_data(CLA, INS_ADDRESS, u8::from(display), 0x00, encode_path(path))).await?;
        let short = || Error::InvalidResponse("short address reply".into());
        let klen = *resp.first().ok_or_else(short)? as usize;
        let key = resp.get(1..1 + klen).ok_or_else(short)?.to_vec();
        let alen = *resp.get(1 + klen).ok_or_else(short)? as usize;
        let address = resp.get(2 + klen..2 + klen + alen).ok_or_else(short)?;
        let address = std::str::from_utf8(address).map_err(|_| Error::InvalidResponse("address is not text".into()))?.to_owned();
        Ok((key, address))
    }

    /// Sign a transaction's `raw_data`: `r ‖ s ‖ v`.
    pub async fn sign_transaction(&self, path: &DerivationPath, raw_data: &[u8]) -> Result<[u8; 65]> {
        let chunks = sign_chunks(path, raw_data)?;
        let last = chunks.len() - 1;
        let mut resp = Vec::new();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let p1 = match (i, last) {
                (0, 0) => 0x10,
                (0, _) => 0x00,
                (i, last) if i == last => 0x90,
                _ => 0x80,
            };
            resp = self.device.send(&Apdu::with_data(CLA, INS_SIGN, p1, 0x00, chunk)).await?;
        }
        signature(&resp)
    }

    /// Sign a message as TronWeb's `signMessageV2` does: `r ‖ s ‖ v`.
    pub async fn sign_message(&self, path: &DerivationPath, message: &[u8]) -> Result<[u8; 65]> {
        let len = u32::try_from(message.len()).map_err(|_| Error::InvalidInput("message too long".into()))?;
        let mut packed = len.to_be_bytes().to_vec();
        packed.extend_from_slice(message);
        let head = encode_path(path);
        let mut first = head.clone();
        let take = packed.len().min(CHUNK - head.len());
        first.extend_from_slice(&packed[..take]);
        let mut resp = self.device.send(&Apdu::with_data(CLA, INS_SIGN_MESSAGE, 0x00, 0x00, first)).await?;
        for chunk in packed[take..].chunks(CHUNK) {
            resp = self.device.send(&Apdu::with_data(CLA, INS_SIGN_MESSAGE, 0x80, 0x00, chunk.to_vec())).await?;
        }
        signature(&resp)
    }
}

fn signature(resp: &[u8]) -> Result<[u8; 65]> {
    resp.get(..65).and_then(|s| s.try_into().ok()).ok_or_else(|| Error::InvalidResponse("bad signature length".into()))
}
