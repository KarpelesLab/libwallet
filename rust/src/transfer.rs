//! Device-to-device wallet transfer crypto + pairing URL (port of
//! wltwallet/transfer_crypto.go + the pairing-code helpers). A transfer's
//! payload is encrypted with a token-derived key (HKDF-SHA-256 → AES-256-GCM),
//! layered on top of Spot's own bottle encryption, and bound to the session id
//! via the GCM additional-authenticated-data. The endpoints
//! (Wallet:exportToDevice / importFromDevice) drive this over the Spot network.

use purecrypto::cipher::{Aes256, Aes256Gcm};
use purecrypto::hash::Sha256;
use purecrypto::rng::RngCore;

use crate::{Error, Result};

/// Pairing token / derived-key length; HKDF info string (bumping it needs a
/// protocol-version bump). Matches Go `transfer_crypto.go`.
pub const TOKEN_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const KEY_INFO: &[u8] = b"libwallet-device-transfer";
pub const PROTOCOL_VERSION: i64 = 1;

/// HKDF-SHA-256(ikm=token, salt=sid, info="libwallet-device-transfer") → 32-byte
/// AES-256 key (Go `deriveTransferKey`).
fn derive_transfer_key(token: &[u8], sid: &str) -> Result<[u8; 32]> {
    if token.len() != TOKEN_BYTES {
        return Err(Error::Env(format!("transfer: token must be {TOKEN_BYTES} bytes")));
    }
    if sid.is_empty() {
        return Err(Error::Env("transfer: sid must be non-empty".into()));
    }
    let mut out = [0u8; KEY_BYTES];
    purecrypto::kdf::hkdf::<Sha256>(sid.as_bytes(), token, KEY_INFO, &mut out);
    Ok(out)
}

/// Seal `plaintext` for a transfer session: `[nonce:12][ciphertext][tag:16]`,
/// AES-256-GCM under the token-derived key with the sid bound as AAD.
pub fn seal(token: &[u8], sid: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = derive_transfer_key(token, sid)?;
    let aead = Aes256Gcm::new(Aes256::new(&key));
    let mut nonce = [0u8; 12];
    purecrypto::rng::OsRng.fill_bytes(&mut nonce);
    let mut buf = plaintext.to_vec();
    let tag = aead.encrypt(&nonce, sid.as_bytes(), &mut buf);
    let mut out = Vec::with_capacity(12 + buf.len() + 16);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Open a sealed transfer payload (inverse of [`seal`]).
pub fn open(token: &[u8], sid: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return Err(Error::Env("transfer: ciphertext too short".into()));
    }
    let key = derive_transfer_key(token, sid)?;
    let aead = Aes256Gcm::new(Aes256::new(&key));
    let nonce: [u8; 12] = sealed[..12].try_into().unwrap();
    let tag: [u8; 16] = sealed[sealed.len() - 16..].try_into().unwrap();
    let mut buf = sealed[12..sealed.len() - 16].to_vec();
    aead.decrypt(&nonce, sid.as_bytes(), &mut buf, &tag).map_err(|_| Error::Env("transfer: decrypt failed".into()))?;
    Ok(buf)
}

/// Build the `tibane://device-transfer?...` pairing URL (Go `buildTransferPairingURL`).
pub fn build_pairing_url(spot_id: &str, token_b64: &str, sid: &str) -> String {
    // Query order matches Go's url.Values.Encode (sorted keys): sid, spot, token, v.
    format!(
        "tibane://device-transfer?sid={}&spot={}&token={}&v={PROTOCOL_VERSION}",
        url_escape(sid),
        url_escape(spot_id),
        url_escape(token_b64),
    )
}

/// Parse a pairing URL → `(spot_id, token_b64, sid)` (Go `parseTransferPairingURL`).
pub fn parse_pairing_url(raw: &str) -> Result<(String, String, String)> {
    let rest = raw.strip_prefix("tibane://device-transfer?").ok_or_else(|| Error::Env("transfer: malformed pairing url".into()))?;
    let (mut spot, mut token, mut sid, mut ver) = (String::new(), String::new(), String::new(), String::new());
    for kv in rest.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = url_unescape(v);
        match k {
            "spot" => spot = v,
            "token" => token = v,
            "sid" => sid = v,
            "v" => ver = v,
            _ => {}
        }
    }
    if spot.is_empty() || token.is_empty() || sid.is_empty() {
        return Err(Error::Env("transfer: malformed pairing url".into()));
    }
    if !ver.is_empty() && ver != "1" {
        return Err(Error::Env("transfer: unsupported pairing version".into()));
    }
    Ok((spot, token, sid))
}

/// Go `url.QueryEscape`: space→'+', unreserved (`-_.~` + alnum) literal, else %XX.
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub(crate) fn url_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let token = [7u8; 32];
        let sid = "session-abc";
        let plaintext = b"the wallet backup blob + device shares";
        let sealed = seal(&token, sid, plaintext).unwrap();
        // [nonce:12][ct][tag:16] — longer than plaintext by 28.
        assert_eq!(sealed.len(), plaintext.len() + 28);
        assert_eq!(open(&token, sid, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn wrong_token_sid_or_tamper_fails() {
        let token = [7u8; 32];
        let sealed = seal(&token, "sid-1", b"secret").unwrap();
        // Wrong token, wrong sid (AAD), and a tampered byte all fail the GCM tag.
        assert!(open(&[8u8; 32], "sid-1", &sealed).is_err());
        assert!(open(&token, "sid-2", &sealed).is_err());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&token, "sid-1", &bad).is_err());
    }

    #[test]
    fn pairing_url_round_trips() {
        let url = build_pairing_url("k.AbC-dEf", "tok_EN123", "sid_9");
        assert!(url.starts_with("tibane://device-transfer?"));
        let (spot, token, sid) = parse_pairing_url(&url).unwrap();
        assert_eq!(spot, "k.AbC-dEf");
        assert_eq!(token, "tok_EN123");
        assert_eq!(sid, "sid_9");
        // A non-transfer scheme / missing field is rejected.
        assert!(parse_pairing_url("https://x").is_err());
        assert!(parse_pairing_url("tibane://device-transfer?spot=x&sid=y").is_err());
    }
}
