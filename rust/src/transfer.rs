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

// --- Solana native-send MAX resolution --------------------------------------
//
// Port of the MAX-sentinel branch of Go `wlttx/preflight.go`
// (`preflightSolanaNativeSend`) plus `computeSolanaMaxSendable` from
// `wlttx/maxsendable.go`. When a native-SOL send carries the MAX amount
// sentinel (`Amount.max(9)` — see `crate::amount`), the concrete lamports must
// be resolved to `balance − fee − rent reserve` at build time so the signer
// sends a real value instead of the sentinel. Lives here (a public module)
// rather than in the private `handlers` module so it stays unit-testable, and
// is wired into the Solana `Transaction:signAndSend` path.

/// Canonical rent-exempt minimum for a 0-byte system account, used as the
/// fallback when `getMinimumBalanceForRentExemption` is unavailable. Matches
/// Go's 890880 fallback.
pub const SOLANA_DEFAULT_SENDER_RENT: u64 = 890_880;

/// Solana native-transfer base signature fee (lamports). Used when the tx
/// carries no explicit (priority-inclusive) fee. Matches Go's flat 5000.
pub const SOLANA_BASE_FEE_LAMPORTS: u64 = 5_000;

/// RPC-free max-sendable math (port of Go `computeSolanaMaxSendable`). All
/// arguments are lamports; `recipient_exists == false` also reserves
/// `recipient_rent`. Returns `(max, reserved, reason)` where `reason` is
/// `Some` (and `max == 0`) when nothing is sendable.
pub fn compute_solana_max_sendable(
    balance: u64,
    fee: u64,
    sender_rent: u64,
    recipient_rent: u64,
    recipient_exists: bool,
) -> (u64, u64, Option<String>) {
    let reserved = if recipient_exists {
        fee + sender_rent
    } else {
        fee + sender_rent + recipient_rent
    };
    if balance <= reserved {
        let mut reason = format!(
            "balance {balance} lamports is not enough to cover fee {fee} + sender rent {sender_rent}"
        );
        if !recipient_exists {
            reason = format!("{reason} + new-recipient rent {recipient_rent}");
        }
        return (0, reserved, Some(reason));
    }
    (balance - reserved, reserved, None)
}

/// Resolve the MAX sentinel on a native-SOL send to a concrete lamport amount:
/// `balance − fee − sender rent (− new-recipient rent)`, using the same
/// balance/rent inputs as `Transaction:maxSendable`. Port of the MAX branch of
/// Go `preflightSolanaNativeSend`. `to` may be empty (no recipient-rent
/// reservation). Fails loudly rather than let an unresolved sentinel reach the
/// signer when the balance lookup fails or nothing is sendable.
pub fn resolve_solana_max_lamports(
    rpc: &str,
    from_address: &str,
    to: &str,
    fee_lamports: u64,
) -> Result<u64> {
    // Balance (lamports). Without it MAX can't be resolved — fail loudly.
    let bal_res = crate::rpc::call(rpc, "getBalance", serde_json::json!([from_address]))
        .map_err(|e| Error::Env(format!("cannot resolve MAX amount: balance lookup failed: {e}")))?;
    let balance = bal_res
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::Env("cannot resolve MAX amount: unexpected getBalance response".into()))?;

    // Sender rent-exempt minimum (0-byte system account); canonical fallback.
    let sender_rent = crate::rpc::call(rpc, "getMinimumBalanceForRentExemption", serde_json::json!([0]))
        .ok()
        .and_then(|v| v.as_u64())
        .unwrap_or(SOLANA_DEFAULT_SENDER_RENT);

    // A brand-new recipient must be funded to its own rent-exempt minimum,
    // which comes out of the sendable max.
    let mut recipient_exists = true;
    let mut recipient_rent = 0u64;
    if !to.is_empty() {
        if let Ok(info) = crate::rpc::call(
            rpc,
            "getAccountInfo",
            serde_json::json!([to, { "encoding": "base64" }]),
        ) {
            // getAccountInfo returns "value": null for missing accounts.
            let exists = info.get("value").map(|v| !v.is_null()).unwrap_or(false);
            if !exists {
                recipient_exists = false;
                recipient_rent = sender_rent;
            }
        }
    }

    let (max, _reserved, reason) =
        compute_solana_max_sendable(balance, fee_lamports, sender_rent, recipient_rent, recipient_exists);
    if max == 0 {
        return Err(Error::Env(reason.unwrap_or_else(|| "insufficient balance".into())));
    }
    Ok(max)
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
