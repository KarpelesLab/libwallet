//! WalletSign backend glue for RemoteKey shares (port of the wdrone-facing
//! bits of wltwallet/walletkey.go + broker.go). A RemoteKey share is generated
//! locally like any other, then its sealed bottle is UPLOADED to the WalletSign
//! backend (`Crypto/WalletSign:setGeneratedKey`) encrypted to the wdrone fleet's
//! decrypt keys, so a wdrone can later pull it to co-sign / reshare.
//!
//! Auth is the `Sec-ClientId` header only (from Info:setWalletInfo).

use base64::Engine;
use bottlers::key::PublicKey;
use serde_json::Value;

use crate::{Error, Result};

/// Parse the `Crypto/WalletSign:keys` response body (a list of base64url IDCard
/// bottles) into the wdrone fleet's "decrypt"-purpose public keys — the
/// recipients a RemoteKey share is sealed to before upload. Shared by the native
/// (sync) and wasm (async) `fetch_decrypt_keys` wrappers, which differ only in
/// how they perform the HTTP GET.
fn parse_decrypt_keys(data: Value) -> Result<Vec<PublicKey>> {
    let ids = data.as_array().ok_or_else(|| Error::Env("WalletSign:keys did not return a list".into()))?;
    let now = now_unix();
    let mut keys = Vec::new();
    for id in ids {
        let s = match id.as_str() {
            Some(s) => s,
            None => continue,
        };
        let bin = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| Error::Env(format!("bad idcard base64: {e}")))?;
        // The list carries signed IDCard bottles (Go cryptutil.IDCard.
        // UnmarshalBinary parses the signed form); tolerate a bare CBOR card too.
        let card = bottlers::idcard::IDCard::from_signed(&bin)
            .or_else(|_| bottlers::idcard::IDCard::from_cbor(&bin))
            .map_err(|e| Error::Env(format!("parse idcard: {e}")))?;
        keys.extend(card.keys_for("decrypt", now));
    }
    if keys.is_empty() {
        return Err(Error::Env("no wdrone decrypt keys available".into()));
    }
    Ok(keys)
}

/// Fetch the wdrone fleet's decrypt public keys (Go `encrypt`'s RemoteKey arm:
/// GET `Crypto/WalletSign:keys` → parse each base64url IDCard → collect the
/// "decrypt"-purpose subkeys). These are the recipients a RemoteKey share is
/// sealed to before upload.
#[cfg(not(target_arch = "wasm32"))]
pub fn fetch_decrypt_keys(base: &str, client_id: Option<&str>) -> Result<Vec<PublicKey>> {
    let data = crate::rest::do_get_with_client_id(base, "Crypto/WalletSign:keys", client_id)?;
    parse_decrypt_keys(data)
}

/// Browser twin of [`fetch_decrypt_keys`]: same parsing, async Fetch-backed GET.
#[cfg(target_arch = "wasm32")]
pub async fn fetch_decrypt_keys(base: &str, client_id: Option<&str>) -> Result<Vec<PublicKey>> {
    let data = crate::rest::do_get_with_client_id(base, "Crypto/WalletSign:keys", client_id).await?;
    parse_decrypt_keys(data)
}

/// Fetch the wdrone fleet's Spot ids (Go `selectPeer`'s discovery half): GET
/// `Crypto/WalletSign:keys` → for each signed IDCard, `k.<b64url(sha256(self))>`
/// (the same derivation spotlib uses for a client's own target id).
#[cfg(not(target_arch = "wasm32"))]
pub fn fetch_peer_spot_ids(base: &str, client_id: Option<&str>) -> Result<Vec<String>> {
    let data = crate::rest::do_get_with_client_id(base, "Crypto/WalletSign:keys", client_id)?;
    let ids = data.as_array().ok_or_else(|| Error::Env("WalletSign:keys did not return a list".into()))?;
    let mut out = Vec::new();
    for id in ids {
        let s = match id.as_str() {
            Some(s) => s,
            None => continue,
        };
        let bin = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| Error::Env(format!("bad idcard base64: {e}")))?;
        let card = bottlers::idcard::IDCard::from_signed(&bin)
            .or_else(|_| bottlers::idcard::IDCard::from_cbor(&bin))
            .map_err(|e| Error::Env(format!("parse idcard: {e}")))?;
        let h = bottlers::hash::sha256(&card.self_key);
        out.push(format!("k.{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h)));
    }
    if out.is_empty() {
        return Err(Error::Env("no wdrone peers available".into()));
    }
    Ok(out)
}

/// Upload a sealed RemoteKey share to the backend (Go `encrypt`'s
/// `Crypto/WalletSign:setGeneratedKey` POST). `data_cbor` is the CBOR bottle
/// (sealed to the fleet keys); `curve`/`protocol` are the on-wire vocabulary
/// wdrone's loadShare recognises ("ed25519"/"frost", "secp256k1"/"dkls23").
#[cfg(not(target_arch = "wasm32"))]
pub fn upload_generated_key(
    base: &str,
    client_id: Option<&str>,
    remote_key: &str,
    curve: &str,
    protocol: &str,
    data_cbor: &[u8],
) -> Result<()> {
    let mut params = serde_json::json!({
        "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data_cbor),
        "key": remote_key,
        "curve": curve,
    });
    if !protocol.is_empty() {
        params["protocol"] = serde_json::json!(protocol);
    }
    crate::rest::do_post(base, "Crypto/WalletSign:setGeneratedKey", &params, client_id)?;
    Ok(())
}

fn now_unix() -> i64 {
    // chrono works on both native and wasm (SystemTime::now panics on wasm32).
    chrono::Utc::now().timestamp()
}
