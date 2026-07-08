//! WalletSign backend glue for RemoteKey shares (port of the wdrone-facing
//! bits of wltwallet/walletkey.go + broker.go). A RemoteKey share is generated
//! locally like any other, then its sealed bottle is UPLOADED to the WalletSign
//! backend (`Crypto/WalletSign:setGeneratedKey`) encrypted to the wdrone fleet's
//! decrypt keys, so a wdrone can later pull it to co-sign / reshare.
//!
//! Auth is the `Sec-ClientId` header only (from Info:setWalletInfo).

use base64::Engine;
use bottlers::key::PublicKey;

use crate::{Error, Result};

/// Fetch the wdrone fleet's decrypt public keys (Go `encrypt`'s RemoteKey arm:
/// GET `Crypto/WalletSign:keys` → parse each base64url IDCard → collect the
/// "decrypt"-purpose subkeys). These are the recipients a RemoteKey share is
/// sealed to before upload.
pub fn fetch_decrypt_keys(base: &str, client_id: Option<&str>) -> Result<Vec<PublicKey>> {
    let data = crate::rest::do_get_with_client_id(base, "Crypto/WalletSign:keys", client_id)?;
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

/// Upload a sealed RemoteKey share to the backend (Go `encrypt`'s
/// `Crypto/WalletSign:setGeneratedKey` POST). `data_cbor` is the CBOR bottle
/// (sealed to the fleet keys); `curve`/`protocol` are the on-wire vocabulary
/// wdrone's loadShare recognises ("ed25519"/"frost", "secp256k1"/"dkls23").
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
