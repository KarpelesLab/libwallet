//! `CatCard:*` — CatCard hardware wallets (see [`crate::catcard`]).
//!
//! Every route that talks to the device takes the link to use: `Transport`
//! (`hid` on desktop, `webhid` in the browser, `ccid` or `bridge` anywhere —
//! the default is the built-in one where there is one, `ccid` on iOS and
//! Android), `Device` (a `CatCard:list` path) and, for WebHID, `Request: true`
//! to show the browser's device picker.
//!
//! The first route that needs the encrypted channel pairs it: a `catcard:pair`
//! event `{id, code}` carries the six-digit code the user must compare with
//! the device's screen, answered with `CatCard:pairResponse`. The session is
//! then reused by later requests until the device ends it.
//!
//!   CatCard:list                     → the devices the built-in transport sees
//!   CatCard:info                     → {board, firmware, unlocked, paired,
//!                                      hostInfo, …}
//!   CatCard:getKeys {Account?, Scripts?}
//!                                    → the keys the person shares on the
//!                                      device ({format, keys:[…]})
//!   CatCard:getKeys {Paths, Chain?, Format?}
//!                                    → the keys at those paths, each asked
//!                                      for on the device (later firmware)
//!   CatCard:import {Keys, Name?, Wallet?}
//!                                    → a `catcard` wallet + accounts (no device)
//!   CatCard:signTransaction {Account, Transaction, Network|RPC?, Offline?,
//!                            Broadcast?}
//!   CatCard:showAddress {Account}    → display + verify the address on the
//!                                      device (later firmware; 501 before)
//!   CatCard:signMessage {Account, Message (base64), Scheme?}
//!                                    → EIP-191 / BIP-137 / BIP-322 signature
//!                                      (later firmware; 501 before)
//!   CatCard:pairResponse {Id, Accept}
//!                                    → the user's answer to a `catcard:pair`
//!                                      event
//!   CatCard:disconnect               → end the paired session
//!   CatCard:apduResponse {Id, Data|Error}
//!                                    → the host's answer to a `catcard:apdu`
//!                                      event (ccid transport): the response
//!                                      APDU, status word included
//!   CatCard:packetResponse {Id, Data|Error}
//!                                    → the host's answer to a `catcard:packet`
//!                                      event (bridge transport)

use serde_json::{json, Value};

use crate::airgap::import::{self, DiscoveredKey, Export};
use crate::catcard::{self, session, transport};
use crate::Env;

use super::{ApiError, ApiResult};

fn str_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn account_param(params: &Value) -> Result<&str, ApiError> {
    str_param(params, "Account").or_else(|| str_param(params, "Id")).ok_or_else(|| ApiError::new(400, "Account required"))
}

/// Route a `CatCard:<action>` request. Async because the device (and, when
/// signing, the node) is: native drives it with `rt::block_on`, the browser
/// awaits it.
pub async fn route(env: &Env, action: &str, params: &Value) -> ApiResult {
    match action {
        "list" => Ok(json!({ "devices": transport::list().await?, "transports": transport::kinds(), "default": transport::default_kind() })),
        "packetResponse" => host_response(params, "packet", transport::bridge_resolve),
        "apduResponse" => host_response(params, "APDU", transport::apdu_resolve),
        "pairResponse" => pair_response(params),
        "import" => import_keys(env, params),
        "info" => catcard::info(&transport::open(env, params).await?).await,
        "disconnect" => {
            let link = transport::open(env, params).await?;
            Ok(json!({ "disconnected": session::disconnect(&link).await? }))
        }
        "getKeys" => {
            let query = catcard::KeyQuery::from_params(params)?;
            let link = transport::open(env, params).await?;
            let export = catcard::keys(env, &link, &query).await?;
            Ok(serde_json::to_value(export).map_err(ApiError::internal)?)
        }
        "showAddress" => {
            let (account, info) = catcard::load_account(env, account_param(params)?)?;
            let link = transport::open(env, params).await?;
            catcard::show_address(env, &link, &account, &info).await
        }
        "signMessage" => {
            use base64::Engine;
            let (account, info) = catcard::load_account(env, account_param(params)?)?;
            let message = str_param(params, "Message").ok_or_else(|| ApiError::new(400, "Message (base64) required"))?;
            let message = base64::engine::general_purpose::STANDARD.decode(message).map_err(|e| ApiError::new(400, format!("Message: {e}")))?;
            let link = transport::open(env, params).await?;
            catcard::sign_message(env, &link, &account, &info, &message, str_param(params, "Scheme")).await
        }
        "signTransaction" => {
            let (account, info) = catcard::load_account(env, account_param(params)?)?;
            let link = transport::open(env, params).await?;
            catcard::sign_transaction(env, &link, &account, &info, params).await
        }
        other => Err(ApiError::not_found(&format!("CatCard:{other}"))),
    }
}

/// The host's answer to a bridged message, or to a relayed APDU.
fn host_response(params: &Value, what: &str, resolve: fn(&str, Result<Vec<u8>, String>) -> bool) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id required"))?;
    let reply = match (str_param(params, "Error"), params.get("Data").and_then(Value::as_str)) {
        (Some(e), _) => Err(e.to_owned()),
        (None, Some(d)) => Ok(transport::unhex(d).ok_or_else(|| ApiError::new(400, "Data must be hex"))?),
        (None, None) => return Err(ApiError::new(400, "Data (hex) or Error required")),
    };
    if !resolve(id, reply) {
        return Err(ApiError::new(404, format!("no {what} {id} is waiting")));
    }
    Ok(json!({ "id": id }))
}

/// The user's answer to a pairing code: `Accept: true` only once they have
/// compared it with the code on the device's screen.
fn pair_response(params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id required"))?;
    let accept = params.get("Accept").and_then(Value::as_bool).ok_or_else(|| ApiError::new(400, "Accept (true or false) required"))?;
    if !session::pair_resolve(id, accept) {
        return Err(ApiError::new(404, format!("no pairing {id} is waiting")));
    }
    Ok(json!({ "id": id, "accepted": accept }))
}

/// Persist keys read with `CatCard:getKeys` as a CatCard wallet (or add them
/// to the `Wallet` given — the device shares one account at a time).
fn import_keys(env: &Env, params: &Value) -> ApiResult {
    let keys: Vec<DiscoveredKey> = params
        .get("Keys")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| ApiError::new(400, format!("Keys: {e}")))?
        .ok_or_else(|| ApiError::new(400, "Keys (from CatCard:getKeys) required"))?;
    let export = Export {
        format: "catcard".into(),
        master_fingerprint: str_param(params, "MasterFingerprint").map(str::to_owned).or_else(|| keys.iter().find_map(|k| k.master_fingerprint.clone())),
        device: Some("CatCard".into()),
        keys,
        ..Default::default()
    };
    let opts = import::ImportOptions {
        name: str_param(params, "Name").map(str::to_owned),
        select_paths: params.get("Select").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
        protocol: Some("catcard".into()),
        wallet: str_param(params, "Wallet").map(str::to_owned),
        ..Default::default()
    };
    let imported = import::import(env, &export, &opts).map_err(|e| ApiError::new(400, e.to_string()))?;
    if opts.wallet.is_none() {
        env.broadcast(&crate::response::event("wallet:created", json!({ "id": imported.wallet.id, "protocol": "catcard", "imported": true })));
    }
    Ok(serde_json::to_value(&imported).map_err(ApiError::internal)?)
}
