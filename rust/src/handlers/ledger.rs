//! `Ledger:*` — Ledger hardware wallets (see [`crate::ledger`]).
//!
//! Every route that talks to the device takes the link to use: `Transport`
//! (`hid` on desktop, `webhid` in the browser, `bridge` anywhere — the default
//! is the built-in one where there is one), `Device` (a `Ledger:list` path) and,
//! for WebHID, `Request: true` to show the browser's device picker.
//!
//!   Ledger:list                      → the devices the built-in transport sees
//!   Ledger:info                      → {app:{name,version}, dashboard, model?}
//!   Ledger:openApp {Name}            → open an app from the dashboard
//!   Ledger:getKeys {Account?, Count?, Scripts?, Paths?}
//!                                    → the open app's keys ({format, keys:[…]})
//!   Ledger:import {Keys, Name?, Wallet?}
//!                                    → a `ledger` wallet + accounts (no device)
//!   Ledger:showAddress {Account}     → display + verify the address on device
//!   Ledger:signMessage {Account, Message (base64)}
//!   Ledger:signTypedData {Account, TypedData (EIP-712 JSON)}
//!   Ledger:signTransaction {Account, Transaction, Network|RPC?, Offline?,
//!                           Broadcast?}
//!   Ledger:quitApp                   → back to the dashboard
//!   Ledger:status | apps | catalog | installApp {Name} | uninstallApp {Name}
//!     | genuineCheck | firmwareUpdate {Update} | firmwareFlash {Update?}
//!                                    → device management
//!   Ledger:apduResponse {Id, Data|Error}
//!                                    → the host's answer to a `ledger:apdu`
//!                                      event (bridge transport)

use serde_json::{json, Value};

use crate::airgap::import::{self, DiscoveredKey, Export};
use crate::ledger::{self, transport};
use crate::Env;

use super::{ApiError, ApiResult};

fn str_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn account_param(params: &Value) -> Result<&str, ApiError> {
    str_param(params, "Account").or_else(|| str_param(params, "Id")).ok_or_else(|| ApiError::new(400, "Account required"))
}

/// Route a `Ledger:<action>` request. Async because the device (and, when
/// signing, the node) is: native drives it with `rt::block_on`, the browser
/// awaits it.
pub async fn route(env: &Env, action: &str, params: &Value) -> ApiResult {
    match action {
        "list" => Ok(json!({ "devices": transport::list().await?, "transports": transport::kinds(), "default": transport::default_kind() })),
        "apduResponse" => apdu_response(params),
        "import" => import_keys(env, params),
        "info" => {
            let device = lsdk::Device::new(transport::open(env, params).await?);
            ledger::info(&device).await
        }
        "openApp" => {
            let name = str_param(params, "Name").ok_or_else(|| ApiError::new(400, "Name required"))?;
            let device = lsdk::Device::new(transport::open(env, params).await?);
            device.open_app(name).await.map_err(ledger::lerr)?;
            Ok(json!({ "opened": name }))
        }
        "getKeys" => {
            let query = ledger::KeyQuery::from_params(params)?;
            let device = lsdk::Device::new(transport::open(env, params).await?);
            let export = ledger::keys(env, &device, &query).await?;
            Ok(serde_json::to_value(export).map_err(ApiError::internal)?)
        }
        "showAddress" => {
            let (account, info) = ledger::load_account(env, account_param(params)?)?;
            let device = lsdk::Device::new(transport::open(env, params).await?);
            ledger::show_address(&device, &account, &info).await
        }
        "signMessage" => {
            use base64::Engine;
            let (account, info) = ledger::load_account(env, account_param(params)?)?;
            let message = str_param(params, "Message").ok_or_else(|| ApiError::new(400, "Message (base64) required"))?;
            let message = base64::engine::general_purpose::STANDARD.decode(message).map_err(|e| ApiError::new(400, format!("Message: {e}")))?;
            let device = lsdk::Device::new(transport::open(env, params).await?);
            ledger::sign_message(&device, &account, &info, &message).await
        }
        "signTypedData" => {
            let (account, info) = ledger::load_account(env, account_param(params)?)?;
            let typed = match params.get("TypedData") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                Some(td @ Value::Object(_)) => td.to_string(),
                _ => return Err(ApiError::new(400, "TypedData (the EIP-712 JSON) required")),
            };
            let device = lsdk::Device::new(transport::open(env, params).await?);
            ledger::sign_typed_data(&device, &account, &info, &typed).await
        }
        "signTransaction" => {
            let (account, info) = ledger::load_account(env, account_param(params)?)?;
            let device = lsdk::Device::new(transport::open(env, params).await?);
            ledger::sign_transaction(env, &device, &account, &info, params).await
        }
        "quitApp" => {
            let device = lsdk::Device::new(transport::open(env, params).await?);
            device.quit_app().await.map_err(ledger::lerr)?;
            Ok(json!({ "quit": true }))
        }
        // Device management (see ledger/manage.rs).
        "status" | "apps" | "catalog" | "installApp" | "uninstallApp" | "genuineCheck" | "firmwareUpdate" | "firmwareFlash" => {
            use ledger::manage;
            let name = || str_param(params, "Name").ok_or_else(|| ApiError::new(400, "Name required"));
            let device = lsdk::Device::new(transport::open(env, params).await?);
            match action {
                "status" => manage::status(&device).await,
                "apps" => manage::apps(&device).await,
                "catalog" => manage::catalog(&device).await,
                "installApp" => manage::install_app(env, &device, name()?).await,
                "uninstallApp" => manage::uninstall_app(env, &device, name()?).await,
                "genuineCheck" => manage::genuine_check(env, &device).await,
                "firmwareUpdate" => manage::firmware_update(env, &device, params).await,
                _ => manage::firmware_flash(env, &device, params).await,
            }
        }
        other => Err(ApiError::not_found(&format!("Ledger:{other}"))),
    }
}

/// The host's answer to a bridged APDU exchange.
fn apdu_response(params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id required"))?;
    let reply = match (str_param(params, "Error"), params.get("Data").and_then(Value::as_str)) {
        (Some(e), _) => Err(e.to_owned()),
        (None, Some(d)) => Ok(transport::unhex(d).ok_or_else(|| ApiError::new(400, "Data must be hex"))?),
        (None, None) => return Err(ApiError::new(400, "Data (hex) or Error required")),
    };
    if !transport::bridge_resolve(id, reply) {
        return Err(ApiError::new(404, format!("no APDU exchange {id} is waiting")));
    }
    Ok(json!({ "id": id }))
}

/// Persist keys read with `Ledger:getKeys` as a Ledger wallet (or add them to
/// the `Wallet` given — the device exports one app's keys at a time).
fn import_keys(env: &Env, params: &Value) -> ApiResult {
    let keys: Vec<DiscoveredKey> = params
        .get("Keys")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| ApiError::new(400, format!("Keys: {e}")))?
        .ok_or_else(|| ApiError::new(400, "Keys (from Ledger:getKeys) required"))?;
    let export = Export {
        format: "ledger".into(),
        master_fingerprint: str_param(params, "MasterFingerprint").map(str::to_owned).or_else(|| keys.iter().find_map(|k| k.master_fingerprint.clone())),
        device: Some("Ledger".into()),
        keys,
        ..Default::default()
    };
    let opts = import::ImportOptions {
        name: str_param(params, "Name").map(str::to_owned),
        select_paths: params.get("Select").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
        protocol: Some("ledger".into()),
        wallet: str_param(params, "Wallet").map(str::to_owned),
        ..Default::default()
    };
    let imported = import::import(env, &export, &opts).map_err(|e| ApiError::new(400, e.to_string()))?;
    if opts.wallet.is_none() {
        env.broadcast(&crate::response::event("wallet:created", json!({ "id": imported.wallet.id, "protocol": "ledger", "imported": true })));
    }
    Ok(serde_json::to_value(&imported).map_err(ApiError::internal)?)
}
