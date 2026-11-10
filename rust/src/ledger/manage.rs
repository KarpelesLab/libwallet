//! Device management — firmware, apps, genuine check — for the browser build.
//!
//! These go through the vendor's manager API (the app catalog and firmware
//! metadata, over fetch) and its HSM secure channel (a WebSocket that drives
//! the device), both via `lsdk`'s `manager` feature. The device must be on the
//! dashboard, and asks the user to allow the "manager" before anything is
//! installed or removed. Long operations report through `ledger:progress`
//! events `{op, app?, type, progress?}`.

use lsdk::manager::ops::{FirmwareUpdate, Manager};
use lsdk::{Device, Transport};
use serde_json::{json, Value};

use crate::handlers::{ApiError, ApiResult};
use crate::Env;

use super::lerr;

fn to_json<T: serde::Serialize>(v: &T) -> ApiResult {
    serde_json::to_value(v).map_err(ApiError::internal)
}

/// Forward an HSM event to the host as a `ledger:progress` event. The raw
/// APDU exchanges are not forwarded.
fn progress(env: &Env, op: &str, app: Option<&str>, ev: &lsdk::hsm::HsmEvent) {
    use lsdk::hsm::HsmEvent;
    let (kind, extra) = match ev {
        HsmEvent::Opened => ("opened", json!({})),
        HsmEvent::PermissionRequested => ("permissionRequested", json!({})),
        HsmEvent::PermissionGranted => ("permissionGranted", json!({})),
        HsmEvent::Progress { .. } => ("progress", json!({ "progress": ev.progress() })),
        HsmEvent::Warning { message } => ("warning", json!({ "message": message })),
        _ => return,
    };
    let mut data = json!({ "op": op, "app": app, "type": kind });
    if let (Some(d), Some(e)) = (data.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    env.broadcast(&crate::response::event("ledger:progress", data));
}

/// `Ledger:status` — model, firmware and whether an update is available.
/// Needs the dashboard. While an update is in progress the device reports
/// `bootloader` / `updater` instead.
pub async fn status<T: Transport>(device: &Device<T>) -> ApiResult {
    let os = device.get_version().await.map_err(lerr)?;
    let mut out = json!({
        "model": os.model().map(|m| m.name()),
        "firmware": os.version(),
        "bootloader": os.is_bootloader,
        "updater": os.is_osu,
        "update": Value::Null,
    });
    if !os.is_bootloader {
        // No update information is not a failure of the status itself.
        match Manager::default().check_firmware_update(&os).await {
            Ok(Some(u)) => out["update"] = json!({ "version": u.final_firmware.name, "flashMcu": u.should_flash_mcu, "handle": to_json(&u)? }),
            Ok(None) => {}
            Err(e) => out["updateError"] = json!(e.to_string()),
        }
    }
    Ok(out)
}

/// `Ledger:apps` — the installed apps (the device asks the user to allow the
/// listing) with their catalog entries.
pub async fn apps<T: Transport>(device: &Device<T>) -> ApiResult {
    let list = Manager::default().installed_apps(device).await.map_err(lerr)?;
    Ok(Value::Array(
        list.iter()
            .map(|a| {
                json!({
                    "name": a.installed.name,
                    "blocks": a.installed.blocks,
                    "version": a.catalog.as_ref().map(|c| c.version.clone()),
                    "displayName": a.catalog.as_ref().and_then(|c| c.version_display_name.clone()),
                })
            })
            .collect(),
    ))
}

/// `Ledger:catalog` — the apps available for this device and firmware.
pub async fn catalog<T: Transport>(device: &Device<T>) -> ApiResult {
    let os = device.get_version().await.map_err(lerr)?;
    let list = Manager::default().catalog(&os).await.map_err(lerr)?;
    Ok(Value::Array(
        list.iter()
            .filter(|a| !a.is_dev_tools)
            .map(|a| {
                json!({
                    "name": a.version_name,
                    "displayName": a.version_display_name,
                    "version": a.version,
                    "description": a.description,
                    "bytes": a.bytes,
                    "requires": a.parent_name,
                })
            })
            .collect(),
    ))
}

/// `Ledger:installApp {Name}` — install an app and what it depends on.
pub async fn install_app<T: Transport>(env: &Env, device: &Device<T>, name: &str) -> ApiResult {
    Manager::default()
        .install_app_with_deps(device, name, None, &mut |app, ev| progress(env, "install", Some(app), &ev))
        .await
        .map_err(lerr)?;
    Ok(json!({ "installed": name }))
}

/// `Ledger:uninstallApp {Name}`.
pub async fn uninstall_app<T: Transport>(env: &Env, device: &Device<T>, name: &str) -> ApiResult {
    Manager::default().uninstall_app_by_name(device, name, &mut |ev| progress(env, "uninstall", Some(name), &ev)).await.map_err(lerr)?;
    Ok(json!({ "uninstalled": name }))
}

/// `Ledger:genuineCheck` — whether the vendor's HSM vouches for the device.
pub async fn genuine_check<T: Transport>(env: &Env, device: &Device<T>) -> ApiResult {
    let genuine = Manager::default().genuine_check(device, &mut |ev| progress(env, "genuine", None, &ev)).await.map_err(lerr)?;
    Ok(json!({ "genuine": genuine }))
}

fn update_param(params: &Value) -> Result<FirmwareUpdate, ApiError> {
    let handle = params.get("Update").cloned().ok_or_else(|| ApiError::new(400, "Update (the handle from Ledger:status) required"))?;
    serde_json::from_value(handle).map_err(|e| ApiError::new(400, format!("Update: {e}")))
}

/// `Ledger:firmwareUpdate {Update}` — step 1 of an update: install the OS
/// updater. The user confirms on the device, which then reboots.
pub async fn firmware_update<T: Transport>(env: &Env, device: &Device<T>, params: &Value) -> ApiResult {
    let update = update_param(params)?;
    Manager::default().install_osu(device, &update, &mut |ev| progress(env, "firmware", None, &ev)).await.map_err(lerr)?;
    Ok(json!({ "flashMcu": update.should_flash_mcu }))
}

/// `Ledger:firmwareFlash {Update?}` — with the device in bootloader mode,
/// flash the MCU or bootloader the firmware needs (repeat while it stays in
/// bootloader mode). Without `Update` (page reloaded, update interrupted) the
/// requirement is derived from what the bootloader reports.
pub async fn firmware_flash<T: Transport>(env: &Env, device: &Device<T>, params: &Value) -> ApiResult {
    let mut on_event = |ev| progress(env, "flash", None, &ev);
    let flashed = if params.get("Update").is_some_and(|u| !u.is_null()) {
        Some(Manager::default().flash_mcu(device, &update_param(params)?, &mut on_event).await.map_err(lerr)?)
    } else {
        Manager::default().repair_mcu(device, &mut on_event).await.map_err(lerr)?
    };
    Ok(json!({ "flashed": to_json(&flashed)? }))
}
