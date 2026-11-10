//! Device management: firmware, apps and the genuine check.
//!
//! These combine dashboard APDUs with two vendor services: the manager API
//! (the app catalog and firmware metadata, plain HTTPS) and the HSM "script
//! runner" (a WebSocket that opens a secure channel with the device and
//! streams the APDUs to run — the client only relays them). The device must be
//! on the dashboard, and asks the user to allow the "manager" before anything
//! is installed or removed.
//!
//! The logic follows `lsdk`'s `manager` module; it lives here, on `rsurl`'s
//! async HTTP + WebSocket client, so the native library and the browser build
//! run the same code without a second HTTP / TLS stack. Long operations report
//! through `ledger:progress` events `{op, app?, type, progress?}`.

use lsdk::apdu::{Response, StatusWord};
use lsdk::os::OsVersion;
use lsdk::{Device, Error, Transport};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use crate::handlers::{ApiError, ApiResult};
use crate::Env;

use super::lerr;

const API_BASE: &str = "https://manager.api.live.ledger.com/api";
const HSM_BASE: &str = "wss://scriptrunner.api.live.ledger.com/update";
/// What the HSM answers for a genuine device.
const GENUINE_RESULT: &str = "0000";
/// One manager API call.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

type Result<T> = std::result::Result<T, Error>;

// ── Manager API ──────────────────────────────────────────────────────────────

/// A device version (hardware family) as known by the API.
#[derive(Clone, Debug, Deserialize)]
struct DeviceVersion {
    id: u32,
}

/// A final (installed) secure element firmware.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalFirmware {
    pub id: u32,
    pub name: String,
    pub version: String,
    pub perso: String,
    #[serde(default)]
    pub mcu_versions: Vec<u32>,
}

/// An OS updater: the package that moves a device to a new final firmware.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsuFirmware {
    pub id: u32,
    pub name: String,
    pub perso: String,
    pub firmware: String,
    pub firmware_key: String,
    pub next_se_firmware_final_version: u32,
}

#[derive(Clone, Debug, Deserialize)]
struct McuVersion {
    id: u32,
    name: String,
    #[serde(default)]
    providers: Vec<u32>,
    #[serde(default)]
    from_bootloader_version: String,
}

/// An app in the catalog (v2 API).
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Application {
    /// App name, as reported by `LIST_APPS` once installed.
    version_name: String,
    #[serde(default)]
    version_display_name: Option<String>,
    version: String,
    #[serde(default)]
    description: Option<String>,
    hash: String,
    perso: String,
    firmware: String,
    firmware_key: String,
    delete: String,
    delete_key: String,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    is_dev_tools: bool,
    /// Name of the app this one depends on (e.g. Ethereum for plugins).
    #[serde(default)]
    parent_name: Option<String>,
}

#[derive(Deserialize)]
struct LatestFirmware {
    result: String,
    se_firmware_osu_version: Option<OsuFirmware>,
}

/// An available firmware update — the `handle` `Ledger:status` returns and
/// `Ledger:firmwareUpdate` / `Ledger:firmwareFlash` take back.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirmwareUpdate {
    pub osu: OsuFirmware,
    #[serde(rename = "final")]
    pub final_firmware: FinalFirmware,
    /// The MCU must be flashed after the updater (older models only).
    pub should_flash_mcu: bool,
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `base + path + ?k=v&…`, values percent-encoded.
fn build_url(base: &str, path: &str, params: &[(&str, &str)]) -> String {
    let mut url = format!("{}{}", base.trim_end_matches('/'), path);
    for (i, (k, v)) in params.iter().enumerate() {
        url.push(if i == 0 { '?' } else { '&' });
        url.push_str(&percent_encode(k));
        url.push('=');
        url.push_str(&percent_encode(v));
    }
    url
}

async fn http<T: DeserializeOwned>(req: rsurl::aio::Request, what: &str) -> Result<T> {
    let resp = crate::rpc::aio_send(&req.timeout(HTTP_TIMEOUT)).await.map_err(|e| Error::Http(format!("{what}: {e}")))?;
    if resp.status == 404 {
        return Err(Error::NotFound(what.to_owned()));
    }
    if !(200..300).contains(&resp.status) {
        return Err(Error::Http(format!("{what}: HTTP {}", resp.status)));
    }
    serde_json::from_slice(&resp.body).map_err(|e| Error::InvalidResponse(format!("{what}: {e}")))
}

async fn api_get<T: DeserializeOwned>(path: &str, query: &[(&str, &str)]) -> Result<T> {
    http(rsurl::aio::Request::get(build_url(API_BASE, path, query)), path).await
}

async fn device_version(target_id: u32, provider: u32) -> Result<DeviceVersion> {
    api_get("/get_device_version", &[("target_id", &target_id.to_string()), ("provider", &provider.to_string())]).await
}

async fn firmware_version(device_version: u32, version_name: &str, provider: u32) -> Result<FinalFirmware> {
    api_get(
        "/get_firmware_version",
        &[("device_version", &device_version.to_string()), ("version_name", version_name), ("provider", &provider.to_string())],
    )
    .await
}

async fn mcu_versions() -> Result<Vec<McuVersion>> {
    api_get("/mcu_versions", &[]).await
}

async fn catalog_for(os: &OsVersion) -> Result<Vec<Application>> {
    api_get(
        "/v2/apps/by-target",
        &[("target_id", &os.target_id.to_string()), ("provider", &os.provider_id().to_string()), ("firmware_version_name", &os.version())],
    )
    .await
}

/// The final firmware the device runs (absent while it is updating).
async fn current_firmware(os: &OsVersion) -> Result<FinalFirmware> {
    if os.is_osu || os.is_bootloader {
        return Err(Error::App("device is updating its firmware".into()));
    }
    let provider = os.provider_id();
    let dv = device_version(os.target_id, provider).await?;
    firmware_version(dv.id, &os.version(), provider).await
}

/// Whether a firmware update is available for the device.
async fn check_firmware_update(os: &OsVersion) -> Result<Option<FirmwareUpdate>> {
    if os.is_bootloader {
        return Err(Error::App("device is in bootloader mode: finish the update (flash the MCU) first".into()));
    }
    let provider = os.provider_id();
    let dv = device_version(os.target_id, provider).await?;
    let osu: Option<OsuFirmware> = if os.is_osu {
        Some(
            api_get(
                "/get_osu_version",
                &[("device_version", &dv.id.to_string()), ("version_name", &os.raw_version), ("provider", &provider.to_string())],
            )
            .await?,
        )
    } else {
        let current = firmware_version(dv.id, &os.version(), provider).await?;
        let r: LatestFirmware = api_get(
            "/get_latest_firmware",
            &[
                ("current_se_firmware_final_version", &current.id.to_string()),
                ("device_version", &dv.id.to_string()),
                ("provider", &provider.to_string()),
                // Firmware distribution salt (staged rollouts).
                ("salt", "0"),
            ],
        )
        .await?;
        match r.result.as_str() {
            "null" => None,
            "success" => r.se_firmware_osu_version,
            other => return Err(Error::Http(format!("get_latest_firmware: {other}"))),
        }
    };
    let Some(osu) = osu else { return Ok(None) };
    let final_firmware: FinalFirmware = api_get(&format!("/firmware_final_versions/{}", osu.next_se_firmware_final_version), &[]).await?;
    let mcus = mcu_versions().await?;
    let should_flash_mcu = match mcus.iter().find(|m| m.name == os.mcu_version()) {
        Some(current) => !final_firmware.mcu_versions.contains(&current.id),
        None if os.mcu_version().is_empty() => false,
        None => return Err(Error::NotFound(format!("unknown MCU version {:?}", os.mcu_version()))),
    };
    Ok(Some(FirmwareUpdate { osu, final_firmware, should_flash_mcu }))
}

// ── HSM secure channel ───────────────────────────────────────────────────────
//
// * `{"query":"exchange","nonce":n,"data":"<apdu hex>"}`: send the APDU, reply
//   `{"nonce":n,"response":"success"|"error","data":"<resp hex>"}`
// * `{"query":"bulk","data":["<apdu hex>",…]}`: close the socket and send
//   every APDU to the device
// * `{"query":"success","result":…}`: done, with an optional result
// * `{"query":"error","data":"…"}` / `{"query":"warning","data":"…"}`

#[cfg(not(target_arch = "wasm32"))]
type Socket = rsurl::aio::TokioWebSocket;
#[cfg(target_arch = "wasm32")]
type Socket = rsurl::aio::WebSocket;

async fn ws_connect(url: &str) -> Result<Socket> {
    #[cfg(not(target_arch = "wasm32"))]
    let ws = Socket::connect(&rsurl::aio::TokioRuntime, url).await;
    #[cfg(target_arch = "wasm32")]
    let ws = Socket::connect(url).await;
    ws.map_err(|e| Error::WebSocket(e.to_string()))
}

/// What a secure channel session reports while it runs.
enum HsmEvent {
    Opened,
    /// The device is asking the user to allow the secure channel.
    PermissionRequested,
    PermissionGranted,
    /// Bulk phase: `index` APDUs out of `total` sent.
    Progress { index: usize, total: usize },
    Warning(String),
}

#[derive(Deserialize)]
struct HsmMessage {
    query: String,
    #[serde(default)]
    nonce: Option<Value>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    result: Option<Value>,
}

/// A device status met during a secure channel session, as an error.
fn device_error(sw: StatusWord) -> Error {
    match sw.0 {
        _ if sw.is_refused() => Error::UserRefused,
        0x5515 => Error::Locked,
        0x6615 | 0x6616 => Error::App(format!(
            "the device refused a secure command ({sw}): make sure it is set up, unlocked (PIN entered) and on the dashboard, then retry"
        )),
        0x6a84 | 0x5102 => Error::App("not enough space on the device".into()),
        _ => Error::Status(sw),
    }
}

fn unhex(s: &str, what: &str) -> Result<Vec<u8>> {
    super::transport::unhex(s).ok_or_else(|| Error::Hsm(format!("bad {what} hex")))
}

/// Run a secure channel session at `url`, relaying APDUs to `transport`.
/// Returns the final `success` payload, or `None` after a bulk phase.
async fn hsm_run<T: Transport + ?Sized>(transport: &T, url: &str, on_event: &mut dyn FnMut(HsmEvent)) -> Result<Option<Value>> {
    let mut ws = ws_connect(url).await?;
    on_event(HsmEvent::Opened);
    // An error from the device is only fatal if the HSM hangs up right after.
    let mut pending_error: Option<Error> = None;
    loop {
        let text = match ws.recv().await {
            Some(Ok(m)) => String::from_utf8_lossy(m.as_bytes()).into_owned(),
            Some(Err(e)) if pending_error.is_none() => return Err(Error::WebSocket(e.to_string())),
            _ => return Err(pending_error.unwrap_or_else(|| Error::WebSocket("connection closed unexpectedly".into()))),
        };
        pending_error = None;
        let msg: HsmMessage = serde_json::from_str(&text).map_err(|e| Error::Hsm(format!("invalid message from HSM: {e}")))?;
        match msg.query.as_str() {
            "exchange" => {
                let apdu = unhex(msg.data.as_ref().and_then(Value::as_str).unwrap_or_default(), "APDU")?;
                if apdu.len() < 5 {
                    return Err(Error::Hsm("invalid APDU from HSM".into()));
                }
                let asks_permission = apdu[0] == 0xe0 && apdu[1] == 0x51;
                if asks_permission {
                    on_event(HsmEvent::PermissionRequested);
                }
                let resp = Response::from_raw(transport.exchange(&apdu).await?)?;
                let response = match resp.sw {
                    StatusWord::OK => "success",
                    StatusWord::LOCKED_DEVICE => return Err(Error::Locked),
                    sw if asks_permission && sw.is_refused() => return Err(Error::UserRefused),
                    sw => {
                        pending_error = Some(device_error(sw));
                        "error"
                    }
                };
                if asks_permission && resp.sw.is_ok() {
                    on_event(HsmEvent::PermissionGranted);
                }
                let reply = json!({ "nonce": msg.nonce.unwrap_or(Value::Null), "response": response, "data": super::transport::hex(&resp.data) });
                ws.send_text(&reply.to_string()).await.map_err(|e| Error::WebSocket(e.to_string()))?;
            }
            "bulk" => {
                let _ = ws.close().await;
                let list: Vec<Vec<u8>> = msg
                    .data
                    .as_ref()
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::Hsm("invalid bulk payload".into()))?
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(|s| unhex(s, "bulk APDU"))
                    .collect::<Result<_>>()?;
                let total = list.len();
                on_event(HsmEvent::Progress { index: 0, total });
                for (i, apdu) in list.iter().enumerate() {
                    let resp = Response::from_raw(transport.exchange(apdu).await?)?;
                    if !resp.sw.is_ok() {
                        return Err(device_error(resp.sw));
                    }
                    on_event(HsmEvent::Progress { index: i + 1, total });
                }
                return Ok(None);
            }
            "success" => {
                let _ = ws.close().await;
                return Ok(msg.result.or(msg.data).filter(|v| !v.is_null()));
            }
            "error" => {
                let _ = ws.close().await;
                let data = msg.data.map(|v| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string()));
                return Err(Error::Hsm(data.unwrap_or_else(|| "unknown error".into())));
            }
            "warning" => {
                let data = msg.data.map(|v| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string()));
                on_event(HsmEvent::Warning(data.unwrap_or_default()));
            }
            _ => {}
        }
    }
}

// ── Operations ───────────────────────────────────────────────────────────────

fn to_json<T: Serialize>(v: &T) -> ApiResult {
    serde_json::to_value(v).map_err(ApiError::internal)
}

/// Forward a secure-channel event to the host as a `ledger:progress` event.
fn progress(env: &Env, op: &str, app: Option<&str>, ev: HsmEvent) {
    let mut data = json!({ "op": op, "app": app });
    match ev {
        HsmEvent::Opened => data["type"] = json!("opened"),
        HsmEvent::PermissionRequested => data["type"] = json!("permissionRequested"),
        HsmEvent::PermissionGranted => data["type"] = json!("permissionGranted"),
        HsmEvent::Progress { index, total } => {
            data["type"] = json!("progress");
            data["progress"] = json!(if total > 0 { index as f64 / total as f64 } else { 1.0 });
        }
        HsmEvent::Warning(message) => {
            data["type"] = json!("warning");
            data["message"] = json!(message);
        }
    }
    env.broadcast(&crate::response::event("ledger:progress", data));
}

async fn ensure_dashboard<T: Transport>(device: &Device<T>) -> Result<()> {
    if device.is_on_dashboard().await? {
        Ok(())
    } else {
        Err(Error::DashboardExpected)
    }
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
        match check_firmware_update(&os).await {
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
    let installed = device.list_apps().await.map_err(lerr)?;
    let mut meta: Vec<Option<Application>> = Vec::new();
    if !installed.is_empty() {
        let hashes: Vec<&str> = installed.iter().map(|a| a.hash.as_str()).collect();
        let body = serde_json::to_vec(&hashes).map_err(ApiError::internal)?;
        let req = rsurl::aio::Request::post(format!("{API_BASE}/v2/apps/hash"), body).header("Content-Type", "application/json");
        // The catalog entries only add version / display name.
        meta = http(req, "/v2/apps/hash").await.unwrap_or_default();
    }
    Ok(Value::Array(
        installed
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let c = meta.get(i).and_then(Option::as_ref);
                json!({
                    "name": a.name,
                    "blocks": a.blocks,
                    "version": c.map(|c| c.version.clone()),
                    "displayName": c.and_then(|c| c.version_display_name.clone()),
                })
            })
            .collect(),
    ))
}

/// `Ledger:catalog` — the apps available for this device and firmware.
pub async fn catalog<T: Transport>(device: &Device<T>) -> ApiResult {
    let os = device.get_version().await.map_err(lerr)?;
    let list = catalog_for(&os).await.map_err(lerr)?;
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

/// Statuses returned when installing an app that is already installed.
fn is_already_installed(sw: StatusWord) -> bool {
    matches!(sw.0, 0x6a80 | 0x6a81 | 0x6a8e | 0x6a8f)
}

async fn install_one<T: Transport>(env: &Env, device: &Device<T>, os: &OsVersion, app: &Application) -> Result<()> {
    let url = build_url(
        HSM_BASE,
        "/install",
        &[
            ("targetId", &os.target_id.to_string()),
            ("perso", &app.perso),
            ("deleteKey", &app.delete_key),
            ("firmware", &app.firmware),
            ("firmwareKey", &app.firmware_key),
            ("hash", &app.hash),
        ],
    );
    match hsm_run(device.transport(), &url, &mut |ev| progress(env, "install", Some(&app.version_name), ev)).await {
        Ok(_) => Ok(()),
        Err(Error::Status(sw)) if sw.0 == 0x6a83 || sw.0 == 0x6811 => Err(Error::App(format!(
            "{} requires {} to be installed first",
            app.version_name,
            app.parent_name.as_deref().unwrap_or("another app")
        ))),
        Err(Error::Status(sw)) if sw.0 == 0x6a84 || sw.0 == 0x5102 => Err(Error::App("not enough space on the device".into())),
        Err(e) => Err(e),
    }
}

/// `Ledger:installApp {Name}` — install an app, and first the app it depends
/// on (a parent that is already there is not an error).
pub async fn install_app<T: Transport>(env: &Env, device: &Device<T>, name: &str) -> ApiResult {
    let run = async {
        ensure_dashboard(device).await?;
        let os = device.get_version().await?;
        let catalog = catalog_for(&os).await?;
        let find = |n: &str| {
            catalog
                .iter()
                .find(|a| a.version_name.eq_ignore_ascii_case(n))
                .ok_or_else(|| Error::NotFound(format!("app {n:?} is not available for this device")))
        };
        let app = find(name)?;
        if let Some(parent) = app.parent_name.as_deref() {
            match install_one(env, device, &os, find(parent)?).await {
                Ok(()) => {}
                Err(Error::Status(sw)) if is_already_installed(sw) => {}
                Err(e) => return Err(e),
            }
        }
        install_one(env, device, &os, app).await?;
        Ok(app.version_name.clone())
    };
    Ok(json!({ "installed": run.await.map_err(lerr)? }))
}

/// `Ledger:uninstallApp {Name}` — by its catalog entry (no app listing, which
/// would need the user's approval).
pub async fn uninstall_app<T: Transport>(env: &Env, device: &Device<T>, name: &str) -> ApiResult {
    let run = async {
        ensure_dashboard(device).await?;
        let os = device.get_version().await?;
        let app = catalog_for(&os)
            .await?
            .into_iter()
            .find(|a| a.version_name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::NotFound(format!("no catalog entry for {name:?}")))?;
        let url = build_url(
            HSM_BASE,
            "/install",
            &[
                ("targetId", &os.target_id.to_string()),
                ("perso", &app.perso),
                ("deleteKey", &app.delete_key),
                ("firmware", &app.delete),
                ("firmwareKey", &app.delete_key),
                ("hash", &app.hash),
            ],
        );
        match hsm_run(device.transport(), &url, &mut |ev| progress(env, "uninstall", Some(&app.version_name), ev)).await {
            Ok(_) => Ok(app.version_name),
            Err(Error::Status(sw)) if sw.0 == 0x6a83 => Err(Error::App(format!("other apps depend on {}, uninstall them first", app.version_name))),
            Err(e) => Err(e),
        }
    };
    Ok(json!({ "uninstalled": run.await.map_err(lerr)? }))
}

/// `Ledger:genuineCheck` — whether the vendor's HSM vouches for the device.
/// The user has to allow the secure channel on the device.
pub async fn genuine_check<T: Transport>(env: &Env, device: &Device<T>) -> ApiResult {
    let run = async {
        ensure_dashboard(device).await?;
        let os = device.get_version().await?;
        let fw = current_firmware(&os).await?;
        let url = build_url(HSM_BASE, "/genuine", &[("targetId", &os.target_id.to_string()), ("perso", &fw.perso)]);
        let out = hsm_run(device.transport(), &url, &mut |ev| progress(env, "genuine", None, ev)).await?;
        Ok(out.as_ref().and_then(Value::as_str) == Some(GENUINE_RESULT))
    };
    Ok(json!({ "genuine": run.await.map_err(lerr)? }))
}

fn update_param(params: &Value) -> std::result::Result<FirmwareUpdate, ApiError> {
    let handle = params.get("Update").cloned().ok_or_else(|| ApiError::new(400, "Update (the handle from Ledger:status) required"))?;
    serde_json::from_value(handle).map_err(|e| ApiError::new(400, format!("Update: {e}")))
}

/// `Ledger:firmwareUpdate {Update}` — step 1 of an update: install the OS
/// updater. The user confirms on the device, which then reboots (losing the
/// link at the end is expected).
pub async fn firmware_update<T: Transport>(env: &Env, device: &Device<T>, params: &Value) -> ApiResult {
    let update = update_param(params)?;
    let run = async {
        let os = device.get_version().await?;
        if os.is_bootloader {
            return Err(Error::App("device is in bootloader mode, flash the MCU instead".into()));
        }
        let url = build_url(
            HSM_BASE,
            "/install",
            &[
                ("targetId", &os.target_id.to_string()),
                ("perso", &update.osu.perso),
                ("firmware", &update.osu.firmware),
                ("firmwareKey", &update.osu.firmware_key),
            ],
        );
        match hsm_run(device.transport(), &url, &mut |ev| progress(env, "firmware", None, ev)).await {
            Ok(_) | Err(Error::Disconnected) => Ok(()),
            Err(e) => Err(e),
        }
    };
    run.await.map_err(lerr)?;
    Ok(json!({ "flashMcu": update.should_flash_mcu }))
}

/// Flash the MCU or the bootloader `final_firmware` needs. Returns which.
async fn flash_for<T: Transport>(env: &Env, device: &Device<T>, os: &OsVersion, final_firmware: &FinalFirmware) -> Result<&'static str> {
    let provider = os.provider_id();
    let candidates: Vec<McuVersion> = mcu_versions()
        .await?
        .into_iter()
        .filter(|m| m.providers.contains(&provider) && m.from_bootloader_version != "none" && final_firmware.mcu_versions.contains(&m.id))
        .collect();
    let mcu = candidates.iter().max_by_key(|m| lsdk::model::parse_version(&m.name)).ok_or_else(|| Error::NotFound("no suitable MCU version".into()))?;
    let bootloader_version = mcu.from_bootloader_version.split('.').take(3).collect::<Vec<_>>().join(".");
    let is_mcu = os.maj_min() == bootloader_version;
    let version = if is_mcu { mcu.name.clone() } else { bootloader_version };
    let url = build_url(HSM_BASE, "/mcu", &[("targetId", &os.target_id.to_string()), ("version", &version)]);
    match hsm_run(device.transport(), &url, &mut |ev| progress(env, "flash", None, ev)).await {
        Ok(_) | Err(Error::Disconnected) => Ok(if is_mcu { "mcu" } else { "bootloader" }),
        Err(e) => Err(e),
    }
}

/// `Ledger:firmwareFlash {Update?}` — with the device in bootloader mode,
/// flash the MCU or bootloader the firmware needs (repeat, reopening the
/// device, while it stays in bootloader mode). Without `Update` (the update
/// was interrupted) the requirement is derived from what the bootloader
/// reports. `flashed` is null when the device is not in bootloader mode.
pub async fn firmware_flash<T: Transport>(env: &Env, device: &Device<T>, params: &Value) -> ApiResult {
    let update = if params.get("Update").is_some_and(|u| !u.is_null()) { Some(update_param(params)?) } else { None };
    let run = async {
        let os = device.get_version().await?;
        if !os.is_bootloader {
            return match update {
                Some(_) => Err(Error::App("device is not in bootloader mode".into())),
                None => Ok(None),
            };
        }
        let final_firmware = match update {
            Some(u) => u.final_firmware,
            None => {
                let (Some(se_target), false) = (os.se_target_id, os.se_version.is_empty()) else {
                    return Err(Error::App("the bootloader does not report the installed firmware; cannot pick an MCU version".into()));
                };
                let provider = os.provider_id();
                let dv = device_version(se_target, provider).await?;
                firmware_version(dv.id, &os.se_version, provider).await?
            }
        };
        flash_for(env, device, &os, &final_firmware).await.map(Some)
    };
    Ok(json!({ "flashed": run.await.map_err(lerr)? }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsm_url_is_percent_encoded() {
        let u = build_url(HSM_BASE, "/install", &[("targetId", "856686596"), ("firmware", "nanos+/1.4.1/app 1")]);
        assert_eq!(u, "wss://scriptrunner.api.live.ledger.com/update/install?targetId=856686596&firmware=nanos%2B%2F1.4.1%2Fapp%201");
    }

    /// Live check of the manager API shapes (network; run with `--ignored`).
    #[test]
    #[ignore]
    fn manager_api_answers_parse() {
        crate::rt::block_on(async {
            // Nano S Plus.
            let dv = device_version(0x3310_0004, 1).await.unwrap();
            let fw = firmware_version(dv.id, "1.4.1", 1).await.unwrap();
            assert!(!fw.perso.is_empty());
            assert!(!mcu_versions().await.unwrap().is_empty());
            let apps: Vec<Application> = api_get("/v2/apps/by-target", &[("target_id", "856686596"), ("provider", "1"), ("firmware_version_name", "1.4.1")]).await.unwrap();
            assert!(apps.iter().any(|a| a.version_name == "Bitcoin"), "{} apps", apps.len());
            let r: LatestFirmware = api_get(
                "/get_latest_firmware",
                &[("current_se_firmware_final_version", &fw.id.to_string()), ("device_version", &dv.id.to_string()), ("provider", "1"), ("salt", "0")],
            )
            .await
            .unwrap();
            assert!(matches!(r.result.as_str(), "null" | "success"), "{}", r.result);
        });
    }

    #[test]
    fn update_handle_round_trips() {
        let u = FirmwareUpdate {
            osu: OsuFirmware { id: 1, name: "1.5.0-osu".into(), perso: "p".into(), firmware: "f".into(), firmware_key: "k".into(), next_se_firmware_final_version: 9 },
            final_firmware: FinalFirmware { id: 9, name: "1.5.0".into(), version: "1.5.0".into(), perso: "p".into(), mcu_versions: vec![3] },
            should_flash_mcu: true,
        };
        let back = update_param(&json!({ "Update": serde_json::to_value(&u).unwrap() })).unwrap();
        assert_eq!(back.final_firmware.name, "1.5.0");
        assert!(back.should_flash_mcu);
        assert!(update_param(&json!({})).is_err());
        assert!(update_param(&json!({ "Update": { "osu": 1 } })).is_err());
    }
}
