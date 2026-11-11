//! How APDUs reach the device.
//!
//! Three links, one [`lsdk::Transport`]:
//!
//! - **hid** — lsdk's USB HID transport, on desktop (macOS / Linux / Windows).
//! - **webhid** — lsdk's WebHID transport, in the browser (Chromium).
//! - **bridge** — the host carries the APDUs: every exchange is broadcast as a
//!   `ledger:apdu` event `{id, apdu}` (hex) and the host answers with
//!   `Ledger:apduResponse {Id, Data}` (hex, status word included) or
//!   `{Id, Error}`. This is what a mobile app uses for Bluetooth or USB-OTG,
//!   which the library has no transport of its own for.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::handlers::ApiError;
use crate::Env;

/// How long a bridged exchange waits for the host: long enough for the user to
/// review and approve a transaction on the device.
#[cfg(not(target_arch = "wasm32"))]
const BRIDGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

type BridgeReply = std::result::Result<Vec<u8>, String>;
#[cfg(not(target_arch = "wasm32"))]
type BridgeSender = std::sync::mpsc::Sender<BridgeReply>;
#[cfg(target_arch = "wasm32")]
type BridgeSender = futures_channel::oneshot::Sender<BridgeReply>;

/// Bridged exchanges awaiting the host's answer, by exchange id.
static BRIDGE_WAITERS: Mutex<Option<HashMap<String, BridgeSender>>> = Mutex::new(None);

fn waiters<R>(f: impl FnOnce(&mut HashMap<String, BridgeSender>) -> R) -> R {
    let mut g = BRIDGE_WAITERS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// Deliver the host's answer to a bridged exchange. False when nothing is
/// waiting under `id` (unknown, answered already, or timed out).
pub fn bridge_resolve(id: &str, reply: BridgeReply) -> bool {
    match waiters(|w| w.remove(id)) {
        Some(tx) => tx.send(reply).is_ok(),
        None => false,
    }
}

/// The host-relayed link.
pub struct Bridge<'a> {
    env: &'a Env,
}

impl Bridge<'_> {
    async fn exchange(&self, apdu: &[u8]) -> lsdk::Result<Vec<u8>> {
        let id = xuid::Xuid::new("apdu").to_string();
        #[cfg(not(target_arch = "wasm32"))]
        let (tx, rx) = std::sync::mpsc::channel();
        #[cfg(target_arch = "wasm32")]
        let (tx, rx) = futures_channel::oneshot::channel();
        waiters(|w| w.insert(id.clone(), tx));
        self.env.broadcast(&crate::response::event("ledger:apdu", json!({ "id": id, "apdu": hex(apdu) })));

        // Native requests each run on their own worker thread, so blocking it
        // here is what waiting for the host means; the browser awaits.
        #[cfg(not(target_arch = "wasm32"))]
        let got = rx.recv_timeout(BRIDGE_TIMEOUT).map_err(|_| lsdk::Error::Timeout);
        #[cfg(target_arch = "wasm32")]
        let got = rx.await.map_err(|_| lsdk::Error::Cancelled);

        waiters(|w| w.remove(&id));
        match got? {
            Ok(data) => Ok(data),
            Err(e) => Err(lsdk::Error::Transport(e)),
        }
    }
}

/// An open link to a device.
pub enum Link<'a> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    Hid(lsdk::transport::hid::HidTransport),
    #[cfg(target_arch = "wasm32")]
    WebHid(lsdk::transport::webhid::WebHidTransport),
    Bridge(Bridge<'a>),
}

impl lsdk::Transport for Link<'_> {
    async fn exchange(&self, apdu: &[u8]) -> lsdk::Result<Vec<u8>> {
        match self {
            #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
            Link::Hid(t) => t.exchange(apdu).await,
            #[cfg(target_arch = "wasm32")]
            Link::WebHid(t) => t.exchange(apdu).await,
            Link::Bridge(b) => b.exchange(apdu).await,
        }
    }
}

/// The transport used when the request names none: the built-in one where
/// there is one, the host bridge elsewhere (iOS, Android).
pub fn default_kind() -> &'static str {
    if cfg!(target_arch = "wasm32") {
        "webhid"
    } else if cfg!(any(target_os = "macos", target_os = "linux", target_os = "windows")) {
        "hid"
    } else {
        "bridge"
    }
}

/// The transports this build can open.
pub fn kinds() -> Vec<&'static str> {
    let mut v = Vec::new();
    if cfg!(target_arch = "wasm32") {
        v.push("webhid");
    } else if cfg!(any(target_os = "macos", target_os = "linux", target_os = "windows")) {
        v.push("hid");
    }
    v.push("bridge");
    v
}

/// Open the link the request asks for: `Transport` (`hid` | `webhid` |
/// `bridge`, default per platform); `Device` picks a USB device by the path
/// `Ledger:list` returned; `Request: true` shows the browser's device picker
/// (WebHID — needs a user gesture) instead of reusing an already-granted device.
pub async fn open<'a>(env: &'a Env, params: &Value) -> Result<Link<'a>, ApiError> {
    let kind = params.get("Transport").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(default_kind());
    match kind {
        "bridge" => Ok(Link::Bridge(Bridge { env })),
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        "hid" => {
            use lsdk::transport::hid::HidTransport;
            crate::rt::hid_init();
            let t = match params.get("Device").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(path) => {
                    let list = HidTransport::list().map_err(super::lerr)?;
                    let info = list.iter().find(|d| d.path == path).ok_or_else(|| ApiError::new(404, format!("no Ledger device at {path}")))?;
                    HidTransport::open(info)
                }
                None => HidTransport::open_first(),
            };
            Ok(Link::Hid(t.map_err(super::lerr)?))
        }
        #[cfg(target_arch = "wasm32")]
        "webhid" => {
            use lsdk::transport::webhid::WebHidTransport;
            let t = if params.get("Request").and_then(Value::as_bool) == Some(true) {
                WebHidTransport::request().await
            } else {
                WebHidTransport::open_granted().await
            };
            Ok(Link::WebHid(t.map_err(super::lerr)?))
        }
        other => Err(ApiError::new(400, format!("Ledger transport {other:?} is not available here (available: {})", kinds().join(", ")))),
    }
}

/// The devices the built-in transport can see. Empty for the bridge-only
/// builds, where finding the device is the host's job.
pub async fn list() -> Result<Value, ApiError> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        crate::rt::hid_init();
        let list = lsdk::transport::hid::HidTransport::list().map_err(super::lerr)?;
        return Ok(Value::Array(
            list.iter()
                .map(|d| {
                    json!({
                        "transport": "hid",
                        "path": d.path,
                        "productId": d.product_id,
                        "model": d.model.map(|m| m.name()),
                        "product": d.product,
                        "serial": d.serial,
                        "bootloader": d.bootloader,
                    })
                })
                .collect(),
        ));
    }
    #[cfg(target_arch = "wasm32")]
    {
        // Only devices the user already granted this origin; a new one needs
        // the picker (`Request: true`).
        let list = lsdk::transport::webhid::granted_devices().await.map_err(super::lerr)?;
        return Ok(Value::Array(
            list.iter()
                .map(|d| {
                    let pid = d.product_id();
                    json!({
                        "transport": "webhid",
                        "productId": pid,
                        "model": lsdk::DeviceModel::from_product_id(pid).map(|m| m.name()),
                        "product": d.product_name(),
                        "bootloader": lsdk::DeviceModel::is_bootloader_product_id(pid),
                    })
                })
                .collect(),
        ));
    }
    #[allow(unreachable_code)]
    Ok(json!([]))
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
