//! How messages reach the device.
//!
//! A [`Transport`] carries one message — an opcode and a payload — to the
//! device and brings back its reply (a status and a payload). Three links:
//!
//! - **hid** — the vendor HID interface over hidapi, on desktop (macOS / Linux
//!   / Windows): the message framed into 64-byte reports.
//! - **webhid** — the same reports over WebHID, in the browser (Chromium).
//! - **ccid** — the host carries APDUs to the device's smart-card reader: a
//!   phone cannot open the HID interface, but it can drive a class-compliant
//!   reader (CryptoTokenKit on iOS), whose card answers one APDU carrying a
//!   message. Each APDU is broadcast as a `catcard:apdu` event `{id, apdu}`
//!   (hex) and the host answers with `CatCard:apduResponse {Id, Data}` (hex,
//!   status word included) or `{Id, Error}` — the default on iOS / Android.
//! - **bridge** — the host carries the messages: each one is broadcast as a
//!   `catcard:packet` event `{id, packet}` (hex of `[u16 opcode][u32 length]
//!   [payload]`) and the host answers with `CatCard:packetResponse {Id, Data}`
//!   (hex of `[u16 status][u32 length][payload]`) or `{Id, Error}`, over
//!   whatever it has that reaches the device.
//!
//! Nothing secret crosses a link in the clear: everything that matters travels
//! sealed (see [`super::session`]), so the host relaying a bridge sees only
//! ciphertext.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use super::proto;
use crate::handlers::ApiError;
use crate::Env;

/// One message to the device, and its reply.
#[allow(async_fn_in_trait)]
pub trait Transport {
    async fn request(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError>;

    /// Names the device this link reaches, so a paired session is only ever
    /// reused on the link it was paired over.
    fn id(&self) -> String;
}

fn terr(m: impl std::fmt::Display) -> ApiError {
    ApiError::new(502, format!("catcard: {m}"))
}

// ── Answers the host owes us ─────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
type Sender<T> = std::sync::mpsc::Sender<T>;
#[cfg(target_arch = "wasm32")]
type Sender<T> = futures_channel::oneshot::Sender<T>;

/// Requests waiting for an answer from the host, by id: a bridged message
/// waiting for the device's reply, a pairing code waiting to be confirmed.
pub(crate) struct Waiters<T>(Mutex<Option<HashMap<String, Sender<T>>>>);

impl<T> Waiters<T> {
    pub(crate) const fn new() -> Self {
        Waiters(Mutex::new(None))
    }

    fn with<R>(&self, f: impl FnOnce(&mut HashMap<String, Sender<T>>) -> R) -> R {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(g.get_or_insert_with(HashMap::new))
    }

    /// Deliver the host's answer. False when nothing is waiting under `id`
    /// (unknown, answered already, or timed out).
    pub(crate) fn resolve(&self, id: &str, answer: T) -> bool {
        match self.with(|w| w.remove(id)) {
            Some(tx) => tx.send(answer).is_ok(),
            None => false,
        }
    }

    /// Register `id`, run `announce` (which tells the host), and wait up to
    /// `timeout_ms` for the answer. `None` when none came.
    ///
    /// Native requests each run on their own worker thread, so blocking it is
    /// what waiting for the host means; the browser awaits.
    pub(crate) async fn wait(&self, id: &str, timeout_ms: u32, announce: impl FnOnce()) -> Option<T> {
        #[cfg(not(target_arch = "wasm32"))]
        let (tx, rx) = std::sync::mpsc::channel();
        #[cfg(target_arch = "wasm32")]
        let (tx, rx) = futures_channel::oneshot::channel();
        self.with(|w| w.insert(id.to_owned(), tx));
        announce();

        #[cfg(not(target_arch = "wasm32"))]
        let got = rx.recv_timeout(std::time::Duration::from_millis(timeout_ms as u64)).ok();
        #[cfg(target_arch = "wasm32")]
        let got = {
            use futures_util::future::{select, Either};
            match select(rx, gloo_timers::future::TimeoutFuture::new(timeout_ms)).await {
                Either::Left((answer, _)) => answer.ok(),
                Either::Right(_) => None,
            }
        };
        self.with(|w| w.remove(id));
        got
    }
}

/// Pause between two polls of the device.
pub(crate) async fn sleep_ms(ms: u32) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::TimeoutFuture::new(ms).await;
}

// ── The host bridge ──────────────────────────────────────────────────────────

/// How long a bridged message waits for the host. The device answers every
/// message at once (a question for its owner is polled, not held), so this
/// only has to cover the host's own relay.
const BRIDGE_TIMEOUT_MS: u32 = 30_000;

type BridgeReply = std::result::Result<Vec<u8>, String>;

static BRIDGE_WAITERS: Waiters<BridgeReply> = Waiters::new();

/// Deliver the host's answer to a bridged message.
pub fn bridge_resolve(id: &str, reply: BridgeReply) -> bool {
    BRIDGE_WAITERS.resolve(id, reply)
}

/// The host-relayed link.
pub struct Bridge<'a> {
    env: &'a Env,
}

impl Transport for Bridge<'_> {
    async fn request(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
        let id = xuid::Xuid::new("pkt").to_string();
        let packet = hex(&proto::message(opcode, payload));
        let got = BRIDGE_WAITERS
            .wait(&id, BRIDGE_TIMEOUT_MS, || self.env.broadcast(&crate::response::event("catcard:packet", json!({ "id": id, "packet": packet }))))
            .await
            .ok_or_else(|| ApiError::new(408, "catcard: the host did not answer the catcard:packet event"))?;
        let reply = got.map_err(terr)?;
        let (status, body) = proto::parse_message(&reply).map_err(terr)?;
        Ok((status, body.to_vec()))
    }

    fn id(&self) -> String {
        "bridge".into()
    }
}

// ── The smart-card reader, through the host ─────────────────────────────────

static APDU_WAITERS: Waiters<BridgeReply> = Waiters::new();

/// Deliver the host's answer (the response APDU) to a relayed APDU.
pub fn apdu_resolve(id: &str, reply: BridgeReply) -> bool {
    APDU_WAITERS.resolve(id, reply)
}

/// Most GET RESPONSE pages one reply may take: every reply the firmware gives
/// is at most a few hundred bytes.
const MAX_PAGES: usize = 64;

/// The device's smart-card reader, each APDU relayed by the host.
pub struct Ccid<'a> {
    env: &'a Env,
    /// Short APDUs only (chunks of 255, replies paged by GET RESPONSE).
    short: bool,
}

impl Ccid<'_> {
    /// One APDU to the card: `(response data, status word)`.
    async fn transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16), ApiError> {
        let id = xuid::Xuid::new("apdu").to_string();
        let got = APDU_WAITERS
            .wait(&id, BRIDGE_TIMEOUT_MS, || self.env.broadcast(&crate::response::event("catcard:apdu", json!({ "id": id, "apdu": hex(apdu) }))))
            .await
            .ok_or_else(|| ApiError::new(408, "catcard: the host did not answer the catcard:apdu event"))?;
        let reply = got.map_err(terr)?;
        let (data, sw) = proto::apdu::response(&reply).map_err(terr)?;
        Ok((data.to_vec(), sw))
    }
}

impl Transport for Ccid<'_> {
    async fn request(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
        let commands = proto::apdu::commands(opcode, payload, self.short);
        let last = commands.len() - 1;
        let mut body = Vec::new();
        let mut sw = proto::apdu::SW_OK;
        for (i, command) in commands.iter().enumerate() {
            let (data, got) = self.transmit(command).await?;
            // A chunk that is not the last is answered with no data and 9000.
            if i < last && (got != proto::apdu::SW_OK || !data.is_empty()) {
                return Err(terr(if got == proto::apdu::SW_OK { "a chained APDU was answered with data".to_owned() } else { proto::apdu::refusal(got) }));
            }
            body = data;
            sw = got;
        }
        let mut pages = 0;
        while proto::apdu::more(sw) {
            pages += 1;
            if pages > MAX_PAGES {
                return Err(terr("the card's reply does not end"));
            }
            let (data, got) = self.transmit(&proto::apdu::get_response(self.short)).await?;
            body.extend_from_slice(&data);
            sw = got;
        }
        if sw != proto::apdu::SW_OK {
            return Err(terr(proto::apdu::refusal(sw)));
        }
        let (status, reply) = proto::parse_message(&body).map_err(terr)?;
        Ok((status, reply.to_vec()))
    }

    fn id(&self) -> String {
        "ccid".into()
    }
}

// ── USB HID (desktop) ────────────────────────────────────────────────────────

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub mod hid {
    use std::ffi::CString;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use hidapi::{HidApi, HidDevice};

    use super::{proto, terr, ApiError, Transport};

    /// How long the device has to answer one message. It never holds a reply
    /// for its owner — those are polled — so this is generous.
    const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

    fn api() -> Result<&'static Mutex<HidApi>, ApiError> {
        static API: OnceLock<Result<Mutex<HidApi>, String>> = OnceLock::new();
        API.get_or_init(|| HidApi::new().map(Mutex::new).map_err(|e| e.to_string())).as_ref().map_err(terr)
    }

    /// A CatCard found on the bus.
    #[derive(Debug, Clone)]
    pub struct HidInfo {
        /// Platform path: pass it back as `Device`.
        pub path: String,
        pub product: Option<String>,
        pub serial: Option<String>,
    }

    /// The vendor HID interface of every connected CatCard.
    pub fn list() -> Result<Vec<HidInfo>, ApiError> {
        let mut api = api()?.lock().map_err(|_| terr("hidapi poisoned"))?;
        api.refresh_devices().map_err(terr)?;
        let mut out: Vec<HidInfo> = Vec::new();
        for d in api.device_list() {
            if d.vendor_id() != proto::VENDOR_ID || d.product_id() != proto::PRODUCT_ID {
                continue;
            }
            // The device may also present a keyboard and a security key: keep
            // the vendor interface (the first one, where a backend does not
            // report usages).
            let vendor = d.usage_page() == proto::USAGE_PAGE || (d.usage_page() == 0 && d.interface_number() <= 0);
            let path = d.path().to_string_lossy().into_owned();
            if !vendor || out.iter().any(|o| o.path == path) {
                continue;
            }
            out.push(HidInfo { path, product: d.product_string().map(str::to_owned), serial: d.serial_number().map(str::to_owned) });
        }
        Ok(out)
    }

    /// An open vendor HID interface.
    pub struct HidLink {
        device: Mutex<HidDevice>,
        path: String,
    }

    impl HidLink {
        /// Open the device at `path` (from [`list`]), or the first one found.
        pub fn open(path: Option<&str>) -> Result<Self, ApiError> {
            let found = list()?;
            let info = match path {
                Some(p) => found.iter().find(|d| d.path == p).ok_or_else(|| ApiError::new(404, format!("no CatCard at {p}")))?,
                None => found.first().ok_or_else(|| ApiError::new(404, "no CatCard found (is it plugged in, and in its CatCard USB mode?)"))?,
            };
            let cpath = CString::new(info.path.clone()).map_err(|e| ApiError::new(400, e.to_string()))?;
            let api = api()?.lock().map_err(|_| terr("hidapi poisoned"))?;
            let device = api.open_path(&cpath).map_err(|e| {
                let m = e.to_string();
                if cfg!(target_os = "linux") && (m.contains("ermission") || m.contains("Failed to open")) {
                    terr(format!("{m}: no access to {}; add a udev rule for USB 39f2:0401 (see docs/catcard.md)", info.path))
                } else {
                    terr(m)
                }
            })?;
            Ok(HidLink { device: Mutex::new(device), path: info.path.clone() })
        }

        fn request_blocking(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
            let dev = self.device.lock().map_err(|_| terr("device mutex poisoned"))?;
            let mut buf = [0u8; proto::REPORT_LEN + 1];
            // Anything still queued belongs to an exchange nobody is waiting for.
            while dev.read_timeout(&mut buf, 0).map_err(terr)? > 0 {}
            for frame in proto::frames(opcode, payload) {
                // No report id is declared, so a zero leads every write.
                let mut report = [0u8; proto::REPORT_LEN + 1];
                report[1..].copy_from_slice(&frame);
                dev.write(&report).map_err(terr)?;
            }
            let mut reply = proto::Reassembler::new();
            let start = Instant::now();
            loop {
                let n = dev.read_timeout(&mut buf, 500).map_err(terr)?;
                if n == 0 {
                    if start.elapsed() > REPLY_TIMEOUT {
                        return Err(ApiError::new(408, "catcard: the device did not answer"));
                    }
                    continue;
                }
                if let Some(done) = reply.push(&buf[..n]).map_err(terr)? {
                    return Ok(done);
                }
            }
        }
    }

    impl Transport for HidLink {
        async fn request(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
            self.request_blocking(opcode, payload)
        }

        fn id(&self) -> String {
            format!("hid:{}", self.path)
        }
    }
}

// ── WebHID (browser) ─────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
pub mod webhid {
    use std::cell::RefCell;

    use futures_channel::mpsc::{unbounded, UnboundedReceiver};
    use futures_util::future::{select, Either};
    use futures_util::StreamExt;
    use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    use super::{proto, terr, ApiError, Transport};

    /// As the native link: the device answers every message at once.
    const REPLY_TIMEOUT_MS: u32 = 10_000;

    #[wasm_bindgen]
    extern "C" {
        /// The browser `HIDDevice` object.
        #[wasm_bindgen(js_name = HIDDevice)]
        #[derive(Clone, Debug)]
        pub type HidDevice;

        #[wasm_bindgen(method, getter)]
        fn opened(this: &HidDevice) -> bool;
        #[wasm_bindgen(method, getter, js_name = productId)]
        fn product_id(this: &HidDevice) -> u16;
        #[wasm_bindgen(method, getter, js_name = vendorId)]
        fn vendor_id(this: &HidDevice) -> u16;
        #[wasm_bindgen(method, getter, js_name = productName)]
        pub fn product_name(this: &HidDevice) -> String;
        #[wasm_bindgen(method, getter)]
        fn collections(this: &HidDevice) -> Array;
        #[wasm_bindgen(method)]
        fn open(this: &HidDevice) -> Promise;
        #[wasm_bindgen(method, js_name = sendReport)]
        fn send_report(this: &HidDevice, report_id: u8, data: &Uint8Array) -> Promise;
        #[wasm_bindgen(method, js_name = addEventListener)]
        fn add_event_listener(this: &HidDevice, kind: &str, cb: &js_sys::Function);
        #[wasm_bindgen(method, js_name = removeEventListener)]
        fn remove_event_listener(this: &HidDevice, kind: &str, cb: &js_sys::Function);
    }

    fn js_err(e: JsValue) -> ApiError {
        let msg = e.dyn_ref::<js_sys::Error>().map(|e| String::from(e.message())).or_else(|| e.as_string()).unwrap_or_else(|| format!("{e:?}"));
        terr(msg)
    }

    fn hid_object() -> Result<JsValue, ApiError> {
        let navigator = Reflect::get(&js_sys::global(), &"navigator".into()).map_err(js_err)?;
        let hid = Reflect::get(&navigator, &"hid".into()).map_err(js_err)?;
        if hid.is_undefined() || hid.is_null() {
            return Err(ApiError::new(501, "catcard: WebHID is not supported by this browser (use Chrome or Edge, over https)"));
        }
        Ok(hid)
    }

    async fn call_hid(method: &str, args: &Array) -> Result<Vec<HidDevice>, ApiError> {
        let hid = hid_object()?;
        let f: js_sys::Function = Reflect::get(&hid, &method.into()).map_err(js_err)?.dyn_into().map_err(js_err)?;
        let p: Promise = f.apply(&hid, args).map_err(js_err)?.dyn_into().map_err(js_err)?;
        let list: Array = JsFuture::from(p).await.map_err(js_err)?.dyn_into().map_err(js_err)?;
        Ok(list.iter().map(|d| d.unchecked_into::<HidDevice>()).collect())
    }

    /// Whether this `HIDDevice` is the vendor interface: the device may also
    /// present a keyboard and a security key, each its own `HIDDevice`.
    fn is_vendor_interface(d: &HidDevice) -> bool {
        d.vendor_id() == proto::VENDOR_ID
            && d.product_id() == proto::PRODUCT_ID
            && d.collections().iter().any(|c| Reflect::get(&c, &"usagePage".into()).ok().and_then(|v| v.as_f64()) == Some(proto::USAGE_PAGE as f64))
    }

    /// Open the browser's device picker. Requires a user gesture.
    pub async fn request_devices() -> Result<Vec<HidDevice>, ApiError> {
        let filter = Object::new();
        Reflect::set(&filter, &"vendorId".into(), &JsValue::from(proto::VENDOR_ID)).map_err(js_err)?;
        Reflect::set(&filter, &"productId".into(), &JsValue::from(proto::PRODUCT_ID)).map_err(js_err)?;
        Reflect::set(&filter, &"usagePage".into(), &JsValue::from(proto::USAGE_PAGE)).map_err(js_err)?;
        let opts = Object::new();
        Reflect::set(&opts, &"filters".into(), &Array::of1(&filter)).map_err(js_err)?;
        Ok(call_hid("requestDevice", &Array::of1(&opts)).await?.into_iter().filter(is_vendor_interface).collect())
    }

    /// The devices the user already granted this origin.
    pub async fn granted_devices() -> Result<Vec<HidDevice>, ApiError> {
        Ok(call_hid("getDevices", &Array::new()).await?.into_iter().filter(is_vendor_interface).collect())
    }

    /// An open vendor HID interface.
    pub struct WebHidLink {
        device: HidDevice,
        rx: RefCell<UnboundedReceiver<Vec<u8>>>,
        on_report: Closure<dyn FnMut(JsValue)>,
    }

    impl WebHidLink {
        /// `request`: show the picker; else the first already-granted device.
        pub async fn open(request: bool) -> Result<Self, ApiError> {
            let found = if request { request_devices().await? } else { granted_devices().await? };
            let device = found.into_iter().next().ok_or_else(|| ApiError::new(404, "no CatCard was selected or granted (pass Request: true from a click to show the picker)"))?;
            if !device.opened() {
                JsFuture::from(device.open()).await.map_err(js_err)?;
            }
            let (tx, rx) = unbounded();
            let on_report = Closure::<dyn FnMut(JsValue)>::new(move |ev: JsValue| {
                let Ok(data) = Reflect::get(&ev, &"data".into()) else { return };
                let Ok(view) = data.dyn_into::<js_sys::DataView>() else { return };
                let bytes = Uint8Array::new_with_byte_offset_and_length(&view.buffer(), view.byte_offset() as u32, view.byte_length() as u32).to_vec();
                let _ = tx.unbounded_send(bytes);
            });
            device.add_event_listener("inputreport", on_report.as_ref().unchecked_ref());
            Ok(WebHidLink { device, rx: RefCell::new(rx), on_report })
        }
    }

    // Dropping detaches the listener and leaves the device open: a session
    // paired over it is reused by the next request.
    impl Drop for WebHidLink {
        fn drop(&mut self) {
            self.device.remove_event_listener("inputreport", self.on_report.as_ref().unchecked_ref());
        }
    }

    impl Transport for WebHidLink {
        async fn request(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
            let mut rx = self.rx.try_borrow_mut().map_err(|_| ApiError::new(409, "catcard: another request is using this device"))?;
            // Anything still queued belongs to an exchange nobody is waiting for.
            while rx.try_recv().is_ok() {}
            for frame in proto::frames(opcode, payload) {
                JsFuture::from(self.device.send_report(0, &Uint8Array::from(&frame[..]))).await.map_err(js_err)?;
            }
            let mut reply = proto::Reassembler::new();
            loop {
                let report = match select(rx.next(), gloo_timers::future::TimeoutFuture::new(REPLY_TIMEOUT_MS)).await {
                    Either::Left((Some(report), _)) => report,
                    Either::Left((None, _)) => return Err(terr("the device went away")),
                    Either::Right(_) => return Err(ApiError::new(408, "catcard: the device did not answer")),
                };
                if let Some(done) = reply.push(&report).map_err(terr)? {
                    return Ok(done);
                }
            }
        }

        fn id(&self) -> String {
            "webhid".into()
        }
    }
}

// ── Opening a link ───────────────────────────────────────────────────────────

/// An open link to a device.
pub enum Link<'a> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    Hid(hid::HidLink),
    #[cfg(target_arch = "wasm32")]
    WebHid(webhid::WebHidLink),
    Ccid(Ccid<'a>),
    Bridge(Bridge<'a>),
}

impl Transport for Link<'_> {
    async fn request(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
        match self {
            #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
            Link::Hid(t) => t.request(opcode, payload).await,
            #[cfg(target_arch = "wasm32")]
            Link::WebHid(t) => t.request(opcode, payload).await,
            Link::Ccid(c) => c.request(opcode, payload).await,
            Link::Bridge(b) => b.request(opcode, payload).await,
        }
    }

    fn id(&self) -> String {
        match self {
            #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
            Link::Hid(t) => t.id(),
            #[cfg(target_arch = "wasm32")]
            Link::WebHid(t) => t.id(),
            Link::Ccid(c) => c.id(),
            Link::Bridge(b) => b.id(),
        }
    }
}

/// The transport used when the request names none: the built-in one where
/// there is one; elsewhere (iOS, Android) the device's smart-card reader,
/// relayed by the host — the one interface a phone can open.
pub fn default_kind() -> &'static str {
    if cfg!(target_arch = "wasm32") {
        "webhid"
    } else if cfg!(any(target_os = "macos", target_os = "linux", target_os = "windows")) {
        "hid"
    } else {
        "ccid"
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
    v.push("ccid");
    v.push("bridge");
    v
}

/// Open the link the request asks for: `Transport` (`hid` | `webhid` |
/// `ccid` | `bridge`, default per platform); `ShortApdu: true` keeps `ccid`
/// to short APDUs; `Device` picks a USB device by the path
/// `CatCard:list` returned; `Request: true` shows the browser's device picker
/// (WebHID — needs a user gesture) instead of reusing an already-granted device.
pub async fn open<'a>(env: &'a Env, params: &Value) -> Result<Link<'a>, ApiError> {
    let kind = params.get("Transport").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(default_kind());
    match kind {
        "bridge" => Ok(Link::Bridge(Bridge { env })),
        "ccid" => Ok(Link::Ccid(Ccid { env, short: params.get("ShortApdu").and_then(Value::as_bool) == Some(true) })),
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        "hid" => Ok(Link::Hid(hid::HidLink::open(params.get("Device").and_then(Value::as_str).filter(|s| !s.is_empty()))?)),
        #[cfg(target_arch = "wasm32")]
        "webhid" => Ok(Link::WebHid(webhid::WebHidLink::open(params.get("Request").and_then(Value::as_bool) == Some(true)).await?)),
        other => Err(ApiError::new(400, format!("CatCard transport {other:?} is not available here (available: {})", kinds().join(", ")))),
    }
}

/// The devices the built-in transport can see. Empty for the bridge-only
/// builds, where finding the device is the host's job.
pub async fn list() -> Result<Value, ApiError> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        return Ok(Value::Array(
            hid::list()?
                .iter()
                .map(|d| json!({ "transport": "hid", "path": d.path, "productId": proto::PRODUCT_ID, "product": d.product, "serial": d.serial }))
                .collect(),
        ));
    }
    #[cfg(target_arch = "wasm32")]
    {
        // Only devices the user already granted this origin; a new one needs
        // the picker (`Request: true`).
        return Ok(Value::Array(
            webhid::granted_devices()
                .await?
                .iter()
                .map(|d| json!({ "transport": "webhid", "productId": proto::PRODUCT_ID, "product": d.product_name() }))
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
