//! Request parsing + dispatch. Replaces the apirouter/pobj reflection layer
//! with a plain match on the path string (see `handlers::route`).

use std::cell::RefCell;

use serde::Deserialize;
use serde_json::Value;

use crate::handle::Handle;
use crate::handlers;
use crate::response;

thread_local! {
    /// Per-request progress sink. Each request runs on its own worker thread
    /// (see `LibwalletRequest`), so this thread-local is naturally scoped to a
    /// single in-flight request and never shared. Installed by
    /// [`with_progress_sink`]; consumed by [`emit_progress`]. `None` when the
    /// caller drives a handler directly (unit tests) or the request came in
    /// without a way to stream (in which case progress is silently dropped).
    static PROGRESS_SINK: RefCell<Option<Box<dyn Fn(f64)>>> = const { RefCell::new(None) };
}

/// Install `sink` as the current thread's progress sink for the duration of
/// `f`, restoring the previous value afterwards. `f` (and anything it calls,
/// e.g. a handler) can emit intermediate progress via [`emit_progress`]. The
/// FFI worker wraps `handle_request` with this so `emit_progress` forwards to
/// the request's response callback as `{"result":"progress",...}` envelopes.
pub fn with_progress_sink<R>(sink: Box<dyn Fn(f64)>, f: impl FnOnce() -> R) -> R {
    PROGRESS_SINK.with(|c| *c.borrow_mut() = Some(sink));
    let r = f();
    PROGRESS_SINK.with(|c| *c.borrow_mut() = None);
    r
}

/// Emit a progress update in `[0.0, 1.0]` on the current request's response
/// stream, if a sink is installed for this thread. A no-op otherwise, so
/// handlers and model code can call it unconditionally.
pub fn emit_progress(fraction: f64) {
    PROGRESS_SINK.with(|c| {
        if let Some(sink) = c.borrow().as_ref() {
            sink(fraction);
        }
    });
}

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    path: String,
    #[serde(default)]
    verb: String,
    #[serde(default)]
    params: Value,
}

/// Parse a raw request JSON string, route it, and return the response JSON
/// string ready to hand back over the callback. Never panics; all error paths
/// produce a well-formed error envelope.
pub fn handle_request(handle: &Handle, raw: &str) -> String {
    let req: Request = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => return response::error(&e.to_string(), 400),
    };

    let verb = if req.verb.is_empty() { "GET" } else { req.verb.as_str() };

    match handlers::route(handle, &req.path, verb, &req.params) {
        Ok(data) => response::success(data),
        Err(e) => response::error(&e.message, e.code),
    }
}

/// wasm async entry: mirrors [`handle_request`] but is `async` so browser
/// handlers that must `.await` network I/O (rsurl fetch, spot ceremonies)
/// can be dispatched from the Promise-returning `libwallet_request`. For now
/// it intercepts the create routes (whose RemoteKey uploads must `.await` the
/// browser Fetch API) and delegates everything else to the synchronous router.
#[cfg(target_arch = "wasm32")]
pub async fn handle_request_async(handle: &Handle, raw: &str) -> String {
    let req: Request = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => return response::error(&e.to_string(), 400),
    };
    let verb = if req.verb.is_empty() { "GET" } else { req.verb.as_str() };
    let out = match (req.path.as_str(), verb) {
        ("Wallet", "POST") => crate::handlers::wallet::create_async(&handle.env, &req.params).await,
        ("Wallet:multiCreate", _) => crate::handlers::wallet::multi_create_async(&handle.env, &req.params).await,
        ("RemoteKey:new", _) => crate::handlers::remotekey::new_async(&handle.env, &req.params).await,
        ("RemoteKey:reshare", _) => crate::handlers::remotekey::reshare_async(&handle.env, &req.params).await,
        ("RemoteKey:validate", _) => crate::handlers::remotekey::validate_async(&handle.env, &req.params).await,
        ("Wallet:initiateKeygen", _) => crate::handlers::spot_wasm::initiate_keygen_async(&handle.env, &req.params).await,
        ("Wallet:joinSign", _) => crate::handlers::spot_wasm::join_sign_async(&handle.env, &req.params).await,
        _ => return handle_request(handle, raw),
    };
    match out {
        Ok(d) => response::success(d),
        Err(e) => response::error(&e.message, e.code),
    }
}
