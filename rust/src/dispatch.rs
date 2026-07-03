//! Request parsing + dispatch. Replaces the apirouter/pobj reflection layer
//! with a plain match on the path string (see `handlers::route`).

use serde::Deserialize;
use serde_json::Value;

use crate::handle::Handle;
use crate::handlers;
use crate::response;

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
