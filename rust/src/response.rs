//! Response envelope. Must match exactly what the Dart client expects
//! (`dart/lib/src/client/response.dart`): a JSON object with a `result`
//! field of "success" | "progress" | "event" | "error", plus `data` /
//! `error` / `code` as appropriate.

use serde_json::{json, Value};

pub fn success(data: Value) -> String {
    json!({ "result": "success", "data": data }).to_string()
}

pub fn error(message: &str, code: i64) -> String {
    json!({ "result": "error", "error": message, "code": code }).to_string()
}

/// A progress update (keeps the Dart response stream open). `fraction` is in
/// [0.0, 1.0]. Unused in Phase 0 but defined here so the sink has one place
/// to format from.
#[allow(dead_code)]
pub fn progress(fraction: f64) -> String {
    json!({ "result": "progress", "data": { "progress": fraction } }).to_string()
}

/// A broadcast event, delivered on the event channel rather than a request's
/// response stream. Shape matches `LibwalletEvent.fromJson`.
#[allow(dead_code)]
pub fn event(name: &str, data: Value) -> String {
    json!({ "result": "event", "event": name, "data": data }).to_string()
}
