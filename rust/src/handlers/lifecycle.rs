//! `Lifecycle:update` (port of wltbase/lifecycle.go). The host reports its app
//! lifecycle state so the library can pause/resume background work.

use serde_json::{json, Value};

use crate::Env;

use super::ApiResult;

/// `Lifecycle:update` {Status} — accept the host lifecycle status and echo it.
/// In Go this pauses the balance poller in `background`/`paused` and resumes it
/// on `foreground`/`resumed`/`active`; the poller isn't ported yet, so the
/// pause/resume is a no-op and only the echo contract is honored.
///
/// Leaving the foreground also locks the vault: every cached unsealed secret
/// is wiped, whatever its `CacheSeconds`.
pub fn update(_env: &Env, params: &Value) -> ApiResult {
    let status = params.get("Status").or_else(|| params.get("status")).and_then(Value::as_str).unwrap_or("");
    // Not "inactive": iOS reports that while the Face ID sheet is up (and
    // Android's system prompt can take focus too), so locking then would
    // cancel the very prompt the user is answering.
    if matches!(status.to_ascii_lowercase().as_str(), "background" | "paused" | "hidden" | "detached") {
        crate::vault::session::lock_all();
    }
    Ok(json!({ "status": status }))
}
