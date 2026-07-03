//! Info endpoints — ports of `wltbase/info.go`.
//!
//! Build-time version metadata is injected via environment variables at
//! compile time (the Rust analogue of the Go `-ldflags -X` in the Makefile).
//! Empty strings — the default for dev builds — signal a non-release binary,
//! exactly like the Go side.

use serde_json::{json, Value};

use super::ApiResult;

const VERSION: &str = match option_env!("LIBWALLET_VERSION") {
    Some(v) => v,
    None => "",
};
const GIT_TAG: &str = match option_env!("LIBWALLET_GIT_TAG") {
    Some(v) => v,
    None => "",
};
const DATE_TAG: &str = match option_env!("LIBWALLET_DATE_TAG") {
    Some(v) => v,
    None => "",
};

/// `Info:ping` — liveness check. Returns the string "pong".
pub fn ping() -> ApiResult {
    Ok(json!("pong"))
}

/// `Info:version` — release version + commit SHA + commit date. Consumed by
/// `InfoApi.version()` / `versionInfo()` on the Dart side.
pub fn version() -> ApiResult {
    Ok(version_value())
}

fn version_value() -> Value {
    json!({
        "version": VERSION,
        "gitTag": GIT_TAG,
        "dateTag": DATE_TAG,
    })
}
