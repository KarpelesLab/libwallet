//! Endpoint routing. Each Go `pobj.RegisterStatic("Path:action", fn)` and
//! object CRUD registration becomes an arm here. As packages are ported their
//! handlers are added and this match grows toward the ~107 Go endpoints.

mod info;

use serde_json::Value;

use crate::handle::Handle;

/// Error returned by an endpoint handler. `code` mirrors the numeric HTTP-ish
/// codes the Go side used (400/404/500/503...).
pub struct ApiError {
    pub message: String,
    pub code: i64,
}

impl ApiError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        ApiError { message: message.into(), code }
    }

    pub fn not_found(path: &str) -> Self {
        ApiError::new(404, format!("unknown endpoint: {path}"))
    }
}

pub type ApiResult = Result<Value, ApiError>;

/// Route a request to its handler. `_verb`/`_params`/`_handle` are threaded
/// through for handlers that need them; Phase 0 only wires the Info endpoints.
pub fn route(handle: &Handle, path: &str, _verb: &str, _params: &Value) -> ApiResult {
    match path {
        "Info:ping" => info::ping(),
        "Info:version" => info::version(),
        "Info:paths" => info::paths(&handle.env),
        "Info:first_run" => info::first_run(&handle.env),
        _ => Err(ApiError::not_found(path)),
    }
}

impl ApiError {
    /// Wrap a wltbase error as a 500.
    pub fn internal(e: impl std::fmt::Display) -> Self {
        ApiError::new(500, e.to_string())
    }
}
