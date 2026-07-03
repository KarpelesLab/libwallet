//! wltbase — core environment + database layer (port of the Go `wltbase`).
//!
//! Exposes [`Env`], which owns the SQLite database (`sql.db`) and the
//! configuration/cache/current-selection accessors the rest of the library
//! builds on.

mod db;
mod env;
mod error;

pub use env::Env;
pub use error::{Error, Result};
