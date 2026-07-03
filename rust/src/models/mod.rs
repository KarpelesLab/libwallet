//! Object models — ports of the Go `wlt*` object packages. Each module owns a
//! serde struct (JSON keys matching the Go tags), its table DDL, and the
//! fetch/list/create functions over the generic [`crate::Env`] query layer.

pub mod account;
pub mod asset;
pub mod contact;
pub mod crash;
pub mod network;
pub mod wallet;
