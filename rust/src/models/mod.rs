//! Object models — ports of the Go `wlt*` object packages. Each module owns a
//! serde struct (JSON keys matching the Go tags), its table DDL, and the
//! fetch/list/create functions over the generic [`crate::Env`] query layer.

pub mod account;
// asset + transaction are fiat/RPC-heavy (live balances, price quotes) and are
// driven only by their native handlers — kept native-only until their
// networking is async-ported for the browser.
#[cfg(not(target_arch = "wasm32"))]
pub mod asset;
pub mod connected_site;
pub mod contact;
pub mod crash;
pub mod network;
pub mod nft;
pub mod request;
pub mod token;
#[cfg(not(target_arch = "wasm32"))]
pub mod transaction;
pub mod wallet;
pub mod wc_session;
