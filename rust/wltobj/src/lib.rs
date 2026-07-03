//! wltobj — core value types shared across libwallet (port of Go `wltobj`).

mod amount;
mod timeid;

pub use amount::{Amount, AmountError};
pub use timeid::{ParseTimeIdError, TimeId};
