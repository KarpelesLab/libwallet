//! Placeholder until the platform backend lands: reports no secure storage,
//! so entries fall back to the password backend.

use super::SecureBackend;

pub(super) fn backend() -> Option<&'static dyn SecureBackend> {
    None
}
