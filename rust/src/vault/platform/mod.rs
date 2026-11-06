//! Platform secure storage behind the vault's `secure` backend.
//!
//! A backend never sees the entry's secret. It owns one non-exportable key per
//! entry (Secure Enclave / Keychain / Android Keystore) and does exactly two
//! things with it: produce a fresh 32-byte data-encryption key together with
//! a wrapped form of it to store ([`SecureBackend::seal_key`]), and release
//! that key again from its wrapped form ([`SecureBackend::open_key`]) — the
//! step where the OS shows Face ID / Touch ID / fingerprint / passcode when
//! the entry's policy requires user presence. All symmetric crypto on the
//! secret itself stays in Rust ([`super::blob`]).

use purecrypto::zeroize::Zeroizing;

use super::Policy;

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple;
#[cfg(target_os = "android")]
mod android;

/// What the device offers, for `Vault:capabilities`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Capabilities {
    /// A `secure` entry can be created here.
    #[serde(rename = "Secure")]
    pub secure: bool,
    /// The keys live in dedicated hardware (Secure Enclave, StrongBox/TEE).
    #[serde(rename = "Hardware")]
    pub hardware: bool,
    /// The user-presence check the OS will show: "faceID", "touchID",
    /// "opticID", "biometric", "passcode" or "none".
    #[serde(rename = "Biometry")]
    pub biometry: String,
    /// Backend id stored with each entry ("apple-se", "apple-keychain",
    /// "android-keystore"), empty when unsupported.
    #[serde(rename = "Provider")]
    pub provider: String,
    /// Why `Secure` is false, when it is.
    #[serde(rename = "Reason", skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

pub trait SecureBackend: Send + Sync {
    /// The provider id written into each envelope.
    fn provider(&self) -> &str;
    fn capabilities(&self) -> Capabilities;
    /// Create the entry's platform key under `policy` and return a fresh dek
    /// plus the bytes [`open_key`](Self::open_key) needs to release it.
    fn seal_key(&self, entry_id: &str, policy: &Policy) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), String>;
    /// Release the dek; `reason` is the text shown in the OS prompt.
    fn open_key(&self, entry_id: &str, wrapped: &[u8], reason: &str) -> Result<Zeroizing<[u8; 32]>, String>;
    /// Destroy the entry's platform key (idempotent).
    fn delete_key(&self, entry_id: &str) -> Result<(), String>;
    /// Dismiss any authentication prompt this backend has on screen (the
    /// vault was locked). The waiting caller then fails with "user
    /// cancelled". The OS does this itself on Apple when the app leaves the
    /// foreground.
    fn cancel_prompts(&self) {}
}

/// The real backend for this build, or None where the platform has none
/// (Linux, Windows, wasm: use the `password` backend there).
fn native() -> Option<&'static dyn SecureBackend> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        return apple::backend();
    }
    #[cfg(target_os = "android")]
    {
        return android::backend();
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(test)]
thread_local! {
    static TEST_BACKEND: std::cell::Cell<Option<&'static dyn SecureBackend>> = const { std::cell::Cell::new(None) };
}

/// Install a backend for this test thread (tests only).
#[cfg(test)]
pub(crate) fn set_test_backend(b: Option<&'static dyn SecureBackend>) {
    TEST_BACKEND.with(|c| c.set(b));
}

pub(crate) fn backend() -> Option<&'static dyn SecureBackend> {
    #[cfg(test)]
    if let Some(b) = TEST_BACKEND.with(|c| c.get()) {
        return Some(b);
    }
    native()
}

/// The backend that sealed an envelope, by its provider id. Envelopes from a
/// different provider (a restored backup from another OS) cannot be opened.
pub(crate) fn backend_for(provider: &str) -> Result<&'static dyn SecureBackend, String> {
    match backend() {
        Some(b) if b.provider() == provider => Ok(b),
        Some(b) if provider.starts_with("apple-") && b.provider().starts_with("apple-") => Ok(b),
        _ => Err(format!("this vault entry is bound to {provider} storage, which is not available on this device")),
    }
}

pub fn capabilities() -> Capabilities {
    match backend() {
        Some(b) => b.capabilities(),
        None => Capabilities {
            secure: false,
            hardware: false,
            biometry: "none".into(),
            provider: String::new(),
            reason: "no platform secure storage in this build; use the password backend".into(),
        },
    }
}

/// An in-memory backend for unit tests: keys live in a map, `open_key` can be
/// told to fail (a cancelled prompt) and counts its prompts.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct MemoryBackend {
        keys: Mutex<HashMap<String, [u8; 32]>>,
        pub prompts: AtomicUsize,
        pub cancel: AtomicBool,
    }

    impl MemoryBackend {
        pub fn leak() -> &'static MemoryBackend {
            Box::leak(Box::default())
        }
    }

    impl SecureBackend for MemoryBackend {
        fn provider(&self) -> &str {
            "test-memory"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities { secure: true, hardware: false, biometry: "none".into(), provider: "test-memory".into(), reason: String::new() }
        }
        fn seal_key(&self, entry_id: &str, _policy: &Policy) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), String> {
            use purecrypto::rng::RngCore;
            let mut k = [0u8; 32];
            purecrypto::rng::OsRng.fill_bytes(&mut k);
            self.keys.lock().unwrap().insert(entry_id.to_owned(), k);
            Ok((Zeroizing::new(k), b"memory".to_vec()))
        }
        fn open_key(&self, entry_id: &str, _wrapped: &[u8], _reason: &str) -> Result<Zeroizing<[u8; 32]>, String> {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            if self.cancel.load(Ordering::SeqCst) {
                return Err("user cancelled".into());
            }
            self.keys.lock().unwrap().get(entry_id).map(|k| Zeroizing::new(*k)).ok_or_else(|| "platform key is gone".into())
        }
        fn delete_key(&self, entry_id: &str) -> Result<(), String> {
            self.keys.lock().unwrap().remove(entry_id);
            Ok(())
        }
    }
}
