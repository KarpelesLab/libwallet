//! Request-scoped references to vault entries, and the unlock cache.
//!
//! [`bind_params`] runs in the dispatcher before a request is routed: every
//! KeyDescription `{"Type":"Vault","Key":"<entry id>"}` in the params becomes
//! `{"Type":"StoreKey"|"Password","Key":"<token>"}`, where the token is an
//! unguessable, request-scoped reference held in [`Lease`]. Handlers pass the
//! token around like any other key material; [`crate::keystore`] recognises it
//! at the point of use and asks [`secret_for_token`] for the real secret,
//! which is unsealed then (prompting Face ID etc. if the policy says so),
//! used, and wiped. A use that only needs the public half (a StoreKey
//! recipient at wallet creation) gets it from [`public_for_token`] without
//! unsealing anything. Dropping the lease at the end of the request revokes
//! its tokens.
//!
//! The cache holds unsealed secrets for entries whose policy allows it
//! (`CacheSeconds` ≠ 0), until expiry, [`lock`], or the app going to the
//! background. Values are `Zeroizing`, wiped on removal.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use purecrypto::hash::sha256;
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::zeroize::{Zeroize, Zeroizing};
use serde_json::Value;

use super::{Entry, Kind};
use crate::{Env, Error, Result};

/// Prefix of every token. It starts with NUL, which no JSON-sourced password a
/// user typed will (and a forged token resolves to nothing anyway: tokens are
/// 128-bit random and live only for their request).
const TOKEN_PREFIX: &str = "\u{0}lwvault:";

/// Default text for the OS prompt when the request gives no `Reason`.
pub const DEFAULT_REASON: &str = "Unlock your wallet";

struct Ref {
    entry: Entry,
    scope: u64,
    password: Option<Zeroizing<String>>,
    reason: String,
}

struct Cached {
    secret: Zeroizing<Vec<u8>>,
    /// SHA-256 of the envelope (`Entry::data`) this secret was unsealed from:
    /// a cached secret only ever answers for that exact envelope, so a row
    /// whose envelope or policy changed since has to be unsealed again.
    sealed: [u8; 32],
    /// Unix ms; None = until locked.
    expires_ms: Option<i64>,
}

static REFS: LazyLock<Mutex<HashMap<String, Arc<Ref>>>> = LazyLock::new(Default::default);
/// Keyed by (session scope, entry id): see [`crate::Env::vault_scope`].
static CACHE: LazyLock<Mutex<HashMap<(u64, String), Cached>>> = LazyLock::new(Default::default);

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The tokens one request bound; dropping it revokes them.
#[derive(Default)]
pub struct Lease {
    tokens: Vec<String>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut refs = REFS.lock().unwrap();
        for t in self.tokens.drain(..) {
            refs.remove(&t);
        }
    }
}

/// Rewrite every `Type:"Vault"` KeyDescription in `params` into a token (see
/// the module docs). `Password` and `Reason` on such a KeyDescription are
/// consumed: the password backend's password for this one use, and the text
/// of the OS prompt.
pub fn bind_params(env: &Env, params: &mut Value) -> Result<Lease> {
    let mut lease = Lease::default();
    walk(env, params, &mut lease)?;
    Ok(lease)
}

fn walk(env: &Env, v: &mut Value, lease: &mut Lease) -> Result<()> {
    match v {
        Value::Object(m) if m.get("Type").and_then(Value::as_str) == Some("Vault") => {
            let id = m.get("Key").and_then(Value::as_str).unwrap_or("").to_owned();
            let entry = super::fetch(env, &id)?.ok_or_else(|| Error::Env(format!("vault entry {id:?} not found")))?;
            let key_type = entry
                .kind
                .key_type()
                .ok_or_else(|| Error::Env(format!("vault entry {id} holds data, which cannot unlock a key")))?;
            let password = match m.remove("Password") {
                Some(Value::String(s)) => Some(Zeroizing::new(s)),
                _ => None,
            };
            let reason = m.remove("Reason").and_then(|r| r.as_str().map(str::to_owned)).unwrap_or_default();
            let mut raw = [0u8; 16];
            OsRng.fill_bytes(&mut raw);
            let token = format!("{TOKEN_PREFIX}{}", raw.iter().map(|b| format!("{b:02x}")).collect::<String>());
            REFS.lock().unwrap().insert(token.clone(), Arc::new(Ref { entry, scope: env.vault_scope(), password, reason }));
            m.insert("Type".into(), Value::String(key_type.into()));
            m.insert("Key".into(), Value::String(token.clone()));
            lease.tokens.push(token);
            Ok(())
        }
        Value::Object(m) => m.values_mut().try_for_each(|x| walk(env, x, lease)),
        Value::Array(a) => a.iter_mut().try_for_each(|x| walk(env, x, lease)),
        _ => Ok(()),
    }
}

pub fn is_token(material: &str) -> bool {
    material.starts_with(TOKEN_PREFIX)
}

fn lookup(token: &str) -> Option<Arc<Ref>> {
    REFS.lock().unwrap().get(token).cloned()
}

/// The secret behind a token, or None when `material` is not a token. A token
/// whose request ended resolves to an error, never to the token text.
pub fn secret_for_token(material: &str) -> Option<Result<Zeroizing<Vec<u8>>>> {
    if !is_token(material) {
        return None;
    }
    Some(match lookup(material) {
        Some(r) => {
            let reason = if r.reason.is_empty() { DEFAULT_REASON } else { &r.reason };
            secret(&r.entry, r.scope, r.password.as_ref().map(|p| p.as_str()), reason)
        }
        None => Err(Error::Env("vault reference expired".into())),
    })
}

/// The StoreKey public key behind a token (no unsealing), or None when
/// `material` is not a token.
pub fn public_for_token(material: &str) -> Option<Result<String>> {
    if !is_token(material) {
        return None;
    }
    Some(match lookup(material) {
        Some(r) if r.entry.kind == Kind::StoreKey && !r.entry.public.is_empty() => Ok(r.entry.public.clone()),
        Some(_) => Err(Error::Env("this vault entry has no public key".into())),
        None => Err(Error::Env("vault reference expired".into())),
    })
}

/// An entry's secret in session `scope` ([`crate::Env::vault_scope`]): from
/// the cache when it holds a live copy, else unsealed (and cached when the
/// policy allows it).
pub fn secret(e: &Entry, scope: u64, password: Option<&str>, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = (scope, e.id.clone());
    {
        let mut cache = CACHE.lock().unwrap();
        match cache.get(&key) {
            // The row must still be the envelope the secret came out of, and
            // agree with the policy sealed in it: the cache never answers for
            // an entry that was replaced or edited after the unlock.
            Some(c) if c.expires_ms.is_none_or(|t| t > now_ms()) && c.sealed == sha256(&e.data) && e.matches_envelope() => {
                return Ok(c.secret.clone());
            }
            Some(_) => {
                cache.remove(&key);
            }
            None => {}
        }
    }
    let s = super::unseal(e, password, reason)?;
    keep(e, key, &s);
    Ok(s)
}

fn keep(e: &Entry, key: (u64, String), s: &Zeroizing<Vec<u8>>) {
    let expires_ms = match e.policy.cache_seconds {
        0 => return,
        n if n < 0 => None,
        n => Some(now_ms().saturating_add(n.saturating_mul(1000))),
    };
    CACHE.lock().unwrap().insert(key, Cached { secret: s.clone(), sealed: sha256(&e.data), expires_ms });
}

/// `Vault:unlock`: unseal now and keep the secret for the entry's
/// `CacheSeconds`, so later uses don't prompt. Returns the expiry (Unix ms,
/// None = until locked).
pub fn unlock(e: &Entry, scope: u64, password: Option<&str>, reason: &str) -> Result<Option<i64>> {
    if e.policy.cache_seconds == 0 {
        return Err(Error::Env(format!(
            "vault entry {} is set to unlock on every use (CacheSeconds 0); use it directly instead",
            e.id
        )));
    }
    forget(scope, &e.id);
    secret(e, scope, password, reason)?;
    Ok(CACHE.lock().unwrap().get(&(scope, e.id.clone())).and_then(|c| c.expires_ms))
}

/// Whether the entry has a live cached secret.
pub fn is_unlocked(scope: u64, id: &str) -> bool {
    CACHE.lock().unwrap().get(&(scope, id.to_owned())).is_some_and(|c| c.expires_ms.is_none_or(|t| t > now_ms()))
}

/// Drop one entry's cached secret in session `scope` (wiped by `Zeroizing`).
pub fn forget(scope: u64, id: &str) {
    CACHE.lock().unwrap().remove(&(scope, id.to_owned()));
}

/// Drop one entry's cached secret in every session (the entry was deleted).
pub fn forget_everywhere(id: &str) {
    CACHE.lock().unwrap().retain(|(_, e), _| e != id);
}

/// `Vault:lock` without an id, or the session closing: drop every cached
/// secret of session `scope`.
pub fn lock_scope(scope: u64) {
    CACHE.lock().unwrap().retain(|(s, _), _| *s != scope);
}

/// App backgrounded: drop every cached secret of every session, and dismiss
/// any prompt on screen.
pub fn lock_all() {
    CACHE.lock().unwrap().clear();
    if let Some(b) = super::platform::backend() {
        b.cancel_prompts();
    }
}

/// Overwrite every string in a request's params in place. The dispatcher runs
/// this once the request is answered, so passwords, imported secrets and the
/// like don't linger in the parsed request.
pub fn wipe_value(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_value),
        Value::Object(m) => m.values_mut().for_each(wipe_value),
        _ => {}
    }
}
