use std::sync::atomic::Ordering;

use serde_json::json;

use super::platform::{self, testing::MemoryBackend};
use super::*;

const FAST: blob::Kdf = blob::Kdf { m_kib: 64, t: 1, p: 1 };

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    crate::handlers::init_models(&env).unwrap();
    env
}

fn new<'a>(kind: Kind, backend: &'a str, policy: Policy, password: Option<&'a str>) -> NewEntry<'a> {
    NewEntry { label: "test", kind, backend, policy, password, secret: None, kdf: FAST }
}

#[test]
fn password_entry_roundtrip_load_and_change_password() {
    let env = env();
    let e = create(&env, new(Kind::Data, "password", Policy { exportable: true, ..Default::default() }, Some("correct horse"))).unwrap();
    assert_eq!(e.provider, "argon2id");
    assert!(!e.policy.user_presence);
    let s1 = unseal(&e, Some("correct horse"), "").unwrap();
    assert_eq!(s1.len(), 32);
    assert!(unseal(&e, Some("wrong horse!"), "").is_err());
    assert!(unseal(&e, None, "").is_err());

    // The blob alone re-registers the entry in a fresh env (browser extension).
    let other = super::tests::env();
    let loaded = load_blob(&other, &e.data).unwrap();
    assert_eq!((loaded.id.as_str(), loaded.kind), (e.id.as_str(), Kind::Data));
    assert_eq!(*unseal(&loaded, Some("correct horse"), "").unwrap(), *s1);

    let e2 = change_password(&env, &e.id, "correct horse", "battery staple", FAST).unwrap();
    assert!(unseal(&e2, Some("correct horse"), "").is_err());
    assert_eq!(*unseal(&e2, Some("battery staple"), "").unwrap(), *s1);
}

#[test]
fn edited_policy_in_the_database_is_refused() {
    let env = env();
    let e = create(&env, new(Kind::Data, "password", Policy::default(), Some("correct horse"))).unwrap();
    let mut forged = e.clone();
    forged.policy.exportable = true;
    let err = unseal(&forged, Some("correct horse"), "").unwrap_err().to_string();
    assert!(err.contains("does not match"), "{err}");
}

#[test]
fn secure_entry_prompts_per_policy_and_caches() {
    let be = MemoryBackend::leak();
    platform::set_test_backend(Some(be));
    let env = env();

    // CacheSeconds 0: every use prompts.
    let e = create(&env, new(Kind::StoreKey, "secure", Policy::default(), None)).unwrap();
    assert_eq!(e.provider, "test-memory");
    assert!(!e.public.is_empty());
    session::secret(&e, None, "x").unwrap();
    session::secret(&e, None, "x").unwrap();
    assert_eq!(be.prompts.load(Ordering::SeqCst), 2);
    assert!(session::unlock(&e, None, "x").is_err(), "unlock is refused when caching is off");

    // CacheSeconds -1: one prompt, then cached until locked.
    let c = create(&env, new(Kind::StoreKey, "secure", Policy { cache_seconds: -1, ..Default::default() }, None)).unwrap();
    be.prompts.store(0, Ordering::SeqCst);
    session::unlock(&c, None, "x").unwrap();
    session::secret(&c, None, "x").unwrap();
    assert_eq!(be.prompts.load(Ordering::SeqCst), 1);
    session::lock_all();
    assert!(!session::is_unlocked(&c.id));
    be.cancel.store(true, Ordering::SeqCst);
    assert!(session::secret(&c, None, "x").is_err(), "a cancelled prompt is an error");
    be.cancel.store(false, Ordering::SeqCst);

    // Delete destroys the platform key.
    assert!(delete(&env, &c.id).unwrap());
    assert!(fetch(&env, &c.id).unwrap().is_none());
    platform::set_test_backend(None);
}

#[test]
fn vault_key_descriptions_create_and_sign_without_the_secret_in_params() {
    let be = MemoryBackend::leak();
    platform::set_test_backend(Some(be));
    let env = env();
    let sk = create(&env, new(Kind::StoreKey, "secure", Policy::default(), None)).unwrap();
    let pw = create(&env, new(Kind::Password, "password", Policy::default(), Some("vault password"))).unwrap();

    // Wallet:create with one vault StoreKey and one vault Password share. The
    // StoreKey recipient resolves to its public key without a prompt.
    let mut params = json!({ "Keys": [
        {"Type": "Vault", "Key": sk.id},
        {"Type": "Vault", "Key": pw.id, "Password": "vault password"},
        {"Type": "Password", "Key": "plain password"},
    ]});
    let lease = session::bind_params(&env, &mut params).unwrap();
    assert_eq!(params["Keys"][0]["Type"], "StoreKey");
    assert_eq!(params["Keys"][1]["Type"], "Password");
    assert!(params["Keys"][1].get("Password").is_none(), "the vault password is consumed");
    assert!(session::is_token(params["Keys"][0]["Key"].as_str().unwrap()));
    let kds: Vec<crate::sign::KeyDescription> = serde_json::from_value(params["Keys"].clone()).unwrap();
    let w = crate::models::wallet::create(&env, "V", "secp256k1", &kds).unwrap();
    assert_eq!(be.prompts.load(Ordering::SeqCst), 0, "creating to a StoreKey entry needs no unlock");
    assert_eq!(w.keys[0].key, sk.public, "the share is sealed to the entry's public key");
    drop(lease);

    // Sign with the two vault shares (2-of-3).
    let mut params = json!({ "Keys": [
        {"Type": "Vault", "Id": w.keys[0].id, "Key": sk.id},
        {"Type": "Vault", "Id": w.keys[1].id, "Key": pw.id, "Password": "vault password"},
    ]});
    let lease = session::bind_params(&env, &mut params).unwrap();
    let unlock: Vec<(String, String)> = params["Keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| (k["Id"].as_str().unwrap().to_owned(), k["Key"].as_str().unwrap().to_owned()))
        .collect();
    let (r, s, _) = crate::models::wallet::dkls_sign_digest(&env, &w.id, &unlock, &[0u8; 32], &[0x11; 32]).unwrap();
    assert_eq!((r.len(), s.len()), (32, 32));
    assert_eq!(be.prompts.load(Ordering::SeqCst), 1, "the secure share prompted once");

    // Tokens die with their request.
    drop(lease);
    let err = crate::models::wallet::dkls_sign_digest(&env, &w.id, &unlock, &[0u8; 32], &[0x11; 32]).unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");

    // A data entry cannot stand in for a key.
    let data = create(&env, new(Kind::Data, "secure", Policy::default(), None)).unwrap();
    let mut params = json!({ "Keys": [{"Type": "Vault", "Key": data.id}] });
    assert!(session::bind_params(&env, &mut params).is_err());
    platform::set_test_backend(None);
}

#[test]
fn import_decodes_storekey_format_and_rejects_bad_secrets() {
    let env = env();
    let (private, public) = crate::keystore::create_store_key().unwrap();
    let secret = decode_secret(Kind::StoreKey, &private, None).unwrap();
    let e = create(&env, NewEntry { secret: Some(secret), ..new(Kind::StoreKey, "password", Policy::default(), Some("migrate me!")) }).unwrap();
    assert_eq!(e.public, public, "an imported StoreKey keeps its public key");
    assert_eq!(*encode_secret(Kind::StoreKey, &unseal(&e, Some("migrate me!"), "").unwrap()), private);

    let short = decode_secret(Kind::StoreKey, "AAAA", None).unwrap();
    assert!(create(&env, NewEntry { secret: Some(short), ..new(Kind::StoreKey, "password", Policy::default(), Some("migrate me!")) }).is_err());
    assert!(create(&env, new(Kind::Data, "password", Policy::default(), Some("short"))).is_err(), "8-char minimum");
}

#[test]
fn no_platform_backend_reports_why() {
    platform::set_test_backend(None);
    let caps = platform::capabilities();
    if !caps.secure {
        let env = env();
        let err = create(&env, new(Kind::StoreKey, "secure", Policy::default(), None)).unwrap_err().to_string();
        assert!(err.contains("password backend"), "{err}");
    }
}

#[test]
fn wipe_value_clears_every_string() {
    let mut v = json!({"a": "secret", "b": [{"c": "pw"}], "n": 1});
    session::wipe_value(&mut v);
    assert_eq!(v["a"].as_str().unwrap().bytes().all(|b| b == 0), true);
    assert_eq!(v["b"][0]["c"].as_str().unwrap().bytes().all(|b| b == 0), true);
}
