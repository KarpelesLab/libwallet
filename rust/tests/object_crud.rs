//! Object PATCH (ApiUpdate) / DELETE (ApiDelete) paths for Contact, Account,
//! Wallet, and Crash — the model-level update/delete functions the handler
//! route() arms drive. Mirrors tests/contact_crud.rs in style.

use libwallet::models::{account, connected_site, contact, crash, wallet};
use libwallet::models::contact::Contact;
use libwallet::sign::KeyDescription;
use libwallet::Env;

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

#[allow(non_snake_case)]
fn blank_contact() -> Contact {
    Contact {
        id: String::new(),
        name: String::new(),
        address: String::new(),
        kind: String::new(),
        flags: Vec::new(),
        memo: String::new(),
        created: String::new(),
        updated: String::new(),
    }
}

// ── Contact ────────────────────────────────────────────────────────────────

#[test]
fn contact_update_mutates_name_and_memo() {
    let env = Env::init_memory().unwrap();
    contact::init(&env).unwrap();

    let created = contact::create(
        &env,
        Contact { name: "Alice".into(), address: "0xabc".into(), kind: "ethereum".into(), ..blank_contact() },
    )
    .unwrap();

    let updated = contact::update(&env, &created.id, Some("Alice B"), Some("bff"), None, None)
        .unwrap()
        .expect("found");
    assert_eq!(updated.name, "Alice B");
    assert_eq!(updated.memo, "bff");
    assert_eq!(updated.address, "0xabc"); // unchanged
    assert_eq!(updated.kind, "ethereum");

    // Persisted.
    let got = contact::fetch(&env, &created.id).unwrap().expect("found");
    assert_eq!(got.name, "Alice B");
    assert_eq!(got.memo, "bff");
}

#[test]
fn contact_update_address_with_type_validates() {
    let env = Env::init_memory().unwrap();
    contact::init(&env).unwrap();
    let created = contact::create(
        &env,
        Contact { name: "Bob".into(), address: "0xabc".into(), kind: "ethereum".into(), ..blank_contact() },
    )
    .unwrap();

    // Change address + type to bitcoin.
    let updated = contact::update(&env, &created.id, None, None, Some("bc1qxyz"), Some("bitcoin"))
        .unwrap()
        .expect("found");
    assert_eq!(updated.address, "bc1qxyz");
    assert_eq!(updated.kind, "bitcoin");

    // An unsupported type is rejected.
    assert!(contact::update(&env, &created.id, None, None, Some("x"), Some("dogecoin")).is_err());
}

#[test]
fn contact_update_no_fields_is_noop() {
    let env = Env::init_memory().unwrap();
    contact::init(&env).unwrap();
    let created = contact::create(
        &env,
        Contact { name: "C".into(), address: "0x1".into(), kind: "ethereum".into(), ..blank_contact() },
    )
    .unwrap();
    // No updatable field -> row unchanged, still returns the contact.
    let same = contact::update(&env, &created.id, None, None, None, None).unwrap().expect("found");
    assert_eq!(same, created);
}

#[test]
fn contact_update_unknown_id_is_none() {
    let env = Env::init_memory().unwrap();
    contact::init(&env).unwrap();
    assert!(contact::update(&env, "ct-nope", Some("x"), None, None, None).unwrap().is_none());
}

#[test]
fn contact_delete_removes_row() {
    let env = Env::init_memory().unwrap();
    contact::init(&env).unwrap();
    let created = contact::create(
        &env,
        Contact { name: "D".into(), address: "0x2".into(), kind: "ethereum".into(), ..blank_contact() },
    )
    .unwrap();
    assert_eq!(contact::list(&env).unwrap().len(), 1);
    contact::delete(&env, &created.id).unwrap();
    assert!(contact::fetch(&env, &created.id).unwrap().is_none());
    assert!(contact::list(&env).unwrap().is_empty());
}

// ── Account ────────────────────────────────────────────────────────────────

fn account_env() -> (Env, account::Account) {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    connected_site::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "W", "ed25519", &kds).unwrap();
    let a = account::create(&env, &w.id, "First", "solana", 0).unwrap();
    (env, a)
}

#[test]
fn account_update_only_name() {
    let (env, a) = account_env();
    let updated = account::update(&env, &a.id, Some("Renamed")).unwrap().expect("found");
    assert_eq!(updated.name, "Renamed");
    assert_eq!(updated.address, a.address); // untouched
    let got = account::fetch(&env, &a.id).unwrap().expect("found");
    assert_eq!(got.name, "Renamed");
}

#[test]
fn account_update_no_name_is_noop() {
    let (env, a) = account_env();
    let same = account::update(&env, &a.id, None).unwrap().expect("found");
    assert_eq!(same.name, a.name);
}

#[test]
fn account_update_unknown_id_is_none() {
    let (env, _a) = account_env();
    assert!(account::update(&env, "acct-nope", Some("x")).unwrap().is_none());
}

#[test]
fn account_delete_cascades_connected_sites() {
    let (env, a) = account_env();
    // Link the account to a dApp, then delete the account.
    connected_site::connect(&env, "https://dapp.example", &a.id).unwrap();
    assert_eq!(connected_site::for_host(&env, "https://dapp.example").unwrap().len(), 1);

    account::delete(&env, &a.id).unwrap();
    assert!(account::fetch(&env, &a.id).unwrap().is_none());
    // Cascade dropped the ConnectedSite row.
    assert!(connected_site::for_host(&env, "https://dapp.example").unwrap().is_empty());
}

// ── Wallet ─────────────────────────────────────────────────────────────────

#[test]
fn wallet_update_only_name() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "Orig", "ed25519", &kds).unwrap();

    let updated = wallet::update(&env, &w.id, Some("Renamed")).unwrap().expect("found");
    assert_eq!(updated.name, "Renamed");
    // Keys still loaded on the returned object.
    assert_eq!(updated.keys.len(), w.keys.len());
    let got = wallet::fetch(&env, &w.id).unwrap().expect("found");
    assert_eq!(got.name, "Renamed");
}

#[test]
fn wallet_update_unknown_id_is_none() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    assert!(wallet::update(&env, "wlt-nope", Some("x")).unwrap().is_none());
}

#[test]
fn wallet_delete_removes_wallet_and_keys() {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
    let w = wallet::create(&env, "ToDelete", "ed25519", &kds).unwrap();
    assert!(!wallet::keys_for(&env, &w.id).unwrap().is_empty());

    wallet::delete(&env, &w.id).unwrap();
    assert!(wallet::fetch(&env, &w.id).unwrap().is_none());
    // WalletKey rows are gone too (no orphan shares).
    assert!(wallet::keys_for(&env, &w.id).unwrap().is_empty());
}

// ── Crash ──────────────────────────────────────────────────────────────────

#[test]
fn crash_delete_removes_row() {
    let env = Env::init_memory().unwrap();
    crash::init(&env).unwrap();
    let id = crash::log(&env, "signer", "boom", "stack").unwrap();
    assert_eq!(crash::list(&env).unwrap().len(), 1);
    crash::delete(&env, &id).unwrap();
    assert!(crash::fetch(&env, &id).unwrap().is_none());
    assert!(crash::list(&env).unwrap().is_empty());
}
