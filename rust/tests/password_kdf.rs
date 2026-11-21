//! Password shares: new shares are sealed with Argon2id, shares sealed before
//! 0.5.11 (PBKDF2) keep opening, `recrypt` moves a share to Argon2id, and
//! `Wallet/Key/<id>:verify` reports whether a local share opens.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::keystore;
use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::{Env, LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback, SqlValue};

const PW: &str = "seal-password";

fn pw(p: &str) -> KeyDescription {
    KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    libwallet::vault::init(&env).unwrap();
    env
}

fn uuid(key_id: &str) -> Vec<u8> {
    let x: xuid::Xuid = key_id.parse().unwrap();
    x.uuid().as_bytes().to_vec()
}

/// Rewrite a Password share the way libwallet < 0.5.11 sealed it (PBKDF2).
fn make_legacy(env: &Env, key_id: &str, password: &str, legacy_password: &str) {
    let wk = wallet::fetch_key(env, key_id).unwrap().unwrap();
    let salt = uuid(key_id);
    let cur = keystore::password_to_ed25519(password, &salt).unwrap();
    let payload = keystore::open(&wk.data, [cur]).unwrap();
    let legacy = keystore::password_to_ed25519_legacy(legacy_password, &salt).unwrap();
    let data = keystore::seal(&payload, &[legacy.public()]).unwrap();
    let key = keystore::public_key_to_pkix_b64(&legacy.public()).unwrap();
    env.exec(
        r#"UPDATE "WalletKey" SET "Key" = ?1, "Data" = ?2 WHERE "Id" = ?3"#,
        vec![SqlValue::Text(key), SqlValue::Blob(data), SqlValue::Text(key_id.into())],
    )
    .unwrap();
}

fn signs(env: &Env, account_id: &str, address: &str, key_id: &str, password: &str) -> bool {
    match libwallet::evm::personal_sign(env, account_id, &[(key_id.into(), password.into())], b"hi") {
        Ok(sig) => libwallet::evm::personal_ec_recover(b"hi", &sig).unwrap().to_lowercase() == address.to_lowercase(),
        Err(_) => false,
    }
}

#[test]
fn new_shares_use_argon2id() {
    let env = env();
    let w = wallet::import_private_key(&env, "k", "secp256k1", &[0x61u8; 32], &pw(PW)).unwrap();
    let wk = &w.keys[0];
    let salt = uuid(&wk.id);
    let argon = keystore::password_to_ed25519(PW, &salt).unwrap();
    let legacy = keystore::password_to_ed25519_legacy(PW, &salt).unwrap();
    assert_eq!(wk.key, keystore::public_key_to_pkix_b64(&argon.public()).unwrap());
    assert_ne!(wk.key, keystore::public_key_to_pkix_b64(&legacy.public()).unwrap());

    let c = wallet::verify_key(&env, &wk.id, Some(&pw(PW))).unwrap();
    assert!(c.valid);
    assert_eq!((c.checked, c.kdf), ("unsealed", Some("argon2id")));
    let c = wallet::verify_key(&env, &wk.id, Some(&pw("not-the-password"))).unwrap();
    assert!(!c.valid);
}

#[test]
fn legacy_shares_open_and_recrypt_upgrades_them() {
    let env = env();
    let w = wallet::import_private_key(&env, "k", "secp256k1", &[0x62u8; 32], &pw(PW)).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let id = w.keys[0].id.clone();
    // A 7-character password: allowed before 0.5.11, too short to seal now.
    make_legacy(&env, &id, PW, "short77");

    assert!(signs(&env, &a.id, &a.address, &id, "short77"));
    assert!(!signs(&env, &a.id, &a.address, &id, "short78"));
    let c = wallet::verify_key(&env, &id, Some(&pw("short77"))).unwrap();
    assert!(c.valid);
    assert_eq!(c.kdf, Some("pbkdf2"));

    // Re-sealing to the same short password is refused (the floor is 8 now);
    // nothing changes.
    let before = wallet::fetch_key(&env, &id).unwrap().unwrap();
    assert!(wallet::recrypt_key(&env, &id, &pw("short77"), &pw("short77")).is_err());
    assert_eq!(wallet::fetch_key(&env, &id).unwrap().unwrap(), before);

    // Recrypt to a real password: the share moves to Argon2id and still signs.
    wallet::recrypt_key(&env, &id, &pw("short77"), &pw("a longer password")).unwrap();
    let c = wallet::verify_key(&env, &id, Some(&pw("a longer password"))).unwrap();
    assert!(c.valid);
    assert_eq!(c.kdf, Some("argon2id"));
    assert!(signs(&env, &a.id, &a.address, &id, "a longer password"));
    assert!(!signs(&env, &a.id, &a.address, &id, "short77"));
}

#[test]
fn legacy_share_with_same_password_upgrades_in_place() {
    let env = env();
    let w = wallet::import_private_key(&env, "k", "secp256k1", &[0x63u8; 32], &pw(PW)).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let id = w.keys[0].id.clone();
    make_legacy(&env, &id, PW, PW);
    assert_eq!(wallet::verify_key(&env, &id, Some(&pw(PW))).unwrap().kdf, Some("pbkdf2"));
    wallet::recrypt_key(&env, &id, &pw(PW), &pw(PW)).unwrap();
    assert_eq!(wallet::verify_key(&env, &id, Some(&pw(PW))).unwrap().kdf, Some("argon2id"));
    assert!(signs(&env, &a.id, &a.address, &id, PW));
}

#[test]
fn sealing_requires_eight_characters() {
    let env = env();
    assert!(wallet::import_private_key(&env, "k", "secp256k1", &[0x64u8; 32], &pw("seven77")).is_err());
    assert!(wallet::import_private_key(&env, "k", "secp256k1", &[0x64u8; 32], &pw("eight888")).is_ok());
}

#[test]
fn verify_needs_a_matching_key() {
    let env = env();
    let w = wallet::import_private_key(&env, "k", "secp256k1", &[0x65u8; 32], &pw(PW)).unwrap();
    let id = &w.keys[0].id;
    // A Password share needs the password.
    assert!(wallet::verify_key(&env, id, None).is_err());
    let sk = KeyDescription { kind: "StoreKey".into(), key: keystore::create_store_key().unwrap().0, id: String::new() };
    assert!(wallet::verify_key(&env, id, Some(&sk)).is_err());
    assert!(wallet::verify_key(&env, "wkey-aaaaaa-aaaa-aaaa-aaaa-aaaaaaaa", Some(&pw(PW))).is_err());
}

// --- through the request API (vault references are bound by the dispatcher) ---

extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    tx.send(json).unwrap();
}

fn request(h: usize, body: &str) -> serde_json::Value {
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx)) as usize;
    let req = CString::new(body).unwrap();
    let cb: ResponseCallback = capture;
    LibwalletRequest(h, req.as_ptr(), Some(cb), ud);
    let value = loop {
        let v: serde_json::Value = serde_json::from_str(&rx.recv_timeout(Duration::from_secs(60)).expect("callback")).unwrap();
        if v["result"] != "progress" {
            break v;
        }
    };
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    value
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-pwkdf-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0);
    h
}

fn ok(r: serde_json::Value) -> serde_json::Value {
    assert_eq!(r["result"], "success", "{r}");
    r["data"].clone()
}

#[test]
fn verify_endpoint_checks_vault_and_password_shares() {
    let h = new_env();
    let entry = ok(request(h, r#"{"path":"Vault:create","params":{"Kind":"storekey","Backend":"password","Password":"vault password","Policy":{"CacheSeconds":-1}}}"#));
    let eid = entry["Id"].as_str().unwrap().to_owned();
    let other = ok(request(h, r#"{"path":"Vault:create","params":{"Kind":"storekey","Backend":"password","Password":"vault password","Policy":{"CacheSeconds":-1}}}"#));
    let oid = other["Id"].as_str().unwrap().to_owned();
    let w = ok(request(h, &format!(
        r#"{{"path":"Wallet","verb":"POST","params":{{"Name":"V","Curve":"ed25519","Keys":[{{"Type":"Vault","Key":"{eid}"}},{{"Type":"Password","Key":"password two"}},{{"Type":"Password","Key":"password three"}}]}}}}"#
    )));
    let dev = w["Keys"][0]["Id"].as_str().unwrap().to_owned();
    let p2 = w["Keys"][1]["Id"].as_str().unwrap().to_owned();

    // No key: public-key match against this device's vault, no unseal.
    let c = ok(request(h, &format!(r#"{{"path":"Wallet/Key/{dev}:verify","params":{{}}}}"#)));
    assert_eq!((c["Valid"].as_bool(), c["Checked"].as_str(), c["Entry"].as_str()), (Some(true), Some("public"), Some(eid.as_str())));

    // With the vault entry: the share is actually opened.
    ok(request(h, &format!(r#"{{"path":"Vault/{eid}:unlock","params":{{"Password":"vault password"}}}}"#)));
    ok(request(h, &format!(r#"{{"path":"Vault/{oid}:unlock","params":{{"Password":"vault password"}}}}"#)));
    let c = ok(request(h, &format!(r#"{{"path":"Wallet/Key/{dev}:verify","params":{{"Key":{{"Type":"Vault","Key":"{eid}"}}}}}}"#)));
    assert_eq!((c["Valid"].as_bool(), c["Checked"].as_str()), (Some(true), Some("unsealed")));
    let c = ok(request(h, &format!(r#"{{"path":"Wallet/Key/{dev}:verify","params":{{"Key":{{"Type":"Vault","Key":"{oid}"}}}}}}"#)));
    assert_eq!(c["Valid"].as_bool(), Some(false));

    // Password share, right and wrong.
    let c = ok(request(h, &format!(r#"{{"path":"Wallet/Key/{p2}:verify","params":{{"Key":{{"Type":"Password","Key":"password two"}}}}}}"#)));
    assert_eq!((c["Valid"].as_bool(), c["Kdf"].as_str()), (Some(true), Some("argon2id")));
    let c = ok(request(h, &format!(r#"{{"path":"Wallet/Key/{p2}:verify","params":{{"Key":{{"Type":"Password","Key":"password 2"}}}}}}"#)));
    assert_eq!(c["Valid"].as_bool(), Some(false));

    // derivePassword matches the share's Key for the right password.
    let d = ok(request(h, &format!(r#"{{"path":"StoreKey:derivePassword","params":{{"Password":"password two","WalletKeyId":"{p2}"}}}}"#)));
    assert_eq!(d["Public_Key"], w["Keys"][1]["Key"]);
    assert_eq!(d["Kdf"], "argon2id");

    // Once the entry is gone (a new device), the no-key check fails.
    ok(request(h, &format!(r#"{{"path":"Vault/{eid}","verb":"DELETE"}}"#)));
    let c = ok(request(h, &format!(r#"{{"path":"Wallet/Key/{dev}:verify","params":{{}}}}"#)));
    assert_eq!(c["Valid"].as_bool(), Some(false));
    assert!(c.get("Entry").is_none());
    LibwalletDestroy(h);
}
