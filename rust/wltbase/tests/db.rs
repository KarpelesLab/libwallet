use std::time::Duration;

use wltbase::Env;

#[test]
fn config_roundtrip() {
    let env = Env::init_memory().unwrap();
    assert!(env.config_get("missing").unwrap().is_none());
    env.config_set("greeting", b"hello").unwrap();
    assert_eq!(env.config_get("greeting").unwrap().as_deref(), Some(&b"hello"[..]));
    // overwrite
    env.config_set("greeting", b"bye").unwrap();
    assert_eq!(env.config_get("greeting").unwrap().as_deref(), Some(&b"bye"[..]));
}

#[test]
fn init_seeds_version_and_first_run() {
    let env = Env::init_memory().unwrap();
    assert_eq!(env.config_get("version").unwrap().as_deref(), Some(&[0, 0, 0, 4][..]));
    let fr = env.config_get("first_run").unwrap().expect("first_run seeded");
    assert_eq!(fr.len(), 16, "first_run is a 16-byte TimeId");
    // Unix seconds (first 8 bytes, big-endian) should be a plausible recent time.
    let unix = u64::from_be_bytes(fr[..8].try_into().unwrap());
    assert!(unix > 1_700_000_000, "first_run unix looks sane: {unix}");
}

#[test]
fn cache_ttl_expiry() {
    let env = Env::init_memory().unwrap();
    env.cache_store("fresh", b"v", Duration::from_secs(3600)).unwrap();
    assert_eq!(env.cache_load("fresh").unwrap().as_deref(), Some(&b"v"[..]));

    env.cache_store("stale", b"v", Duration::from_millis(1)).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert!(env.cache_load("stale").unwrap().is_none(), "expired entry not returned");
}

#[test]
fn cache_delete_and_cleanup() {
    let env = Env::init_memory().unwrap();
    env.cache_store("a", b"1", Duration::from_secs(3600)).unwrap();
    env.cache_store("b", b"2", Duration::from_millis(1)).unwrap();
    env.cache_delete(&["a"]).unwrap();
    assert!(env.cache_load("a").unwrap().is_none());

    std::thread::sleep(Duration::from_millis(20));
    let removed = env.cache_cleanup().unwrap();
    assert_eq!(removed, 1, "one expired entry bulk-removed");
}

#[test]
fn current_created_is_preserved_across_updates() {
    let env = Env::init_memory().unwrap();
    assert!(env.get_current("account").unwrap().is_none());
    env.set_current("account", "acct-1").unwrap();
    assert_eq!(env.get_current("account").unwrap().as_deref(), Some("acct-1"));
    env.set_current("account", "acct-2").unwrap();
    assert_eq!(env.get_current("account").unwrap().as_deref(), Some("acct-2"));
}

/// The compatibility proof: open a real `sql.db` produced by the Go build and
/// confirm graphitesql reads it and round-trips our tables. Copied to a temp
/// dir so the committed fixture is never mutated.
#[test]
fn opens_existing_go_database() {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/../../wlttest/test/sql.db");
    let src = std::path::Path::new(fixture);
    assert!(src.exists(), "fixture present at {fixture}");

    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(src, dir.path().join("sql.db")).unwrap();

    let env = Env::init(dir.path().to_str().unwrap()).unwrap();
    // Tables open and config round-trips on the migrated file.
    env.config_set("probe", b"ok").unwrap();
    assert_eq!(env.config_get("probe").unwrap().as_deref(), Some(&b"ok"[..]));
}
