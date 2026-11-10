//! Regression coverage for the core security-audit fixes (network selection,
//! RPC URL guard, network validation, data-dir permissions, event sink).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::models::network::{self, Network};
use libwallet::Env;
use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};

extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let json = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    tx.send(json).unwrap();
}

fn request(h: usize, body: &str) -> serde_json::Value {
    let (tx, rx) = channel::<String>();
    let boxed: Box<Sender<String>> = Box::new(tx);
    let ud = Box::into_raw(boxed) as usize;

    let req = CString::new(body).unwrap();
    let cb: ResponseCallback = capture;
    LibwalletRequest(h, req.as_ptr(), Some(cb), ud);

    let value = loop {
        let json = rx.recv_timeout(Duration::from_secs(30)).expect("callback fired");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON envelope");
        if v["result"] == "progress" {
            continue;
        }
        break v;
    };
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    value
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("libwallet-audit-{tag}-{}-{}", std::process::id(), n))
}

fn new_env() -> usize {
    let dir = temp_dir("ffi");
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0, "init returned a valid handle");
    h
}

fn mem_env() -> Env {
    let env = Env::init_memory().unwrap();
    network::init(&env).unwrap();
    env
}

// --- F1: the current-network selection can never refer to itself ----------

#[test]
fn set_current_rejects_self_reference() {
    let h = new_env();
    for id in ["@", ""] {
        let set = request(h, &format!(r#"{{"path":"Network:setCurrent","params":{{"Id":"{id}"}}}}"#));
        assert_eq!(set["result"], "error", "setCurrent({id:?}) must fail: {set}");
    }
    // A real selection still works and resolves through "@".
    let set = request(h, r#"{"path":"Network:setCurrent","params":{"Id":"evm.137"}}"#);
    assert_eq!(set["result"], "success", "{set}");
    let cur = request(h, r#"{"path":"Network/@","verb":"GET"}"#);
    assert_eq!(cur["data"]["ChainId"], "137", "{cur}");
    LibwalletDestroy(h);
}

#[test]
fn fetch_current_survives_a_stored_self_reference() {
    // A "@" already persisted (older build / another write path) must resolve
    // as "nothing selected" instead of recursing until the stack overflows.
    let env = mem_env();
    for stored in ["@", ""] {
        env.set_current("network", stored).unwrap();
        let n = network::fetch(&env, "@").unwrap().expect("default network");
        assert_eq!((n.kind.as_str(), n.chain_id.as_str()), ("evm", "1"));
    }
}

// --- F6: one row per EVM chain; sane currency decimals --------------------

#[test]
fn evm_chain_id_is_canonicalised() {
    let env = mem_env();
    env.exec(r#"DELETE FROM "Network""#, Vec::new()).unwrap();
    let evm = |chain: &str| Network { kind: "evm".into(), chain_id: chain.into(), ..Default::default() };

    let canonical = network::create(&env, evm("1")).unwrap();
    for spelling in ["01", "+1", "0x1", "0X01", "0001"] {
        let n = network::create(&env, evm(spelling)).unwrap();
        assert_eq!(n.chain_id, "1", "{spelling}");
        assert_eq!(n.id, canonical.id, "{spelling} must map to the chain-1 row");
    }
    assert_eq!(network::list(&env).unwrap().len(), 1);

    for bad in ["", " 1", "1 ", "abc", "1a", "0x", "0xzz", "-1", "1.0", "99999999999999999999999"] {
        assert!(network::create(&env, evm(bad)).is_err(), "{bad:?} must be rejected");
    }
    assert_eq!(network::list(&env).unwrap().len(), 1);

    // Non-EVM chain ids are names and are untouched.
    let b = network::create(&env, Network { kind: "bitcoin".into(), chain_id: "bitcoin".into(), ..Default::default() }).unwrap();
    assert_eq!(b.chain_id, "bitcoin");
}

#[test]
fn currency_decimals_are_bounded() {
    let env = mem_env();
    let net = |d: i64| Network { kind: "evm".into(), chain_id: "424242".into(), currency_decimals: d, ..Default::default() };
    for bad in [-1, 37, 255, i64::MAX, i64::MIN] {
        assert!(network::create(&env, net(bad)).is_err(), "{bad} must be rejected");
    }
    for good in [0, 6, 18, 36] {
        assert!(network::create(&env, net(good)).is_ok(), "{good} must be accepted");
    }
}

// --- F5: the data dir and database files are owner-only -------------------

#[cfg(unix)]
#[test]
fn data_dir_and_db_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

    // A directory we create (parents included) is 0700; the db files 0600.
    let root = temp_dir("perm");
    let dir = root.join("nested").join("wallet");
    let env = Env::init(dir.to_str().unwrap()).unwrap();
    env.config_set("probe", b"1").unwrap();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&root), 0o700);
    let mut seen = 0;
    for name in ["sql.db", "sql.db-journal", "sql.db-wal"] {
        let p = dir.join(name);
        if p.exists() {
            assert_eq!(mode(&p), 0o600, "{name}");
            seen += 1;
        }
    }
    assert!(seen >= 1, "sql.db exists");
    drop(env);

    // Reopening keeps the data; a database left world-readable by an older
    // build is tightened.
    std::fs::set_permissions(dir.join("sql.db"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let env = Env::init(dir.to_str().unwrap()).unwrap();
    assert_eq!(env.config_get("probe").unwrap().as_deref(), Some(&b"1"[..]));
    assert_eq!(mode(&dir.join("sql.db")), 0o600);
    drop(env);

    // A pre-existing directory is the host's: its mode is not changed.
    let existing = temp_dir("perm-existing");
    std::fs::create_dir_all(&existing).unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = Env::init(existing.to_str().unwrap()).unwrap();
    assert_eq!(mode(&existing), 0o755);
    assert_eq!(mode(&existing.join("sql.db")), 0o600);
    drop(env);

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&existing);
}

// --- F2: SSRF guard — IPv4 wrapped in IPv6, and numeric host spellings -----

#[test]
fn rpc_guard_unwraps_ipv4_embedded_in_ipv6() {
    for url in [
        "https://[::ffff:10.0.0.1]/rpc",     // IPv4-mapped private
        "https://[::ffff:a00:1]/rpc",        // same, hex spelling
        "https://[::ffff:127.0.0.1]/rpc",    // IPv4-mapped loopback
        "http://[::ffff:127.0.0.1]:8545",    // ... is not the http escape hatch
        "https://[::ffff:169.254.169.254]/", // cloud metadata
        "https://[64:ff9b::a00:1]/rpc",      // NAT64 -> 10.0.0.1
        "https://[64:ff9b::c0a8:101]/rpc",   // NAT64 -> 192.168.1.1
        "https://[::10.0.0.1]/rpc",          // IPv4-compatible
        "https://[fe80::1%25eth0]/rpc",      // zone id: not a parseable literal
    ] {
        assert!(network::validate_rpc_url(url).is_err(), "{url} must be rejected");
    }
    // Public addresses in the same forms stay allowed.
    assert!(network::validate_rpc_url("https://[::ffff:8.8.8.8]/rpc").is_ok());
    assert!(network::validate_rpc_url("https://[64:ff9b::808:808]/rpc").is_ok());
    assert!(network::validate_rpc_url("https://[2606:4700::1111]/rpc").is_ok());
}

#[test]
fn rpc_guard_rejects_numeric_host_spellings() {
    for url in [
        "https://167772161/rpc",  // 10.0.0.1 as one number
        "https://2130706433/rpc", // 127.0.0.1
        "https://10.1/rpc",       // short dotted form
        "https://192.168.257/rpc",
        "https://0x0a000001/rpc", // hex
        "https://0xa.0.0.1/rpc",
        "https://0XA.0.0.0X1/rpc",
        "https://012.0.0.1/rpc",  // octal component
        "https://10.0.0.1./rpc",  // trailing dot
        "http://127.1:8545",      // not the loopback escape hatch either
        "https://0x/rpc",
    ] {
        assert!(network::validate_rpc_url(url).is_err(), "{url} must be rejected");
    }
    // Ordinary names (including digit-heavy ones) and literals are unaffected.
    for url in [
        "https://mainnet.example/rpc",
        "https://1rpc.io/eth",
        "https://123.example.com/rpc",
        "https://rpc.0x.example/rpc",
        "https://8.8.8.8/rpc",
        "http://localhost:8545",
        "http://127.0.0.1:8545",
        "http://[::1]:8545",
    ] {
        assert!(network::validate_rpc_url(url).is_ok(), "{url} must be accepted");
    }
}
