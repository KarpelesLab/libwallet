//! Regression coverage for the core security-audit fixes (network selection,
//! RPC URL guard, network validation, data-dir permissions, event sink).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use libwallet::models::network;
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
