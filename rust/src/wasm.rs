//! wasm-bindgen bindings for the browser wallet. Thin wrappers over
//! [`crate::walletcore`] — all crypto logic lives there and is unit-tested on
//! native; this module only marshals strings/objects across the JS boundary and
//! turns `Err(String)` into a thrown JS exception. Compiled only for wasm32.

use wasm_bindgen::prelude::*;

use crate::walletcore;

fn js_err(e: String) -> JsValue {
    JsValue::from_str(&e)
}

/// Generate a fresh BIP-39 mnemonic (`words` = 12 or 24).
#[wasm_bindgen]
pub fn generate_mnemonic(words: u32) -> Result<String, JsValue> {
    walletcore::generate_mnemonic(words).map_err(js_err)
}

/// Whether `mnemonic` is a valid BIP-39 phrase.
#[wasm_bindgen]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    walletcore::validate_mnemonic(mnemonic)
}

/// Derive the EVM / Bitcoin / Solana addresses, returned as a JS object
/// `{ evm, bitcoin, solana }`.
#[wasm_bindgen]
pub fn derive_addresses(mnemonic: &str) -> Result<JsValue, JsValue> {
    let a = walletcore::derive_addresses(mnemonic).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&a).map_err(|e| js_err(e.to_string()))
}

/// Password-encrypt `plaintext` (the mnemonic) into a base64 vault blob.
#[wasm_bindgen]
pub fn encrypt_blob(plaintext: &str, password: &str) -> Result<String, JsValue> {
    walletcore::encrypt(plaintext, password).map_err(js_err)
}

/// Decrypt a vault blob; throws on a wrong password or tampering.
#[wasm_bindgen]
pub fn decrypt_blob(blob: &str, password: &str) -> Result<String, JsValue> {
    walletcore::decrypt(blob, password).map_err(js_err)
}

/// EIP-191 personal_sign; returns the 0x-hex 65-byte signature.
#[wasm_bindgen]
pub fn sign_evm_personal(mnemonic: &str, message: &str) -> Result<String, JsValue> {
    walletcore::sign_evm_personal(mnemonic, message).map_err(js_err)
}

/// Sign an EVM transaction (`tx_json` = the JSON object). Returns 0x-hex raw tx.
#[wasm_bindgen]
pub fn sign_evm_tx(mnemonic: &str, tx_json: &str) -> Result<String, JsValue> {
    walletcore::sign_evm_tx(mnemonic, tx_json).map_err(js_err)
}

/// Sign a native SOL transfer. Returns the base58 signed transaction.
#[wasm_bindgen]
pub fn sign_solana_transfer(mnemonic: &str, tx_json: &str) -> Result<String, JsValue> {
    walletcore::sign_solana_transfer(mnemonic, tx_json).map_err(js_err)
}

/// Sign a P2WPKH Bitcoin transaction. Returns the raw signed tx as hex.
#[wasm_bindgen]
pub fn sign_bitcoin_tx(mnemonic: &str, tx_json: &str) -> Result<String, JsValue> {
    walletcore::sign_bitcoin_tx(mnemonic, tx_json).map_err(js_err)
}

// ─────────────────────────────────────────────────────────────────────────────
// Real request API — drives the same `dispatch::handle_request` the native C
// FFI uses, exposing every offline handler (wallet/account/keygen/sign/
// tx-build/…) to the browser. The networking handlers are gated out on wasm, so
// these calls never touch the network and can be synchronous.
//
// The browser is single-threaded, so sessions live in a thread-local registry
// keyed by a small integer handle (no Arc/Mutex sharing needed).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use crate::dispatch;
use crate::handle::Handle;
use crate::handlers;
use crate::Env;

thread_local! {
    static HANDLES: RefCell<HashMap<u32, Rc<Handle>>> = RefCell::new(HashMap::new());
    static NEXT_ID: Cell<u32> = const { Cell::new(1) };
}

/// Open a new in-memory libwallet session and return its handle id. Mirrors the
/// native `LibwalletInit` (minus the data-dir: the browser has no filesystem, so
/// storage is the in-memory DB and persistence is the host's concern).
#[wasm_bindgen]
pub fn libwallet_init() -> Result<u32, JsValue> {
    // Surface Rust panics as console errors (a panic otherwise aborts with an
    // opaque "unreachable" RuntimeError).
    console_error_panic_hook::set_once();
    let env = Env::init_memory().map_err(|e| js_err(e.to_string()))?;
    handlers::init_models(&env).map_err(|e| js_err(e.to_string()))?;
    let handle = Rc::new(Handle::new(env));
    let id = NEXT_ID.with(|n| {
        let id = n.get();
        n.set(id + 1);
        id
    });
    HANDLES.with(|h| h.borrow_mut().insert(id, handle));
    Ok(id)
}

/// Dispatch a JSON request against the session and return the JSON response —
/// the exact request/response contract of the native `LibwalletRequest`.
#[wasm_bindgen]
pub fn libwallet_request(handle: u32, request_json: &str) -> String {
    match HANDLES.with(|h| h.borrow().get(&handle).cloned()) {
        Some(h) => dispatch::handle_request(&h, request_json),
        None => r#"{"result":"error","error":"invalid handle","code":500}"#.to_string(),
    }
}

/// Register (or, with a null `cb`, this is a no-op) a host event callback: the
/// session's `env.broadcast(json)` invokes `cb(json)`. Mirrors the native
/// `LibwalletSetEventCallback`.
#[wasm_bindgen]
pub fn libwallet_set_event_callback(handle: u32, cb: js_sys::Function) {
    if let Some(h) = HANDLES.with(|m| m.borrow().get(&handle).cloned()) {
        h.env.set_event_sink(Some(Box::new(move |json: &str| {
            let _ = cb.call1(&JsValue::NULL, &JsValue::from_str(json));
        })));
    }
}

/// Tear down a session, dropping its Env (and in-memory DB).
#[wasm_bindgen]
pub fn libwallet_destroy(handle: u32) {
    HANDLES.with(|h| {
        h.borrow_mut().remove(&handle);
    });
}
