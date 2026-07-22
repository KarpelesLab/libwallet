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
