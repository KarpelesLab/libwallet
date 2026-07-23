//! walletcore — the offline, single-key HD wallet operations behind the
//! browser-WASM build (`src/wasm.rs`). Pure crypto only: mnemonic ↔ seed,
//! address derivation, password-based vault encryption, and raw-key
//! transaction/message signing for EVM, Bitcoin (P2WPKH), and Solana. No DB, no
//! network, no threads — every function here compiles for `wasm32` and is
//! unit-tested on native so the fund-critical paths are verified before they
//! ever reach the browser.
//!
//! Signing uses a single derived key per chain (not libwallet's TSS model): the
//! web wallet holds one mnemonic. secp256k1 signing (EVM, BTC) and the tx
//! encoders come from `outscript`; ed25519 (Solana) and the vault AEAD from
//! `purecrypto`.

use num_bigint::BigInt;
use serde::Deserialize;

use crate::{bip39, hdderive, solana};

use outscript::btctx::{BtcTx, BtcTxInput, BtcTxSign};
use outscript::crypto::secp256k1::{SecpPrivateKey, SecpPublicKey};
use outscript::evmtx::{EvmTx, EvmTxType};
use outscript::script::Script;
use purecrypto::cipher::XChaCha20Poly1305;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::hash::{keccak256, Sha256};
use purecrypto::kdf::pbkdf2;
use purecrypto::rng::{OsRng, RngCore};

/// Default single-key derivation paths.
pub const EVM_PATH: &str = "m/44'/60'/0'/0/0";
pub const BTC_PATH: &str = "m/84'/0'/0'/0/0"; // native SegWit (bc1…)
pub const SOL_PATH: &str = "m/44'/501'/0'/0'"; // Phantom-compatible

/// Vault KDF cost. PBKDF2-HMAC-SHA256; OWASP-2023 floor is 210k.
const PBKDF2_ITERS: u32 = 210_000;
/// Vault format magic, so a future scheme change is detectable.
const VAULT_MAGIC: &[u8; 3] = b"LW1";
/// Below this many sats a change output costs more than it's worth (dust).
const DUST_SATS: u64 = 546;

type R<T> = Result<T, String>;

/// Fill `buf` with cryptographic randomness via purecrypto's OsRng. On native
/// this is the OS CSPRNG; on wasm32 it routes to the host-supplied
/// `purecrypto.random_get` import (wired to crypto.getRandomValues in the web
/// build). `fill_bytes` is infallible (it traps if the host can't supply
/// entropy), so this never returns Err — the Result is kept for call-site
/// symmetry.
fn fill_random(buf: &mut [u8]) -> R<()> {
    let mut rng = OsRng;
    rng.fill_bytes(buf);
    Ok(())
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_dec(s: &str) -> R<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("bad base64: {e}"))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(s: &str) -> R<Vec<u8>> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

fn hex_32(s: &str) -> R<[u8; 32]> {
    from_hex(s)?.try_into().map_err(|_| "expected 32-byte hex".to_string())
}

fn bs58_32(s: &str) -> R<[u8; 32]> {
    bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("bad base58: {e}"))?
        .try_into()
        .map_err(|_| "expected 32-byte base58 value".to_string())
}

fn dec_bigint(s: &str) -> R<BigInt> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(BigInt::from(0));
    }
    s.parse::<BigInt>().map_err(|e| format!("bad decimal integer {s:?}: {e}"))
}

// ── Mnemonic ────────────────────────────────────────────────────────────────

/// Generate a fresh BIP-39 mnemonic (`words` = 12 or 24).
pub fn generate_mnemonic(words: u32) -> R<String> {
    let entropy_len = match words {
        12 => 16,
        24 => 32,
        _ => return Err("words must be 12 or 24".into()),
    };
    let mut ent = vec![0u8; entropy_len];
    fill_random(&mut ent)?;
    bip39::entropy_to_mnemonic(&ent).map_err(|e| e.to_string())
}

/// Whether `mnemonic` is a valid BIP-39 phrase (checksum included).
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    bip39::mnemonic_to_entropy(mnemonic).is_ok()
}

// ── Addresses ─────────────────────────────────────────────────────────────--

/// The three chain addresses for a mnemonic.
#[derive(serde::Serialize)]
pub struct Addresses {
    pub evm: String,
    pub bitcoin: String,
    pub solana: String,
}

pub fn derive_addresses(mnemonic: &str) -> R<Addresses> {
    let seed = bip39::mnemonic_to_seed(mnemonic, "");

    let evm_pub = hdderive::derive_pubkey_for_path(&seed, "secp256k1", EVM_PATH).map_err(|e| e.to_string())?;
    let evm = hdderive::evm_address(&evm_pub).map_err(|e| e.to_string())?;

    let btc_pub = hdderive::derive_pubkey_for_path(&seed, "secp256k1", BTC_PATH).map_err(|e| e.to_string())?;
    let pk = SecpPublicKey::from_sec1(&btc_pub).map_err(|e| format!("btc pubkey: {e:?}"))?;
    let bitcoin = Script::new(pk).address("p2wpkh", &["bitcoin"]).map_err(|e| format!("btc address: {e}"))?;

    let sol_pub = hdderive::derive_pubkey_for_path(&seed, "ed25519", SOL_PATH).map_err(|e| e.to_string())?;
    let solana = bs58::encode(&sol_pub).into_string();

    Ok(Addresses { evm, bitcoin, solana })
}

// ── Vault (password-encrypted localStorage blob) ────────────────────────────

/// Encrypt `plaintext` (typically the mnemonic) under `password`. Returns a
/// base64 string: `MAGIC ‖ salt(16) ‖ nonce(24) ‖ tag(16) ‖ ciphertext`.
/// PBKDF2-HMAC-SHA256 → 32-byte key → XChaCha20-Poly1305.
pub fn encrypt(plaintext: &str, password: &str) -> R<String> {
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    let mut nonce = [0u8; 24];
    fill_random(&mut nonce)?;

    let mut key = [0u8; 32];
    pbkdf2::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITERS, &mut key);

    let cipher = XChaCha20Poly1305::new(&key);
    let mut buf = plaintext.as_bytes().to_vec();
    let tag = cipher.encrypt(&nonce, &[], &mut buf);

    let mut out = Vec::with_capacity(VAULT_MAGIC.len() + 16 + 24 + 16 + buf.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buf);
    Ok(b64(&out))
}

/// Decrypt a vault produced by [`encrypt`]. Errors (without leaking which part
/// failed) on a wrong password or tampering.
pub fn decrypt(blob_b64: &str, password: &str) -> R<String> {
    let data = b64_dec(blob_b64)?;
    let header = VAULT_MAGIC.len() + 16 + 24 + 16;
    if data.len() < header || &data[..3] != VAULT_MAGIC {
        return Err("unrecognised vault format".into());
    }
    let salt = &data[3..19];
    let nonce: [u8; 24] = data[19..43].try_into().unwrap();
    let tag: [u8; 16] = data[43..59].try_into().unwrap();
    let mut buf = data[59..].to_vec();

    let mut key = [0u8; 32];
    pbkdf2::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    let cipher = XChaCha20Poly1305::new(&key);
    cipher
        .decrypt(&nonce, &[], &mut buf, &tag)
        .map_err(|_| "wrong password or corrupt vault".to_string())?;
    String::from_utf8(buf).map_err(|_| "decrypted data is not valid UTF-8".to_string())
}

// ── Signing ─────────────────────────────────────────────────────────────────

fn secp_key(seed: &[u8], path: &str) -> R<SecpPrivateKey> {
    let priv_bytes = hdderive::derive_privkey_from_seed(seed, "secp256k1", path).map_err(|e| e.to_string())?;
    SecpPrivateKey::from_bytes(&priv_bytes).map_err(|e| format!("bad secp key: {e:?}"))
}

/// EIP-191 `personal_sign`: sign `message` with the EVM key, returning the
/// 0x-prefixed 65-byte `R ‖ S ‖ V` (V ∈ {27,28}) signature ecrecover expects.
pub fn sign_evm_personal(mnemonic: &str, message: &str) -> R<String> {
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let key = secp_key(&seed, EVM_PATH)?;
    let mut full = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    full.extend_from_slice(message.as_bytes());
    let digest = keccak256(&full);
    let (r, s, recid) = key.sign_recoverable(&digest);
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&s);
    sig.push(27 + recid);
    Ok(format!("0x{}", to_hex(&sig)))
}

#[derive(Deserialize)]
struct EvmTxJson {
    #[serde(rename = "chainId")]
    chain_id: u64,
    nonce: u64,
    gas: u64,
    to: String,
    value: String,
    #[serde(default)]
    data: String,
    #[serde(rename = "maxFeePerGas", default)]
    max_fee: Option<String>,
    #[serde(rename = "maxPriorityFeePerGas", default)]
    max_priority: Option<String>,
    #[serde(rename = "gasPrice", default)]
    gas_price: Option<String>,
}

/// Sign an EVM transfer/transaction. `tx_json` carries decimal-wei amounts and
/// 0x-hex calldata; EIP-1559 when `maxFeePerGas` is present, else legacy.
/// Returns the 0x-hex raw signed transaction ready for `eth_sendRawTransaction`.
pub fn sign_evm_tx(mnemonic: &str, tx_json: &str) -> R<String> {
    let p: EvmTxJson = serde_json::from_str(tx_json).map_err(|e| format!("bad EVM tx json: {e}"))?;
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let key = secp_key(&seed, EVM_PATH)?;

    let eip1559 = p.max_fee.is_some();
    let gas_fee_cap = dec_bigint(p.max_fee.as_deref().or(p.gas_price.as_deref()).unwrap_or("0"))?;
    let gas_tip_cap = if eip1559 {
        dec_bigint(p.max_priority.as_deref().unwrap_or("0"))?
    } else {
        BigInt::from(0)
    };

    let mut tx = EvmTx {
        nonce: p.nonce,
        gas: p.gas,
        gas_fee_cap,
        gas_tip_cap,
        to: p.to,
        value: dec_bigint(&p.value)?,
        data: if p.data.is_empty() { Vec::new() } else { from_hex(&p.data)? },
        chain_id: p.chain_id,
        tx_type: if eip1559 { EvmTxType::Eip1559 } else { EvmTxType::Legacy },
        ..Default::default()
    };
    tx.sign(&key)?;
    Ok(format!("0x{}", to_hex(&tx.to_bytes()?)))
}

#[derive(Deserialize)]
struct SolTxJson {
    to: String,
    lamports: u64,
    #[serde(rename = "recentBlockhash")]
    blockhash: String,
}

/// Sign a native SOL transfer. Returns the base58-encoded signed transaction
/// for `sendTransaction` (base58 encoding).
pub fn sign_solana_transfer(mnemonic: &str, tx_json: &str) -> R<String> {
    let p: SolTxJson = serde_json::from_str(tx_json).map_err(|e| format!("bad Solana tx json: {e}"))?;
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let priv_bytes = hdderive::derive_privkey_from_seed(&seed, "ed25519", SOL_PATH).map_err(|e| e.to_string())?;
    let key = Ed25519PrivateKey::from_bytes(priv_bytes);

    let from = key.public_key().to_bytes();
    let to = bs58_32(&p.to)?;
    let blockhash = bs58_32(&p.blockhash)?;

    let msg = solana::build_transfer_message(&from, &to, p.lamports, &blockhash);
    let sig = key.sign(&msg).to_bytes();
    let raw = solana::assemble_tx(&msg, &sig);
    Ok(bs58::encode(&raw).into_string())
}

#[derive(Deserialize)]
struct BtcUtxo {
    txid: String,
    vout: u32,
    value: u64,
}

#[derive(Deserialize)]
struct BtcTxJson {
    utxos: Vec<BtcUtxo>,
    to: String,
    #[serde(rename = "amountSats")]
    amount: u64,
    #[serde(rename = "feeSats")]
    fee: u64,
    #[serde(rename = "changeAddress")]
    change: String,
}

/// Sign a P2WPKH Bitcoin transaction spending the provided UTXOs (all belonging
/// to the wallet's single key) to `to`, with change back to `changeAddress`.
/// Returns the raw signed tx as hex for broadcast.
pub fn sign_bitcoin_tx(mnemonic: &str, tx_json: &str) -> R<String> {
    let p: BtcTxJson = serde_json::from_str(tx_json).map_err(|e| format!("bad Bitcoin tx json: {e}"))?;
    if p.utxos.is_empty() {
        return Err("no UTXOs provided".into());
    }
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let key = secp_key(&seed, BTC_PATH)?;

    // Every UTXO is the wallet's own P2WPKH output, so the prev scriptPubKey
    // (OP_0 ‖ hash160(pubkey)) — needed for the segwit sighash — is the same for
    // all inputs and derivable from our own key. mempool.space's /utxo endpoint
    // doesn't return it, so we reconstruct it rather than require it as input.
    let btc_pub = hdderive::derive_pubkey_for_path(&seed, "secp256k1", BTC_PATH).map_err(|e| e.to_string())?;
    let mut script_pubkey = Vec::with_capacity(22);
    script_pubkey.push(0x00); // OP_0 (witness v0)
    script_pubkey.push(0x14); // push 20 bytes
    script_pubkey.extend_from_slice(&outscript::hash::hash160(&btc_pub));

    let total: u64 = p.utxos.iter().map(|u| u.value).sum();
    let spend = p.amount.checked_add(p.fee).ok_or("amount+fee overflow")?;
    if total < spend {
        return Err(format!("insufficient funds: have {total} sats, need {spend}"));
    }

    let mut tx = BtcTx { version: 2, locktime: 0, ..BtcTx::default() };
    for u in &p.utxos {
        tx.inputs.push(BtcTxInput {
            txid: hex_32(&u.txid)?,
            vout: u.vout,
            script: Vec::new(),
            sequence: 0xffff_ffff,
            witnesses: Vec::new(),
        });
    }
    tx.add_output(&p.to, p.amount)?;
    let change = total - spend;
    if change > DUST_SATS {
        tx.add_output(&p.change, change)?;
    }

    // One key signs every input; each carries the same reconstructed scriptPubKey.
    let signs: Vec<BtcTxSign> = p
        .utxos
        .iter()
        .map(|u| BtcTxSign::new(&key, "p2wpkh").amount(u.value).prev_script(script_pubkey.clone()))
        .collect();
    tx.sign(&signs)?;
    Ok(to_hex(&tx.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical all-zero-entropy mnemonic.
    const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn mnemonic_generate_validate_roundtrip() {
        let m12 = generate_mnemonic(12).unwrap();
        assert_eq!(m12.split_whitespace().count(), 12);
        assert!(validate_mnemonic(&m12));
        let m24 = generate_mnemonic(24).unwrap();
        assert_eq!(m24.split_whitespace().count(), 24);
        assert!(validate_mnemonic(&m24));
        assert!(!validate_mnemonic("not a real mnemonic phrase at all here nope"));
        assert!(generate_mnemonic(15).is_err());
    }

    #[test]
    fn addresses_match_known_vectors() {
        let a = derive_addresses(M).unwrap();
        // Standard BIP-44 m/44'/60'/0'/0/0 address for this mnemonic (MetaMask vector).
        assert_eq!(a.evm, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        // P2WPKH m/84'/0'/0'/0/0 (BIP-84 test vector).
        assert_eq!(a.bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        // Solana address is a base58 ed25519 pubkey (44 chars typical).
        assert!(a.solana.len() >= 32 && a.solana.len() <= 44);
    }

    #[test]
    fn vault_roundtrip_and_wrong_password() {
        let blob = encrypt(M, "correct horse battery staple").unwrap();
        assert_ne!(blob, M);
        assert_eq!(decrypt(&blob, "correct horse battery staple").unwrap(), M);
        assert!(decrypt(&blob, "wrong password").is_err());
        // Two encryptions differ (random salt+nonce).
        assert_ne!(encrypt(M, "pw").unwrap(), encrypt(M, "pw").unwrap());
    }

    #[test]
    fn evm_personal_sign_recovers_to_address() {
        let a = derive_addresses(M).unwrap();
        let sig = sign_evm_personal(M, "hello world").unwrap();
        let sig_bytes = from_hex(&sig).unwrap();
        let recovered = crate::evm::personal_ec_recover(b"hello world", &sig_bytes).unwrap();
        assert_eq!(recovered, a.evm);
    }

    #[test]
    fn evm_tx_recovers_to_sender() {
        let a = derive_addresses(M).unwrap();
        let tx = r#"{"chainId":1,"nonce":0,"maxFeePerGas":"30000000000","maxPriorityFeePerGas":"1000000000","gas":21000,"to":"0x0000000000000000000000000000000000000001","value":"1000000000000000","data":"0x"}"#;
        let raw = sign_evm_tx(M, tx).unwrap();
        let raw_bytes = from_hex(&raw).unwrap();
        let sender = crate::evm::recover_sender(&raw_bytes).unwrap();
        assert_eq!(sender, a.evm);
    }

    #[test]
    fn solana_transfer_signs_and_verifies() {
        let tx = r#"{"to":"11111111111111111111111111111112","lamports":1000000,"recentBlockhash":"11111111111111111111111111111111"}"#;
        let signed = sign_solana_transfer(M, tx).unwrap();
        let raw = bs58::decode(&signed).into_vec().unwrap();
        // shortvec(1) + 64-byte sig + message; verify the sig over the message.
        let msg = crate::solana::tx_message(&raw).expect("message");
        let seed = bip39::mnemonic_to_seed(M, "");
        let pk = hdderive::derive_pubkey_for_path(&seed, "ed25519", SOL_PATH).unwrap();
        let pk32: [u8; 32] = pk.try_into().unwrap();
        let sig64: [u8; 64] = raw[1..65].try_into().unwrap();
        assert!(crate::tss::ed25519_verify(&pk32, msg, &sig64));
    }

    #[test]
    fn bitcoin_tx_signs() {
        // One 100k-sat P2WPKH utxo on the wallet's own address, send 40k, fee 1k.
        let a = derive_addresses(M).unwrap();
        let tx = format!(
            r#"{{"utxos":[{{"txid":"{}","vout":0,"value":100000}}],"to":"{}","amountSats":40000,"feeSats":1000,"changeAddress":"{}"}}"#,
            "0".repeat(64),
            a.bitcoin,
            a.bitcoin
        );
        let hex = sign_bitcoin_tx(M, &tx).unwrap();
        assert!(!hex.is_empty());
        // Version 2, little-endian, is the first 4 bytes.
        assert!(hex.starts_with("02000000"));
    }
}
