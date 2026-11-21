//! Ethereum "Web3 Secret Storage" v3 keystore decryption — the JSON files
//! MetaMask, Geth, MyEtherWallet and most other EVM wallets export.
//!
//! The file is untrusted input: every KDF cost is bounded before any memory or
//! CPU is spent on it, lengths are checked exactly, and the MAC
//! (`keccak256(dk[16..32] ‖ ciphertext)`) is verified in constant time before
//! anything is decrypted, so a wrong password is reported as such rather than
//! yielding a garbage key.
//!
//! scrypt: purecrypto's `scrypt` enforces RFC 7914's `N < 2^(16·r)` relation,
//! which rejects `r = 1` with `N ≥ 2^15` — and the spec's own reference vector
//! (and some older exporters) use exactly `n = 262144, r = 1`. Parameters
//! purecrypto accepts go through it; the rest fall back to a local ROMix
//! (same algorithm, same bounds applied here first).

use purecrypto::cipher::{Aes128, Ctr};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::ec::secp256k1::{ProjectivePoint, Scalar};
use purecrypto::hash::{keccak256, Sha256};
use purecrypto::zeroize::{Zeroize, Zeroizing};
use serde_json::Value;

/// scrypt working memory cap: `128·r·N` bytes.
const MAX_SCRYPT_MEM: u64 = 1 << 30;
/// scrypt parallelism cap (`r·p`): Geth "standard" is 8, "light" 48.
const MAX_SCRYPT_RP: u64 = 256;
/// Total scrypt work cap, in `N·r·p` units (each a 128-byte block pass):
/// 2^24 is 8× Geth's standard `2^18·8·1`.
const MAX_SCRYPT_WORK: u64 = 1 << 24;
/// PBKDF2 iteration cap.
const MAX_PBKDF2_C: u64 = 10_000_000;
/// Salt length cap (bytes); real files use 32.
const MAX_SALT: usize = 1024;

/// Decrypt a v3 keystore. Returns the 32-byte secp256k1 private key and the
/// address the file claims (lowercase 0x-hex, if present).
pub fn decrypt_v3(json: &str, password: &[u8]) -> Result<(Zeroizing<[u8; 32]>, Option<String>), String> {
    let root: Value = serde_json::from_str(json).map_err(|e| format!("keystore: not valid JSON: {e}"))?;
    let root = root.as_object().ok_or("keystore: top level is not a JSON object")?;

    match root.get("version") {
        Some(v) if as_u64(v) == Some(3) => {}
        Some(v) => return Err(format!("keystore: unsupported version {v} (only v3 is supported)")),
        None => return Err("keystore: missing \"version\"".into()),
    }

    let claimed = match root.get("address") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(parse_address(s)?),
        Some(_) => return Err("keystore: \"address\" is not a string".into()),
    };

    let crypto = root
        .get("crypto")
        .or_else(|| root.get("Crypto"))
        .ok_or("keystore: missing \"crypto\" section")?
        .as_object()
        .ok_or("keystore: \"crypto\" is not an object")?;

    let cipher = get_str(crypto, "cipher")?;
    if cipher != "aes-128-ctr" {
        return Err(format!("keystore: unsupported cipher {cipher:?} (only aes-128-ctr)"));
    }
    let iv = crypto
        .get("cipherparams")
        .and_then(Value::as_object)
        .ok_or("keystore: missing \"cipherparams\"")?;
    let iv: [u8; 16] = get_hex(iv, "iv")?
        .try_into()
        .map_err(|v: Vec<u8>| format!("keystore: iv must be 16 bytes, got {}", v.len()))?;
    let ciphertext: [u8; 32] = get_hex(crypto, "ciphertext")?
        .try_into()
        .map_err(|v: Vec<u8>| format!("keystore: ciphertext must be 32 bytes, got {}", v.len()))?;
    let mac: [u8; 32] = get_hex(crypto, "mac")?
        .try_into()
        .map_err(|v: Vec<u8>| format!("keystore: mac must be 32 bytes, got {}", v.len()))?;

    let kdf = get_str(crypto, "kdf")?;
    let params = crypto
        .get("kdfparams")
        .and_then(Value::as_object)
        .ok_or("keystore: missing \"kdfparams\"")?;
    let dklen = get_u64(params, "dklen")?;
    if dklen != 32 {
        return Err(format!("keystore: dklen must be 32, got {dklen}"));
    }
    let salt = get_hex(params, "salt")?;
    if salt.len() > MAX_SALT {
        return Err(format!("keystore: salt too long ({} bytes)", salt.len()));
    }

    let mut dk = Zeroizing::new([0u8; 32]);
    match kdf {
        "scrypt" => {
            let n = get_u64(params, "n")?;
            let r = get_u64(params, "r")?;
            let p = get_u64(params, "p")?;
            let log_n = check_scrypt(n, r, p)?;
            scrypt(password, &salt, log_n, r as u32, p as u32, &mut *dk)?;
        }
        "pbkdf2" => {
            let c = get_u64(params, "c")?;
            if c == 0 || c > MAX_PBKDF2_C {
                return Err(format!("keystore: pbkdf2 c={c} outside 1..={MAX_PBKDF2_C}"));
            }
            let prf = get_str(params, "prf")?;
            if prf != "hmac-sha256" {
                return Err(format!("keystore: unsupported pbkdf2 prf {prf:?} (only hmac-sha256)"));
            }
            purecrypto::kdf::try_pbkdf2::<Sha256>(password, &salt, c as u32, &mut *dk)
                .map_err(|e| format!("keystore: pbkdf2: {e}"))?;
        }
        other => return Err(format!("keystore: unsupported kdf {other:?} (only scrypt, pbkdf2)")),
    }

    // MAC first: keccak256(dk[16..32] ‖ ciphertext).
    let mut mac_in = Zeroizing::new([0u8; 48]);
    mac_in[..16].copy_from_slice(&dk[16..32]);
    mac_in[16..].copy_from_slice(&ciphertext);
    let expect = keccak256(&*mac_in);
    if !bool::from(expect.ct_eq(&mac)) {
        return Err("keystore: wrong password (MAC mismatch — or the file is corrupted)".into());
    }

    let mut key = Zeroizing::new(ciphertext);
    {
        let mut aes_key = Zeroizing::new([0u8; 16]);
        aes_key.copy_from_slice(&dk[..16]);
        let mut ctr = Ctr::new(Aes128::new(&aes_key), &iv);
        ctr.apply_keystream(&mut *key);
    }

    let derived = address_of(&key)?;
    if let Some(claimed) = &claimed {
        if *claimed != derived {
            return Err(format!(
                "keystore: decrypted key belongs to {derived}, but the file claims {claimed}"
            ));
        }
    }
    Ok((key, claimed))
}

/// Validates untrusted scrypt parameters; returns `log2(n)`.
fn check_scrypt(n: u64, r: u64, p: u64) -> Result<u8, String> {
    if n < 2 || !n.is_power_of_two() {
        return Err(format!("keystore: scrypt n={n} must be a power of two ≥ 2"));
    }
    if r == 0 || p == 0 {
        return Err("keystore: scrypt r and p must be ≥ 1".into());
    }
    if r.saturating_mul(p) > MAX_SCRYPT_RP {
        return Err(format!("keystore: scrypt r·p={} exceeds {MAX_SCRYPT_RP}", r.saturating_mul(p)));
    }
    let mem = n.saturating_mul(r).saturating_mul(128);
    if mem > MAX_SCRYPT_MEM {
        return Err(format!("keystore: scrypt n={n}, r={r} needs {mem} bytes (limit {MAX_SCRYPT_MEM})"));
    }
    let work = n.saturating_mul(r).saturating_mul(p);
    if work > MAX_SCRYPT_WORK {
        return Err(format!("keystore: scrypt n·r·p={work} exceeds the work limit {MAX_SCRYPT_WORK}"));
    }
    Ok(n.trailing_zeros() as u8)
}

/// scrypt with already-bounded parameters (see [`check_scrypt`]).
fn scrypt(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32, out: &mut [u8]) -> Result<(), String> {
    // purecrypto rejects RFC 7914's N ≥ 2^(16·r) — only binding for r ≤ 2.
    if 16 * (r as u64) > log_n as u64 {
        return purecrypto::kdf::scrypt::scrypt(password, salt, log_n, r, p, out)
            .map_err(|e| format!("keystore: {e}"));
    }
    scrypt_fallback(password, salt, 1usize << log_n, r as usize, p as usize, out)
}

/// Plain scrypt (Percival / RFC 7914 without the `N < 2^(16r)` relation).
fn scrypt_fallback(password: &[u8], salt: &[u8], n: usize, r: usize, p: usize, out: &mut [u8]) -> Result<(), String> {
    let bs = 128 * r;
    // V (128·r·N bytes, as words): reserved fallibly, the size already capped.
    let mut vw: Zeroizing<Vec<u32>> = Zeroizing::new(Vec::new());
    vw.try_reserve_exact(32 * r * n)
        .map_err(|_| "keystore: scrypt: cannot allocate the working memory".to_string())?;
    vw.resize(32 * r * n, 0);
    let mut b = Zeroizing::new(vec![0u8; p * bs]);
    let mut x = Zeroizing::new(vec![0u32; 32 * r]);
    let mut y = Zeroizing::new(vec![0u32; 32 * r]);

    purecrypto::kdf::pbkdf2::<Sha256>(password, salt, 1, &mut b);
    for chunk in b.chunks_mut(bs) {
        for (w, c) in x.iter_mut().zip(chunk.chunks_exact(4)) {
            *w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }
        let words = 32 * r;
        for i in 0..n {
            vw[i * words..(i + 1) * words].copy_from_slice(&x);
            block_mix(&x, &mut y, r);
            core::mem::swap(&mut *x, &mut *y);
        }
        for _ in 0..n {
            let j = (x[(2 * r - 1) * 16] as usize) & (n - 1);
            for (xi, vi) in x.iter_mut().zip(&vw[j * words..(j + 1) * words]) {
                *xi ^= *vi;
            }
            block_mix(&x, &mut y, r);
            core::mem::swap(&mut *x, &mut *y);
        }
        for (c, w) in chunk.chunks_exact_mut(4).zip(x.iter()) {
            c.copy_from_slice(&w.to_le_bytes());
        }
    }
    purecrypto::kdf::pbkdf2::<Sha256>(password, &b, 1, out);
    Ok(())
}

/// scrypt BlockMix with Salsa20/8 over `2r` 64-byte (16-word) blocks.
fn block_mix(input: &[u32], out: &mut [u32], r: usize) {
    let mut t = [0u32; 16];
    t.copy_from_slice(&input[(2 * r - 1) * 16..]);
    for i in 0..2 * r {
        for (tw, iw) in t.iter_mut().zip(&input[i * 16..(i + 1) * 16]) {
            *tw ^= *iw;
        }
        salsa20_8(&mut t);
        // Even blocks to the first half, odd to the second.
        let dst = (i / 2 + (i & 1) * r) * 16;
        out[dst..dst + 16].copy_from_slice(&t);
    }
    t.zeroize();
}

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            x[$b] ^= x[$a].wrapping_add(x[$d]).rotate_left(7);
            x[$c] ^= x[$b].wrapping_add(x[$a]).rotate_left(9);
            x[$d] ^= x[$c].wrapping_add(x[$b]).rotate_left(13);
            x[$a] ^= x[$d].wrapping_add(x[$c]).rotate_left(18);
        };
    }
    for _ in 0..4 {
        qr!(0, 4, 8, 12);
        qr!(5, 9, 13, 1);
        qr!(10, 14, 2, 6);
        qr!(15, 3, 7, 11);
        qr!(0, 1, 2, 3);
        qr!(5, 6, 7, 4);
        qr!(10, 11, 8, 9);
        qr!(15, 12, 13, 14);
    }
    for (bw, xw) in b.iter_mut().zip(x.iter()) {
        *bw = bw.wrapping_add(*xw);
    }
    x.zeroize();
}

/// The lowercase 0x-hex Ethereum address of a secp256k1 private key.
fn address_of(key: &[u8; 32]) -> Result<String, String> {
    let d = Scalar::from_bytes_be(key).map_err(|_| "keystore: decrypted key is out of range".to_string())?;
    let point = ProjectivePoint::mul_generator(&d)
        .to_affine()
        .ok_or("keystore: decrypted key is zero")?;
    crate::hdderive::evm_address(&point.to_sec1_compressed())
        .map(|a| a.to_ascii_lowercase())
        .map_err(|e| format!("keystore: {e}"))
}

fn parse_address(s: &str) -> Result<String, String> {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if h.len() != 40 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("keystore: \"address\" {s:?} is not a 20-byte hex address"));
    }
    Ok(format!("0x{}", h.to_ascii_lowercase()))
}

fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn get_u64(obj: &serde_json::Map<String, Value>, k: &str) -> Result<u64, String> {
    obj.get(k)
        .and_then(as_u64)
        .ok_or_else(|| format!("keystore: missing or non-integer \"{k}\""))
}

fn get_str<'a>(obj: &'a serde_json::Map<String, Value>, k: &str) -> Result<&'a str, String> {
    obj.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("keystore: missing or non-string \"{k}\""))
}

fn get_hex(obj: &serde_json::Map<String, Value>, k: &str) -> Result<Vec<u8>, String> {
    let s = get_str(obj, k)?;
    let h = s.strip_prefix("0x").unwrap_or(s).as_bytes();
    if h.len() % 2 != 0 {
        return Err(format!("keystore: \"{k}\" has odd hex length"));
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    h.chunks_exact(2)
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| format!("keystore: \"{k}\" is not valid hex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";

    // Web3 Secret Storage Definition, "Test Vectors" (verbatim).
    const PBKDF2_VECTOR: &str = r#"{
        "crypto" : {
            "cipher" : "aes-128-ctr",
            "cipherparams" : {
                "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
            },
            "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
            "kdf" : "pbkdf2",
            "kdfparams" : {
                "c" : 262144,
                "dklen" : 32,
                "prf" : "hmac-sha256",
                "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
            },
            "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
        },
        "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version" : 3
    }"#;

    const SCRYPT_VECTOR: &str = r#"{
        "crypto" : {
            "cipher" : "aes-128-ctr",
            "cipherparams" : {
                "iv" : "83dbcc02d8ccb40e466191a123791e0e"
            },
            "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf" : "scrypt",
            "kdfparams" : {
                "dklen" : 32,
                "n" : 262144,
                "r" : 1,
                "p" : 8,
                "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
            },
            "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version" : 3
    }"#;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Encrypts `key` as a cheap (c=2) PBKDF2 v3 keystore.
    fn encrypt_pbkdf2(key: &[u8; 32], password: &[u8], crypto_key: &str, address: Option<&str>) -> String {
        let salt = [7u8; 32];
        let iv = [9u8; 16];
        let mut dk = [0u8; 32];
        purecrypto::kdf::pbkdf2::<Sha256>(password, &salt, 2, &mut dk);
        let mut ct = *key;
        Ctr::new(Aes128::new(dk[..16].try_into().unwrap()), &iv).apply_keystream(&mut ct);
        let mut m = dk[16..].to_vec();
        m.extend_from_slice(&ct);
        let mac = keccak256(&m);
        let addr = address.map(|a| format!(r#""address":"{a}","#)).unwrap_or_default();
        format!(
            r#"{{{addr}"{crypto_key}":{{"cipher":"aes-128-ctr","cipherparams":{{"iv":"{}"}},"ciphertext":"{}","kdf":"pbkdf2","kdfparams":{{"c":2,"dklen":32,"prf":"hmac-sha256","salt":"{}"}},"mac":"{}"}},"version":3}}"#,
            hex(&iv),
            hex(&ct),
            hex(&salt),
            hex(&mac)
        )
    }

    #[test]
    fn official_pbkdf2_vector() {
        let (key, addr) = decrypt_v3(PBKDF2_VECTOR, b"testpassword").unwrap();
        assert_eq!(hex(&*key), KEY);
        assert_eq!(addr, None);
        // Same vector, with the address of that key attached.
        let mut v: Value = serde_json::from_str(PBKDF2_VECTOR).unwrap();
        v["address"] = "008aeeda4d805471df9b2a5b0f38a0c3bcba786b".into();
        let (_, addr) = decrypt_v3(&v.to_string(), b"testpassword").unwrap();
        assert_eq!(addr.as_deref(), Some("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b"));
    }

    #[test]
    fn official_scrypt_vector() {
        let (key, _) = decrypt_v3(SCRYPT_VECTOR, b"testpassword").unwrap();
        assert_eq!(hex(&*key), KEY);
    }

    #[test]
    fn scrypt_fallback_matches_purecrypto() {
        for (log_n, r, p) in [(4u8, 8u32, 1u32), (10, 4, 2), (14, 1, 3)] {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            purecrypto::kdf::scrypt::scrypt(b"pw", b"salt", log_n, r, p, &mut a).unwrap();
            scrypt_fallback(b"pw", b"salt", 1 << log_n, r as usize, p as usize, &mut b).unwrap();
            assert_eq!(a, b, "log_n={log_n} r={r} p={p}");
        }
    }

    #[test]
    fn wrong_password() {
        let json = encrypt_pbkdf2(&unhex(KEY).try_into().unwrap(), b"right", "crypto", None);
        let err = decrypt_v3(&json, b"wrong").unwrap_err();
        assert!(err.contains("wrong password"), "{err}");
    }

    #[test]
    fn tampered_ciphertext() {
        let mut v: Value = serde_json::from_str(PBKDF2_VECTOR).unwrap();
        v["crypto"]["ciphertext"] = "6318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46".into();
        let err = decrypt_v3(&v.to_string(), b"testpassword").unwrap_err();
        assert!(err.contains("MAC"), "{err}");
    }

    #[test]
    fn oversized_scrypt_rejected() {
        let mut v: Value = serde_json::from_str(SCRYPT_VECTOR).unwrap();
        v["crypto"]["kdfparams"]["n"] = (1u64 << 40).into();
        let err = decrypt_v3(&v.to_string(), b"testpassword").unwrap_err();
        assert!(err.contains("limit"), "{err}");
        v["crypto"]["kdfparams"]["n"] = 262143.into();
        assert!(decrypt_v3(&v.to_string(), b"x").unwrap_err().contains("power of two"));
        v["crypto"]["kdfparams"]["n"] = 1024.into();
        v["crypto"]["kdfparams"]["p"] = 100_000.into();
        assert!(decrypt_v3(&v.to_string(), b"x").unwrap_err().contains("r·p"));
        let mut v: Value = serde_json::from_str(PBKDF2_VECTOR).unwrap();
        v["crypto"]["kdfparams"]["c"] = 10_000_001.into();
        assert!(decrypt_v3(&v.to_string(), b"x").unwrap_err().contains("pbkdf2 c"));
    }

    #[test]
    fn capitalised_crypto_and_address_checks() {
        let key: [u8; 32] = unhex(KEY).try_into().unwrap();
        let good = "0x008AEEDA4D805471DF9B2A5B0F38A0C3BCBA786B";
        let json = encrypt_pbkdf2(&key, b"pw", "Crypto", Some(good));
        let (k, addr) = decrypt_v3(&json, b"pw").unwrap();
        assert_eq!(*k, key);
        assert_eq!(addr.as_deref(), Some("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b"));

        let json = encrypt_pbkdf2(&key, b"pw", "crypto", Some("0000000000000000000000000000000000000001"));
        let err = decrypt_v3(&json, b"pw").unwrap_err();
        assert!(err.contains("claims"), "{err}");
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        for bad in [
            "", "[]", "{}", r#"{"version":2}"#, r#"{"version":3}"#, r#"{"version":3,"crypto":1}"#,
            r#"{"version":3,"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"00"},"ciphertext":"","mac":"","kdf":"scrypt","kdfparams":{}}}"#,
        ] {
            assert!(decrypt_v3(bad, b"x").is_err(), "{bad}");
        }
        let mut v: Value = serde_json::from_str(PBKDF2_VECTOR).unwrap();
        v["crypto"]["cipherparams"]["iv"] = "6087dab2f9fdbbfaddc31a909735c1".into();
        assert!(decrypt_v3(&v.to_string(), b"x").unwrap_err().contains("iv must be 16"));
        let mut v: Value = serde_json::from_str(PBKDF2_VECTOR).unwrap();
        v["crypto"]["ciphertext"] = "5318b4d5".into();
        assert!(decrypt_v3(&v.to_string(), b"x").unwrap_err().contains("ciphertext must be 32"));
    }
}
