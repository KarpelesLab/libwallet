//! Wallet object endpoints — fetch/list and create (ed25519/FROST local path).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

/// `Wallet:probeActivity` {Keys, Networks?, RPC?} — decrypt a mnemonic-backed
/// wallet, derive the canonical addresses for each supported chain, and probe
/// each chain's RPC for on-chain activity (Go `apiWalletProbeActivity`).
/// Read-only. `Id` is the wallet id (from the object path or params).
#[cfg(not(target_arch = "wasm32"))]
pub fn probe_activity(env: &Env, id: &str, params: &Value) -> ApiResult {
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    if keys.len() != 1 {
        return Err(ApiError::new(400, "probeActivity requires exactly 1 KeyDescription"));
    }
    let unlock: Vec<(String, String)> = keys
        .iter()
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain"))
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();

    let seed = crate::models::wallet::decrypt_mnemonic_seed(env, id, &unlock)
        .map_err(|e| ApiError::new(400, e.to_string()))?;

    let networks: Vec<String> = params
        .get("Networks")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    // A per-network RPC map lets callers (and tests) point each chain at a node;
    // absent entries fall back to the network's resolved RPC.
    let rpc_for = |candidate: &crate::probe::Candidate| -> Option<String> {
        if let Some(u) = params.get("RPC").and_then(|m| m.get(candidate.network_type)).and_then(Value::as_str) {
            return Some(u.to_owned());
        }
        let net = crate::models::network::fetch(env, &format!("{}.{}", candidate.network_type, candidate.network_chain_id)).ok().flatten()?;
        net.resolved_rpc().ok()
    };

    let results: Vec<Value> = crate::probe::candidates_for(&networks)
        .iter()
        .map(|c| match rpc_for(c) {
            Some(rpc) => crate::probe::probe_one(&seed, c, &rpc),
            None => {
                // No reachable RPC: derive the address but skip the probe.
                let mut out = serde_json::json!({ "network": c.network, "variant": c.variant, "curve": c.curve, "derivationPath": c.path });
                if let Ok((pubkey, address)) = crate::probe::derive_address(&seed, c) {
                    out["pubkey"] = Value::String(pubkey);
                    out["address"] = Value::String(address);
                }
                out["error"] = Value::String("no RPC available for probe".into());
                out
            }
        })
        .collect();
    Ok(Value::Array(results))
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use crate::db::SqlValue;
    use base64::Engine as _;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use xuid::Xuid;

    fn mock_rpc(result_json: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b);
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn probe_activity_decrypts_mnemonic_and_probes() {
        let env = Env::init_memory().unwrap();
        crate::models::wallet::init(&env).unwrap();

        // A mnemonic-keep WalletKey: encrypt the MnemonicKeyShare to a
        // Password-derived key (all-zero 16-byte entropy = "abandon … about").
        let wk_id = Xuid::new("wkey").to_string();
        let xid: Xuid = wk_id.parse().unwrap();
        let uuid = xid.uuid().as_bytes().to_vec();
        let priv_key = crate::keystore::password_to_ed25519("password1", &uuid).unwrap();
        let pkix = crate::keystore::public_key_to_pkix_b64(&priv_key.public()).unwrap();
        let entropy_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let share = format!(r#"{{"curve":"secp256k1","entropy":"{entropy_b64}","language":"english","passphrase":""}}"#);
        let sealed = crate::keystore::seal(share.as_bytes(), &[priv_key.public()]).unwrap();

        let wallet_id = Xuid::new("wlt").to_string();
        env.exec(
            r#"INSERT INTO "Wallet" ("Id","Name","Curve","Protocol","Threshold","Gen","Pubkey","Chaincode","Created","Modified") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
            vec![
                SqlValue::Text(wallet_id.clone()), SqlValue::Text("Seed".into()), SqlValue::Text("secp256k1".into()),
                SqlValue::Text("mnemonic".into()), SqlValue::Int(0), SqlValue::Int(1),
                SqlValue::Text(String::new()), SqlValue::Text(String::new()),
                SqlValue::Text(crate::now_rfc3339()), SqlValue::Text(crate::now_rfc3339()),
            ],
        ).unwrap();
        env.exec(
            r#"INSERT INTO "WalletKey" ("Id","Wallet","Type","Schema","Key","Data","Gen") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            vec![
                SqlValue::Text(wk_id.clone()), SqlValue::Text(wallet_id.clone()), SqlValue::Text("Password".into()),
                SqlValue::Text("mnemonic".into()), SqlValue::Text(pkix), SqlValue::Blob(sealed), SqlValue::Int(1),
            ],
        ).unwrap();

        let rpc = mock_rpc(r#""0xde0b6b3a7640000""#); // 1 ETH
        let params = serde_json::json!({
            "Keys": [{ "Type": "Password", "Id": wk_id, "Key": "password1" }],
            "Networks": ["ethereum"],
            "RPC": { "evm": rpc },
        });
        let res = probe_activity(&env, &wallet_id, &params).unwrap();
        let arr = res.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        // The decrypted mnemonic derives the canonical BIP44 ETH address.
        assert_eq!(arr[0]["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(arr[0]["balance"], "1000000000000000000");
        assert_eq!(arr[0]["hasActivity"], true);
    }

    #[test]
    fn probe_activity_rejects_wrong_password() {
        let env = Env::init_memory().unwrap();
        crate::models::wallet::init(&env).unwrap();
        let wk_id = Xuid::new("wkey").to_string();
        let xid: Xuid = wk_id.parse().unwrap();
        let uuid = xid.uuid().as_bytes().to_vec();
        let priv_key = crate::keystore::password_to_ed25519("password1", &uuid).unwrap();
        let sealed = crate::keystore::seal(br#"{"curve":"secp256k1","entropy":"AAAAAAAAAAAAAAAAAAAAAA==","language":"english","passphrase":""}"#, &[priv_key.public()]).unwrap();
        let wallet_id = Xuid::new("wlt").to_string();
        env.exec(r#"INSERT INTO "Wallet" ("Id","Name","Curve","Protocol","Threshold","Gen","Pubkey","Chaincode","Created","Modified") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
            vec![SqlValue::Text(wallet_id.clone()), SqlValue::Text("S".into()), SqlValue::Text("secp256k1".into()), SqlValue::Text("mnemonic".into()), SqlValue::Int(0), SqlValue::Int(1), SqlValue::Text(String::new()), SqlValue::Text(String::new()), SqlValue::Text(crate::now_rfc3339()), SqlValue::Text(crate::now_rfc3339())]).unwrap();
        env.exec(r#"INSERT INTO "WalletKey" ("Id","Wallet","Type","Schema","Key","Data","Gen") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            vec![SqlValue::Text(wk_id.clone()), SqlValue::Text(wallet_id.clone()), SqlValue::Text("Password".into()), SqlValue::Text("mnemonic".into()), SqlValue::Text(String::new()), SqlValue::Blob(sealed), SqlValue::Int(1)]).unwrap();

        let params = serde_json::json!({ "Keys": [{ "Type": "Password", "Id": wk_id, "Key": "wrongpass" }] });
        assert_eq!(probe_activity(&env, &wallet_id, &params).unwrap_err().code, 400);
    }
}

/// `Wallet:promoteMnemonic` {Old, Chains, New, Threshold} — migrate a
/// mnemonic-keep wallet into fresh N-of-M MPC wallets, one per chain (Go
/// `apiWalletPromoteMnemonic`). secp256k1 chains only (synchronous DKLs reshare);
/// the source wallet is left intact. `Id` is the source wallet id.
pub fn promote_mnemonic(env: &Env, id: &str, params: &Value) -> ApiResult {
    let unlock_from = |field: &str| -> Vec<(String, String)> {
        let ks: Vec<crate::sign::KeyDescription> = params.get(field).and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
        ks.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain")).map(|k| (k.id.clone(), k.key.clone())).collect()
    };
    let old_unlock = unlock_from("Old");
    let new_keys: Vec<crate::sign::KeyDescription> = params
        .get("New")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .ok_or_else(|| ApiError::new(400, "New key descriptors required"))?;
    let threshold = params.get("Threshold").and_then(Value::as_i64).unwrap_or(1);

    let chains: Vec<crate::models::wallet::ChainMigration> = params
        .get("Chains")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|c| crate::models::wallet::ChainMigration {
                    network: c.get("network").and_then(Value::as_str).unwrap_or("").to_owned(),
                    path: c.get("derivationPath").and_then(Value::as_str).unwrap_or("").to_owned(),
                    name: c.get("name").and_then(Value::as_str).unwrap_or("").to_owned(),
                    curve: c.get("curve").and_then(Value::as_str).unwrap_or("").to_owned(),
                })
                .collect()
        })
        .unwrap_or_default();

    let wallets = crate::models::wallet::promote_mnemonic(env, id, &old_unlock, &chains, &new_keys, threshold)
        .map_err(|e| ApiError::new(400, e.to_string()))?;
    Ok(serde_json::to_value(wallets).unwrap())
}

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::wallet::fetch(env, id).map_err(ApiError::internal)? {
                Some(w) => Ok(serde_json::to_value(w).unwrap()),
                None => Err(ApiError::new(404, "wallet not found")),
            },
            None => {
                let list = crate::models::wallet::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => {
            #[derive(serde::Deserialize)]
            struct CreateReq {
                #[serde(rename = "Name", default)]
                name: String,
                #[serde(rename = "Curve", default)]
                curve: String,
                #[serde(rename = "Keys", default)]
                keys: Vec<crate::sign::KeyDescription>,
            }
            let req: CreateReq =
                serde_json::from_value(params.clone()).map_err(|e| ApiError::new(400, e.to_string()))?;
            // Stream keygen progress so the Dart `wallets.create(...)` stream
            // yields at least one `Progress` before `Complete` (Go streams
            // progress during the keygen ceremony). No-op unless the FFI worker
            // installed a progress sink for this request; direct/unit callers
            // and the non-streaming FFI helpers see nothing extra.
            crate::dispatch::emit_progress(0.05); // keygen starting
            let w = crate::models::wallet::create(env, &req.name, &req.curve, &req.keys)
                .map_err(ApiError::internal)?;
            crate::dispatch::emit_progress(0.9); // keygen done, persisting
            // Notify the host (balance poller / UI) that a wallet appeared.
            env.broadcast(&crate::response::event(
                "wallet:created",
                serde_json::json!({ "id": w.id, "curve": w.curve }),
            ));
            Ok(serde_json::to_value(w).unwrap())
        }
        // PATCH Wallet/<id> — ApiUpdate: only Name is mutable (bumps Modified).
        // Returns the updated object.
        "PATCH" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            let name = params.get("Name").and_then(Value::as_str);
            match crate::models::wallet::update(env, id, name).map_err(ApiError::internal)? {
                Some(w) => Ok(serde_json::to_value(w).unwrap()),
                None => Err(ApiError::new(404, "wallet not found")),
            }
        }
        // DELETE Wallet/<id> — ApiDelete: emits wallet:deleted, then removes the
        // wallet and its keys. Returns the deleted object.
        "DELETE" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            let w = crate::models::wallet::fetch(env, id)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(404, "wallet not found"))?;
            env.broadcast(&crate::response::event(
                "wallet:deleted",
                serde_json::json!({ "id": w.id }),
            ));
            crate::models::wallet::delete(env, id).map_err(ApiError::internal)?;
            Ok(serde_json::to_value(w).unwrap())
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Wallet"))),
    }
}

/// `Wallet:multiCreate` {Name, Keys} — create both a secp256k1 (dkls23) and an
/// ed25519 (frost) wallet with the same key set (Go apiMultiCreateWallet).
/// Returns both wallets.
pub fn multi_create(env: &Env, params: &Value) -> ApiResult {
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("").to_owned();
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    // Capture one timestamp and give it to both wallets so their `Created`
    // fields are byte-identical — some hosts pair the ed25519 + secp256k1
    // wallets by equal creation time (matches Go apiMultiCreateWallet).
    let now = crate::now_rfc3339();
    let secp = crate::models::wallet::create_at(env, &name, "secp256k1", &keys, &now).map_err(ApiError::internal)?;
    let ed = crate::models::wallet::create_at(env, &name, "ed25519", &keys, &now).map_err(ApiError::internal)?;
    for w in [&secp, &ed] {
        env.broadcast(&crate::response::event(
            "wallet:created",
            serde_json::json!({ "id": w.id, "curve": w.curve }),
        ));
    }
    Ok(serde_json::json!({
        "secp256k1": serde_json::to_value(&secp).unwrap(),
        "ed25519": serde_json::to_value(&ed).unwrap(),
    }))
}

/// Browser (wasm32) async twin of the `POST Wallet` create arm. Identical
/// request shape and progress/broadcast behaviour; awaits the async
/// `models::wallet::create` so RemoteKey shares can upload over the browser
/// Fetch API. Wired in via `dispatch::handle_request_async`.
#[cfg(target_arch = "wasm32")]
pub async fn create_async(env: &Env, params: &Value) -> ApiResult {
    #[derive(serde::Deserialize)]
    struct CreateReq {
        #[serde(rename = "Name", default)]
        name: String,
        #[serde(rename = "Curve", default)]
        curve: String,
        #[serde(rename = "Keys", default)]
        keys: Vec<crate::sign::KeyDescription>,
    }
    let req: CreateReq =
        serde_json::from_value(params.clone()).map_err(|e| ApiError::new(400, e.to_string()))?;
    crate::dispatch::emit_progress(0.05); // keygen starting
    let w = crate::models::wallet::create_async(env, &req.name, &req.curve, &req.keys)
        .await
        .map_err(ApiError::internal)?;
    crate::dispatch::emit_progress(0.9); // keygen done, persisting
    env.broadcast(&crate::response::event(
        "wallet:created",
        serde_json::json!({ "id": w.id, "curve": w.curve }),
    ));
    Ok(serde_json::to_value(w).unwrap())
}

/// Browser (wasm32) async twin of [`multi_create`]. Same shared `now` for both
/// wallets; awaits each async `create_at`.
#[cfg(target_arch = "wasm32")]
pub async fn multi_create_async(env: &Env, params: &Value) -> ApiResult {
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("").to_owned();
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let now = crate::now_rfc3339();
    let secp = crate::models::wallet::create_at_async(env, &name, "secp256k1", &keys, &now)
        .await
        .map_err(ApiError::internal)?;
    let ed = crate::models::wallet::create_at_async(env, &name, "ed25519", &keys, &now)
        .await
        .map_err(ApiError::internal)?;
    for w in [&secp, &ed] {
        env.broadcast(&crate::response::event(
            "wallet:created",
            serde_json::json!({ "id": w.id, "curve": w.curve }),
        ));
    }
    Ok(serde_json::json!({
        "secp256k1": serde_json::to_value(&secp).unwrap(),
        "ed25519": serde_json::to_value(&ed).unwrap(),
    }))
}

/// `Wallet:backup` {Id?} — export the wallet(s) as backup entries (including the
/// encrypted key shares). One wallet when `Id` is given, else all (Go
/// apiWalletBackup).
pub fn backup(env: &Env, params: &Value) -> ApiResult {
    let entries = match params.get("Id").and_then(Value::as_str) {
        Some(id) => {
            let w = crate::models::wallet::fetch(env, id)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(404, "wallet not found"))?;
            vec![crate::models::wallet::backup_entry(env, &w).map_err(ApiError::internal)?]
        }
        None => crate::models::wallet::list(env)
            .map_err(ApiError::internal)?
            .iter()
            .map(|w| crate::models::wallet::backup_entry(env, w))
            .collect::<crate::Result<Vec<_>>>()
            .map_err(ApiError::internal)?,
    };
    Ok(Value::Array(entries))
}

/// `Wallet:restore` {files: [{filename, data}]} — restore wallets from backup
/// entries (Go apiWalletRestore). Accepts lowercase (Dart/Go) or capitalised
/// keys. Returns the restored wallet ids.
pub fn restore(env: &Env, params: &Value) -> ApiResult {
    // Accept both the lowercase keys the Dart client sends (`files`/`data`,
    // matching Go's `walletRestoreRequest`/`backupDataEntry` json tags) and the
    // capitalised variants some callers use — Go's json.Unmarshal is
    // case-insensitive, so both must round-trip here.
    let files = params
        .get("files")
        .or_else(|| params.get("Files"))
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::new(400, "files (backup entries) required"))?;
    let mut restored = Vec::new();
    for f in files {
        let data = f
            .get("data")
            .or_else(|| f.get("Data"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::new(400, "backup entry missing data"))?;
        restored.push(crate::models::wallet::restore_entry(env, data).map_err(ApiError::internal)?);
    }
    Ok(serde_json::json!({ "restored": restored }))
}

/// `Wallet:exportSecret` {Id, Keys(1)} — reveal a single-key imported wallet's
/// mnemonic or private key (see [`crate::models::wallet::export_secret`]).
pub fn export_secret(env: &Env, params: &Value) -> ApiResult {
    let id = params.get("Id").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Id (wallet) required"))?;
    let keys: Vec<crate::sign::KeyDescription> =
        params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    if keys.len() != 1 {
        return Err(ApiError::new(400, format!("exportSecret requires exactly 1 KeyDescription (got {})", keys.len())));
    }
    if crate::models::wallet::fetch(env, id).map_err(ApiError::internal)?.is_none() {
        return Err(ApiError::new(404, "wallet not found"));
    }
    let unlock = vec![(keys[0].id.clone(), keys[0].key.clone())];
    crate::models::wallet::export_secret(env, id, &unlock).map_err(|e| ApiError::new(400, e.to_string()))
}

/// An imported private key, decoded: a big-endian scalar, or an Ed25519 seed
/// (kept so the wallet can export it back in the standard Solana form).
pub(crate) enum DecodedKey {
    Scalar(Vec<u8>),
    Ed25519Seed([u8; 32]),
}

/// Decode an imported private key into what the 1-of-1 import wraps.
///
/// secp256k1: 32-byte hex (0x optional) or a Bitcoin-family WIF.
///
/// ed25519 — the wallet key is the secret *scalar*, while Solana wallets
/// export the RFC 8032 *seed* (whose SHA-512 expands to the scalar):
/// - a 64-byte keypair `seed ‖ pubkey` — base58 (Phantom/Solflare export), a
///   JSON byte array (solana-keygen `id.json`) or 128 hex chars — is always
///   treated as a seed, and the derived public key must match the embedded one;
/// - a 32-byte base58 string or JSON byte array is a seed;
/// - 32-byte hex is the raw scalar, as it always was, unless `Format` is
///   `"seed"`. `Format: "scalar"` forces scalar for any 32-byte input.
pub(crate) fn decode_private_key(curve: &str, input: &str, format: &str) -> Result<DecodedKey, ApiError> {
    let input = input.trim();
    if !matches!(format, "" | "seed" | "scalar") {
        return Err(ApiError::new(400, format!("unsupported Format {format:?} (expected seed or scalar)")));
    }
    let hex_body = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")).unwrap_or(input);
    let as_hex = (hex_body.len() % 2 == 0 && hex_body.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| (0..hex_body.len()).step_by(2).map(|i| u8::from_str_radix(&hex_body[i..i + 2], 16).unwrap()).collect::<Vec<u8>>());

    if curve == "secp256k1" {
        if let Some(b) = as_hex {
            if b.len() != 32 {
                return Err(ApiError::new(400, format!("hex private key must be 64 chars, got {}", hex_body.len())));
            }
            return Ok(DecodedKey::Scalar(b));
        }
        return decode_wif(input).map(DecodedKey::Scalar);
    }

    // ed25519
    let (bytes, is_hex) = if input.starts_with('[') {
        let arr: Vec<u8> = serde_json::from_str(input).map_err(|e| ApiError::new(400, format!("bad JSON key array: {e}")))?;
        (arr, false)
    } else if let Some(b) = as_hex {
        (b, true)
    } else {
        let b = bs58::decode(input).into_vec().map_err(|e| ApiError::new(400, format!("private key is neither hex nor base58: {e}")))?;
        (b, false)
    };
    match bytes.len() {
        64 => {
            if format == "scalar" {
                return Err(ApiError::new(400, "a 64-byte keypair carries a seed, not a scalar"));
            }
            let seed: [u8; 32] = bytes[..32].try_into().unwrap();
            let derived = purecrypto::ec::ed25519::Ed25519PrivateKey::from_bytes(seed).public_key().to_bytes();
            if derived[..] != bytes[32..] {
                return Err(ApiError::new(400, "keypair public key does not match its secret key"));
            }
            Ok(DecodedKey::Ed25519Seed(seed))
        }
        32 if format == "scalar" || (is_hex && format != "seed") => Ok(DecodedKey::Scalar(bytes)),
        32 => Ok(DecodedKey::Ed25519Seed(bytes.try_into().unwrap())),
        n => Err(ApiError::new(400, format!("ed25519 private key must be 32 or 64 bytes, got {n}"))),
    }
}

/// Decode a WIF private key (base58check: version ‖ 32-byte key ‖ [0x01]).
fn decode_wif(input: &str) -> Result<Vec<u8>, ApiError> {
    let raw = bs58::decode(input).into_vec().map_err(|_| ApiError::new(400, "private key is neither 32-byte hex nor WIF"))?;
    if raw.len() != 37 && raw.len() != 38 {
        return Err(ApiError::new(400, "private key is neither 32-byte hex nor WIF"));
    }
    let (body, check) = raw.split_at(raw.len() - 4);
    if purecrypto::hash::sha256(&purecrypto::hash::sha256(body))[..4] != *check {
        return Err(ApiError::new(400, "WIF checksum mismatch"));
    }
    if body.len() == 34 && body[33] != 0x01 {
        return Err(ApiError::new(400, "bad WIF compression flag"));
    }
    Ok(body[1..33].to_vec())
}

/// `Wallet:importMnemonic` {Mnemonic, Passphrase?, Curve, Name, Keys(1)} — import
/// a BIP-39 mnemonic as a 1-of-1 wallet (Go apiImportMnemonic).
pub fn import_mnemonic(env: &Env, params: &Value) -> ApiResult {
    let curve = params.get("Curve").and_then(Value::as_str).unwrap_or("");
    if curve != "secp256k1" && curve != "ed25519" {
        return Err(ApiError::new(400, format!("unsupported curve {curve:?}")));
    }
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("").to_owned();
    let mnemonic = params
        .get("Mnemonic")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Mnemonic required"))?;
    let passphrase = params.get("Passphrase").and_then(Value::as_str).unwrap_or("");
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    if keys.len() != 1 {
        return Err(ApiError::new(400, format!("import requires exactly 1 KeyDescription (got {})", keys.len())));
    }
    let w = crate::models::wallet::import_mnemonic(env, &name, curve, mnemonic, passphrase, &keys[0])
        .map_err(ApiError::internal)?;
    env.broadcast(&crate::response::event(
        "wallet:created",
        serde_json::json!({ "id": w.id, "curve": w.curve, "imported": true }),
    ));
    Ok(serde_json::to_value(w).unwrap())
}

/// `Wallet:importPrivateKey` {PrivateKey, Curve, Name, Keys(1), Format?} — wrap
/// a private key as a 1-of-1 wallet (Go apiImportPrivateKey). See
/// [`decode_private_key`] for the accepted encodings.
pub fn import_private_key(env: &Env, params: &Value) -> ApiResult {
    let curve = params.get("Curve").and_then(Value::as_str).unwrap_or("");
    if curve != "secp256k1" && curve != "ed25519" {
        return Err(ApiError::new(400, format!("unsupported curve {curve:?}")));
    }
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("").to_owned();
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    if keys.len() != 1 {
        return Err(ApiError::new(400, format!("import requires exactly 1 KeyDescription (got {})", keys.len())));
    }
    let pk_s = params
        .get("PrivateKey")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "PrivateKey required"))?;
    let format = params.get("Format").and_then(Value::as_str).unwrap_or("");
    let w = match decode_private_key(curve, pk_s, format)? {
        DecodedKey::Scalar(b) => crate::models::wallet::import_private_key(env, &name, curve, &b, &keys[0]),
        DecodedKey::Ed25519Seed(seed) => crate::models::wallet::import_ed25519_seed(env, &name, &seed, &keys[0]),
    }
    .map_err(ApiError::internal)?;
    env.broadcast(&crate::response::event(
        "wallet:created",
        serde_json::json!({ "id": w.id, "curve": w.curve, "imported": true }),
    ));
    Ok(serde_json::to_value(w).unwrap())
}
