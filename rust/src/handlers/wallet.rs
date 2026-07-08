//! Wallet object endpoints — fetch/list and create (ed25519/FROST local path).

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

/// `Wallet:probeActivity` {Keys, Networks?, RPC?} — decrypt a mnemonic-backed
/// wallet, derive the canonical addresses for each supported chain, and probe
/// each chain's RPC for on-chain activity (Go `apiWalletProbeActivity`).
/// Read-only. `Id` is the wallet id (from the object path or params).
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
            let w = crate::models::wallet::create(env, &req.name, &req.curve, &req.keys)
                .map_err(ApiError::internal)?;
            // Notify the host (balance poller / UI) that a wallet appeared.
            env.broadcast(&crate::response::event(
                "wallet:created",
                serde_json::json!({ "id": w.id, "curve": w.curve }),
            ));
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
    let secp = crate::models::wallet::create(env, &name, "secp256k1", &keys).map_err(ApiError::internal)?;
    let ed = crate::models::wallet::create(env, &name, "ed25519", &keys).map_err(ApiError::internal)?;
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
            vec![crate::models::wallet::backup_entry(&w).map_err(ApiError::internal)?]
        }
        None => crate::models::wallet::list(env)
            .map_err(ApiError::internal)?
            .iter()
            .map(crate::models::wallet::backup_entry)
            .collect::<crate::Result<Vec<_>>>()
            .map_err(ApiError::internal)?,
    };
    Ok(Value::Array(entries))
}

/// `Wallet:restore` {Files: [{Data}]} — restore wallets from backup entries (Go
/// apiWalletRestore). Returns the restored wallet ids.
pub fn restore(env: &Env, params: &Value) -> ApiResult {
    let files = params
        .get("Files")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::new(400, "Files (backup entries) required"))?;
    let mut restored = Vec::new();
    for f in files {
        let data = f
            .get("Data")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::new(400, "backup entry missing Data"))?;
        restored.push(crate::models::wallet::restore_entry(env, data).map_err(ApiError::internal)?);
    }
    Ok(serde_json::json!({ "restored": restored }))
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

/// `Wallet:importPrivateKey` {PrivateKey, Curve, Name, Keys(1)} — wrap a raw
/// 32-byte hex private key as a 1-of-1 wallet (Go apiImportPrivateKey).
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
    // 32-byte hex private key (0x optional).
    let pk_s = params
        .get("PrivateKey")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "PrivateKey required"))?
        .trim();
    let hexs = pk_s.strip_prefix("0x").or_else(|| pk_s.strip_prefix("0X")).unwrap_or(pk_s);
    if hexs.len() != 64 {
        return Err(ApiError::new(400, format!("hex private key must be 64 chars, got {}", hexs.len())));
    }
    let priv_bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| ApiError::new(400, format!("decode hex: {e}")))?;

    let w = crate::models::wallet::import_private_key(env, &name, curve, &priv_bytes, &keys[0])
        .map_err(ApiError::internal)?;
    env.broadcast(&crate::response::event(
        "wallet:created",
        serde_json::json!({ "id": w.id, "curve": w.curve, "imported": true }),
    ));
    Ok(serde_json::to_value(w).unwrap())
}
