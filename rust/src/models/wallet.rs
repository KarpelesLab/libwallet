//! wltwallet — wallets and their key shares.
//!
//! Fetch/list plus `create` for the all-local ed25519/FROST path: generate the
//! shares (party-keyed by each WalletKey's UUID, as Go does), derive the group
//! pubkey, encrypt each share per its KeyDescription, and persist the Wallet +
//! WalletKey rows. The secp256k1/DKLs23 path and cross-device (RemoteKey)
//! shares follow the same shape and land next.
//!
//! WalletKey.Data (the encrypted share) is `#[serde(skip)]` — it is loaded for
//! internal use but never emitted to the host, matching the Go `json:",protect"`
//! tag. The Dart client only reads Id/Wallet/Type/Key/Gen.

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xuid::Xuid;

use tsslib::tss::PartyId;

use crate::keystore;
use crate::sign::{KeyDescription, Recipient};
use crate::tss::{ed25519_verify, frost_group_pubkey, frost_keygen_with_parties, frost_sign_local, Key};
use crate::{Env, Error, Result, SqlValue};

const WALLET_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Wallet" ("Id" text, "Name" text, "Curve" text, "Protocol" text, "Threshold" integer, "Gen" integer, "Pubkey" text, "Chaincode" text, "Created" text, "Modified" text, PRIMARY KEY ("Id"));"#;
const WALLETKEY_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "WalletKey" ("Id" text, "Wallet" text, "Type" text, "Schema" text, "Key" text, "Data" blob, "Gen" integer, PRIMARY KEY ("Id"));"#;

const WALLET_COLS: &str =
    r#""Id", "Name", "Curve", "Protocol", "Threshold", "Gen", "Pubkey", "Chaincode", "Created", "Modified""#;
const WALLETKEY_COLS: &str = r#""Id", "Wallet", "Type", "Schema", "Key", "Data", "Gen""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Wallet {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Curve", default)]
    pub curve: String,
    #[serde(rename = "Protocol", default)]
    pub protocol: String,
    #[serde(rename = "Threshold", default)]
    pub threshold: i64,
    #[serde(rename = "Gen", default)]
    pub generation: u64,
    #[serde(rename = "Pubkey", default)]
    pub pubkey: String,
    #[serde(rename = "Chaincode", default)]
    pub chaincode: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Modified", default)]
    pub modified: String,
    #[serde(rename = "Keys", default)]
    pub keys: Vec<WalletKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WalletKey {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Wallet", default)]
    pub wallet: String,
    #[serde(rename = "Type", default)]
    pub kind: String,
    #[serde(rename = "Schema", default)]
    pub schema: String,
    #[serde(rename = "Key", default, skip_serializing_if = "String::is_empty")]
    pub key: String,
    /// Encrypted share — loaded internally, never serialized to the host.
    #[serde(skip)]
    pub data: Vec<u8>,
    #[serde(rename = "Gen", default)]
    pub generation: u64,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(WALLET_DDL)?;
    env.ensure_table(WALLETKEY_DDL)?;
    Ok(())
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Wallet>> {
    let sql = format!(r#"SELECT {WALLET_COLS} FROM "Wallet" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    match rows.first() {
        None => Ok(None),
        Some(row) => {
            let mut w = row_to_wallet(row);
            w.keys = keys_for(env, &w.id)?;
            Ok(Some(w))
        }
    }
}

pub fn list(env: &Env) -> Result<Vec<Wallet>> {
    let sql = format!(r#"SELECT {WALLET_COLS} FROM "Wallet" ORDER BY "Created" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    let mut wallets: Vec<Wallet> = rows.iter().map(|r| row_to_wallet(r)).collect();
    for w in &mut wallets {
        w.keys = keys_for(env, &w.id)?;
    }
    Ok(wallets)
}

/// The WalletKey rows belonging to a wallet.
pub fn keys_for(env: &Env, wallet_id: &str) -> Result<Vec<WalletKey>> {
    let sql = format!(r#"SELECT {WALLETKEY_COLS} FROM "WalletKey" WHERE "Wallet" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(wallet_id.to_owned())])?;
    Ok(rows.iter().map(|r| row_to_key(r)).collect())
}

/// Load a single WalletKey (including its encrypted `Data`) by id.
pub fn fetch_key(env: &Env, key_id: &str) -> Result<Option<WalletKey>> {
    let sql = format!(r#"SELECT {WALLETKEY_COLS} FROM "WalletKey" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(key_id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_key(r)))
}

/// `Wallet/Key:recrypt` — decrypt a WalletKey's share with the `old` descriptor
/// and re-encrypt it under `new`, in place (Go `walletKeyRecrypt`). The raw
/// bottle payload is re-sealed as-is, so `Schema` and the underlying share are
/// preserved. Only local schemes (Password / StoreKey / Plain) are supported;
/// RemoteKey re-encryption needs the backend fleet keys and is rejected.
pub fn recrypt_key(env: &Env, key_id: &str, old: &KeyDescription, new: &KeyDescription) -> Result<WalletKey> {
    let mut wk = fetch_key(env, key_id)?.ok_or_else(|| Error::Env("wallet key not found".into()))?;
    let xid: Xuid = key_id.parse().map_err(|e| Error::Env(format!("bad walletkey id {key_id}: {e}")))?;
    let uuid = xid.uuid().as_bytes().to_vec();

    // Decrypt with the old descriptor.
    let payload = match old.kind.as_str() {
        "Plain" => keystore::open(&wk.data, std::iter::empty())
            .map_err(|e| Error::Env(format!("open plain: {e}")))?,
        "Password" | "StoreKey" => {
            let priv_key = resolve_unlock_key(&old.kind, &old.key, &uuid)?;
            keystore::open(&wk.data, std::iter::once(priv_key))
                .map_err(|e| Error::Env(format!("decrypt with old key: {e}")))?
        }
        other => return Err(Error::Env(format!("recrypt old type {other} not supported locally"))),
    };

    // Re-encrypt with the new descriptor.
    match new.kind.as_str() {
        "Plain" => {
            wk.data = keystore::wrap_plain(&payload).map_err(|e| Error::Env(e.to_string()))?;
            wk.key = String::new();
        }
        "Password" | "StoreKey" => {
            let priv_key = resolve_unlock_key(&new.kind, &new.key, &uuid)?;
            let pub_key = priv_key.public();
            wk.key = keystore::public_key_to_pkix_b64(&pub_key).map_err(|e| Error::Env(e.to_string()))?;
            wk.data = keystore::seal(&payload, &[pub_key]).map_err(|e| Error::Env(e.to_string()))?;
        }
        other => return Err(Error::Env(format!("recrypt new type {other} not supported locally"))),
    }
    wk.kind = new.kind.clone();

    // Persist the updated row (delete + reinsert — SQLite upsert without a
    // dedicated statement; the Id is the primary key).
    env.exec(r#"DELETE FROM "WalletKey" WHERE "Id" = ?1"#, vec![SqlValue::Text(wk.id.clone())])?;
    env.exec(
        &format!(r#"INSERT INTO "WalletKey" ({WALLETKEY_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7)"#),
        vec![
            SqlValue::Text(wk.id.clone()),
            SqlValue::Text(wk.wallet.clone()),
            SqlValue::Text(wk.kind.clone()),
            SqlValue::Text(wk.schema.clone()),
            SqlValue::Text(wk.key.clone()),
            SqlValue::Blob(wk.data.clone()),
            SqlValue::Int(wk.generation as i64),
        ],
    )?;
    Ok(wk)
}

/// Create an all-local ed25519/FROST wallet: keygen (party-keyed by each
/// WalletKey UUID), derive the group pubkey, encrypt each share per its
/// KeyDescription, and persist. Port of Wallet:create's initializeFrostWallet.
/// Create a wallet, stamping `Created`/`Modified` with the current time.
pub fn create(env: &Env, name: &str, curve: &str, key_descs: &[KeyDescription]) -> Result<Wallet> {
    create_at(env, name, curve, key_descs, &crate::now_rfc3339())
}

/// Like [`create`] but uses the supplied `created` timestamp. `Wallet:multiCreate`
/// captures one `now` and passes it to both the secp256k1 and ed25519 wallets so
/// they share a byte-identical `Created` — some hosts use equal creation
/// timestamps to recognise a paired multi-create. Mirrors Go apiMultiCreateWallet,
/// which computes `now := time.Now()` once and assigns it to both.
pub fn create_at(env: &Env, name: &str, curve: &str, key_descs: &[KeyDescription], created: &str) -> Result<Wallet> {
    if key_descs.len() < 3 {
        return Err(Error::Env(format!("need at least 3 keys, got {}", key_descs.len())));
    }
    let threshold: usize = 1;
    let n = key_descs.len();
    if threshold >= n {
        return Err(Error::Env("threshold too high".into()));
    }

    let wallet_id = Xuid::new("wlt").to_string();
    // Party keys are the WalletKey UUIDs (Go derives the PartyID from WalletKey.Id.UUID).
    let wk_ids: Vec<Xuid> = (0..n).map(|_| Xuid::new("wkey")).collect();
    let party_keys: Vec<Vec<u8>> = wk_ids.iter().map(|x| x.uuid().as_bytes().to_vec()).collect();

    // Keygen per curve: FROST (ed25519) or DKLs23 (secp256k1). Both yield, for
    // each party key, that share's Go-compatible JSON, plus the group pubkey.
    // An unspecified curve defaults to secp256k1 (matches Go apiCreateWallet,
    // which only branches to the ed25519 path on an explicit "ed25519").
    let (pubkey, protocol, curve_out, shares): (String, &str, &str, Vec<(Vec<u8>, String)>) =
        match curve {
            "ed25519" => {
                let ks = frost_keygen_with_parties(party_keys, threshold)
                    .map_err(|e| Error::Env(format!("frost keygen: {e}")))?;
                let pk = b64url(&frost_group_pubkey(&ks[0].1));
                let shares = shares_json(ks, |k| k.to_json().map_err(|e| format!("{e:?}")))?;
                (pk, "frost", "ed25519", shares)
            }
            "" | "secp256k1" => {
                let ks = crate::tss::dkls_keygen_local(party_keys, threshold)
                    .map_err(|e| Error::Env(format!("dkls keygen: {e}")))?;
                let pk = b64url(&crate::tss::dkls_group_pubkey(&ks[0].1).map_err(|e| Error::Env(e.to_string()))?);
                let shares = shares_json(ks, |k| k.to_json().map_err(|e| format!("{e:?}")))?;
                (pk, "dkls23", "secp256k1", shares)
            }
            other => return Err(Error::Env(format!("unsupported curve {other:?}"))),
        };

    let mut cc = Uuid::new_v4().into_bytes().to_vec();
    cc.extend_from_slice(&Uuid::new_v4().into_bytes());
    let chaincode = b64url(&cc);
    let now = created.to_owned();

    let mut wkeys: Vec<WalletKey> = Vec::with_capacity(n);
    for (i, kd) in key_descs.iter().enumerate() {
        let uuid = wk_ids[i].uuid();
        let uuid_bytes = uuid.as_bytes();
        let json = shares
            .iter()
            .find(|(pk, _)| pk.as_slice() == uuid_bytes.as_slice())
            .map(|(_, j)| j.clone())
            .ok_or_else(|| Error::Env("share/party mismatch".into()))?;

        let (data, key_field) = seal_share_full(env, curve_out, protocol, kd, uuid_bytes, json.as_bytes())?;

        wkeys.push(WalletKey {
            id: wk_ids[i].to_string(),
            wallet: wallet_id.clone(),
            kind: kd.kind.clone(),
            schema: protocol.into(),
            key: key_field,
            data,
            generation: 1,
        });
    }

    let wallet = Wallet {
        id: wallet_id,
        name: name.to_owned(),
        curve: curve_out.into(),
        protocol: protocol.into(),
        threshold: threshold as i64,
        generation: 0,
        pubkey,
        chaincode,
        created: now.clone(),
        modified: now,
        keys: wkeys,
    };
    persist(env, &wallet)?;
    Ok(wallet)
}

/// Browser (wasm32) async twin of [`create`]. Local TSS keygen is identical; the
/// only reason this must be `async` is the RemoteKey 2FA-share upload, which on
/// wasm uses the browser Fetch API (rsurl `aio`). Native code stays sync via the
/// `#[cfg(not(wasm32))]` `create`/`create_at` above — this route bypasses
/// `seal_share_full` and inlines the same crypto with an awaited HTTP transport.
#[cfg(target_arch = "wasm32")]
pub async fn create_async(env: &Env, name: &str, curve: &str, key_descs: &[KeyDescription]) -> Result<Wallet> {
    create_at_async(env, name, curve, key_descs, &crate::now_rfc3339()).await
}

/// Browser async twin of [`create_at`] — see [`create`]. Reproduces the sync
/// `create_at`'s keygen/assembly/validation verbatim; the ONLY differences are
/// that the wdrone fleet recipients are fetched once up front (iff any RemoteKey
/// share) and each RemoteKey share is sealed + uploaded via `.await` instead of
/// through the sync `seal_share_full`.
#[cfg(target_arch = "wasm32")]
pub async fn create_at_async(env: &Env, name: &str, curve: &str, key_descs: &[KeyDescription], created: &str) -> Result<Wallet> {
    if key_descs.len() < 3 {
        return Err(Error::Env(format!("need at least 3 keys, got {}", key_descs.len())));
    }
    let threshold: usize = 1;
    let n = key_descs.len();
    if threshold >= n {
        return Err(Error::Env("threshold too high".into()));
    }

    let wallet_id = Xuid::new("wlt").to_string();
    // Party keys are the WalletKey UUIDs (Go derives the PartyID from WalletKey.Id.UUID).
    let wk_ids: Vec<Xuid> = (0..n).map(|_| Xuid::new("wkey")).collect();
    let party_keys: Vec<Vec<u8>> = wk_ids.iter().map(|x| x.uuid().as_bytes().to_vec()).collect();

    // Keygen per curve: FROST (ed25519) or DKLs23 (secp256k1). Both yield, for
    // each party key, that share's Go-compatible JSON, plus the group pubkey.
    // An unspecified curve defaults to secp256k1 (matches Go apiCreateWallet,
    // which only branches to the ed25519 path on an explicit "ed25519").
    let (pubkey, protocol, curve_out, shares): (String, &str, &str, Vec<(Vec<u8>, String)>) =
        match curve {
            "ed25519" => {
                let ks = frost_keygen_with_parties(party_keys, threshold)
                    .map_err(|e| Error::Env(format!("frost keygen: {e}")))?;
                let pk = b64url(&frost_group_pubkey(&ks[0].1));
                let shares = shares_json(ks, |k| k.to_json().map_err(|e| format!("{e:?}")))?;
                (pk, "frost", "ed25519", shares)
            }
            "" | "secp256k1" => {
                let ks = crate::tss::dkls_keygen_local(party_keys, threshold)
                    .map_err(|e| Error::Env(format!("dkls keygen: {e}")))?;
                let pk = b64url(&crate::tss::dkls_group_pubkey(&ks[0].1).map_err(|e| Error::Env(e.to_string()))?);
                let shares = shares_json(ks, |k| k.to_json().map_err(|e| format!("{e:?}")))?;
                (pk, "dkls23", "secp256k1", shares)
            }
            other => return Err(Error::Env(format!("unsupported curve {other:?}"))),
        };

    let mut cc = Uuid::new_v4().into_bytes().to_vec();
    cc.extend_from_slice(&Uuid::new_v4().into_bytes());
    let chaincode = b64url(&cc);
    let now = created.to_owned();

    // Fetch the wdrone fleet recipients ONCE, only if any share is a RemoteKey.
    // The browser rides the authenticated Spot connection (no HTTP host / CORS /
    // clientId): start + wait it once, then reuse the same client for the
    // recipients fetch AND every share upload below.
    let needs_remote = key_descs.iter().any(|kd| kd.kind == "RemoteKey");
    let spot = if needs_remote {
        let c = env.spot_start().map_err(|e| Error::Env(e.to_string()))?;
        c.wait_online(std::time::Duration::from_secs(15)).await.map_err(|e| Error::Env(format!("spot not online: {e}")))?;
        let recips = crate::walletsign::fetch_decrypt_keys(&c).await?;
        Some((c, recips))
    } else {
        None
    };

    let mut wkeys: Vec<WalletKey> = Vec::with_capacity(n);
    for (i, kd) in key_descs.iter().enumerate() {
        let uuid = wk_ids[i].uuid();
        let uuid_bytes = uuid.as_bytes();
        let json = shares
            .iter()
            .find(|(pk, _)| pk.as_slice() == uuid_bytes.as_slice())
            .map(|(_, j)| j.clone())
            .ok_or_else(|| Error::Env("share/party mismatch".into()))?;

        let (data, key_field) = match kd.resolve(uuid_bytes).map_err(|e| Error::Env(e.to_string()))? {
            Recipient::Encrypt(pk) => {
                let sealed = keystore::seal(json.as_bytes(), &[pk.clone()]).map_err(|e| Error::Env(e.to_string()))?;
                let pkix = keystore::public_key_to_pkix_b64(&pk).map_err(|e| Error::Env(e.to_string()))?;
                (sealed, pkix)
            }
            Recipient::Plain => (keystore::wrap_plain(json.as_bytes()).map_err(|e| Error::Env(e.to_string()))?, String::new()),
            Recipient::Remote => {
                let (client, recips) = spot.as_ref().ok_or_else(|| Error::Env("no fleet recipients".into()))?;
                let payload = build_remote_payload(curve_out, json.as_bytes())?;
                let sealed = keystore::seal_json(&payload, recips).map_err(|e| Error::Env(e.to_string()))?;
                upload_remote_share_wasm(client, &kd.key, curve_out, protocol, &sealed).await?;
                (sealed, kd.key.clone())
            }
        };

        wkeys.push(WalletKey {
            id: wk_ids[i].to_string(),
            wallet: wallet_id.clone(),
            kind: kd.kind.clone(),
            schema: protocol.into(),
            key: key_field,
            data,
            generation: 1,
        });
    }

    let wallet = Wallet {
        id: wallet_id,
        name: name.to_owned(),
        curve: curve_out.into(),
        protocol: protocol.into(),
        threshold: threshold as i64,
        generation: 0,
        pubkey,
        chaincode,
        created: now.clone(),
        modified: now,
        keys: wkeys,
    };
    persist(env, &wallet)?;
    Ok(wallet)
}

/// Upload a sealed RemoteKey share to `Crypto/WalletSign:setGeneratedKey` over
/// the authenticated Spot connection (`spot_do` → `@/p_api`), not HTTP Fetch.
/// Mirrors the native [`crate::walletsign::upload_generated_key`] params; no
/// critical-retry wrapper (the browser create path is not the reshare
/// desync-risk path). `client` must already be online.
#[cfg(target_arch = "wasm32")]
async fn upload_remote_share_wasm(client: &spotlib::Client, remote_key: &str, curve: &str, protocol: &str, data_cbor: &[u8]) -> Result<()> {
    let mut params = serde_json::json!({
        "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data_cbor),
        "key": remote_key,
        "curve": curve,
    });
    if !protocol.is_empty() {
        params["protocol"] = serde_json::json!(protocol);
    }
    crate::rest::spot_do(client, "Crypto/WalletSign:setGeneratedKey", "POST", &params).await?;
    Ok(())
}

/// Create a legacy eddsatss (GG18-style Ed25519) wallet — the pre-FROST ed25519
/// scheme. Go retired legacy keygen (only FROST is minted now), so this exists
/// to build legacy wallets for migration/round-trip testing and to mirror the
/// on-disk shape (Protocol="eddsa", Schema="") that Rust must open + sign.
pub fn create_eddsa_legacy(env: &Env, name: &str, threshold: usize, key_descs: &[KeyDescription]) -> Result<Wallet> {
    let n = key_descs.len();
    if n < 2 || threshold >= n {
        return Err(Error::Env(format!("invalid n={n}, threshold={threshold}")));
    }
    let wallet_id = Xuid::new("wlt").to_string();
    let wk_ids: Vec<Xuid> = (0..n).map(|_| Xuid::new("wkey")).collect();
    let party_keys: Vec<Vec<u8>> = wk_ids.iter().map(|x| x.uuid().as_bytes().to_vec()).collect();
    let shares = crate::tss::eddsa_keygen_local(party_keys, threshold).map_err(|e| Error::Env(e.to_string()))?;
    let pubkey = b64url(&crate::tss::eddsa_group_pubkey(&shares[0].1).map_err(|e| Error::Env(e.to_string()))?);

    let now = crate::now_rfc3339();
    let mut wkeys = Vec::with_capacity(n);
    for (i, kd) in key_descs.iter().enumerate() {
        let uuid = wk_ids[i].uuid();
        let uuid_bytes = uuid.as_bytes();
        let key = shares.iter().find(|(pid, _)| pid.key == uuid_bytes.as_slice()).map(|(_, k)| k).ok_or_else(|| Error::Env("share/party mismatch".into()))?;
        let share_json = key.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;
        // Legacy shares carry Schema="" (Go marshals the eddsatss Key directly).
        let (data, key_field) = seal_share(share_json.as_bytes(), kd, uuid_bytes)?;
        wkeys.push(WalletKey { id: wk_ids[i].to_string(), wallet: wallet_id.clone(), kind: kd.kind.clone(), schema: String::new(), key: key_field, data, generation: 1 });
    }
    let wallet = Wallet {
        id: wallet_id,
        name: name.to_owned(),
        curve: "ed25519".into(),
        protocol: "eddsa".into(),
        threshold: threshold as i64,
        generation: 0,
        pubkey,
        chaincode: String::new(),
        created: now.clone(),
        modified: now,
        keys: wkeys,
    };
    persist(env, &wallet)?;
    Ok(wallet)
}

/// Create a legacy ecdsatss (GG18 secp256k1) wallet — the pre-DKLs secp256k1
/// scheme. Like [`create_eddsa_legacy`], exists to build legacy fixtures + mirror
/// the on-disk shape (Protocol="gg18", Schema="") Rust must open + sign.
/// `safe_prime_bits` sets the Paillier size (small = fast test fixtures).
pub fn create_ecdsa_legacy(env: &Env, name: &str, threshold: usize, safe_prime_bits: usize, key_descs: &[KeyDescription]) -> Result<Wallet> {
    let n = key_descs.len();
    if n < 2 || threshold >= n {
        return Err(Error::Env(format!("invalid n={n}, threshold={threshold}")));
    }
    let wallet_id = Xuid::new("wlt").to_string();
    let wk_ids: Vec<Xuid> = (0..n).map(|_| Xuid::new("wkey")).collect();
    let party_keys: Vec<Vec<u8>> = wk_ids.iter().map(|x| x.uuid().as_bytes().to_vec()).collect();
    let shares = crate::tss::ecdsa_keygen_local(party_keys, threshold, safe_prime_bits).map_err(|e| Error::Env(e.to_string()))?;
    let pubkey = b64url(&crate::tss::ecdsa_group_pubkey(&shares[0].1).map_err(|e| Error::Env(e.to_string()))?);
    let mut cc = Uuid::new_v4().into_bytes().to_vec();
    cc.extend_from_slice(&Uuid::new_v4().into_bytes());

    let now = crate::now_rfc3339();
    let mut wkeys = Vec::with_capacity(n);
    for (i, kd) in key_descs.iter().enumerate() {
        let uuid = wk_ids[i].uuid();
        let uuid_bytes = uuid.as_bytes();
        let key = shares.iter().find(|(pid, _)| pid.key == uuid_bytes.as_slice()).map(|(_, k)| k).ok_or_else(|| Error::Env("share/party mismatch".into()))?;
        let share_json = key.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;
        let (data, key_field) = seal_share(share_json.as_bytes(), kd, uuid_bytes)?;
        wkeys.push(WalletKey { id: wk_ids[i].to_string(), wallet: wallet_id.clone(), kind: kd.kind.clone(), schema: String::new(), key: key_field, data, generation: 1 });
    }
    let wallet = Wallet {
        id: wallet_id,
        name: name.to_owned(),
        curve: "secp256k1".into(),
        protocol: "gg18".into(),
        threshold: threshold as i64,
        generation: 0,
        pubkey,
        chaincode: b64url(&cc),
        created: now.clone(),
        modified: now,
        keys: wkeys,
    };
    persist(env, &wallet)?;
    Ok(wallet)
}

/// Import a raw 32-byte private-key scalar as a 1-of-1 wallet with a fresh random
/// chain code (Go `Wallet:importPrivateKey`).
pub fn import_private_key(
    env: &Env,
    name: &str,
    curve: &str,
    priv_bytes: &[u8],
    key_desc: &KeyDescription,
) -> Result<Wallet> {
    let mut cc = Uuid::new_v4().into_bytes().to_vec();
    cc.extend_from_slice(&Uuid::new_v4().into_bytes());
    import_scalar(env, name, curve, priv_bytes, &cc, key_desc)
}

/// Import a raw scalar as a 1-of-1 wallet with an explicit `chaincode` (Go
/// `buildImportedWallet`): wrap the key as a single TSS share, seal it to the one
/// recipient, and persist. `priv_bytes` is the big-endian scalar. `import_private_key`
/// and `import_mnemonic` differ only in the chain code they pass.
pub fn import_scalar(
    env: &Env,
    name: &str,
    curve: &str,
    priv_bytes: &[u8],
    chaincode_bytes: &[u8],
    key_desc: &KeyDescription,
) -> Result<Wallet> {
    let wallet_id = Xuid::new("wlt").to_string();
    let wk_id = Xuid::new("wkey");
    let uuid = wk_id.uuid();
    let uuid_bytes = uuid.as_bytes();

    let (pubkey, protocol, curve_out, share_json): (String, &str, &str, String) = match curve {
        "" | "ed25519" => {
            let (_p, key) = crate::tss::frost_import_key(priv_bytes, uuid_bytes)
                .map_err(|e| Error::Env(format!("frost import: {e}")))?;
            let pk = b64url(&frost_group_pubkey(&key));
            (pk, "frost", "ed25519", key.to_json().map_err(|e| Error::Env(format!("{e:?}")))?)
        }
        "secp256k1" => {
            let arr: [u8; 32] = priv_bytes
                .try_into()
                .map_err(|_| Error::Env("secp256k1 private key must be 32 bytes".into()))?;
            let (_p, key) = crate::tss::dkls_import_key(&arr, uuid_bytes)
                .map_err(|e| Error::Env(format!("dkls import: {e}")))?;
            let pk = b64url(&crate::tss::dkls_group_pubkey(&key).map_err(|e| Error::Env(e.to_string()))?);
            (pk, "dkls23", "secp256k1", key.to_json().map_err(|e| Error::Env(format!("{e:?}")))?)
        }
        other => return Err(Error::Env(format!("unsupported curve {other:?}"))),
    };

    let chaincode = b64url(chaincode_bytes);
    let now = crate::now_rfc3339();

    // Seal the single share to its recipient (same schemes as create).
    let (data, key_field) = seal_share(share_json.as_bytes(), key_desc, uuid_bytes)?;

    let wallet = Wallet {
        id: wallet_id.clone(),
        name: name.to_owned(),
        curve: curve_out.into(),
        protocol: protocol.into(),
        threshold: 0,
        generation: 0,
        pubkey,
        chaincode,
        created: now.clone(),
        modified: now,
        keys: vec![WalletKey {
            id: wk_id.to_string(),
            wallet: wallet_id,
            kind: key_desc.kind.clone(),
            schema: protocol.into(),
            key: key_field,
            data,
            generation: 1,
        }],
    };
    persist(env, &wallet)?;
    Ok(wallet)
}

/// One chain to migrate in `promote_mnemonic`: a derivation path + optional
/// name (secp256k1 only for now — the DKLs reshare is synchronous/local).
pub struct ChainMigration {
    pub network: String,
    pub path: String,
    pub name: String,
    pub curve: String,
}

/// `Wallet:promoteMnemonic` — migrate a mnemonic-keep wallet into fresh N-of-M
/// MPC (DKLs23) wallets, one per chain (Go `PromoteMnemonic`). Decrypt the
/// mnemonic once, then for each secp256k1 chain: derive the privkey at its path,
/// import it as a 1-of-1 DKLs key, and reshare it into the `new_keys` committee
/// (synchronous — no broker). The source wallet is left untouched. ed25519
/// chains (FROST reshare over a broker) are deferred.
pub fn promote_mnemonic(
    env: &Env,
    wallet_id: &str,
    old_unlock: &[(String, String)],
    chains: &[ChainMigration],
    new_keys: &[KeyDescription],
    threshold: i64,
) -> Result<Vec<Wallet>> {
    if chains.is_empty() {
        return Err(Error::Env("promoteMnemonic: at least one chain required".into()));
    }
    if new_keys.len() < 2 {
        return Err(Error::Env("promoteMnemonic: New must contain at least 2 KeyDescriptions".into()));
    }
    if threshold < 1 || threshold as usize >= new_keys.len() {
        return Err(Error::Env(format!("promoteMnemonic: Threshold must be 1 ≤ T < {}", new_keys.len())));
    }
    let seed = decrypt_mnemonic_seed(env, wallet_id, old_unlock)?;

    let mut results = Vec::with_capacity(chains.len());
    for chain in chains {
        let curve = if chain.curve.is_empty() { "secp256k1" } else { chain.curve.as_str() };
        if curve != "secp256k1" {
            return Err(Error::Env(format!("promoteMnemonic: curve {curve} not yet supported (secp256k1 only)")));
        }
        let (privkey, cc) = crate::hdderive::derive_secp_privkey_and_chaincode(&seed, &chain.path)
            .map_err(|e| Error::Env(e.to_string()))?;
        // Import the derived key as a 1-of-1 DKLs source, then reshare.
        let src_uuid = Xuid::new("wkey");
        let (_pid, src_key) = crate::tss::dkls_import_key(&privkey, src_uuid.uuid().as_bytes())
            .map_err(|e| Error::Env(e.to_string()))?;

        let new_wk_ids: Vec<Xuid> = (0..new_keys.len()).map(|_| Xuid::new("wkey")).collect();
        let party_keys: Vec<Vec<u8>> = new_wk_ids.iter().map(|id| id.uuid().as_bytes().to_vec()).collect();
        let reshared = crate::tss::dkls_reshare(src_key, party_keys, threshold as usize)
            .map_err(|e| Error::Env(e.to_string()))?;
        let pubkey = b64url(&crate::tss::dkls_group_pubkey(&reshared[0].1).map_err(|e| Error::Env(e.to_string()))?);

        let new_wallet_id = Xuid::new("wlt").to_string();
        let name = if chain.name.trim().is_empty() { format!("{} / {}", "Seed", chain.network) } else { chain.name.clone() };
        let mut keys = Vec::with_capacity(new_keys.len());
        for (wk_id, key_desc) in new_wk_ids.iter().zip(new_keys) {
            let uuid = wk_id.uuid();
            let uuid_bytes = uuid.as_bytes();
            let key = reshared
                .iter()
                .find(|(pid, _)| pid.key == uuid_bytes)
                .map(|(_, k)| k)
                .ok_or_else(|| Error::Env("reshare produced no share for a new key".into()))?;
            let share_json = key.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;
            let (data, key_field) = seal_share(share_json.as_bytes(), key_desc, uuid_bytes)?;
            keys.push(WalletKey {
                id: wk_id.to_string(),
                wallet: new_wallet_id.clone(),
                kind: key_desc.kind.clone(),
                schema: "dkls23".into(),
                key: key_field,
                data,
                generation: 1,
            });
        }
        let now = crate::now_rfc3339();
        let wallet = Wallet {
            id: new_wallet_id,
            name,
            curve: "secp256k1".into(),
            protocol: "dkls23".into(),
            threshold,
            generation: 0,
            pubkey,
            chaincode: b64url(&cc),
            created: now.clone(),
            modified: now,
            keys,
        };
        persist(env, &wallet)?;
        results.push(wallet);
    }
    Ok(results)
}

/// `Wallet:promote` — convert a 1-of-1 imported wallet (mnemonic-keep, or a
/// raw-import stored as a 1-of-1 DKLs share) into a real N-of-T secp256k1
/// DKLs23 committee (Go `Wallet.Promote`). The imported key lives only on this
/// device, so the reshare runs entirely locally; new RemoteKey shares upload to
/// the wdrone. Master pubkey + chaincode are preserved. secp256k1 only (ed25519
/// FROST import needs clamped-scalar extraction — deferred, as in promoteMnemonic).
pub fn promote(
    env: &Env,
    wallet_id: &str,
    old_unlock: &[(String, String)],
    new_keys: &[KeyDescription],
    threshold: i64,
) -> Result<Wallet> {
    let wallet = fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    if wallet.keys.len() != 1 {
        return Err(Error::Env(format!("Promote requires a 1-of-1 imported wallet (got {} keys)", wallet.keys.len())));
    }
    if new_keys.len() < 2 {
        return Err(Error::Env("Promote: New must contain at least 2 KeyDescriptions".into()));
    }
    if threshold < 1 || threshold as usize >= new_keys.len() {
        return Err(Error::Env(format!("Promote: Threshold must be 1 ≤ T < {}", new_keys.len())));
    }
    if wallet.curve != "secp256k1" {
        return Err(Error::Env("Promote: secp256k1 only (ed25519 deferred)".into()));
    }
    let imported = &wallet.keys[0];

    // Recover the source 1-of-1 DKLs key from the imported share.
    let src_uuid = Xuid::new("wkey");
    let src_key: tsslib::dklstss::Key = match imported.schema.as_str() {
        "mnemonic" => {
            let seed = decrypt_mnemonic_seed(env, wallet_id, old_unlock)?;
            let master = crate::hdderive::derive_privkey_from_seed(&seed, "secp256k1", "m").map_err(|e| Error::Env(e.to_string()))?;
            crate::tss::dkls_import_key(&master, src_uuid.uuid().as_bytes()).map_err(|e| Error::Env(e.to_string()))?.1
        }
        "dkls23" => {
            // A raw private-key import already stored as a 1-of-1 DKLs share.
            let (_, secret) = old_unlock.first().cloned().unwrap_or_default();
            let xid: Xuid = imported.id.parse().map_err(|e| Error::Env(format!("bad walletkey id: {e}")))?;
            let uuid = xid.uuid().as_bytes().to_vec();
            let json = if imported.kind == "Plain" {
                keystore::open(&imported.data, []).map_err(|e| Error::Env(e.to_string()))?
            } else {
                let k = resolve_unlock_key(&imported.kind, &secret, &uuid)?;
                keystore::open(&imported.data, [k]).map_err(|e| Error::Env(e.to_string()))?
            };
            tsslib::dklstss::Key::from_json(std::str::from_utf8(&json).map_err(|e| Error::Env(e.to_string()))?)
                .map_err(|e| Error::Env(format!("load imported dkls share: {e:?}")))?
        }
        other => return Err(Error::Env(format!("Promote requires an imported wallet (schema mnemonic/dkls23; got {other:?})"))),
    };

    // Reshare 1-of-1 → the new committee (synchronous, all-local).
    let new_wk_ids: Vec<Xuid> = (0..new_keys.len()).map(|_| Xuid::new("wkey")).collect();
    let party_keys: Vec<Vec<u8>> = new_wk_ids.iter().map(|id| id.uuid().as_bytes().to_vec()).collect();
    let reshared = crate::tss::dkls_reshare(src_key, party_keys, threshold as usize).map_err(|e| Error::Env(e.to_string()))?;
    let new_pubkey = b64url(&crate::tss::dkls_group_pubkey(&reshared[0].1).map_err(|e| Error::Env(e.to_string()))?);
    if new_pubkey != wallet.pubkey {
        return Err(Error::Env("promote produced a share with a different group pubkey".into()));
    }

    // Seal each new share per its KeyDescription (RemoteKey uploads to the wdrone).
    let mut wkeys: Vec<WalletKey> = Vec::with_capacity(new_keys.len());
    for (wk_id, kd) in new_wk_ids.iter().zip(new_keys) {
        let uuid = wk_id.uuid();
        let uuid_bytes = uuid.as_bytes();
        let key = reshared
            .iter()
            .find(|(pid, _)| pid.key == uuid_bytes)
            .map(|(_, k)| k)
            .ok_or_else(|| Error::Env("reshare produced no share for a new key".into()))?;
        let share_json = key.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;
        let (data, key_field) = seal_share_full(env, "secp256k1", "dkls23", kd, uuid_bytes, share_json.as_bytes())?;
        wkeys.push(WalletKey {
            id: wk_id.to_string(),
            wallet: wallet.id.clone(),
            kind: kd.kind.clone(),
            schema: "dkls23".into(),
            key: key_field,
            data,
            generation: wallet.generation + 1,
        });
    }

    // Swap the committee in place; advance protocol + threshold, keep pubkey/cc.
    replace_wallet_keys(env, &wallet, &wkeys)?;
    env.exec(
        r#"UPDATE "Wallet" SET "Protocol" = ?1, "Threshold" = ?2 WHERE "Id" = ?3"#,
        vec![SqlValue::Text("dkls23".into()), SqlValue::Int(threshold), SqlValue::Text(wallet.id.clone())],
    )?;
    fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet vanished after promote".into()))
}

/// Persist the mobile's wallet after a `Wallet:initiateKeygen` ceremony: a
/// single RemoteKey-typed FROST share (uploaded to the wdrone), pubkey = the
/// group key, no chaincode (Solana uses path "m"). Returns the wallet id.
pub fn persist_agent_keygen(
    env: &Env,
    name: &str,
    pubkey_b64url: &str,
    remote_key: &str,
    share: &Key,
) -> Result<String> {
    let wallet_id = Xuid::new("wlt").to_string();
    let wk_id = Xuid::new("wkey");
    let share_json = share.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;
    let kd = KeyDescription { kind: "RemoteKey".into(), key: remote_key.to_string(), id: String::new() };
    let (data, key_field) = seal_share_full(env, "ed25519", "frost", &kd, wk_id.uuid().as_bytes(), share_json.as_bytes())?;
    let now = crate::now_rfc3339();
    let wallet = Wallet {
        id: wallet_id.clone(),
        name: name.to_owned(),
        curve: "ed25519".into(),
        protocol: "frost".into(),
        threshold: 1,
        generation: 1,
        pubkey: pubkey_b64url.to_owned(),
        chaincode: String::new(),
        created: now.clone(),
        modified: now,
        keys: vec![WalletKey {
            id: wk_id.to_string(),
            wallet: wallet_id.clone(),
            kind: "RemoteKey".into(),
            schema: "frost".into(),
            key: key_field,
            data,
            generation: 1,
        }],
    };
    persist(env, &wallet)?;
    Ok(wallet_id)
}

/// Browser (wasm32) async twin of [`persist_agent_keygen`]. Identical wallet /
/// WalletKey assembly; the ONLY difference is the single RemoteKey share is
/// sealed to the fleet recipients and uploaded over the browser Fetch transport
/// (`.await`) instead of through the sync `seal_share_full` critical-retry path.
#[cfg(target_arch = "wasm32")]
pub async fn persist_agent_keygen_async(
    env: &Env,
    name: &str,
    pubkey_b64url: &str,
    remote_key: &str,
    share: &Key,
) -> Result<String> {
    let wallet_id = Xuid::new("wlt").to_string();
    let wk_id = Xuid::new("wkey");
    let share_json = share.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;

    // Seal the FROST share to the wdrone fleet recipients + upload it, both over
    // the authenticated Spot connection (start + wait once, then reuse).
    let client = env.spot_start().map_err(|e| Error::Env(e.to_string()))?;
    client.wait_online(std::time::Duration::from_secs(15)).await.map_err(|e| Error::Env(format!("spot not online: {e}")))?;
    let recipients = crate::walletsign::fetch_decrypt_keys(&client).await?;
    let payload = build_remote_payload("ed25519", share_json.as_bytes())?;
    let sealed = keystore::seal_json(&payload, &recipients).map_err(|e| Error::Env(e.to_string()))?;
    upload_remote_share_wasm(&client, remote_key, "ed25519", "frost", &sealed).await?;
    let (data, key_field) = (sealed, remote_key.to_string());

    let now = crate::now_rfc3339();
    let wallet = Wallet {
        id: wallet_id.clone(),
        name: name.to_owned(),
        curve: "ed25519".into(),
        protocol: "frost".into(),
        threshold: 1,
        generation: 1,
        pubkey: pubkey_b64url.to_owned(),
        chaincode: String::new(),
        created: now.clone(),
        modified: now,
        keys: vec![WalletKey {
            id: wk_id.to_string(),
            wallet: wallet_id.clone(),
            kind: "RemoteKey".into(),
            schema: "frost".into(),
            key: key_field,
            data,
            generation: 1,
        }],
    };
    persist(env, &wallet)?;
    Ok(wallet_id)
}

/// Seal a share payload to a KeyDescription recipient, returning `(sealed data,
/// Key field)`. Encrypt → bottle + PKIX pubkey; Plain → unencrypted bottle;
/// Remote → error (needs the backend).
fn seal_share(payload: &[u8], key_desc: &KeyDescription, uuid: &[u8]) -> Result<(Vec<u8>, String)> {
    match key_desc.resolve(uuid).map_err(|e| Error::Env(e.to_string()))? {
        Recipient::Encrypt(pk) => {
            let sealed = keystore::seal(payload, &[pk.clone()]).map_err(|e| Error::Env(e.to_string()))?;
            let pkix = keystore::public_key_to_pkix_b64(&pk).map_err(|e| Error::Env(e.to_string()))?;
            Ok((sealed, pkix))
        }
        Recipient::Plain => Ok((keystore::wrap_plain(payload).map_err(|e| Error::Env(e.to_string()))?, String::new())),
        Recipient::Remote => Err(Error::Env("RemoteKey shares need the backend (not yet ported)".into())),
    }
}

/// Import a BIP-39 mnemonic as a mnemonic-keep 1-of-1 wallet (Go
/// `Wallet:importMnemonic` / `buildImportedWallet`): validate the mnemonic, seal
/// the `MnemonicKeyShare` (entropy/passphrase/curve) as the WalletKey Data with
/// Schema "mnemonic", and store the wallet whose Pubkey/Chaincode are the
/// BIP-32/SLIP-0010 master (so accounts derive as they do for TSS wallets, and
/// the wallet is byte-compatible with Go). Signing decrypts the mnemonic and
/// re-derives the key at sign time (see dkls_sign_digest / sign_frost_local).
pub fn import_mnemonic(
    env: &Env,
    name: &str,
    curve: &str,
    mnemonic: &str,
    passphrase: &str,
    key_desc: &KeyDescription,
) -> Result<Wallet> {
    let mnemonic = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    let entropy = crate::bip39::mnemonic_to_entropy(&mnemonic)?; // checksum validation
    let curve_out = if curve.is_empty() { "ed25519" } else { curve };
    let seed = crate::bip39::mnemonic_to_seed(&mnemonic, passphrase);
    let (_master, cc) = crate::bip39::master_from_seed(&seed, curve_out)?;
    let pubkey = crate::hdderive::master_pubkey(&seed, curve_out).map_err(|e| Error::Env(e.to_string()))?;

    let wallet_id = Xuid::new("wlt").to_string();
    let wk_id = Xuid::new("wkey");
    let uuid = wk_id.uuid();
    let uuid_bytes = uuid.as_bytes();

    // MnemonicKeyShare (Go format: entropy is a base64-std []byte string).
    let share_json = serde_json::json!({
        "curve": curve_out,
        "entropy": base64::engine::general_purpose::STANDARD.encode(&entropy),
        "language": "english",
        "passphrase": passphrase,
    })
    .to_string();
    let (data, key_field) = seal_share(share_json.as_bytes(), key_desc, uuid_bytes)?;

    let now = crate::now_rfc3339();
    let wallet = Wallet {
        id: wallet_id.clone(),
        name: name.to_owned(),
        curve: curve_out.into(),
        protocol: "mnemonic".into(),
        threshold: 0,
        generation: 0,
        pubkey: b64url(&pubkey),
        chaincode: b64url(&cc),
        created: now.clone(),
        modified: now,
        keys: vec![WalletKey {
            id: wk_id.to_string(),
            wallet: wallet_id,
            kind: key_desc.kind.clone(),
            schema: "mnemonic".into(),
            key: key_field,
            data,
            generation: 1,
        }],
    };
    persist(env, &wallet)?;
    Ok(wallet)
}

/// Build the device-transfer payload for `wallet_id` (Go `buildTransferPayload`):
/// `{v, wallet: <backup JSON>, device_shares}`. The wallet blob is the same
/// backup shape `Wallet:restore` consumes, so the import side reuses restore.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_transfer_payload(env: &Env, wallet_id: &str, device_shares: &serde_json::Value) -> Result<Vec<u8>> {
    let w = fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    let entry = backup_entry(&w)?;
    let data_b64 = entry.get("data").and_then(|v| v.as_str()).ok_or_else(|| Error::Env("backup produced no data".into()))?;
    let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data_b64)
        .map_err(|e| Error::Env(format!("decode backup: {e}")))?;
    let wallet_json: serde_json::Value = serde_json::from_slice(&blob).map_err(|e| Error::Env(format!("parse backup: {e}")))?;
    let payload = serde_json::json!({
        "v": crate::transfer::PROTOCOL_VERSION,
        "wallet": wallet_json,
        "device_shares": device_shares,
    });
    serde_json::to_vec(&payload).map_err(|e| Error::Env(e.to_string()))
}

/// Serialize a wallet for `Wallet:backup` — includes the encrypted key `Data`
/// (base64, as Go marshals `[]byte`), unlike the FFI response which skips it.
/// Returns the `{filename, data}` backup entry (Go `doBackup`). The entry
/// envelope keys are **lowercase** to match Go's `backupDataEntry` struct tags
/// (`json:"filename"` / `json:"data"`) and the Dart `WalletBackupEntry` model,
/// which reads `json['filename']`/`json['data']`. (The inner wallet JSON inside
/// `data` keeps its capitalised Go field names — that blob must stay
/// byte-compatible with Go's `json.Marshal(*Wallet)`.)
pub fn backup_entry(w: &Wallet) -> Result<serde_json::Value> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    if w.keys.is_empty() {
        return Err(Error::Env("wallet has no keys, cannot be backed up".into()));
    }
    let keys: Vec<serde_json::Value> = w
        .keys
        .iter()
        .map(|k| {
            serde_json::json!({
                "Id": k.id, "Wallet": k.wallet, "Type": k.kind, "Schema": k.schema,
                "Key": k.key, "Data": STANDARD.encode(&k.data), "Gen": k.generation,
            })
        })
        .collect();
    let wj = serde_json::json!({
        "Id": w.id, "Name": w.name, "Curve": w.curve, "Protocol": w.protocol,
        "Threshold": w.threshold, "Gen": w.generation, "Pubkey": w.pubkey,
        "Chaincode": w.chaincode, "Created": w.created, "Modified": w.modified, "Keys": keys,
    });
    let buf = serde_json::to_vec(&wj).map_err(|e| Error::Env(e.to_string()))?;
    let uuid = Xuid::parse_prefix(&w.id, "wlt")
        .map_err(|_| Error::Env("bad wallet id".into()))?
        .uuid();
    Ok(serde_json::json!({
        "filename": format!("wallet_{}.dat", URL_SAFE_NO_PAD.encode(uuid.as_bytes())),
        "data": URL_SAFE_NO_PAD.encode(&buf),
    }))
}

/// Restore a wallet from a `Wallet:backup` entry's base64url `Data` (Go
/// `restoreSingleWalletFile`): decode + parse + persist. Skips a wallet that
/// already exists. Returns the restored wallet id.
pub fn restore_entry(env: &Env, data_b64url: &str) -> Result<String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let buf = URL_SAFE_NO_PAD.decode(data_b64url).map_err(|e| Error::Env(format!("bad backup base64: {e}")))?;
    let wj: serde_json::Value =
        serde_json::from_slice(&buf).map_err(|e| Error::Env(format!("bad backup json: {e}")))?;
    let s = |k: &str| wj.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let id = s("Id");
    if id.is_empty() {
        return Err(Error::Env("backup missing wallet Id".into()));
    }
    if fetch(env, &id)?.is_some() {
        return Ok(id); // already present — idempotent restore
    }
    let keys: Vec<WalletKey> = wj
        .get("Keys")
        .and_then(|k| k.as_array())
        .map(|arr| {
            arr.iter()
                .map(|k| {
                    let ks = |f: &str| k.get(f).and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    WalletKey {
                        id: ks("Id"),
                        wallet: ks("Wallet"),
                        kind: ks("Type"),
                        schema: ks("Schema"),
                        key: ks("Key"),
                        data: STANDARD.decode(ks("Data")).unwrap_or_default(),
                        generation: k.get("Gen").and_then(|v| v.as_u64()).unwrap_or(1),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let w = Wallet {
        id: id.clone(),
        name: s("Name"),
        curve: s("Curve"),
        protocol: s("Protocol"),
        threshold: wj.get("Threshold").and_then(|v| v.as_i64()).unwrap_or(0),
        generation: wj.get("Gen").and_then(|v| v.as_u64()).unwrap_or(0),
        pubkey: s("Pubkey"),
        chaincode: s("Chaincode"),
        created: s("Created"),
        modified: s("Modified"),
        keys,
    };
    persist(env, &w)?;
    Ok(id)
}

/// Update mutable wallet fields (Go `Wallet.ApiUpdate`): only `Name` is
/// mutable. Returns the updated wallet (keys loaded), or `None` when the id is
/// unknown. With no `Name` supplied the row is left untouched (Go returns
/// without saving). `Modified` is bumped on a real update, as Go does.
pub fn update(env: &Env, id: &str, name: Option<&str>) -> Result<Option<Wallet>> {
    if fetch(env, id)?.is_none() {
        return Ok(None);
    }
    if let Some(n) = name {
        env.exec(
            r#"UPDATE "Wallet" SET "Name"=?1, "Modified"=?2 WHERE "Id"=?3"#,
            vec![
                SqlValue::Text(n.to_owned()),
                SqlValue::Text(crate::now_rfc3339()),
                SqlValue::Text(id.to_owned()),
            ],
        )?;
    }
    fetch(env, id)
}

/// Delete a wallet and its WalletKey rows (Go `Wallet.ApiDelete`). The keys are
/// removed first so no orphan shares survive the wallet. The caller (handler)
/// emits the `wallet:deleted` event, mirroring Go.
pub fn delete(env: &Env, id: &str) -> Result<()> {
    env.exec(
        r#"DELETE FROM "WalletKey" WHERE "Wallet" = ?1"#,
        vec![SqlValue::Text(id.to_owned())],
    )?;
    env.exec(
        r#"DELETE FROM "Wallet" WHERE "Id" = ?1"#,
        vec![SqlValue::Text(id.to_owned())],
    )
    .map(|_| ())
}

fn persist(env: &Env, w: &Wallet) -> Result<()> {
    env.exec(
        &format!(r#"INSERT INTO "Wallet" ({WALLET_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#),
        vec![
            SqlValue::Text(w.id.clone()),
            SqlValue::Text(w.name.clone()),
            SqlValue::Text(w.curve.clone()),
            SqlValue::Text(w.protocol.clone()),
            SqlValue::Int(w.threshold),
            SqlValue::Int(w.generation as i64),
            SqlValue::Text(w.pubkey.clone()),
            SqlValue::Text(w.chaincode.clone()),
            SqlValue::Text(w.created.clone()),
            SqlValue::Text(w.modified.clone()),
        ],
    )?;
    for k in &w.keys {
        env.exec(
            &format!(r#"INSERT INTO "WalletKey" ({WALLETKEY_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7)"#),
            vec![
                SqlValue::Text(k.id.clone()),
                SqlValue::Text(k.wallet.clone()),
                SqlValue::Text(k.kind.clone()),
                SqlValue::Text(k.schema.clone()),
                SqlValue::Text(k.key.clone()),
                SqlValue::Blob(k.data.clone()),
                SqlValue::Int(k.generation as i64),
            ],
        )?;
    }
    Ok(())
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Build the per-curve RemoteKey upload payload from a raw share. Matches Go
/// `WalletKey.encrypt`'s RemoteKey wire per curve: FROST (ed25519) seals the
/// frost-key JSON directly; DKLs (secp256k1) seals `json.Marshal(saveBytes)` —
/// i.e. the Save-JSON base64-std-encoded as a JSON string (Go uploads the raw
/// `[]byte` Save() form, and cryptutil.MarshalJson turns a `[]byte` into a
/// base64 string; the wdrone's loadShare reads it back into `[]byte`). Shared by
/// the native (sync) `seal_share_full` and the wasm (async) create path.
pub(crate) fn build_remote_payload(curve_out: &str, share: &[u8]) -> Result<Vec<u8>> {
    if curve_out == "secp256k1" {
        use base64::engine::general_purpose::STANDARD;
        serde_json::to_vec(&STANDARD.encode(share)).map_err(|e| Error::Env(e.to_string()))
    } else {
        Ok(share.to_vec())
    }
}

/// Seal a share for one KeyDescription → `(WalletKey.data, WalletKey.key)`.
/// Encrypt/Plain are local; Remote seals to the wdrone fleet keys and uploads to
/// the WalletSign backend (Go `WalletKey.encrypt`). Shared by create + reshare.
#[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
pub(crate) fn seal_share_full(
    env: &Env,
    curve_out: &str,
    protocol: &str,
    kd: &KeyDescription,
    uuid_bytes: &[u8],
    share: &[u8],
) -> Result<(Vec<u8>, String)> {
    match kd.resolve(uuid_bytes).map_err(|e| Error::Env(e.to_string()))? {
        Recipient::Encrypt(pk) => {
            let sealed = keystore::seal(share, &[pk.clone()]).map_err(|e| Error::Env(e.to_string()))?;
            let pkix = keystore::public_key_to_pkix_b64(&pk).map_err(|e| Error::Env(e.to_string()))?;
            Ok((sealed, pkix))
        }
        Recipient::Plain => Ok((keystore::wrap_plain(share).map_err(|e| Error::Env(e.to_string()))?, String::new())),
        // RemoteKey shares upload to the backend — networking, so browser-only
        // wallets can't use them (local Password/StoreKey/Plain shares work).
        #[cfg(target_arch = "wasm32")]
        Recipient::Remote => Err(Error::Env(
            "RemoteKey shares are not supported in the browser build; use local shares".into(),
        )),
        #[cfg(not(target_arch = "wasm32"))]
        Recipient::Remote => {
            let base = crate::rest::DEFAULT_HOST;
            let client_id = env
                .config_get("walletinfo:clientId")
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
                .filter(|s| !s.is_empty());
            let recipients = crate::walletsign::fetch_decrypt_keys(base, client_id.as_deref())?;
            // Match Go `WalletKey.encrypt` RemoteKey wire per curve. FROST seals
            // the frost-key JSON directly; DKLs seals `json.Marshal(saveBytes)`
            // — i.e. the Save-JSON base64-std-encoded as a JSON string — since Go
            // uploads the raw `[]byte` Save() form (cryptutil.MarshalJson turns a
            // []byte into a base64 string), and the wdrone's loadShare reads it
            // back into []byte → dklstss.Load.
            let payload = build_remote_payload(curve_out, share)?;
            let sealed = keystore::seal_json(&payload, &recipients).map_err(|e| Error::Env(e.to_string()))?;
            // Tenacious retry (Go `WalletKey.encrypt` switched to
            // restDoRetryCritical): this upload is the one reshare step whose
            // abandonment can desync server-side state from the local
            // (unchanged) committee — an interrupted upload may still land
            // server-side and overwrite the live share. Keep pushing for the
            // full budget, then surface the recovery step on final failure.
            upload_remote_share_critical(base, client_id.as_deref(), &kd.key, curve_out, protocol, &sealed).map_err(|e| {
                Error::Env(format!(
                    "RemoteKey share upload failed after extended retries (local wallet committee is unchanged; if any attempt reached the server the stored remote share may be out of sync — re-run this reshare from a device holding the local shares before relying on the RemoteKey): {e}"
                ))
            })?;
            Ok((sealed, kd.key.clone()))
        }
    }
}

/// The `walletinfo:clientId` header value (Go `withClientID`), if set. Native
/// only — the browser authenticates via the Spot connection, not this header.
#[cfg(not(target_arch = "wasm32"))]
fn client_id(env: &Env) -> Option<String> {
    env.config_get("walletinfo:clientId")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.is_empty())
}

/// Upload a sealed RemoteKey share to `Crypto/WalletSign:setGeneratedKey` with
/// the tenacious critical retry (Go `WalletKey.encrypt` / `pushRemoteShare`).
/// Mirrors [`crate::walletsign::upload_generated_key`]'s params but routes the
/// POST through [`crate::reshare::rest_do_retry_critical`].
#[cfg(not(target_arch = "wasm32"))]
fn upload_remote_share_critical(
    base: &str,
    client_id: Option<&str>,
    remote_key: &str,
    curve: &str,
    protocol: &str,
    data_cbor: &[u8],
) -> Result<()> {
    let mut params = serde_json::json!({
        "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data_cbor),
        "key": remote_key,
        "curve": curve,
    });
    if !protocol.is_empty() {
        params["protocol"] = serde_json::json!(protocol);
    }
    crate::reshare::rest_do_retry_critical(base, "Crypto/WalletSign:setGeneratedKey", &params, client_id)?;
    Ok(())
}

/// Derive the `(curve, protocol)` wire tags for a RemoteKey share upload from
/// the PERSISTED `schema` + wallet `curve` (Go `pushRemoteShare`'s switch). A
/// restored wallet has no in-memory share, so the tags come from what was
/// stored — the same recipient vocabulary the wdrone's loadShare recognises.
pub fn remote_share_wire_tags<'a>(schema: &str, wallet_curve: &'a str) -> Result<(&'a str, &'a str)> {
    match schema {
        "dkls23" => Ok(("secp256k1", "dkls23")),
        "frost" => Ok(("ed25519", "frost")),
        // Legacy GG18-family share: the wallet curve disambiguates ecdsa/eddsa.
        "" => match wallet_curve {
            "secp256k1" | "ed25519" => Ok((wallet_curve, "legacy")),
            other => Err(Error::Env(format!("pushRemoteShare: legacy share with unsupported wallet curve {other:?}"))),
        },
        other => Err(Error::Env(format!("pushRemoteShare: unsupported share schema {other:?}"))),
    }
}

/// `WalletKey.pushRemoteShare` (Go): re-upload `wk.data` (the fleet-encrypted
/// RemoteKey share blob, byte-identical to what `seal_share_full` originally
/// sent) under `session_key`. Unlike a live ceremony upload — which knows the
/// wire tags from the in-memory share — this derives `(curve, protocol)` from
/// the PERSISTED `Schema` + wallet curve, because a restored wallet has no
/// in-memory share (the RemoteKey blob is not client-decryptable). Sets
/// `wk.key = session_key` on success.
#[cfg(not(target_arch = "wasm32"))]
pub fn push_remote_share(env: &Env, wallet: &Wallet, wk: &mut WalletKey, session_key: &str) -> Result<()> {
    if wk.kind != "RemoteKey" {
        return Err(Error::Env(format!("pushRemoteShare: key {} is {:?}, not a RemoteKey", wk.id, wk.kind)));
    }
    let (curve_param, protocol_param) = remote_share_wire_tags(&wk.schema, &wallet.curve)?;
    let base = crate::rest::DEFAULT_HOST;
    upload_remote_share_critical(base, client_id(env).as_deref(), session_key, curve_param, protocol_param, &wk.data)
        .map_err(|e| Error::Env(format!("repair RemoteKey share upload failed: {e}")))?;
    wk.key = session_key.to_string();
    Ok(())
}

/// `Wallet:repairRemoteKey` (Go `apiWalletRepairRemoteKey`): re-upload the
/// wallet's locally-stored RemoteKey share blob to the WalletSign backend under
/// a fresh, validated crws session, restoring a server-side share desynced by an
/// abandoned reshare upload. Persists the refreshed session key and returns the
/// updated wallet.
#[cfg(not(target_arch = "wasm32"))]
pub fn repair_remote_key(env: &Env, wallet_id: &str, session_key: &str) -> Result<Wallet> {
    if session_key.is_empty() {
        return Err(Error::Env("Key (validated RemoteKey session) is required".into()));
    }
    let mut wallet = fetch(env, wallet_id)?.ok_or_else(|| Error::Env("Wallet required".into()))?;
    let idx = wallet
        .keys
        .iter()
        .position(|k| k.kind == "RemoteKey")
        .ok_or_else(|| Error::Env("wallet has no RemoteKey share".into()))?;
    if wallet.keys[idx].data.is_empty() {
        return Err(Error::Env(
            "wallet's RemoteKey share has no local data blob — was this wallet restored from a backup that includes key data?".into(),
        ));
    }
    // Split the borrow: push_remote_share needs &wallet (curve) + &mut wk.
    let mut wk = wallet.keys[idx].clone();
    push_remote_share(env, &wallet, &mut wk, session_key)?;
    // Persist the refreshed session key (Go `w.save(e)`).
    env.exec(
        r#"UPDATE "WalletKey" SET "Key"=?1 WHERE "Id"=?2"#,
        vec![SqlValue::Text(wk.key.clone()), SqlValue::Text(wk.id.clone())],
    )?;
    wallet.keys[idx] = wk;
    Ok(wallet)
}

/// Persist a FROST reshare's new committee: seal each new share per its
/// KeyDescription, replace the wallet's WalletKey rows, bump generation, and
/// keep the group pubkey (which reshare preserves). Verifies each new share
/// still derives the stored pubkey before writing.
pub fn persist_reshared_frost(
    env: &Env,
    wallet: &Wallet,
    new_keys: &[KeyDescription],
    new_wk_ids: &[Xuid],
    new_parties: &[PartyId],
    new_shares: &std::collections::HashMap<String, Key>,
) -> Result<()> {
    let mut wkeys: Vec<WalletKey> = Vec::with_capacity(new_keys.len());
    for (i, kd) in new_keys.iter().enumerate() {
        let party = &new_parties[i];
        let share = new_shares
            .get(&party.id)
            .ok_or_else(|| Error::Env(format!("reshare: missing new share for party {}", party.id)))?;
        // Defense in depth: the reshared share must still produce the group key.
        if b64url(&frost_group_pubkey(share)) != wallet.pubkey {
            return Err(Error::Env("reshare produced a share with a different group pubkey".into()));
        }
        let json = share.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;
        let uuid = new_wk_ids[i].uuid();
        let (data, key_field) = seal_share_full(env, &wallet.curve, "frost", kd, uuid.as_bytes(), json.as_bytes())?;
        wkeys.push(WalletKey {
            id: new_wk_ids[i].to_string(),
            wallet: wallet.id.clone(),
            kind: kd.kind.clone(),
            schema: "frost".into(),
            key: key_field,
            data,
            generation: wallet.generation + 1,
        });
    }
    replace_wallet_keys(env, wallet, &wkeys)
}

/// DKLs (secp256k1) twin of [`persist_reshared_frost`]: seal each new dkls23
/// share, verify it still derives the 33-byte compressed group pubkey, and
/// replace the wallet's WalletKey rows.
pub fn persist_reshared_dkls(
    env: &Env,
    wallet: &Wallet,
    new_keys: &[KeyDescription],
    new_wk_ids: &[Xuid],
    new_parties: &[PartyId],
    new_shares: &std::collections::HashMap<String, tsslib::dklstss::Key>,
) -> Result<()> {
    let mut wkeys: Vec<WalletKey> = Vec::with_capacity(new_keys.len());
    for (i, kd) in new_keys.iter().enumerate() {
        let party = &new_parties[i];
        let share = new_shares
            .get(&party.id)
            .ok_or_else(|| Error::Env(format!("reshare: missing new share for party {}", party.id)))?;
        let gpk = crate::tss::dkls_group_pubkey(share).map_err(|e| Error::Env(e.to_string()))?;
        if b64url(&gpk) != wallet.pubkey {
            return Err(Error::Env("reshare produced a share with a different group pubkey".into()));
        }
        let json = share.to_json().map_err(|e| Error::Env(format!("{e:?}")))?;
        let uuid = new_wk_ids[i].uuid();
        let (data, key_field) = seal_share_full(env, &wallet.curve, "dkls23", kd, uuid.as_bytes(), json.as_bytes())?;
        wkeys.push(WalletKey {
            id: new_wk_ids[i].to_string(),
            wallet: wallet.id.clone(),
            kind: kd.kind.clone(),
            schema: "dkls23".into(),
            key: key_field,
            data,
            generation: wallet.generation + 1,
        });
    }
    replace_wallet_keys(env, wallet, &wkeys)
}

/// Replace a wallet's WalletKey rows with `wkeys` and bump its generation
/// (single-threaded DB actor makes the delete+insert+update sequence safe).
fn replace_wallet_keys(env: &Env, wallet: &Wallet, wkeys: &[WalletKey]) -> Result<()> {
    env.exec(r#"DELETE FROM "WalletKey" WHERE "Wallet" = ?1"#, vec![SqlValue::Text(wallet.id.clone())])?;
    for k in wkeys {
        env.exec(
            &format!(r#"INSERT INTO "WalletKey" ({WALLETKEY_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7)"#),
            vec![
                SqlValue::Text(k.id.clone()),
                SqlValue::Text(k.wallet.clone()),
                SqlValue::Text(k.kind.clone()),
                SqlValue::Text(k.schema.clone()),
                SqlValue::Text(k.key.clone()),
                SqlValue::Blob(k.data.clone()),
                SqlValue::Int(k.generation as i64),
            ],
        )?;
    }
    env.exec(
        r#"UPDATE "Wallet" SET "Gen" = ?1, "Modified" = ?2 WHERE "Id" = ?3"#,
        vec![
            SqlValue::Int((wallet.generation + 1) as i64),
            SqlValue::Text(crate::now_rfc3339()),
            SqlValue::Text(wallet.id.clone()),
        ],
    )?;
    Ok(())
}

/// Turn a keygen result into `(party_key_bytes, share_json)` pairs, so the
/// encrypt/persist loop is shared across protocols.
fn shares_json<K>(
    ks: Vec<(PartyId, K)>,
    to_json: impl Fn(&K) -> std::result::Result<String, String>,
) -> Result<Vec<(Vec<u8>, String)>> {
    ks.into_iter()
        .map(|(p, k)| to_json(&k).map(|j| (p.key, j)).map_err(Error::Env))
        .collect()
}

pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Env(format!("bad base64url: {e}")))
}

/// Resolve the decryption key for a WalletKey from the unlock material:
/// Password derives via PBKDF2 (salt = the WalletKey UUID); StoreKey runs the
/// host-supplied 64-byte store key through `storeKeyToEd25519` (PBKDF2 with the
/// store key's own halves), matching Go `walletkey.go`. (RemoteKey unlock happens
/// on the backend and is not handled here.)
pub fn resolve_unlock_key(kind: &str, material: &str, uuid: &[u8]) -> Result<bottlers::PrivateKey> {
    match kind {
        "Password" => {
            crate::keystore::password_to_ed25519(material, uuid).map_err(|e| Error::Env(e.to_string()))
        }
        "StoreKey" => {
            crate::keystore::store_key_to_ed25519(material).map_err(|e| Error::Env(e.to_string()))
        }
        other => Err(Error::Env(format!("unlock type {other} not supported locally"))),
    }
}

/// Decrypt a mnemonic-keep wallet's `MnemonicKeyShare` and return its BIP-39
/// seed (Go `decryptMnemonic` + `reconstructMnemonic` + `NewSeed`). The wallet
/// must have exactly one key with `Schema == "mnemonic"`. `unlock` is the single
/// (walletKeyId, password/store-key) pair. Read-only — used by probeActivity.
pub fn decrypt_mnemonic_seed(env: &Env, wallet_id: &str, unlock: &[(String, String)]) -> Result<Vec<u8>> {
    let wallet = fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    if wallet.keys.len() != 1 || wallet.keys[0].schema != "mnemonic" {
        return Err(Error::Env("probeActivity requires a mnemonic-backed wallet".into()));
    }
    let (wk_id, secret) = unlock.first().ok_or_else(|| Error::Env("exactly one Key required".into()))?;
    let wk = &wallet.keys[0];
    let xid: Xuid = wk.id.parse().map_err(|e| Error::Env(format!("bad walletkey id: {e}")))?;
    let uuid_bytes = xid.uuid().as_bytes().to_vec();
    let unlock_key = resolve_unlock_key(&wk.kind, secret, &uuid_bytes)?;
    let payload = keystore::open(&wk.data, [unlock_key]).map_err(|e| Error::Env(e.to_string()))?;
    let _ = wk_id; // the unlock id is validated by the successful decrypt above
    Ok(mnemonic_share_seed(&payload)?.0)
}

/// Parse a decrypted `MnemonicKeyShare` payload and return `(seed, curve)`.
/// Go marshals the `[]byte` entropy as a base64 (std) string.
fn mnemonic_share_seed(payload: &[u8]) -> Result<(Vec<u8>, String)> {
    #[derive(serde::Deserialize)]
    struct MnemonicShare {
        #[serde(default)]
        curve: String,
        #[serde(default)]
        entropy: String,
        #[serde(default)]
        passphrase: String,
    }
    let share: MnemonicShare = serde_json::from_slice(payload).map_err(|e| Error::Env(format!("decode mnemonic share: {e}")))?;
    let entropy = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(&share.entropy).map_err(|e| Error::Env(format!("bad entropy base64: {e}")))?
    };
    let mnemonic = crate::bip39::entropy_to_mnemonic(&entropy)?;
    Ok((crate::bip39::mnemonic_to_seed(&mnemonic, &share.passphrase).to_vec(), share.curve))
}

/// Direct Ed25519 signing for a mnemonic-keep ed25519 wallet: decrypt the
/// share → seed → SLIP-0010 master → sign `msg` with the master key. Self-
/// verifies against the wallet's stored group pubkey.
fn sign_ed25519_mnemonic(wallet: &Wallet, unlock: &[(String, String)], msg: &[u8]) -> Result<Vec<u8>> {
    let (wk_id, secret) = unlock.first().ok_or_else(|| Error::Env("exactly one Key required".into()))?;
    let wk = wallet.keys.iter().find(|k| &k.id == wk_id).unwrap_or(&wallet.keys[0]);
    let xid: Xuid = wk.id.parse().map_err(|e| Error::Env(format!("bad walletkey id: {e}")))?;
    let uuid = xid.uuid().as_bytes().to_vec();
    let unlock_key = resolve_unlock_key(&wk.kind, secret, &uuid)?;
    let payload = keystore::open(&wk.data, [unlock_key]).map_err(|e| Error::Env(e.to_string()))?;
    let (seed, curve) = mnemonic_share_seed(&payload)?;
    let (master, _cc) = crate::bip39::master_from_seed(&seed, &curve)?;

    let sk = purecrypto::ec::Ed25519PrivateKey::from_bytes(master);
    let sig = sk.sign(msg).to_bytes().to_vec();
    // Defense in depth: the signature must verify under the stored group pubkey.
    if let Ok(pk) = b64url_decode(&wallet.pubkey) {
        if let (Ok(pk32), Ok(sig64)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sig.clone())) {
            if !ed25519_verify(&pk32, msg, &sig64) {
                return Err(Error::Env("mnemonic ed25519 signature failed verification".into()));
            }
        }
    }
    Ok(sig)
}

/// The effective TSS protocol (Go `resolveProtocol`): empty falls back to the
/// curve's legacy value so pre-modern rows still route correctly.
fn resolve_protocol(w: &Wallet) -> &'static str {
    match w.protocol.as_str() {
        "frost" => "frost",
        "dkls23" => "dkls23",
        "eddsa" => "eddsa",
        "gg18" => "gg18",
        "" => match w.curve.as_str() {
            "ed25519" => "eddsa",
            "secp256k1" => "gg18",
            _ => "",
        },
        _ => "",
    }
}

/// Open one committee share to its decrypted JSON (Plain → EmptyOpener; else
/// resolve an unlock key from `password`). Shared by the FROST + legacy paths.
fn open_committee_share(wk: &WalletKey, uuid_bytes: &[u8], password: &str) -> Result<Vec<u8>> {
    if wk.kind == "Plain" {
        keystore::open(&wk.data, []).map_err(|e| Error::Env(e.to_string()))
    } else {
        let unlock_key = resolve_unlock_key(&wk.kind, password, uuid_bytes)?;
        keystore::open(&wk.data, [unlock_key]).map_err(|e| Error::Env(e.to_string()))
    }
}

/// Sign with a legacy eddsatss (GG18-style Ed25519) wallet — the path for
/// opening + using ed25519 wallets created before FROST (Go `subSign`'s
/// ProtocolLegacyEdDSA branch). Unblocked by tsslib 0.2.4.
fn sign_eddsa_legacy(wallet: &Wallet, unlock: &[(String, String)], msg: &[u8]) -> Result<Vec<u8>> {
    let threshold = wallet.threshold.max(0) as usize;
    let mut committee: Vec<(PartyId, tsslib::eddsatss::Key)> = Vec::with_capacity(unlock.len());
    for (wk_id, password) in unlock {
        let wk = wallet.keys.iter().find(|k| &k.id == wk_id).ok_or_else(|| Error::Env(format!("wallet has no key {wk_id}")))?;
        let xid: Xuid = wk_id.parse().map_err(|e| Error::Env(format!("bad walletkey id {wk_id}: {e}")))?;
        let uuid_bytes = xid.uuid().as_bytes().to_vec();
        let json = open_committee_share(wk, &uuid_bytes, password)?;
        let key = tsslib::eddsatss::Key::from_json(std::str::from_utf8(&json).map_err(|e| Error::Env(e.to_string()))?)
            .map_err(|e| Error::Env(format!("load eddsa share: {e:?}")))?;
        committee.push((PartyId::new(hex_bytes(&uuid_bytes), "", uuid_bytes.clone()), key));
    }
    let sig = crate::tss::eddsa_sign_local(&committee, threshold, msg).map_err(|e| Error::Env(e.to_string()))?;
    // Defense in depth: verify under the stored group pubkey.
    if let Ok(pk) = b64url_decode(&wallet.pubkey) {
        if let (Ok(pk32), Ok(sig64)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sig.clone())) {
            if !ed25519_verify(&pk32, msg, &sig64) {
                return Err(Error::Env("legacy eddsa signature failed verification".into()));
            }
        }
    }
    Ok(sig)
}

/// Sign a 32-byte `digest` with a legacy ecdsatss (GG18 secp256k1) wallet,
/// applying the account's HD `tweak` (IL). Threshold scheme — only threshold+1
/// shares are needed (unlike DKLs, which needs all). Returns `(r, s, v)`.
/// Unblocked by tsslib 0.2.5's `new_with_kdd`.
fn sign_ecdsa_legacy(
    wallet: &Wallet,
    unlock: &[(String, String)],
    tweak: &[u8; 32],
    digest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u8)> {
    let threshold = wallet.threshold.max(0) as usize;
    let mut committee: Vec<(PartyId, tsslib::ecdsatss::Key)> = Vec::with_capacity(unlock.len());
    for (wk_id, password) in unlock {
        let wk = wallet.keys.iter().find(|k| &k.id == wk_id).ok_or_else(|| Error::Env(format!("wallet has no key {wk_id}")))?;
        let xid: Xuid = wk_id.parse().map_err(|e| Error::Env(format!("bad walletkey id {wk_id}: {e}")))?;
        let uuid_bytes = xid.uuid().as_bytes().to_vec();
        let json = open_committee_share(wk, &uuid_bytes, password)?;
        let key = tsslib::ecdsatss::Key::from_json(std::str::from_utf8(&json).map_err(|e| Error::Env(e.to_string()))?)
            .map_err(|e| Error::Env(format!("load ecdsa share: {e:?}")))?;
        committee.push((PartyId::new(hex_bytes(&uuid_bytes), "", uuid_bytes.clone()), key));
    }
    crate::tss::ecdsa_sign_local_tweaked(&committee, threshold, tweak, digest).map_err(|e| Error::Env(e.to_string()))
}

/// Sign `msg` with an all-local FROST wallet by unlocking a committee of its
/// Password-protected shares. `unlock` pairs each contributing WalletKey id
/// with its password; at least `threshold + 1` are required. The produced
/// signature is verified against the wallet's stored group public key before
/// being returned. This is the crypto path behind Account:signAndSend for
/// on-device wallets (StoreKey/RemoteKey unlocking follows).
pub fn sign_frost_local(
    env: &Env,
    wallet_id: &str,
    unlock: &[(String, String)],
    msg: &[u8],
) -> Result<Vec<u8>> {
    let wallet = fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    // A mnemonic-keep ed25519 wallet signs directly with its master Ed25519 key
    // (its Solana account uses path "m", so no tweak) — a 1-of-1 FROST sign over
    // the LocalHub would deadlock, so bypass it.
    if wallet.curve == "ed25519" && wallet.keys.iter().any(|k| k.schema == "mnemonic") {
        return sign_ed25519_mnemonic(&wallet, unlock, msg);
    }
    // Legacy eddsatss wallets (Protocol="eddsa", or empty on an ed25519 wallet —
    // Go resolveProtocol) sign through the GG18-style path, unblocked by tsslib
    // 0.2.4. Modern wallets are Protocol="frost".
    let resolved = resolve_protocol(&wallet);
    if resolved == "eddsa" {
        return sign_eddsa_legacy(&wallet, unlock, msg);
    }
    if resolved != "frost" {
        return Err(Error::Env(format!("wallet protocol {} is not frost", wallet.protocol)));
    }
    let threshold = wallet.threshold.max(0) as usize;

    let mut committee: Vec<(PartyId, Key)> = Vec::with_capacity(unlock.len());
    for (wk_id, password) in unlock {
        let wk = wallet
            .keys
            .iter()
            .find(|k| &k.id == wk_id)
            .ok_or_else(|| Error::Env(format!("wallet has no key {wk_id}")))?;
        // Party key + decrypt salt both derive from the WalletKey UUID.
        let xid: Xuid = wk_id.parse().map_err(|e| Error::Env(format!("bad walletkey id {wk_id}: {e}")))?;
        let uuid_bytes = xid.uuid().as_bytes().to_vec();

        // Plain shares are stored unencrypted (Go EmptyOpener) — open with no
        // key; every other type resolves an unlock key from the material.
        let json = if wk.kind == "Plain" {
            keystore::open(&wk.data, []).map_err(|e| Error::Env(e.to_string()))?
        } else {
            let unlock_key = resolve_unlock_key(&wk.kind, password, &uuid_bytes)?;
            keystore::open(&wk.data, [unlock_key]).map_err(|e| Error::Env(e.to_string()))?
        };
        let key = Key::from_json(std::str::from_utf8(&json).map_err(|e| Error::Env(e.to_string()))?)
            .map_err(|e| Error::Env(format!("load share: {e:?}")))?;

        let pid = PartyId::new(hex_bytes(&uuid_bytes), "", uuid_bytes.clone());
        committee.push((pid, key));
    }

    let sig = frost_sign_local(&committee, threshold, msg).map_err(|e| Error::Env(e.to_string()))?;

    // Defense in depth: the produced signature must verify under the stored key.
    let pk: [u8; 32] = b64url_decode(&wallet.pubkey)?
        .try_into()
        .map_err(|_| Error::Env("stored pubkey is not 32 bytes".into()))?;
    let sig64: [u8; 64] =
        sig.clone().try_into().map_err(|_| Error::Env("signature is not 64 bytes".into()))?;
    if !ed25519_verify(&pk, msg, &sig64) {
        return Err(Error::Env("produced signature failed verification".into()));
    }
    Ok(sig)
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Sign a 32-byte digest with a secp256k1/DKLs23 wallet, returning the ECDSA
/// `(r, s, v)`. DKLs signing needs the full key set, so `unlock` must name and
/// unlock ALL of the wallet's Password shares. This is the crypto behind
/// Account:signTransaction for EVM wallets.
pub fn dkls_sign_digest(
    env: &Env,
    wallet_id: &str,
    unlock: &[(String, String)],
    tweak: &[u8; 32],
    digest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u8)> {
    let wallet = fetch(env, wallet_id)?.ok_or_else(|| Error::Env("wallet not found".into()))?;
    // Legacy ecdsatss wallets (Protocol="gg18", or empty on a secp256k1 wallet)
    // sign through the GG18 path with the account's IL tweak (tsslib 0.2.5's
    // new_with_kdd). Modern secp wallets are Protocol="dkls23".
    if resolve_protocol(&wallet) == "gg18" {
        return sign_ecdsa_legacy(&wallet, unlock, tweak, digest);
    }
    // A mnemonic-keep secp wallet signs with the same key the TSS import
    // produces — its master scalar imported into a 1-of-1 dkls Key at sign time.
    let is_mnemonic = wallet.keys.iter().any(|k| k.schema == "mnemonic");
    if wallet.protocol != "dkls23" && !(is_mnemonic && wallet.curve == "secp256k1") {
        return Err(Error::Env(format!("wallet protocol {} is not dkls23", wallet.protocol)));
    }
    let threshold = wallet.threshold.max(0) as usize;

    let mut keys: Vec<tsslib::dklstss::Key> = Vec::with_capacity(unlock.len());
    for (wk_id, password) in unlock {
        let wk = wallet
            .keys
            .iter()
            .find(|k| &k.id == wk_id)
            .ok_or_else(|| Error::Env(format!("wallet has no key {wk_id}")))?;
        let xid: Xuid = wk_id.parse().map_err(|e| Error::Env(format!("bad walletkey id {wk_id}: {e}")))?;
        let uuid = xid.uuid().as_bytes().to_vec();
        let unlock_key = resolve_unlock_key(&wk.kind, password, &uuid)?;
        let payload = keystore::open(&wk.data, [unlock_key]).map_err(|e| Error::Env(e.to_string()))?;
        let key = if wk.schema == "mnemonic" {
            let (seed, curve) = mnemonic_share_seed(&payload)?;
            let (master, _cc) = crate::bip39::master_from_seed(&seed, &curve)?;
            crate::tss::dkls_import_key(&master, &uuid).map_err(|e| Error::Env(e.to_string()))?.1
        } else {
            tsslib::dklstss::Key::from_json(std::str::from_utf8(&payload).map_err(|e| Error::Env(e.to_string()))?)
                .map_err(|e| Error::Env(format!("load dkls share: {e:?}")))?
        };
        keys.push(key);
    }

    if keys.len() < wallet.keys.len() {
        return Err(Error::Env("DKLs signing requires all shares to be unlocked".into()));
    }
    // dkls_sign_local indexes the full array by party index; put keys[i] at i.
    keys.sort_by_key(|k| k.idx);

    crate::tss::dkls_sign_local_tweaked(&keys, threshold, tweak, digest).map_err(|e| Error::Env(e.to_string()))
}

fn row_to_wallet(row: &[SqlValue]) -> Wallet {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let int = |i: usize| row.get(i).and_then(|v| v.as_i64()).unwrap_or(0);
    Wallet {
        id: text(0),
        name: text(1),
        curve: text(2),
        protocol: text(3),
        threshold: int(4),
        generation: int(5).max(0) as u64,
        pubkey: text(6),
        chaincode: text(7),
        created: text(8),
        modified: text(9),
        keys: Vec::new(),
    }
}

fn row_to_key(row: &[SqlValue]) -> WalletKey {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    WalletKey {
        id: text(0),
        wallet: text(1),
        kind: text(2),
        schema: text(3),
        key: text(4),
        data: row.get(5).and_then(|v| v.as_blob()).map(|b| b.to_vec()).unwrap_or_default(),
        generation: row.get(6).and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u64,
    }
}
