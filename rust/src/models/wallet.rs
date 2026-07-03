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

/// Create an all-local ed25519/FROST wallet: keygen (party-keyed by each
/// WalletKey UUID), derive the group pubkey, encrypt each share per its
/// KeyDescription, and persist. Port of Wallet:create's initializeFrostWallet.
pub fn create(env: &Env, name: &str, curve: &str, key_descs: &[KeyDescription]) -> Result<Wallet> {
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
    let (pubkey, protocol, curve_out, shares): (String, &str, &str, Vec<(Vec<u8>, String)>) =
        match curve {
            "" | "ed25519" => {
                let ks = frost_keygen_with_parties(party_keys, threshold)
                    .map_err(|e| Error::Env(format!("frost keygen: {e}")))?;
                let pk = b64url(&frost_group_pubkey(&ks[0].1));
                let shares = shares_json(ks, |k| k.to_json().map_err(|e| format!("{e:?}")))?;
                (pk, "frost", "ed25519", shares)
            }
            "secp256k1" => {
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
    let now = crate::now_rfc3339();

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
                let sealed =
                    keystore::seal(json.as_bytes(), &[pk.clone()]).map_err(|e| Error::Env(e.to_string()))?;
                let pkix = keystore::public_key_to_pkix_b64(&pk).map_err(|e| Error::Env(e.to_string()))?;
                (sealed, pkix)
            }
            Recipient::Plain => {
                (keystore::wrap_plain(json.as_bytes()).map_err(|e| Error::Env(e.to_string()))?, String::new())
            }
            Recipient::Remote => {
                return Err(Error::Env("RemoteKey shares need the backend (not yet ported)".into()))
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

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Env(format!("bad base64url: {e}")))
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
    if wallet.protocol != "frost" {
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
        if wk.kind != "Password" {
            return Err(Error::Env(format!("key {wk_id} is {} (only Password unlock supported)", wk.kind)));
        }
        // Party key + decrypt salt both derive from the WalletKey UUID.
        let xid: Xuid = wk_id.parse().map_err(|e| Error::Env(format!("bad walletkey id {wk_id}: {e}")))?;
        let uuid_bytes = xid.uuid().as_bytes().to_vec();

        let unlock_key = keystore::password_to_ed25519(password, &uuid_bytes)
            .map_err(|e| Error::Env(e.to_string()))?;
        let json = keystore::open(&wk.data, [unlock_key]).map_err(|e| Error::Env(e.to_string()))?;
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
