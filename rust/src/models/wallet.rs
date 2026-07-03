//! wltwallet — wallets and their key shares.
//!
//! This phase ports the **read** surface: the Wallet / WalletKey models, their
//! tables, and fetch/list (a Wallet embeds its Keys). Wallet creation is TSS
//! key generation and lands in Phase 3 (via the `tsslib` crate); until then
//! `create` is intentionally absent and the API returns 501.
//!
//! WalletKey.Data (the encrypted share) is `#[serde(skip)]` — it is loaded for
//! internal use but never emitted to the host, matching the Go `json:",protect"`
//! tag. The Dart client only reads Id/Wallet/Type/Key/Gen.

use serde::{Deserialize, Serialize};
use crate::{Env, Result, SqlValue};

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
