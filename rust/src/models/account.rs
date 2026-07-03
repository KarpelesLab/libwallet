//! wltacct — accounts (addresses derived from a wallet).
//!
//! Read surface only for now: the Account model, its table, and fetch/list.
//! Account creation is HD address derivation (outscript + secp256k1/ed25519)
//! and lands with the address pass; POST returns 501 until then.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Account" ("Id" text, "Wallet" text, "Name" text, "Index" integer, "Type" text, "Curve" text, "Path" text, "Address" text, "URI" text, "Pubkey" text, "Chaincode" text, "IL" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Wallet", "Name", "Index", "Type", "Curve", "Path", "Address", "URI", "Pubkey", "Chaincode", "IL", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Account {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Wallet", default)]
    pub wallet: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Index", default)]
    pub index: i64,
    #[serde(rename = "Type", default)]
    pub kind: String,
    #[serde(rename = "Curve", default)]
    pub curve: String,
    #[serde(rename = "Path", default)]
    pub path: String,
    #[serde(rename = "Address", default)]
    pub address: String,
    #[serde(rename = "URI", default)]
    pub uri: String,
    #[serde(rename = "Pubkey", default)]
    pub pubkey: String,
    #[serde(rename = "Chaincode", default)]
    pub chaincode: String,
    /// Intermediate derivation value (big.Int as JSON). Passed through as-is;
    /// the Dart client ignores it.
    #[serde(rename = "IL", default)]
    pub il: Value,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Account>> {
    let sql = format!(r#"SELECT {COLS} FROM "Account" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_account(r)))
}

pub fn list(env: &Env) -> Result<Vec<Account>> {
    let sql = format!(r#"SELECT {COLS} FROM "Account" ORDER BY "Index" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_account(r)).collect())
}

/// Accounts belonging to a wallet (used by wallet-scoped views).
pub fn for_wallet(env: &Env, wallet_id: &str) -> Result<Vec<Account>> {
    let sql = format!(r#"SELECT {COLS} FROM "Account" WHERE "Wallet" = ?1 ORDER BY "Index" ASC"#);
    let rows = env.query(&sql, vec![SqlValue::Text(wallet_id.to_owned())])?;
    Ok(rows.iter().map(|r| row_to_account(r)).collect())
}

fn row_to_account(row: &[SqlValue]) -> Account {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let il = row
        .get(11)
        .and_then(|v| v.as_text())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or(Value::Null);
    Account {
        id: text(0),
        wallet: text(1),
        name: text(2),
        index: row.get(3).and_then(|v| v.as_i64()).unwrap_or(0),
        kind: text(4),
        curve: text(5),
        path: text(6),
        address: text(7),
        uri: text(8),
        pubkey: text(9),
        chaincode: text(10),
        il,
        created: text(12),
        updated: text(13),
    }
}
