//! wlttx (Transaction model) — port of the Go `wlttx` Transaction type.
//!
//! Read surface: fetch/list of stored transactions. Lowercase JSON keys with
//! omitempty; Fee/Amount/Value are Amount JSON; Raw is a BLOB emitted as a
//! base64 string (matching Go's []byte JSON). Building/signing/broadcast
//! (Validate, signAndSend) is deferred to the tx pass (POST 501).

use base64::Engine;
use serde::{Deserialize, Serialize};
use crate::{Amount, Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Transaction" ("Id" text, "Type" text, "Asset" text, "From" text, "To" text, "Gas" integer, "GasPrice" text, "MaxFeePerGas" text, "MaxPriorityFeePerGas" text, "Fee" text, "Nonce" integer, "Format" text, "Raw" blob, "Hash" text, "URL" text, "Network" text, "Amount" text, "Value" text, "Data" text, "Created" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Type", "Asset", "From", "To", "Gas", "GasPrice", "MaxFeePerGas", "MaxPriorityFeePerGas", "Fee", "Nonce", "Format", "Raw", "Hash", "URL", "Network", "Amount", "Value", "Data", "Created""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Transaction {
    #[serde(rename = "id", default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(rename = "asset", default)]
    pub asset: String,
    #[serde(rename = "from", default, skip_serializing_if = "String::is_empty")]
    pub from: String,
    #[serde(rename = "to", default)]
    pub to: String,
    #[serde(rename = "gas", default)]
    pub gas: u64,
    #[serde(rename = "gasPrice", default, skip_serializing_if = "String::is_empty")]
    pub gas_price: String,
    #[serde(rename = "maxFeePerGas", default, skip_serializing_if = "String::is_empty")]
    pub max_fee_per_gas: String,
    #[serde(rename = "maxPriorityFeePerGas", default, skip_serializing_if = "String::is_empty")]
    pub max_priority_fee_per_gas: String,
    #[serde(rename = "fee", default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<Amount>,
    #[serde(rename = "nonce", default)]
    pub nonce: u64,
    #[serde(rename = "format", default, skip_serializing_if = "String::is_empty")]
    pub format: String,
    /// base64 of the Raw blob (Go marshals []byte as base64).
    #[serde(rename = "raw", default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
    #[serde(rename = "hash", default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
    #[serde(rename = "url", default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(rename = "network", default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    #[serde(rename = "amount", default)]
    pub amount: Option<Amount>,
    #[serde(rename = "value", default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Amount>,
    #[serde(rename = "data", default, skip_serializing_if = "String::is_empty")]
    pub data: String,
    #[serde(rename = "created", default, skip_serializing_if = "String::is_empty")]
    pub created: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Transaction>> {
    let sql = format!(r#"SELECT {COLS} FROM "Transaction" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_tx(r)))
}

pub fn list(env: &Env) -> Result<Vec<Transaction>> {
    let sql = format!(r#"SELECT {COLS} FROM "Transaction" ORDER BY "Created" DESC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_tx(r)).collect())
}

fn amount_at(row: &[SqlValue], i: usize) -> Option<Amount> {
    row.get(i)
        .and_then(|v| v.as_text())
        .filter(|s| !s.is_empty() && *s != "null")
        .and_then(|s| serde_json::from_str::<Amount>(s).ok())
}

fn row_to_tx(row: &[SqlValue]) -> Transaction {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let uint = |i: usize| row.get(i).and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u64;
    let raw = row
        .get(12)
        .and_then(|v| v.as_blob())
        .filter(|b| !b.is_empty())
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
        .unwrap_or_default();
    Transaction {
        id: text(0),
        kind: text(1),
        asset: text(2),
        from: text(3),
        to: text(4),
        gas: uint(5),
        gas_price: text(6),
        max_fee_per_gas: text(7),
        max_priority_fee_per_gas: text(8),
        fee: amount_at(row, 9),
        nonce: uint(10),
        format: text(11),
        raw,
        hash: text(13),
        url: text(14),
        network: text(15),
        amount: amount_at(row, 16),
        value: amount_at(row, 17),
        data: text(18),
        created: text(19),
    }
}
