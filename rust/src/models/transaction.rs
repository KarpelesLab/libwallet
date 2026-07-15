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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
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

    // Computed (never persisted) fiat conversion, matching Go's sql:"-" fields.
    #[serde(rename = "fiat_amount", default, skip_serializing_if = "Option::is_none")]
    pub fiat_amount: Option<Amount>,
    #[serde(rename = "fiat_currency", default, skip_serializing_if = "String::is_empty")]
    pub fiat_currency: String,
    #[serde(rename = "fiat_quote", default, skip_serializing_if = "Option::is_none")]
    pub fiat_quote: Option<crate::quote::CmcQuoteEntry>,
}

impl Transaction {
    /// The native symbol for pricing this tx: resolve the network (the tx's own,
    /// else the current network) and take its native currency. Mirrors Go
    /// `Transaction.getSymbol` (native-only for now).
    fn symbol(&self, env: &Env) -> Result<String> {
        let id = if self.network.is_empty() { "@" } else { &self.network };
        match crate::models::network::fetch(env, id)? {
            Some(n) => n.native_symbol(),
            None => Err(crate::Error::Env("no network for transaction".into())),
        }
    }

    /// Port of Go `Transaction.convertTo`: price the tx's amount (or value) in
    /// `currency` from the quote table and set the fiat_* fields. `Ok(false)`
    /// when no symbol/quote/amount applies.
    pub fn convert_to(&mut self, env: &Env, currency: &str) -> Result<bool> {
        let symbol = match self.symbol(env) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        let quote = match crate::quote::get_quotes_for_token(env, &symbol)? {
            Some(q) => q,
            None => return Ok(false),
        };
        let entry = match quote.quote.get(currency) {
            Some(e) => e.clone(),
            None => return Ok(false),
        };
        // Prefer amount, else value; skip when neither is positive.
        let amt = self
            .amount
            .as_ref()
            .filter(|a| a.sign() > 0)
            .or_else(|| self.value.as_ref().filter(|a| a.sign() > 0));
        let amt = match amt {
            Some(a) => a.clone(),
            None => return Ok(false),
        };
        let price = Amount::from_float64(entry.price, 8);
        let mut fiat = Amount::new(0, 8);
        fiat.mul(&amt, &price);
        self.fiat_amount = Some(fiat);
        self.fiat_currency = currency.to_owned();
        self.fiat_quote = Some(entry);
        Ok(true)
    }
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

/// Insert (or replace) a transaction row after signing/broadcast. `Amount`
/// columns are stored as their JSON encoding (matching the read path's decode).
pub fn persist(env: &Env, tx: &Transaction) -> Result<()> {
    let amount_json = |a: &Option<Amount>| -> String {
        a.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()).unwrap_or_default()
    };
    let raw_bytes = base64::engine::general_purpose::STANDARD.decode(&tx.raw).unwrap_or_default();
    env.exec(r#"DELETE FROM "Transaction" WHERE "Id" = ?1"#, vec![SqlValue::Text(tx.id.clone())])?;
    env.exec(
        &format!(r#"INSERT INTO "Transaction" ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)"#),
        vec![
            SqlValue::Text(tx.id.clone()),
            SqlValue::Text(tx.kind.clone()),
            SqlValue::Text(tx.asset.clone()),
            SqlValue::Text(tx.from.clone()),
            SqlValue::Text(tx.to.clone()),
            SqlValue::Int(tx.gas as i64),
            SqlValue::Text(tx.gas_price.clone()),
            SqlValue::Text(tx.max_fee_per_gas.clone()),
            SqlValue::Text(tx.max_priority_fee_per_gas.clone()),
            SqlValue::Text(amount_json(&tx.fee)),
            SqlValue::Int(tx.nonce as i64),
            SqlValue::Text(tx.format.clone()),
            SqlValue::Blob(raw_bytes),
            SqlValue::Text(tx.hash.clone()),
            SqlValue::Text(tx.url.clone()),
            SqlValue::Text(tx.network.clone()),
            SqlValue::Text(amount_json(&tx.amount)),
            SqlValue::Text(amount_json(&tx.value)),
            SqlValue::Text(tx.data.clone()),
            SqlValue::Text(tx.created.clone()),
        ],
    )?;
    Ok(())
}

/// Delete a single transaction by id (Go `Transaction.ApiDelete` →
/// `psql.ForceDelete[Transaction]{"Id": id}`). No error when the row is
/// already absent — the caller fetches first and 404s on a miss.
pub fn delete_one(env: &Env, id: &str) -> Result<()> {
    env.exec(r#"DELETE FROM "Transaction" WHERE "Id" = ?1"#, vec![SqlValue::Text(id.to_owned())])?;
    Ok(())
}

/// Clear the transaction collection (Go `apiClearTransaction`). Honours the
/// optional `From` (account) and `Network` filters exactly like Go's
/// `psql.ForceDelete` where-clause; with neither, deletes every row.
pub fn clear(env: &Env, from: Option<&str>, network: Option<&str>) -> Result<()> {
    let mut sql = String::from(r#"DELETE FROM "Transaction""#);
    let mut conds: Vec<String> = Vec::new();
    let mut args: Vec<SqlValue> = Vec::new();
    if let Some(f) = from {
        conds.push(format!(r#""From" = ?{}"#, args.len() + 1));
        args.push(SqlValue::Text(f.to_owned()));
    }
    if let Some(n) = network {
        conds.push(format!(r#""Network" = ?{}"#, args.len() + 1));
        args.push(SqlValue::Text(n.to_owned()));
    }
    if !conds.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conds.join(" AND "));
    }
    env.exec(&sql, args)?;
    Ok(())
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
        fiat_amount: None,
        fiat_currency: String::new(),
        fiat_quote: None,
    }
}
