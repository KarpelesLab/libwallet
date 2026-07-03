//! wlttoken (Token model) — port of the Go `wlttoken` package.
//!
//! Read surface: fetch/list of known tokens (PascalCase JSON, plain struct).
//! Token creation discovers on-chain metadata (RPC) and is deferred (POST 501).

use serde::{Deserialize, Serialize};
use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Token" ("Id" text, "Name" text, "Symbol" text, "Address" text, "Decimals" integer, "Type" text, "Network" text, "Logo" text, "Memo" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Name", "Symbol", "Address", "Decimals", "Type", "Network", "Logo", "Memo", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Token {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Symbol", default)]
    pub symbol: String,
    #[serde(rename = "Address", default)]
    pub address: String,
    #[serde(rename = "Decimals", default)]
    pub decimals: i64,
    #[serde(rename = "Type", default)]
    pub kind: String, // erc20 | nft | spl-token | spl-token-2022
    #[serde(rename = "Network", default)]
    pub network: String,
    #[serde(rename = "Logo", default)]
    pub logo: String,
    #[serde(rename = "Memo", default)]
    pub memo: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Token>> {
    let sql = format!(r#"SELECT {COLS} FROM "Token" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_token(r)))
}

pub fn list(env: &Env) -> Result<Vec<Token>> {
    let sql = format!(r#"SELECT {COLS} FROM "Token" ORDER BY "Symbol" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_token(r)).collect())
}

fn row_to_token(row: &[SqlValue]) -> Token {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    Token {
        id: text(0),
        name: text(1),
        symbol: text(2),
        address: text(3),
        decimals: row.get(4).and_then(|v| v.as_i64()).unwrap_or(0),
        kind: text(5),
        network: text(6),
        logo: text(7),
        memo: text(8),
        created: text(9),
        updated: text(10),
    }
}
