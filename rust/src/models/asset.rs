//! wltasset — asset/balance rows. Port of the Go `wltasset` package.
//!
//! Read surface only: assets are populated by balance discovery (RPC), which
//! lands with wltnet; there is no create endpoint. Unlike the other models,
//! Asset uses lowercase JSON keys (explicit Go `json:` tags) — except Created/
//! Updated, which have none and stay PascalCase. Amount is stored as its
//! `{v,e,f}` JSON and round-trips through [`crate::Amount`].

use serde::{Deserialize, Serialize};
use crate::{Amount, Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Asset" ("Id" text, "Key" text, "Name" text, "Symbol" text, "Amount" text, "Type" text, "Network" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));
CREATE UNIQUE INDEX IF NOT EXISTS "Asset_Key" ON "Asset" ("Key");"#;
const COLS: &str = r#""Id", "Key", "Name", "Symbol", "Amount", "Type", "Network", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Asset {
    #[serde(rename = "id", default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(rename = "key", default)]
    pub key: String,
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "symbol", default)]
    pub symbol: String,
    #[serde(rename = "amount")]
    pub amount: Amount,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(rename = "network", default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Asset>> {
    let sql = format!(r#"SELECT {COLS} FROM "Asset" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_asset(r)))
}

pub fn list(env: &Env) -> Result<Vec<Asset>> {
    let sql = format!(r#"SELECT {COLS} FROM "Asset" ORDER BY "Key" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_asset(r)).collect())
}

fn row_to_asset(row: &[SqlValue]) -> Asset {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let amount = row
        .get(4)
        .and_then(|v| v.as_text())
        .and_then(|s| serde_json::from_str::<Amount>(s).ok())
        .unwrap_or_else(|| Amount::new(0, 0));
    Asset {
        id: text(0),
        key: text(1),
        name: text(2),
        symbol: text(3),
        amount,
        kind: text(5),
        network: text(6),
        created: text(7),
        updated: text(8),
    }
}
