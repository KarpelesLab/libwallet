//! wltbase Request — the user-approval queue backing Web3/RemoteKey prompts.
//!
//! A request is a DB row plus an in-memory waiter channel (held in the Env):
//! `run` persists a `pending` row, broadcasts a `request` host event, and blocks
//! until `Request:approve`/`Request:reject` resolves the waiter (or a 2-minute
//! timeout fires). Entirely local — no spot network.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Request" ("Id" text, "Type" text, "Host" text, "Status" text, "Account" text, "Transaction" text, "Value" text, "Result" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Type", "Host", "Status", "Account", "Transaction", "Value", "Result", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Request {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Type", default)]
    pub kind: String,
    #[serde(rename = "Host", default)]
    pub host: String,
    #[serde(rename = "Status", default)]
    pub status: String,
    #[serde(rename = "Account", default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(rename = "Transaction", default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<Value>,
    #[serde(rename = "Value", default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(rename = "Result", default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Request>> {
    let sql = format!(r#"SELECT {COLS} FROM "Request" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_request(r)))
}

pub fn list(env: &Env) -> Result<Vec<Request>> {
    let sql = format!(r#"SELECT {COLS} FROM "Request" ORDER BY "Created" ASC LIMIT 50"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_request(r)).collect())
}

/// Insert or replace a request row (keyed on `Id`).
pub fn save(env: &Env, r: &Request) -> Result<()> {
    let j = |v: &Option<Value>| -> String { v.as_ref().map(|x| x.to_string()).unwrap_or_default() };
    env.exec(r#"DELETE FROM "Request" WHERE "Id" = ?1"#, vec![SqlValue::Text(r.id.clone())])?;
    env.exec(
        &format!(r#"INSERT INTO "Request" ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#),
        vec![
            SqlValue::Text(r.id.clone()),
            SqlValue::Text(r.kind.clone()),
            SqlValue::Text(r.host.clone()),
            SqlValue::Text(r.status.clone()),
            SqlValue::Text(r.account.clone().unwrap_or_default()),
            SqlValue::Text(j(&r.transaction)),
            SqlValue::Text(j(&r.value)),
            SqlValue::Text(j(&r.result)),
            SqlValue::Text(r.created.clone()),
            SqlValue::Text(r.updated.clone()),
        ],
    )?;
    Ok(())
}

fn row_to_request(row: &[SqlValue]) -> Request {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let opt_json = |i: usize| -> Option<Value> {
        row.get(i).and_then(|v| v.as_text()).filter(|s| !s.is_empty()).and_then(|s| serde_json::from_str(s).ok())
    };
    let opt_text = |i: usize| -> Option<String> {
        row.get(i).and_then(|v| v.as_text()).filter(|s| !s.is_empty()).map(str::to_owned)
    };
    Request {
        id: text(0),
        kind: text(1),
        host: text(2),
        status: text(3),
        account: opt_text(4),
        transaction: opt_json(5),
        value: opt_json(6),
        result: opt_json(7),
        created: text(8),
        updated: text(9),
    }
}
