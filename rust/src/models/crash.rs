//! wltcrash — crash/panic log storage. Port of the Go `wltcrash` package.
//!
//! Fetch/List only over the API; rows are written internally by [`log`] when a
//! panic is caught (the Rust analogue of the Go `Log`). Id is a plain UUIDv4.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Crash" ("Id" text, "Where" text, "Message" text, "Stack" text, "Created" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Where", "Message", "Stack", "Created""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Crash {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Where", default)]
    pub where_: String,
    #[serde(rename = "Message", default)]
    pub message: String,
    #[serde(rename = "Stack", default)]
    pub stack: String,
    #[serde(rename = "Created", default)]
    pub created: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Crash>> {
    let sql = format!(r#"SELECT {COLS} FROM "Crash" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_crash(r)))
}

pub fn list(env: &Env) -> Result<Vec<Crash>> {
    let sql = format!(r#"SELECT {COLS} FROM "Crash" ORDER BY "Created" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_crash(r)).collect())
}

/// Record a crash and return its id. Called when a panic is caught.
pub fn log(env: &Env, where_: &str, message: &str, stack: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let created = crate::now_rfc3339();
    let sql = format!(r#"INSERT INTO "Crash" ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5)"#);
    env.exec(
        &sql,
        vec![
            SqlValue::Text(id.clone()),
            SqlValue::Text(where_.to_owned()),
            SqlValue::Text(message.to_owned()),
            SqlValue::Text(stack.to_owned()),
            SqlValue::Text(created),
        ],
    )?;
    Ok(id)
}

/// Delete a crash record by id (Go `Crash.ApiDelete`).
pub fn delete(env: &Env, id: &str) -> Result<()> {
    env.exec(
        r#"DELETE FROM "Crash" WHERE "Id" = ?1"#,
        vec![SqlValue::Text(id.to_owned())],
    )
    .map(|_| ())
}

fn row_to_crash(row: &[SqlValue]) -> Crash {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    Crash { id: text(0), where_: text(1), message: text(2), stack: text(3), created: text(4) }
}
