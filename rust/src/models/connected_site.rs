//! wltbase ConnectedSite — the dApp ↔ account connection store backing
//! Web3:request. A row links a site `Host` (scheme://host) to an `Account`;
//! `connected_accounts` returns a host's accounts with the current one first.

use serde::{Deserialize, Serialize};

use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "ConnectedSite" ("Id" text, "Host" text, "Account" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));
CREATE UNIQUE INDEX IF NOT EXISTS "ConnectedSite_hostAccount" ON "ConnectedSite" ("Host", "Account");"#;
const COLS: &str = r#""Id", "Host", "Account", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ConnectedSite {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Host", default)]
    pub host: String,
    #[serde(rename = "Account", default)]
    pub account: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

/// Connections for a site host, current account first (Go `connectedAccounts`).
pub fn for_host(env: &Env, host: &str) -> Result<Vec<ConnectedSite>> {
    let sql = format!(r#"SELECT {COLS} FROM "ConnectedSite" WHERE "Host" = ?1 ORDER BY "Created" ASC"#);
    let rows = env.query(&sql, vec![SqlValue::Text(host.to_owned())])?;
    let mut conn: Vec<ConnectedSite> = rows.iter().map(|r| row_to_conn(r)).collect();
    if conn.len() <= 1 {
        return Ok(conn);
    }
    // Move the current account to first position when it's connected.
    if let Some(cur) = env.get_current("account")? {
        if let Some(pos) = conn.iter().position(|c| c.account == cur) {
            if pos != 0 {
                let c = conn.remove(pos);
                conn.insert(0, c);
            }
        }
    }
    Ok(conn)
}

pub fn list(env: &Env, host: Option<&str>) -> Result<Vec<ConnectedSite>> {
    match host {
        Some(h) => for_host(env, h),
        None => {
            let sql = format!(r#"SELECT {COLS} FROM "ConnectedSite" ORDER BY "Created" ASC LIMIT 50"#);
            let rows = env.query(&sql, Vec::new())?;
            Ok(rows.iter().map(|r| row_to_conn(r)).collect())
        }
    }
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<ConnectedSite>> {
    let sql = format!(r#"SELECT {COLS} FROM "ConnectedSite" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_conn(r)))
}

/// Connect `account_id` to `host` if not already linked. Idempotent.
pub fn connect(env: &Env, host: &str, account_id: &str) -> Result<()> {
    let existing = for_host(env, host)?;
    if existing.iter().any(|c| c.account == account_id) {
        return Ok(());
    }
    let now = crate::now_rfc3339();
    env.exec(
        &format!(r#"INSERT INTO "ConnectedSite" ({COLS}) VALUES (?1,?2,?3,?4,?5)"#),
        vec![
            SqlValue::Text(xuid::Xuid::new("cnx").to_string()),
            SqlValue::Text(host.to_owned()),
            SqlValue::Text(account_id.to_owned()),
            SqlValue::Text(now.clone()),
            SqlValue::Text(now),
        ],
    )?;
    Ok(())
}

pub fn delete(env: &Env, id: &str) -> Result<()> {
    env.exec(r#"DELETE FROM "ConnectedSite" WHERE "Id" = ?1"#, vec![SqlValue::Text(id.to_owned())]).map(|_| ())
}

fn row_to_conn(row: &[SqlValue]) -> ConnectedSite {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    ConnectedSite { id: text(0), host: text(1), account: text(2), created: text(3), updated: text(4) }
}
