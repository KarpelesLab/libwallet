//! wltcontact — address book. Port of the Go `wltcontact` package.
//!
//! Establishes the object-model pattern reused by the other CRUD packages:
//! a serde struct whose field renames match the Go JSON keys, a table DDL
//! matching the psql schema, and fetch/list/create functions over the generic
//! [`crate::Env`] query layer.

use serde::{Deserialize, Serialize};
use crate::{Env, Result, SqlValue};
use xuid::Xuid;

/// Table DDL, matching the Go psql `Contact` schema (column names = Go field
/// names; time columns render as text, as current psql-sqlite does).
const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Contact" ("Id" text, "Name" text, "Address" text, "Type" text, "Flags" text, "Memo" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));"#;

const ID_PREFIX: &str = "ct";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Contact {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Address", default)]
    pub address: String,
    #[serde(rename = "Type", default)]
    pub kind: String, // ethereum | bitcoin | solana
    #[serde(rename = "Flags", default)]
    pub flags: Vec<String>,
    #[serde(rename = "Memo", default)]
    pub memo: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

/// Column order used by every SELECT/INSERT here.
const COLS: &str = r#""Id", "Name", "Address", "Type", "Flags", "Memo", "Created", "Updated""#;

/// Create the Contact table if needed (called from the FFI init, mirroring the
/// Go `InitEnv`).
pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Contact>> {
    let sql = format!(r#"SELECT {COLS} FROM "Contact" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_contact(r)))
}

pub fn list(env: &Env) -> Result<Vec<Contact>> {
    let sql = format!(r#"SELECT {COLS} FROM "Contact" ORDER BY "Created" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_contact(r)).collect())
}

/// Insert a new contact. Address normalization via outscript (per the Go
/// `validate`) is deferred to the address-handling pass; for now the type is
/// checked and the address is stored as given.
pub fn create(env: &Env, mut c: Contact) -> Result<Contact> {
    validate_type(&c.kind)?;
    c.id = Xuid::new(ID_PREFIX).to_string();
    let now = crate::now_rfc3339();
    c.created = now.clone();
    c.updated = now;

    let flags_json = serde_json::to_string(&c.flags).unwrap_or_else(|_| "[]".into());
    let sql = format!(
        r#"INSERT INTO "Contact" ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#
    );
    env.exec(
        &sql,
        vec![
            SqlValue::Text(c.id.clone()),
            SqlValue::Text(c.name.clone()),
            SqlValue::Text(c.address.clone()),
            SqlValue::Text(c.kind.clone()),
            SqlValue::Text(flags_json),
            SqlValue::Text(c.memo.clone()),
            SqlValue::Text(c.created.clone()),
            SqlValue::Text(c.updated.clone()),
        ],
    )?;
    Ok(c)
}

/// Update mutable fields (Go `contact.ApiUpdate`): `Name`, `Memo`, and
/// `Address` (with an optional `Type`). Returns the updated contact, or `None`
/// when the id is unknown. When no updatable field is supplied the row is left
/// untouched and the current contact is returned (matching Go, which returns
/// without saving). Address normalization via outscript is deferred here, same
/// as [`create`] — only the type is validated.
pub fn update(
    env: &Env,
    id: &str,
    name: Option<&str>,
    memo: Option<&str>,
    address: Option<&str>,
    kind: Option<&str>,
) -> Result<Option<Contact>> {
    let mut c = match fetch(env, id)? {
        Some(c) => c,
        None => return Ok(None),
    };
    let mut updated = false;
    if let Some(n) = name {
        c.name = n.to_owned();
        updated = true;
    }
    if let Some(m) = memo {
        c.memo = m.to_owned();
        updated = true;
    }
    if let Some(a) = address {
        if let Some(k) = kind {
            c.kind = k.to_owned();
        }
        c.address = a.to_owned();
        validate_type(&c.kind)?;
        updated = true;
    }
    if !updated {
        return Ok(Some(c));
    }
    c.updated = crate::now_rfc3339();
    let flags_json = serde_json::to_string(&c.flags).unwrap_or_else(|_| "[]".into());
    env.exec(
        r#"UPDATE "Contact" SET "Name"=?1, "Address"=?2, "Type"=?3, "Flags"=?4, "Memo"=?5, "Updated"=?6 WHERE "Id"=?7"#,
        vec![
            SqlValue::Text(c.name.clone()),
            SqlValue::Text(c.address.clone()),
            SqlValue::Text(c.kind.clone()),
            SqlValue::Text(flags_json),
            SqlValue::Text(c.memo.clone()),
            SqlValue::Text(c.updated.clone()),
            SqlValue::Text(c.id.clone()),
        ],
    )?;
    Ok(Some(c))
}

/// Delete a contact by id (Go `contact.ApiDelete`).
pub fn delete(env: &Env, id: &str) -> Result<()> {
    env.exec(
        r#"DELETE FROM "Contact" WHERE "Id" = ?1"#,
        vec![SqlValue::Text(id.to_owned())],
    )
    .map(|_| ())
}

fn validate_type(kind: &str) -> Result<()> {
    match kind {
        "ethereum" | "bitcoin" | "solana" => Ok(()),
        other => Err(crate::Error::Env(format!("unsupported contact type {other}"))),
    }
}

fn row_to_contact(row: &[SqlValue]) -> Contact {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let flags = row
        .get(4)
        .and_then(|v| v.as_text())
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default();
    Contact {
        id: text(0),
        name: text(1),
        address: text(2),
        kind: text(3),
        flags,
        memo: text(5),
        created: text(6),
        updated: text(7),
    }
}

