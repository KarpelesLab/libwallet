//! SQLite persistence over graphitesql.
//!
//! Schema and column names are byte-identical to what the Go `psql`/
//! `psql-sqlite` layer produces, so an existing `sql.db` written by the Go
//! build opens and round-trips here unchanged. Ground truth was captured by
//! driving the Go structs directly.
//!
//! graphitesql's `Connection` is single-threaded (not `Send`), so it lives on
//! a dedicated actor thread and is never moved off it. Callers interact via a
//! channel; [`Db`] is therefore `Send + Sync` and can be shared across the FFI
//! request worker threads. Access is naturally serialized by the actor, which
//! is also how SQLite wants a single connection used.
//!
//! Timestamps are stored as RFC3339 text (matching the Go `time.Time` render).
//! Reads parse flexibly (any fractional-second width); writes emit fixed
//! nanosecond precision with a `Z` suffix.

use std::path::Path;
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use graphitesql::exec::eval::Params;
use graphitesql::{Connection, Value};

use crate::error::{Error, Result};

/// Current-era table definitions, matching the Go struct `sql:` tags exactly.
const SCHEMA: &str = concat!(
    r#"CREATE TABLE IF NOT EXISTS "KvConfig" ("Key" text, "Value" blob, PRIMARY KEY ("Key"));"#,
    r#"CREATE TABLE IF NOT EXISTS "Cache" ("Key" text, "Value" blob, "ExpiresAt" text, PRIMARY KEY ("Key"));"#,
    r#"CREATE TABLE IF NOT EXISTS "CurrentItem" ("Key" text, "Value" text, "Created" text, "Updated" text, PRIMARY KEY ("Key"));"#,
);

/// A cross-crate SQL value, so model crates can run parameterized queries
/// without depending on graphitesql's own `Value` type.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl SqlValue {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            SqlValue::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SqlValue::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_blob(&self) -> Option<&[u8]> {
        match self {
            SqlValue::Blob(b) => Some(b),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, SqlValue::Null)
    }
}

impl From<SqlValue> for Value {
    fn from(v: SqlValue) -> Value {
        match v {
            SqlValue::Null => Value::Null,
            SqlValue::Int(i) => Value::Integer(i),
            SqlValue::Real(r) => Value::Real(r),
            SqlValue::Text(s) => Value::Text(s),
            SqlValue::Blob(b) => Value::Blob(b),
        }
    }
}

impl From<&Value> for SqlValue {
    fn from(v: &Value) -> SqlValue {
        match v {
            Value::Null => SqlValue::Null,
            Value::Integer(i) => SqlValue::Int(*i),
            Value::Real(r) => SqlValue::Real(*r),
            Value::Text(s) => SqlValue::Text(s.clone()),
            Value::Blob(b) => SqlValue::Blob(b.clone()),
        }
    }
}

type Job = Box<dyn FnOnce(&mut DbInner) + Send>;

/// Handle to the database actor. Cloneable-free: share via `Arc`.
pub struct Db {
    sender: Mutex<mpsc::Sender<Job>>,
}

impl Db {
    pub fn open(path: &str) -> Result<Db> {
        let path = path.to_owned();
        Db::spawn(move || {
            if Path::new(&path).exists() {
                Ok(Connection::open(&path)?)
            } else {
                Ok(Connection::create(&path)?)
            }
        })
    }

    pub fn open_memory() -> Result<Db> {
        Db::spawn(|| Ok(Connection::open_memory()?))
    }

    /// Spawn the actor thread, open the connection on it, and wait for the
    /// open + schema creation to succeed (propagating any error).
    fn spawn(open: impl FnOnce() -> Result<Connection> + Send + 'static) -> Result<Db> {
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        let (job_tx, job_rx) = mpsc::channel::<Job>();
        thread::Builder::new()
            .name("wltbase-db".into())
            .spawn(move || {
                let mut inner = match open().and_then(DbInner::new) {
                    Ok(inner) => {
                        let _ = ready_tx.send(Ok(()));
                        inner
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                // Drains until the last Db (sender) is dropped.
                while let Ok(job) = job_rx.recv() {
                    job(&mut inner);
                }
            })
            .map_err(Error::Io)?;

        ready_rx
            .recv()
            .map_err(|_| Error::Env("db thread failed to start".into()))??;
        Ok(Db { sender: Mutex::new(job_tx) })
    }

    /// Run `f` on the actor thread and wait for its result.
    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut DbInner) -> Result<R> + Send + 'static,
    ) -> Result<R> {
        let (tx, rx) = mpsc::channel();
        self.sender
            .lock()
            .unwrap()
            .send(Box::new(move |inner| {
                let _ = tx.send(f(inner));
            }))
            .map_err(|_| Error::Env("db thread gone".into()))?;
        rx.recv().map_err(|_| Error::Env("db reply lost".into()))?
    }

    // --- Generic query layer (for model crates) ---------------------------

    /// Ensure a table exists (runs `CREATE TABLE IF NOT EXISTS ...` DDL).
    pub fn ensure_table(&self, ddl: &str) -> Result<()> {
        let ddl = ddl.to_owned();
        self.call(move |i| {
            i.conn.execute_batch(&ddl)?;
            Ok(())
        })
    }

    /// Run a parameterized query (`?1`, `?2`, ...) and return the rows.
    pub fn query(&self, sql: &str, args: Vec<SqlValue>) -> Result<Vec<Vec<SqlValue>>> {
        let sql = sql.to_owned();
        self.call(move |i| i.query(&sql, args))
    }

    /// Run a parameterized statement and return the number of affected rows.
    pub fn exec(&self, sql: &str, args: Vec<SqlValue>) -> Result<usize> {
        let sql = sql.to_owned();
        self.call(move |i| i.exec(&sql, args))
    }

    // --- KvConfig ---------------------------------------------------------

    pub fn config_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key = key.to_owned();
        self.call(move |i| i.config_get(&key))
    }

    pub fn config_set(&self, key: &str, value: &[u8]) -> Result<()> {
        let (key, value) = (key.to_owned(), value.to_vec());
        self.call(move |i| i.config_set(&key, &value))
    }

    // --- Cache ------------------------------------------------------------

    pub fn cache_store(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        let (key, value) = (key.to_owned(), value.to_vec());
        self.call(move |i| i.cache_store(&key, &value, ttl))
    }

    pub fn cache_load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key = key.to_owned();
        self.call(move |i| i.cache_load(&key))
    }

    pub fn cache_delete(&self, keys: &[&str]) -> Result<()> {
        let keys: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
        self.call(move |i| i.cache_delete(&keys))
    }

    pub fn cache_cleanup(&self) -> Result<usize> {
        self.call(|i| i.cache_cleanup())
    }

    // --- CurrentItem ------------------------------------------------------

    pub fn current_get(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_owned();
        self.call(move |i| i.current_get(&key))
    }

    pub fn current_set(&self, key: &str, value: &str) -> Result<()> {
        let (key, value) = (key.to_owned(), value.to_owned());
        self.call(move |i| i.current_set(&key, &value))
    }
}

/// The connection-owning state, confined to the actor thread.
struct DbInner {
    conn: Connection,
}

impl DbInner {
    fn new(mut conn: Connection) -> Result<DbInner> {
        conn.execute_batch(SCHEMA)?;
        Ok(DbInner { conn })
    }

    fn query(&mut self, sql: &str, args: Vec<SqlValue>) -> Result<Vec<Vec<SqlValue>>> {
        let p = params(args.into_iter().map(Value::from).collect());
        let r = self.conn.query_params(sql, &p)?;
        Ok(r.rows.iter().map(|row| row.iter().map(SqlValue::from).collect()).collect())
    }

    fn exec(&mut self, sql: &str, args: Vec<SqlValue>) -> Result<usize> {
        let p = params(args.into_iter().map(Value::from).collect());
        Ok(self.conn.execute_params(sql, &p)?)
    }

    fn config_get(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        let r = self.conn.query_params(
            r#"SELECT "Value" FROM "KvConfig" WHERE "Key" = ?1"#,
            &params(vec![Value::Text(key.to_owned())]),
        )?;
        Ok(r.rows.first().and_then(|row| row.first()).and_then(as_bytes))
    }

    fn config_set(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute_params(
            r#"INSERT OR REPLACE INTO "KvConfig" ("Key", "Value") VALUES (?1, ?2)"#,
            &params(vec![Value::Text(key.to_owned()), Value::Blob(value.to_vec())]),
        )?;
        Ok(())
    }

    fn cache_store(&mut self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        self.conn.execute_params(
            r#"INSERT OR REPLACE INTO "Cache" ("Key", "Value", "ExpiresAt") VALUES (?1, ?2, ?3)"#,
            &params(vec![
                Value::Text(key.to_owned()),
                Value::Blob(value.to_vec()),
                Value::Text(ttl_text(ttl)),
            ]),
        )?;
        Ok(())
    }

    fn cache_load(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        let r = self.conn.query_params(
            r#"SELECT "Value", "ExpiresAt" FROM "Cache" WHERE "Key" = ?1"#,
            &params(vec![Value::Text(key.to_owned())]),
        )?;
        let Some(row) = r.rows.first() else { return Ok(None) };
        if let Some(exp) = row.get(1).and_then(as_text) {
            if is_expired(&exp) {
                return Ok(None);
            }
        }
        Ok(row.first().and_then(as_bytes))
    }

    fn cache_delete(&mut self, keys: &[String]) -> Result<()> {
        for key in keys {
            self.conn.execute_params(
                r#"DELETE FROM "Cache" WHERE "Key" = ?1"#,
                &params(vec![Value::Text(key.clone())]),
            )?;
        }
        Ok(())
    }

    fn cache_cleanup(&mut self) -> Result<usize> {
        let n = self.conn.execute_params(
            r#"DELETE FROM "Cache" WHERE "ExpiresAt" < ?1"#,
            &params(vec![Value::Text(now_text())]),
        )?;
        Ok(n)
    }

    fn current_get(&mut self, key: &str) -> Result<Option<String>> {
        let r = self.conn.query_params(
            r#"SELECT "Value" FROM "CurrentItem" WHERE "Key" = ?1"#,
            &params(vec![Value::Text(key.to_owned())]),
        )?;
        Ok(r.rows.first().and_then(|row| row.first()).and_then(as_text))
    }

    fn current_set(&mut self, key: &str, value: &str) -> Result<()> {
        let now = now_text();
        // Preserve the original Created on update; set it to now on insert.
        // Mirrors the Go currentItem.BeforeSave hook.
        let existing = self.conn.query_params(
            r#"SELECT "Created" FROM "CurrentItem" WHERE "Key" = ?1"#,
            &params(vec![Value::Text(key.to_owned())]),
        )?;
        let created = existing
            .rows
            .first()
            .and_then(|row| row.first())
            .and_then(as_text)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| now.clone());
        self.conn.execute_params(
            r#"INSERT OR REPLACE INTO "CurrentItem" ("Key", "Value", "Created", "Updated") VALUES (?1, ?2, ?3, ?4)"#,
            &params(vec![
                Value::Text(key.to_owned()),
                Value::Text(value.to_owned()),
                Value::Text(created),
                Value::Text(now),
            ]),
        )?;
        Ok(())
    }
}

fn params(vals: Vec<Value>) -> Params {
    Params { positional: vals, named: Vec::new() }
}

/// Current UTC instant as RFC3339 text (nanosecond precision, `Z` suffix) —
/// the timestamp format used across the wltbase-owned tables and model rows.
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn now_text() -> String {
    now_rfc3339()
}

fn ttl_text(ttl: Duration) -> String {
    let when =
        Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero());
    when.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

/// True if `expires` (RFC3339 text) is in the past.
fn is_expired(expires: &str) -> bool {
    match DateTime::parse_from_rfc3339(expires) {
        Ok(exp) => Utc::now() > exp.with_timezone(&Utc),
        Err(_) => false, // unparseable: treat as non-expiring rather than dropping data
    }
}

fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Blob(b) => Some(b.clone()),
        Value::Text(s) => Some(s.clone().into_bytes()),
        _ => None,
    }
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        Value::Blob(b) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}
