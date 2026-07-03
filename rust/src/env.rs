//! The libwallet environment — port of `wltbase/env.go`.
//!
//! Phase 1 owns the database and configuration lifecycle. The spotlib client,
//! emitter hub, balance poller and asset cache land in later phases.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::db::{Db, SqlValue};
use crate::error::{Error, Result};

pub struct Env {
    pub data_dir: PathBuf,
    db: Db,
}

impl Env {
    /// Initialize the environment rooted at `data_dir`: ensure the directory
    /// exists, open `sql.db`, create the base tables, and seed initial config.
    pub fn init(data_dir: &str) -> Result<Env> {
        if data_dir.is_empty() {
            return Err(Error::Env("data directory must not be empty".into()));
        }
        let dir = PathBuf::from(data_dir);
        ensure_dir(&dir)?;

        let sql_path = dir.join("sql.db");
        let sql_path = sql_path
            .to_str()
            .ok_or_else(|| Error::Env(format!("non-UTF8 data path: {dir:?}")))?;
        let db = Db::open(sql_path)?;

        let env = Env { data_dir: dir, db };
        env.init_config()?;
        Ok(env)
    }

    /// In-memory environment for tests (mirrors Go `InitTempEnv`).
    pub fn init_memory() -> Result<Env> {
        let env = Env { data_dir: PathBuf::new(), db: Db::open_memory()? };
        env.init_config()?;
        Ok(env)
    }

    /// Seed `version` and `first_run` on first launch, exactly as the Go env
    /// does: version is the 4-byte marker `{0,0,0,4}`, first_run is a 16-byte
    /// TimeId (Unix u64 BE | Nano u32 BE | Index u32 BE).
    fn init_config(&self) -> Result<()> {
        if self.db.config_get("version")?.is_none() {
            self.db.config_set("version", &[0, 0, 0, 4])?;
        }
        if self.db.config_get("first_run")?.is_none() {
            self.db.config_set("first_run", &time_id_now_bytes())?;
        }
        Ok(())
    }

    // --- generic query layer (for model crates) ---------------------------

    pub fn ensure_table(&self, ddl: &str) -> Result<()> {
        self.db.ensure_table(ddl)
    }

    pub fn query(&self, sql: &str, args: Vec<SqlValue>) -> Result<Vec<Vec<SqlValue>>> {
        self.db.query(sql, args)
    }

    pub fn exec(&self, sql: &str, args: Vec<SqlValue>) -> Result<usize> {
        self.db.exec(sql, args)
    }

    // --- config / cache / current: thin delegations to the DB layer -------

    pub fn config_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.db.config_get(key)
    }

    pub fn config_set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.db.config_set(key, value)
    }

    pub fn cache_store(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        self.db.cache_store(key, value, ttl)
    }

    pub fn cache_load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.db.cache_load(key)
    }

    pub fn cache_delete(&self, keys: &[&str]) -> Result<()> {
        self.db.cache_delete(keys)
    }

    pub fn cache_cleanup(&self) -> Result<usize> {
        self.db.cache_cleanup()
    }

    pub fn get_current(&self, key: &str) -> Result<Option<String>> {
        self.db.current_get(key)
    }

    pub fn set_current(&self, key: &str, value: &str) -> Result<()> {
        self.db.current_set(key, value)
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        if !dir.is_dir() {
            return Err(Error::Env(format!("data path {dir:?} exists and is not a directory")));
        }
    } else {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// 16-byte TimeId for the current instant: `Unix(u64 BE) | Nano(u32 BE) |
/// Index(u32 BE)`, matching `wltobj.NewTimeId().Bytes()`.
fn time_id_now_bytes() -> Vec<u8> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&now.as_secs().to_be_bytes()); // Unix, u64
    b.extend_from_slice(&now.subsec_nanos().to_be_bytes()); // Nano, u32
    b.extend_from_slice(&0u32.to_be_bytes()); // Index, u32
    b
}
