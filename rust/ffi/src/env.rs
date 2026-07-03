//! The libwallet environment.
//!
//! Phase 0 stub: today it only owns the data directory. As the port
//! progresses this grows to own the graphitesql database handle, the spotlib
//! client, the emitter/event hub, the balance poller and the asset cache —
//! mirroring `wltbase/env.go`'s `env` struct.

use std::path::PathBuf;

pub struct Env {
    #[allow(dead_code)]
    pub data_dir: PathBuf,
}

impl Env {
    /// Initialize the environment rooted at `data_dir`, creating the directory
    /// if it does not exist. Mirrors the directory check at the top of
    /// `wltbase.InitEnv`.
    pub fn init(data_dir: &str) -> Result<Env, String> {
        if data_dir.is_empty() {
            return Err("data directory must not be empty".into());
        }
        let dir = PathBuf::from(data_dir);
        if dir.exists() {
            if !dir.is_dir() {
                return Err(format!("data path {data_dir:?} exists and is not a directory"));
            }
        } else {
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("failed to create data directory {data_dir:?}: {e}"))?;
        }
        Ok(Env { data_dir: dir })
    }
}
