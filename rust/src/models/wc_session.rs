//! WalletConnect session store — port of the Go `wltwc` `wcSession` model
//! (table "WalletConnect"). Persists pairing and active sessions so encrypted
//! relay traffic survives restarts: a row starts as `state="pairing"` (the
//! pairing topic + symKey + the wallet's proposal keypair) and becomes
//! `state="active"` on settle (the per-session topic + derived symKey +
//! negotiated namespaces).

use serde::{Deserialize, Serialize};
use xuid::Xuid;

use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "WalletConnect" ("Id" text, "Topic" text, "PairingTopic" text, "State" text, "SymKey" text, "SelfPriv" text, "SelfPub" text, "PeerPub" text, "PeerMetadata" text, "Namespaces" text, "Expiry" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));
CREATE UNIQUE INDEX IF NOT EXISTS "WalletConnect_Topic" ON "WalletConnect" ("Topic");"#;
const COLS: &str = r#""Id", "Topic", "PairingTopic", "State", "SymKey", "SelfPriv", "SelfPub", "PeerPub", "PeerMetadata", "Namespaces", "Expiry", "Created", "Updated""#;
const ID_PREFIX: &str = "wc";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WcSession {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Topic", default)]
    pub topic: String,
    #[serde(rename = "PairingTopic", default)]
    pub pairing_topic: String,
    /// "pairing" | "proposed" | "active" | "disconnected".
    #[serde(rename = "State", default)]
    pub state: String,
    /// base64url 32-byte symKey for envelope encryption on Topic.
    #[serde(rename = "SymKey", default)]
    pub sym_key: String,
    #[serde(rename = "SelfPriv", default, skip_serializing)]
    pub self_priv: String,
    #[serde(rename = "SelfPub", default)]
    pub self_pub: String,
    #[serde(rename = "PeerPub", default)]
    pub peer_pub: String,
    #[serde(rename = "PeerMetadata", default)]
    pub peer_metadata: String,
    #[serde(rename = "Namespaces", default)]
    pub namespaces: String,
    #[serde(rename = "Expiry", default)]
    pub expiry: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

/// Persist a new pairing row (state = "pairing") for a parsed pairing URI.
pub fn create_pairing(
    env: &Env,
    pairing_topic: &str,
    sym_key_b64: &str,
    self_priv_b64: &str,
    self_pub_b64: &str,
) -> Result<WcSession> {
    let now = crate::now_rfc3339();
    let s = WcSession {
        id: Xuid::new(ID_PREFIX).to_string(),
        topic: pairing_topic.to_owned(),
        pairing_topic: pairing_topic.to_owned(),
        state: "pairing".to_owned(),
        sym_key: sym_key_b64.to_owned(),
        self_priv: self_priv_b64.to_owned(),
        self_pub: self_pub_b64.to_owned(),
        peer_pub: String::new(),
        peer_metadata: String::new(),
        namespaces: String::new(),
        expiry: String::new(),
        created: now.clone(),
        updated: now,
    };
    insert(env, &s)?;
    Ok(s)
}

fn insert(env: &Env, s: &WcSession) -> Result<()> {
    env.exec(
        &format!(r#"INSERT INTO "WalletConnect" ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"#),
        vec![
            SqlValue::Text(s.id.clone()),
            SqlValue::Text(s.topic.clone()),
            SqlValue::Text(s.pairing_topic.clone()),
            SqlValue::Text(s.state.clone()),
            SqlValue::Text(s.sym_key.clone()),
            SqlValue::Text(s.self_priv.clone()),
            SqlValue::Text(s.self_pub.clone()),
            SqlValue::Text(s.peer_pub.clone()),
            SqlValue::Text(s.peer_metadata.clone()),
            SqlValue::Text(s.namespaces.clone()),
            SqlValue::Text(s.expiry.clone()),
            SqlValue::Text(s.created.clone()),
            SqlValue::Text(s.updated.clone()),
        ],
    )
    .map(|_| ())
}

/// The (one) session using `topic` for its encrypted traffic (Go
/// `sessionByTopic`).
pub fn fetch_by_topic(env: &Env, topic: &str) -> Result<Option<WcSession>> {
    let sql = format!(r#"SELECT {COLS} FROM "WalletConnect" WHERE "Topic" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(topic.to_owned())])?;
    Ok(rows.first().map(|r| row_to_session(r)))
}

/// All sessions in a given state (e.g. "active" — Go `allActiveSessions`).
pub fn list_by_state(env: &Env, state: &str) -> Result<Vec<WcSession>> {
    let sql = format!(r#"SELECT {COLS} FROM "WalletConnect" WHERE "State" = ?1 ORDER BY "Created" ASC"#);
    let rows = env.query(&sql, vec![SqlValue::Text(state.to_owned())])?;
    Ok(rows.iter().map(|r| row_to_session(r)).collect())
}

/// Settle a pairing into an active session: move to the per-session topic with
/// its derived symKey and the negotiated namespaces (Go `ApproveProposal`).
pub fn settle(
    env: &Env,
    id: &str,
    session_topic: &str,
    session_sym_b64: &str,
    peer_pub_b64: &str,
    namespaces_json: &str,
    expiry: &str,
) -> Result<()> {
    env.exec(
        r#"UPDATE "WalletConnect" SET "Topic"=?1, "SymKey"=?2, "PeerPub"=?3, "Namespaces"=?4, "Expiry"=?5, "State"='active', "Updated"=?6 WHERE "Id"=?7"#,
        vec![
            SqlValue::Text(session_topic.to_owned()),
            SqlValue::Text(session_sym_b64.to_owned()),
            SqlValue::Text(peer_pub_b64.to_owned()),
            SqlValue::Text(namespaces_json.to_owned()),
            SqlValue::Text(expiry.to_owned()),
            SqlValue::Text(crate::now_rfc3339()),
            SqlValue::Text(id.to_owned()),
        ],
    )
    .map(|_| ())
}

/// Mark a session disconnected (Go `handleSessionDelete` / expiry).
pub fn set_state(env: &Env, id: &str, state: &str) -> Result<()> {
    env.exec(
        r#"UPDATE "WalletConnect" SET "State"=?1, "Updated"=?2 WHERE "Id"=?3"#,
        vec![
            SqlValue::Text(state.to_owned()),
            SqlValue::Text(crate::now_rfc3339()),
            SqlValue::Text(id.to_owned()),
        ],
    )
    .map(|_| ())
}

fn row_to_session(row: &[SqlValue]) -> WcSession {
    let t = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    WcSession {
        id: t(0),
        topic: t(1),
        pairing_topic: t(2),
        state: t(3),
        sym_key: t(4),
        self_priv: t(5),
        self_pub: t(6),
        peer_pub: t(7),
        peer_metadata: t(8),
        namespaces: t(9),
        expiry: t(10),
        created: t(11),
        updated: t(12),
    }
}
