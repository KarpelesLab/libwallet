//! wltacct — accounts (addresses derived from a wallet).
//!
//! Fetch/list plus create for the ed25519/Solana path: a Solana account is the
//! wallet's group public key used directly (path "m", no HD), base58-encoded
//! as the address. secp256k1 (ethereum/bitcoin) HD derivation via outscript
//! follows next.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use xuid::Xuid;

use crate::{Env, Error, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Account" ("Id" text, "Wallet" text, "Name" text, "Index" integer, "Type" text, "Curve" text, "Path" text, "Address" text, "URI" text, "Pubkey" text, "Chaincode" text, "IL" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Wallet", "Name", "Index", "Type", "Curve", "Path", "Address", "URI", "Pubkey", "Chaincode", "IL", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Account {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Wallet", default)]
    pub wallet: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Index", default)]
    pub index: i64,
    #[serde(rename = "Type", default)]
    pub kind: String,
    #[serde(rename = "Curve", default)]
    pub curve: String,
    #[serde(rename = "Path", default)]
    pub path: String,
    #[serde(rename = "Address", default)]
    pub address: String,
    #[serde(rename = "URI", default)]
    pub uri: String,
    #[serde(rename = "Pubkey", default)]
    pub pubkey: String,
    #[serde(rename = "Chaincode", default)]
    pub chaincode: String,
    /// Intermediate derivation value (big.Int as JSON). Passed through as-is;
    /// the Dart client ignores it.
    #[serde(rename = "IL", default)]
    pub il: Value,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Account>> {
    let sql = format!(r#"SELECT {COLS} FROM "Account" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_account(r)))
}

pub fn list(env: &Env) -> Result<Vec<Account>> {
    let sql = format!(r#"SELECT {COLS} FROM "Account" ORDER BY "Index" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_account(r)).collect())
}

/// Accounts belonging to a wallet (used by wallet-scoped views).
pub fn for_wallet(env: &Env, wallet_id: &str) -> Result<Vec<Account>> {
    let sql = format!(r#"SELECT {COLS} FROM "Account" WHERE "Wallet" = ?1 ORDER BY "Index" ASC"#);
    let rows = env.query(&sql, vec![SqlValue::Text(wallet_id.to_owned())])?;
    Ok(rows.iter().map(|r| row_to_account(r)).collect())
}

/// Create an account for `wallet_id`. Currently the ed25519/Solana path: the
/// account is the wallet's group pubkey directly (path "m"), base58-encoded.
/// Sets the new account as current, matching Go CreateAccount.
pub fn create(env: &Env, wallet_id: &str, name: &str, typ: &str, index: i64) -> Result<Account> {
    let wallet = crate::models::wallet::fetch(env, wallet_id)?
        .ok_or_else(|| Error::Env("wallet not found".into()))?;

    match typ {
        "solana" => {
            if wallet.curve != "ed25519" {
                return Err(Error::Env(format!("solana account requires ed25519 wallet, got {}", wallet.curve)));
            }
        }
        "ethereum" | "bitcoin" => {
            return Err(Error::Env(format!("{typ} account derivation (secp256k1) not yet ported")));
        }
        other => return Err(Error::Env(format!("unsupported account type {other}"))),
    }

    let name = if name.is_empty() { format!("Account {}", index + 1) } else { name.to_owned() };

    // ed25519: the wallet pubkey IS the account key; base58 gives the address.
    let pub_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&wallet.pubkey)
        .map_err(|e| Error::Env(format!("bad wallet pubkey: {e}")))?;
    if pub_bytes.len() != 32 {
        return Err(Error::Env("ed25519 wallet pubkey is not 32 bytes".into()));
    }
    let address = bs58::encode(&pub_bytes).into_string();
    let now = crate::now_rfc3339();

    let account = Account {
        id: Xuid::new("acct").to_string(),
        wallet: wallet_id.to_owned(),
        name,
        index,
        kind: "solana".into(),
        curve: "ed25519".into(),
        path: "m".into(),
        address: address.clone(),
        uri: format!("solana:{address}"),
        pubkey: wallet.pubkey.clone(),
        chaincode: wallet.chaincode.clone(),
        il: Value::Null,
        created: now.clone(),
        updated: now,
    };

    env.exec(
        &format!(r#"INSERT INTO "Account" ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)"#),
        vec![
            SqlValue::Text(account.id.clone()),
            SqlValue::Text(account.wallet.clone()),
            SqlValue::Text(account.name.clone()),
            SqlValue::Int(account.index),
            SqlValue::Text(account.kind.clone()),
            SqlValue::Text(account.curve.clone()),
            SqlValue::Text(account.path.clone()),
            SqlValue::Text(account.address.clone()),
            SqlValue::Text(account.uri.clone()),
            SqlValue::Text(account.pubkey.clone()),
            SqlValue::Text(account.chaincode.clone()),
            SqlValue::Text("null".into()),
            SqlValue::Text(account.created.clone()),
            SqlValue::Text(account.updated.clone()),
        ],
    )?;
    env.set_current("account", &account.id)?;
    Ok(account)
}

fn row_to_account(row: &[SqlValue]) -> Account {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let il = row
        .get(11)
        .and_then(|v| v.as_text())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or(Value::Null);
    Account {
        id: text(0),
        wallet: text(1),
        name: text(2),
        index: row.get(3).and_then(|v| v.as_i64()).unwrap_or(0),
        kind: text(4),
        curve: text(5),
        path: text(6),
        address: text(7),
        uri: text(8),
        pubkey: text(9),
        chaincode: text(10),
        il,
        created: text(12),
        updated: text(13),
    }
}
