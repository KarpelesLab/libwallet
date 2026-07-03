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

    let name = if name.is_empty() { format!("Account {}", index + 1) } else { name.to_owned() };
    if index < 0 {
        return Err(Error::Env("index must be non-negative".into()));
    }

    // Derive (curve, path, account pubkey b64url, address, uri, IL) per chain.
    // IL is the HD-derivation tweak (Σ IL_i mod n), stored so signing can pass
    // it to sign_with_tweak; Null for chains that don't derive (solana).
    let (curve_out, path, pubkey_b64, address, uri, il): (String, String, String, String, String, Value) =
        match typ {
            "solana" => {
                if wallet.curve != "ed25519" {
                    return Err(Error::Env(format!("solana account requires ed25519 wallet, got {}", wallet.curve)));
                }
                // The wallet pubkey IS the account key; base58 gives the address.
                let pb = b64url_decode(&wallet.pubkey)?;
                if pb.len() != 32 {
                    return Err(Error::Env("ed25519 wallet pubkey is not 32 bytes".into()));
                }
                let addr = bs58::encode(&pb).into_string();
                ("ed25519".into(), "m".into(), wallet.pubkey.clone(), addr.clone(), format!("solana:{addr}"), Value::Null)
            }
            "ethereum" => {
                if wallet.curve != "secp256k1" {
                    return Err(Error::Env(format!("ethereum account requires secp256k1 wallet, got {}", wallet.curve)));
                }
                // BIP32 non-hardened public derivation at m/44/60/0/{index}.
                let pb = b64url_decode(&wallet.pubkey)?;
                let cc = b64url_decode(&wallet.chaincode)?;
                let (child, tweak) = crate::hdderive::derive_pub_tweak(&pb, &cc, &[44, 60, 0, index as u32])
                    .map_err(|e| Error::Env(e.to_string()))?;
                let addr = crate::hdderive::evm_address(&child).map_err(|e| Error::Env(e.to_string()))?;
                let il = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &tweak).to_string();
                ("secp256k1".into(), format!("m/44/60/0/{index}"), b64url(&child), addr.clone(), format!("ethereum:{addr}"), Value::String(il))
            }
            "bitcoin" => return Err(Error::Env("bitcoin address (outscript) not yet ported".into())),
            other => return Err(Error::Env(format!("unsupported account type {other}"))),
        };
    let now = crate::now_rfc3339();
    let il_json = serde_json::to_string(&il).unwrap_or_else(|_| "null".into());

    let account = Account {
        id: Xuid::new("acct").to_string(),
        wallet: wallet_id.to_owned(),
        name,
        index,
        kind: typ.to_owned(),
        curve: curve_out,
        path,
        address,
        uri,
        pubkey: pubkey_b64,
        chaincode: wallet.chaincode.clone(),
        il,
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
            SqlValue::Text(il_json),
            SqlValue::Text(account.created.clone()),
            SqlValue::Text(account.updated.clone()),
        ],
    )?;
    env.set_current("account", &account.id)?;
    Ok(account)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Env(format!("bad base64url: {e}")))
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
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
