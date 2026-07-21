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
    // "@" resolves to the current account (Go `apiFetchAccount` / `CurrentAccount`).
    if id == "@" {
        return current(env);
    }
    let sql = format!(r#"SELECT {COLS} FROM "Account" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_account(r)))
}

/// The current account (Go `wltacct.CurrentAccount`): the account selected via
/// `set_current("account", …)`, or — when that is unset or points at a missing
/// row — the first account on record. Returns `None` only when there are no
/// accounts at all.
pub fn current(env: &Env) -> Result<Option<Account>> {
    if let Some(cur) = env.get_current("account")? {
        if let Some(a) = fetch(env, &cur)? {
            return Ok(Some(a));
        }
    }
    // Fall back to the first account (Go `FirstAccount`).
    Ok(list(env)?.into_iter().next())
}

pub fn list(env: &Env) -> Result<Vec<Account>> {
    let sql = format!(r#"SELECT {COLS} FROM "Account" ORDER BY "Index" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_account(r)).collect())
}

/// Resolve an account by its id (acct-…) or, failing that, its address —
/// mirrors Go `wltacct.FindAccount`, which a Transaction's `From` uses.
pub fn find(env: &Env, id_or_address: &str) -> Result<Option<Account>> {
    if let Some(a) = fetch(env, id_or_address)? {
        return Ok(Some(a));
    }
    let sql = format!(r#"SELECT {COLS} FROM "Account" WHERE "Address" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id_or_address.to_owned())])?;
    Ok(rows.first().map(|r| row_to_account(r)))
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
            "bitcoin" => {
                if wallet.curve != "secp256k1" {
                    return Err(Error::Env(format!("bitcoin account requires secp256k1 wallet, got {}", wallet.curve)));
                }
                // BIP32 non-hardened derivation at m/44/0/0/{index}, then P2PKH.
                let pb = b64url_decode(&wallet.pubkey)?;
                let cc = b64url_decode(&wallet.chaincode)?;
                let (child, tweak) = crate::hdderive::derive_pub_tweak(&pb, &cc, &[44, 0, 0, index as u32])
                    .map_err(|e| Error::Env(e.to_string()))?;
                // Display address for the current network (Go
                // `UpdateAddressForNetwork`): on a bitcoin-family network it is
                // the first receive address (m/0/0) in that chain's format
                // (e.g. monacoin → "mona1…" P2WPKH). Off a bitcoin network we
                // keep the mainnet-BTC P2PKH fallback.
                let h160 = outscript::hash::hash160(&child);
                let addr = bitcoin_current_address(env, &child, &cc)
                    .unwrap_or_else(|| outscript::address::encode_base58_addr(0x00, &h160));
                let il = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &tweak).to_string();
                ("secp256k1".into(), format!("m/44/0/0/{index}"), b64url(&child), addr.clone(), format!("bitcoin:{addr}"), Value::String(il))
            }
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

/// Create a view-only account from a bare address (Go `CreateViewAccount`,
/// address path): no wallet, no derivation — just a watch address. Curve is
/// ed25519 for solana, secp256k1 otherwise.
pub fn create_view(env: &Env, name: &str, typ: &str, address: &str) -> Result<Account> {
    if typ != "ethereum" && typ != "bitcoin" && typ != "solana" {
        return Err(Error::Env(format!("unsupported account type {typ}")));
    }
    if address.is_empty() {
        return Err(Error::Env("address required for a view account".into()));
    }
    let name = if name.is_empty() { "View Account".to_owned() } else { name.to_owned() };
    let curve = if typ == "solana" { "ed25519" } else { "secp256k1" };
    let now = crate::now_rfc3339();
    let account = Account {
        id: Xuid::new("acct").to_string(),
        wallet: String::new(), // view-only: no signing wallet
        name,
        index: 0,
        kind: typ.to_owned(),
        curve: curve.to_owned(),
        path: String::new(),
        address: address.to_owned(),
        uri: format!("{typ}:{address}"),
        pubkey: String::new(),
        chaincode: String::new(),
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

/// Create a view-only account from a BIP-32 extended public key (Go
/// `CreateViewAccount`, xpub path). Bitcoin-family only: the xpub's pubkey +
/// chaincode are decoded so HD gap-limit scans work. Stores them base64url
/// (matching Go's `ecckd.FromString` → RawURLEncoding), sets the display
/// address for the current network, and marks the account current.
pub fn create_view_xpub(env: &Env, name: &str, typ: &str, xpub: &str) -> Result<Account> {
    if typ != "bitcoin" {
        return Err(Error::Env(
            "xpub view accounts are only supported for bitcoin-family networks".into(),
        ));
    }
    let (pubkey, chaincode) = crate::bitcoin::parse_xpub(xpub)?;
    let name = if name.is_empty() { "View Account".to_owned() } else { name.to_owned() };
    let now = crate::now_rfc3339();
    // Display address for the current network (empty when no bitcoin-family
    // network is selected; refreshed by callers that know the network).
    let address = bitcoin_current_address(env, &pubkey, &chaincode).unwrap_or_default();
    let uri = if address.is_empty() { String::new() } else { format!("bitcoin:{address}") };
    let account = Account {
        id: Xuid::new("acct").to_string(),
        wallet: String::new(), // view-only: no signing wallet
        name,
        index: 0,
        kind: typ.to_owned(),
        curve: "secp256k1".to_owned(),
        path: String::new(),
        address,
        uri,
        pubkey: b64url(&pubkey),
        chaincode: b64url(&chaincode),
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

/// The bitcoin display address (first receive address, `m/0/0`) for the current
/// network, when it is a bitcoin-family network — the derivation Go
/// `UpdateAddressForNetwork` performs for the bitcoin branch. `pubkey` is the
/// account's compressed key and `chaincode` its 32-byte chain code. `None` when
/// no bitcoin network is selected or derivation fails, so callers keep their
/// own default.
fn bitcoin_current_address(env: &Env, pubkey: &[u8], chaincode: &[u8]) -> Option<String> {
    let net = crate::models::network::fetch(env, "@").ok().flatten()?;
    if net.kind != "bitcoin" {
        return None;
    }
    let child = crate::hdderive::derive_pub(pubkey, chaincode, &[0, 0]).ok()?;
    crate::bitcoin::hd_address(&child, &net.chain_id).ok()
}

/// Update mutable account fields (Go `Account.ApiUpdate`): only `Name` is
/// mutable. Returns the updated account, or `None` when the id is unknown. With
/// no `Name` supplied the row is left untouched (Go returns without saving).
pub fn update(env: &Env, id: &str, name: Option<&str>) -> Result<Option<Account>> {
    let mut a = match fetch(env, id)? {
        Some(a) => a,
        None => return Ok(None),
    };
    let Some(n) = name else {
        return Ok(Some(a));
    };
    a.name = n.to_owned();
    a.updated = crate::now_rfc3339();
    env.exec(
        r#"UPDATE "Account" SET "Name"=?1, "Updated"=?2 WHERE "Id"=?3"#,
        vec![
            SqlValue::Text(a.name.clone()),
            SqlValue::Text(a.updated.clone()),
            SqlValue::Text(a.id.clone()),
        ],
    )?;
    Ok(Some(a))
}

/// Delete an account and cascade-delete its Web3 connections (Go
/// `Account.accountDelete`). The ConnectedSite cleanup is best-effort — a
/// failure there (e.g. the table doesn't exist in a minimal env) is ignored so
/// the account still gets removed, matching Go which logs but does not block.
/// Transactions are intentionally left intact: tx history outlives the account.
pub fn delete(env: &Env, id: &str) -> Result<()> {
    let _ = env.exec(
        r#"DELETE FROM "ConnectedSite" WHERE "Account" = ?1"#,
        vec![SqlValue::Text(id.to_owned())],
    );
    env.exec(
        r#"DELETE FROM "Account" WHERE "Id" = ?1"#,
        vec![SqlValue::Text(id.to_owned())],
    )
    .map(|_| ())
}

impl Account {
    /// The BIP-32 extended public key (`xpub…`) for this account, built from its
    /// compressed pubkey + chain code (Go `Account.Xpub`). Secp256k1-family
    /// (bitcoin/ethereum) only; errors when pubkey/chaincode are missing or the
    /// wrong length.
    pub fn xpub(&self) -> Result<String> {
        if self.pubkey.is_empty() {
            return Err(Error::Env("account has no pubkey".into()));
        }
        if self.chaincode.is_empty() {
            return Err(Error::Env("account has no chaincode".into()));
        }
        let pb: [u8; 33] = b64url_decode(&self.pubkey)?
            .try_into()
            .map_err(|_| Error::Env("pubkey is not 33 bytes (compressed secp256k1)".into()))?;
        let cc: [u8; 32] = b64url_decode(&self.chaincode)?
            .try_into()
            .map_err(|_| Error::Env("chaincode is not 32 bytes".into()))?;
        Ok(crate::bitcoin::build_xpub(&pb, &cc))
    }
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
