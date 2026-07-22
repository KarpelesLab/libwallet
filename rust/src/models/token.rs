//! wlttoken (Token model) — port of the Go `wlttoken` package.
//!
//! Read surface: fetch/list of known tokens (PascalCase JSON, plain struct).
//! Token creation discovers on-chain metadata (RPC) and is deferred (POST 501).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use xuid::Xuid;

use crate::{Env, Result, SqlValue};

/// Bounds applied to untrusted token metadata (on-chain symbol / name /
/// decimals, plus operator-supplied overrides). Symbols/names originate from
/// contract calls or RPC metadata an attacker controls, so they are sanitised
/// and capped to defeat display-spoofing; decimals are bounded because they
/// feed amount scaling. Matches Go `maxTokenSymbolLen` / `maxTokenNameLen` /
/// `maxTokenDecimals`.
pub const MAX_TOKEN_SYMBOL_LEN: usize = 32;
pub const MAX_TOKEN_NAME_LEN: usize = 128;
pub const MAX_TOKEN_DECIMALS: i64 = 36;

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Token" ("Id" text, "Name" text, "Symbol" text, "Address" text, "Decimals" integer, "Type" text, "Network" text, "Logo" text, "Memo" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));"#;
const COLS: &str = r#""Id", "Name", "Symbol", "Address", "Decimals", "Type", "Network", "Logo", "Memo", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Token {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Symbol", default)]
    pub symbol: String,
    #[serde(rename = "Address", default)]
    pub address: String,
    #[serde(rename = "Decimals", default)]
    pub decimals: i64,
    #[serde(rename = "Type", default)]
    pub kind: String, // erc20 | nft | spl-token | spl-token-2022
    #[serde(rename = "Network", default)]
    pub network: String,
    #[serde(rename = "Logo", default)]
    pub logo: String,
    #[serde(rename = "Memo", default)]
    pub memo: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Token>> {
    let sql = format!(r#"SELECT {COLS} FROM "Token" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_token(r)))
}

pub fn list(env: &Env) -> Result<Vec<Token>> {
    let sql = format!(r#"SELECT {COLS} FROM "Token" ORDER BY "Symbol" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_token(r)).collect())
}

/// Every registered Token row for `network_id` (port of Go `TokensByNetwork`).
/// Used by `Asset:list` to enumerate the user's ERC-20 tokens: EVM has no cheap
/// on-chain owner→tokens query (unlike Solana, which discovers token accounts
/// on-chain), so the registry the user builds via `Token:create` /
/// `Token:discoverToken` (or swap EnsureToken) is the source of truth. An empty
/// id yields no rows (Go returns nil for a nil id).
pub fn tokens_by_network(env: &Env, network_id: &str) -> Result<Vec<Token>> {
    if network_id.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(r#"SELECT {COLS} FROM "Token" WHERE "Network" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(network_id.to_owned())])?;
    Ok(rows.iter().map(|r| row_to_token(r)).collect())
}

/// Find the registered token on `network_id` whose on-chain address / mint
/// matches `addr`, comparing via a base58 round-trip so equivalent encodings
/// collapse (port of Go `LookupTokenByMint`). Returns `None` when no row
/// matches. Used to resolve a canonical "<type>.<chainId>.<mint>" asset key to
/// its Token row on the SPL send path.
pub fn lookup_by_mint(env: &Env, network_id: &str, addr: &str) -> Result<Option<Token>> {
    let want = bs58::decode(addr).into_vec().ok();
    for t in tokens_by_network(env, network_id)? {
        if t.address == addr {
            return Ok(Some(t));
        }
        // Fall back to a byte-level compare so a differently-cased/padded but
        // equivalent base58 encoding still matches.
        if let (Some(a), Some(b)) = (&want, bs58::decode(&t.address).into_vec().ok()) {
            if *a == b {
                return Ok(Some(t));
            }
        }
    }
    Ok(None)
}

/// Resolve a network reference to the network's id (xuid string), accepting
/// either form the clients use (port of Go `resolveNetworkRef`):
///
///   - a network xuid ("net-…") passes through unchanged;
///   - the canonical "<type>.<chainId>" key (e.g. "evm.137", "solana.mainnet")
///     — the form `Asset.network` and the Dart Token API send — maps to the
///     deterministic network id.
///
/// The canonical form is the one that previously failed as "invalid UUID
/// length: 7" (e.g. "evm.137") because `Network` was parsed straight as an
/// xuid. Network existence is validated by the caller (`network::fetch`), not
/// here; this only maps ref → id.
pub fn resolve_network_ref(reference: &str) -> Result<String> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Err(crate::Error::Env("Network is required".into()));
    }
    // A real network xuid parses under the "net" prefix; the canonical key uses
    // dots and won't.
    if Xuid::parse_prefix(reference, "net").is_ok() {
        return Ok(reference.to_owned());
    }
    if let Some((typ, chain)) = reference.split_once('.') {
        if !typ.is_empty() && !chain.is_empty() {
            return Ok(crate::models::network::network_id_for(typ, chain));
        }
    }
    Err(crate::Error::Env(format!(
        "invalid network reference {reference:?} (want a net-… id or \"<type>.<chainId>\")"
    )))
}

fn row_to_token(row: &[SqlValue]) -> Token {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    Token {
        id: text(0),
        name: text(1),
        symbol: text(2),
        address: text(3),
        decimals: row.get(4).and_then(|v| v.as_i64()).unwrap_or(0),
        kind: text(5),
        network: text(6),
        logo: text(7),
        memo: text(8),
        created: text(9),
        updated: text(10),
    }
}

/// Validate + normalize a token (port of Go `token.validate`): the network must
/// exist and support tokens, the address is normalized per chain (EVM checksum
/// case / Solana base58 round-trip), the type defaults to the chain canonical
/// ("erc20" / "spl-token"), display metadata is sanitised and decimals bounded.
pub fn validate(env: &Env, t: &mut Token) -> Result<()> {
    if t.network.is_empty() {
        return Err(crate::Error::Env("Network is required".into()));
    }
    if t.address.is_empty() {
        return Err(crate::Error::Env("Address is required".into()));
    }
    let net = crate::models::network::fetch(env, &t.network)?
        .ok_or_else(|| crate::Error::Env(format!("invalid network: {}", t.network)))?;
    match net.kind.as_str() {
        "evm" => {
            t.address = normalize_evm_address(&t.address)?;
            if t.kind.is_empty() {
                t.kind = "erc20".to_owned();
            }
        }
        "solana" => {
            t.address = normalize_solana_address(&t.address)?;
            if t.kind.is_empty() {
                t.kind = "spl-token".to_owned();
            }
        }
        other => {
            return Err(crate::Error::Env(format!(
                "tokens are not supported on {other} networks"
            )))
        }
    }
    // Sanitise display metadata — Symbol/Name may originate from untrusted
    // on-chain sources and are otherwise persisted verbatim.
    t.symbol = sanitize_token_text(&t.symbol, MAX_TOKEN_SYMBOL_LEN);
    t.name = sanitize_token_text(&t.name, MAX_TOKEN_NAME_LEN);
    if t.decimals < 0 || t.decimals > MAX_TOKEN_DECIMALS {
        return Err(crate::Error::Env(format!(
            "Decimals must be between 0 and {MAX_TOKEN_DECIMALS}"
        )));
    }
    Ok(())
}

/// Create a token (port of Go `apiCreateToken`): validate/normalize, assign a
/// random `tok` id, persist, and return the created row.
pub fn create(env: &Env, mut t: Token) -> Result<Token> {
    // Accept the canonical "<type>.<chainId>" network ref (e.g. "evm.137") the
    // Dart Token API sends, in addition to a stored net-… xuid, resolving it to
    // the network id (Go apiCreateToken / resolveNetworkRef). Storing the
    // resolved id — not "evm.137" verbatim — is also what lets Asset:list find
    // the row via tokens_by_network.
    t.network = resolve_network_ref(&t.network)?;
    validate(env, &mut t)?;
    t.id = Xuid::new_random("tok").to_string();
    save(env, &mut t)?;
    Ok(t)
}

/// Apply the mutable fields Go `token.ApiUpdate` allows (Name, Symbol,
/// Decimals, Logo, Memo, Type) from `params` and persist. Name/Symbol are
/// sanitised; Decimals is bounds-checked. A no-op update returns the row
/// unchanged.
pub fn update(env: &Env, id: &str, params: &Value) -> Result<Token> {
    let mut t = fetch(env, id)?
        .ok_or_else(|| crate::Error::Env(format!("token not found: {id}")))?;
    let mut updated = false;
    if let Some(v) = params.get("Name").and_then(Value::as_str) {
        t.name = sanitize_token_text(v, MAX_TOKEN_NAME_LEN);
        updated = true;
    }
    if let Some(v) = params.get("Symbol").and_then(Value::as_str) {
        t.symbol = sanitize_token_text(v, MAX_TOKEN_SYMBOL_LEN);
        updated = true;
    }
    if let Some(v) = params.get("Decimals").and_then(Value::as_i64) {
        if v < 0 || v > MAX_TOKEN_DECIMALS {
            return Err(crate::Error::Env(format!(
                "Decimals must be between 0 and {MAX_TOKEN_DECIMALS}"
            )));
        }
        t.decimals = v;
        updated = true;
    }
    if let Some(v) = params.get("Logo").and_then(Value::as_str) {
        t.logo = v.to_owned();
        updated = true;
    }
    if let Some(v) = params.get("Memo").and_then(Value::as_str) {
        t.memo = v.to_owned();
        updated = true;
    }
    if let Some(v) = params.get("Type").and_then(Value::as_str) {
        t.kind = v.to_owned();
        updated = true;
    }
    if !updated {
        return Ok(t);
    }
    save(env, &mut t)?;
    Ok(t)
}

/// Delete a token by id (port of Go `token.ApiDelete` — ForceDelete by Id).
pub fn delete(env: &Env, id: &str) -> Result<()> {
    env.exec(r#"DELETE FROM "Token" WHERE "Id" = ?1"#, vec![SqlValue::Text(id.to_owned())])?;
    Ok(())
}

/// Insert or replace a token row (Go `token.save` via psql.Replace). Sets
/// Created (first save) / Updated timestamps on `t`.
fn save(env: &Env, t: &mut Token) -> Result<()> {
    let now = crate::now_rfc3339();
    if t.created.is_empty() {
        t.created = now.clone();
    }
    t.updated = now;
    env.exec(r#"DELETE FROM "Token" WHERE "Id" = ?1"#, vec![SqlValue::Text(t.id.clone())])?;
    env.exec(
        &format!(r#"INSERT INTO "Token" ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#),
        vec![
            SqlValue::Text(t.id.clone()),
            SqlValue::Text(t.name.clone()),
            SqlValue::Text(t.symbol.clone()),
            SqlValue::Text(t.address.clone()),
            SqlValue::Int(t.decimals),
            SqlValue::Text(t.kind.clone()),
            SqlValue::Text(t.network.clone()),
            SqlValue::Text(t.logo.clone()),
            SqlValue::Text(t.memo.clone()),
            SqlValue::Text(t.created.clone()),
            SqlValue::Text(t.updated.clone()),
        ],
    )?;
    Ok(())
}

/// Normalize an EVM token address to its EIP-55 checksummed form (Go uses
/// `outscript.ParseEvmAddress(..).Address()`).
fn normalize_evm_address(addr: &str) -> Result<String> {
    let hex = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")).unwrap_or(addr);
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(crate::Error::Env(format!("invalid EVM address: {addr}")));
    }
    let bytes: Vec<u8> = (0..40)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    Ok(outscript::address::eip55(&bytes))
}

/// Normalize a Solana token mint address via a base58 round-trip, verifying it
/// decodes to exactly 32 bytes (Go `base58.Bitcoin.Decode` + length check).
fn normalize_solana_address(addr: &str) -> Result<String> {
    let decoded = bs58::decode(addr)
        .into_vec()
        .map_err(|e| crate::Error::Env(format!("invalid Solana address: {e}")))?;
    if decoded.len() != 32 {
        return Err(crate::Error::Env("invalid Solana address: must be 32 bytes".into()));
    }
    Ok(bs58::encode(&decoded).into_string())
}

/// Strip control / replacement / bidi-invisible characters, cap the kept runes
/// at `max`, then trim surrounding whitespace (Go `sanitizeTokenText`).
pub fn sanitize_token_text(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut kept = 0usize;
    for c in s.chars() {
        if c == '\u{FFFD}' || c.is_control() || is_bidi_or_invisible(c) {
            continue;
        }
        out.push(c);
        kept += 1;
        if kept >= max {
            break;
        }
    }
    out.trim().to_owned()
}

/// Bidi formatting controls / zero-width / BOM commonly abused to spoof token
/// names (Go `isBidiOrInvisible`).
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}'   // LRE RLE PDF LRO RLO
        | '\u{2066}'..='\u{2069}' // LRI RLI FSI PDI
        | '\u{200B}'..='\u{200F}' // ZWSP ZWNJ ZWJ LRM RLM
        | '\u{061C}'              // Arabic letter mark
        | '\u{FEFF}'              // BOM / ZWNBSP
    )
}
