//! wltnet (Network model) — port of the Go `wltnet` Network type.
//!
//! Read surface: fetch/list from the DB, plus the "type.chainId" ephemeral
//! form and the "@" current-network shortcut. The JSON is a custom object
//! (matching Go's Network.MarshalJSON): it omits CurrencyDecimals/Priority and
//! adds the computed ResolvedBlockExplorer / TxHistoryProvider, plus EVM_Info
//! from the ethrpc-rs chain registry. Network creation runs check() + RPC and
//! is deferred (POST returns 501); default-network seeding likewise.

use ethrpc_rs::chains;
use serde_json::{json, Map, Value};

use crate::{Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Network" ("Id" text, "Type" text, "ChainId" text, "Name" text, "RPC" text, "CurrencySymbol" text, "CurrencyDecimals" integer, "BlockExplorer" text, "TestNet" numeric, "Priority" integer, "Created" text, "Updated" text, PRIMARY KEY ("Id"));
CREATE UNIQUE INDEX IF NOT EXISTS "Network_typeChain" ON "Network" ("Type", "ChainId");"#;
const COLS: &str = r#""Id", "Type", "ChainId", "Name", "RPC", "CurrencySymbol", "CurrencyDecimals", "BlockExplorer", "TestNet", "Priority", "Created", "Updated""#;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Network {
    pub id: String,
    pub kind: String, // "evm" | "bitcoin" | "solana"
    pub chain_id: String,
    pub name: String,
    pub rpc: String,
    pub currency_symbol: String,
    pub currency_decimals: i64,
    pub block_explorer: String,
    pub testnet: bool,
    pub priority: i64,
    pub created: String,
    pub updated: String,
}

impl Network {
    /// The name of the tx-history provider, or "" when none. Matches Go
    /// TxHistoryProvider.
    pub fn tx_history_provider(&self) -> &'static str {
        match self.kind.as_str() {
            "evm" => "modchain",
            "solana" => "signatures",
            _ => "",
        }
    }

    /// Block-explorer base URL, resolving the "auto" sentinel against the chain
    /// registry. Matches Go ResolvedBlockExplorer.
    pub fn resolved_block_explorer(&self) -> String {
        if !self.block_explorer.is_empty() && self.block_explorer != "auto" {
            return self.block_explorer.clone();
        }
        match self.kind.as_str() {
            "solana" => "https://explorer.solana.com".to_owned(),
            "evm" => self
                .chain_info()
                .and_then(|i| i.explorer_url())
                .unwrap_or("")
                .to_owned(),
            _ => String::new(),
        }
    }

    fn chain_info(&self) -> Option<&'static chains::ChainInfo> {
        parse_chain_id(&self.chain_id).and_then(chains::get)
    }

    /// The Network JSON object, matching Go's custom MarshalJSON.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("Id".into(), json!(self.id));
        m.insert("Type".into(), json!(self.kind));
        m.insert("ChainId".into(), json!(self.chain_id));
        m.insert("Name".into(), json!(self.name));
        m.insert("RPC".into(), json!(self.rpc));
        m.insert("CurrencySymbol".into(), json!(self.currency_symbol));
        m.insert("BlockExplorer".into(), json!(self.block_explorer));
        m.insert("ResolvedBlockExplorer".into(), json!(self.resolved_block_explorer()));
        m.insert("TestNet".into(), json!(self.testnet));
        m.insert("Created".into(), json!(self.created));
        m.insert("Updated".into(), json!(self.updated));
        m.insert("TxHistoryProvider".into(), json!(self.tx_history_provider()));
        if self.kind == "evm" {
            let info = self.chain_info().map(chain_info_json).unwrap_or(Value::Null);
            m.insert("EVM_Info".into(), info);
        }
        Value::Object(m)
    }
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

/// Fetch by id. Supports "@" (current network), "type.chainId" (ephemeral),
/// and a plain stored id.
pub fn fetch(env: &Env, id: &str) -> Result<Option<Network>> {
    if id == "@" {
        if let Some(cur) = env.get_current("network")? {
            return by_id(env, &cur);
        }
        // Default when nothing is selected: Ethereum mainnet (ephemeral).
        return Ok(Some(ephemeral("evm", "1")));
    }
    if let Some((kind, chain)) = id.split_once('.') {
        return Ok(Some(ephemeral(kind, chain)));
    }
    by_id(env, id)
}

fn by_id(env: &Env, id: &str) -> Result<Option<Network>> {
    let sql = format!(r#"SELECT {COLS} FROM "Network" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_network(r)))
}

pub fn list(env: &Env) -> Result<Vec<Network>> {
    let sql = format!(r#"SELECT {COLS} FROM "Network" ORDER BY "Priority" DESC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_network(r)).collect())
}

fn ephemeral(kind: &str, chain_id: &str) -> Network {
    Network { kind: kind.to_owned(), chain_id: chain_id.to_owned(), ..Network::default() }
}

fn row_to_network(row: &[SqlValue]) -> Network {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let int = |i: usize| row.get(i).and_then(|v| v.as_i64()).unwrap_or(0);
    Network {
        id: text(0),
        kind: text(1),
        chain_id: text(2),
        name: text(3),
        rpc: text(4),
        currency_symbol: text(5),
        currency_decimals: int(6),
        block_explorer: text(7),
        testnet: int(8) != 0,
        priority: int(9),
        created: text(10),
        updated: text(11),
    }
}

/// Build the EVM_Info object from a chain registry entry. ChainInfo only
/// derives Deserialize in ethrpc-rs, so we assemble the JSON from its public
/// fields (the subset the host uses: name, native currency, explorers).
fn chain_info_json(i: &chains::ChainInfo) -> Value {
    let native = i
        .native_currency
        .as_ref()
        .map(|c| json!({ "name": c.name, "symbol": c.symbol, "decimals": c.decimals }))
        .unwrap_or(Value::Null);
    let explorers: Vec<Value> =
        i.explorers.iter().map(|e| json!({ "name": e.name, "url": e.url })).collect();
    json!({ "name": i.name, "nativeCurrency": native, "explorers": explorers })
}

fn parse_chain_id(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse::<u64>().ok(),
    }
}
