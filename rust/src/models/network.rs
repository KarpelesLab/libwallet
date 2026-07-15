//! wltnet (Network model) — port of the Go `wltnet` Network type.
//!
//! Read surface: fetch/list from the DB, plus the "type.chainId" ephemeral
//! form and the "@" current-network shortcut. The JSON is a custom object
//! (matching Go's Network.MarshalJSON): it omits CurrencyDecimals/Priority and
//! adds the computed ResolvedBlockExplorer / TxHistoryProvider, plus EVM_Info
//! from the ethrpc-rs chain registry. Network creation runs check() + RPC and
//! is deferred (POST returns 501); default-network seeding likewise.

use std::net::IpAddr;

use ethrpc_rs::chains;
use serde_json::{json, Map, Value};
use xuid::Xuid;

use crate::{Env, Result, SqlValue};

/// modchain API key (public build constant, matching Go `wltnet.ModChainApiKey`).
/// Bitcoin-family chains route all RPC through modchain with this key.
const MODCHAIN_API_KEY: &str = "crapi-nx4p6j-ifez-cjli-p5wj-uml43cte";
/// Solana Helius endpoints, matching Go getRPC (public build constants).
const HELIUS_MAINNET: &str = "https://kristi-cykm4t-fast-mainnet.helius-rpc.com";
const HELIUS_DEVNET: &str = "https://trudie-xvrnf4-fast-devnet.helius-rpc.com";

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

    /// The RPC URL to dial for this network (port of the static cases of Go
    /// `Network.getRPC`):
    /// - an explicit, non-"auto" `rpc` is used as-is (all types);
    /// - Bitcoin family always routes through modchain (URL + API key + chain);
    /// - Solana falls back to the Helius devnet/mainnet endpoint;
    /// - EVM with `rpc == "" | "auto"` needs the live chain-info RPC picker
    ///   (freshness-aware, not ported) — returns an error so the caller supplies
    ///   an explicit RPC.
    pub fn resolved_rpc(&self) -> Result<String> {
        let explicit = !self.rpc.is_empty() && self.rpc != "auto";
        match self.kind.as_str() {
            "bitcoin" => Ok(format!(
                "https://rpc.modchain.net/api/{MODCHAIN_API_KEY}/{}/rpc",
                self.chain_id
            )),
            "solana" if explicit => Ok(self.rpc.clone()),
            "solana" => Ok(match self.chain_id.as_str() {
                "devnet" => HELIUS_DEVNET.to_owned(),
                _ => HELIUS_MAINNET.to_owned(),
            }),
            "evm" if explicit => Ok(self.rpc.clone()),
            "evm" => Err(crate::Error::Env(
                "auto EVM RPC selection is not ported; supply an explicit RPC".into(),
            )),
            other => Err(crate::Error::Env(format!("no RPC resolution for type {other}"))),
        }
    }

    /// The network's native currency symbol (Go `Network.NativeSymbol`): EVM
    /// from the chain registry, Bitcoin-family by chain id, Solana = SOL.
    pub fn native_symbol(&self) -> Result<String> {
        match self.kind.as_str() {
            "evm" => self
                .chain_info()
                .and_then(|i| i.native_currency.as_ref())
                .map(|c| c.symbol.clone())
                .ok_or_else(|| crate::Error::Env(format!("no chain info for evm {}", self.chain_id))),
            "bitcoin" => match self.chain_id.as_str() {
                "bitcoin" => Ok("BTC".into()),
                "bitcoin-cash" => Ok("BCH".into()),
                "litecoin" => Ok("LTC".into()),
                "dogecoin" => Ok("DOGE".into()),
                other => Err(crate::Error::Env(format!("unsupported bitcoin chain type {other}"))),
            },
            "solana" => Ok("SOL".into()),
            other => Err(crate::Error::Env(format!("symbol not available for type {other}"))),
        }
    }

    /// The native-currency decimals for this network: the stored
    /// `currency_decimals`, else the chain registry (EVM), else the chain
    /// default (SOL=9, BTC-family=8). Matches Go's decimals resolution.
    pub fn native_decimals(&self) -> i64 {
        if self.currency_decimals > 0 {
            return self.currency_decimals;
        }
        match self.kind.as_str() {
            "evm" => self
                .chain_info()
                .and_then(|i| i.native_currency.as_ref())
                .map(|c| c.decimals as i64)
                .unwrap_or(18),
            "solana" => 9,
            _ => 8, // bitcoin family (satoshi)
        }
    }

    /// The account's native balance as a scaled [`crate::Amount`] (port of Go
    /// `Network.nativeBalance`, in currency units rather than raw base units):
    /// EVM eth_getBalance (wei / decimals), Solana getBalance minus the
    /// rent-exempt reserve (lamports / 9), Bitcoin summed NATIVE UTXOs
    /// (satoshi / 8). `rpc` is a dialable endpoint; `address` the account.
    pub fn native_amount(&self, rpc: &str, address: &str) -> Result<crate::Amount> {
        use num_bigint::BigInt;
        match self.kind.as_str() {
            "evm" => {
                let hex = crate::rpc::call(rpc, "eth_getBalance", json!([address, "latest"]))?;
                let hex = hex.as_str().ok_or_else(|| crate::Error::Env("balance not a string".into()))?;
                let stripped = hex.strip_prefix("0x").unwrap_or(hex);
                let n = BigInt::parse_bytes(stripped.as_bytes(), 16)
                    .ok_or_else(|| crate::Error::Env(format!("bad balance hex {hex}")))?;
                Ok(crate::Amount::new_raw(n, self.native_decimals()))
            }
            "solana" => {
                let res = crate::rpc::call(rpc, "getBalance", json!([address]))?;
                let raw = res
                    .get("value")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| crate::Error::Env("unexpected getBalance response".into()))?;
                let rent = crate::rpc::call(rpc, "getMinimumBalanceForRentExemption", json!([0]))
                    .ok()
                    .and_then(|v| v.as_u64())
                    .unwrap_or(890_880);
                Ok(crate::Amount::new_raw(BigInt::from(raw.saturating_sub(rent)), 9))
            }
            "bitcoin" => {
                let sats = crate::bitcoin::native_balance_satoshi(rpc, address)?;
                Ok(crate::Amount::new_raw(BigInt::from(sats), 8))
            }
            other => Err(crate::Error::Env(format!("native balance unsupported for {other}"))),
        }
    }

    /// The `type.chainId` string form (Go `Network.String`).
    pub fn key_prefix(&self) -> String {
        format!("{}.{}", self.kind, self.chain_id)
    }

    /// Build the live native-currency [`Asset`](crate::models::asset::Asset) for
    /// `address` (port of Go `Network.NativeAsset`): fetch the balance, key it
    /// `<type>.<chainId>.NATIVE`, and label it from the chain registry (EVM) or
    /// the network/native symbol (Bitcoin/Solana). Computed, not persisted, so
    /// the Id is left empty.
    pub fn native_asset(&self, rpc: &str, address: &str) -> Result<crate::models::asset::Asset> {
        let amount = self.native_amount(rpc, address)?;
        let symbol = self.native_symbol()?;
        // EVM takes the currency name from the chain registry; the others use
        // the network name, falling back to the symbol.
        let name = match self.kind.as_str() {
            "evm" => self
                .chain_info()
                .and_then(|i| i.native_currency.as_ref())
                .map(|c| c.name.clone())
                .unwrap_or_else(|| symbol.clone()),
            _ if !self.name.is_empty() => self.name.clone(),
            _ => symbol.clone(),
        };
        Ok(crate::models::asset::Asset {
            id: String::new(),
            key: format!("{}.NATIVE", self.key_prefix()),
            name,
            symbol,
            amount,
            kind: "fungible".to_owned(),
            network: self.id.clone(),
            created: String::new(),
            updated: String::new(),
            fiat_amount: None,
            fiat_currency: String::new(),
            fiat_quote: None,
            testnet: self.testnet,
        })
    }

    /// Validate the network and fill anything missing (port of Go
    /// `Network.check`). Rejects a caller-supplied RPC that points at an
    /// internal address / downgrades the scheme (SSRF guard) before it is ever
    /// persisted, then fills chain-derived defaults. Unknown EVM chain ids are
    /// accepted (create succeeds) but leave no defaults filled — matching Go's
    /// "ignore fetch failed but do not input anything either".
    pub fn check(&mut self) -> Result<()> {
        validate_network_rpc(&self.rpc)?;
        match self.kind.as_str() {
            "evm" => {} // fall through to the chain-registry fill below
            "bitcoin" => {
                let (name, sym) = match self.chain_id.as_str() {
                    "bitcoin" => ("Bitcoin", "BTC"),
                    "bitcoin-cash" => ("Bitcoin Cash", "BCH"),
                    "litecoin" => ("Litecoin", "LTC"),
                    "dogecoin" => ("Dogecoin", "DOGE"),
                    "monacoin" => ("Monacoin", "MONA"),
                    "namecoin" => ("Namecoin", "NMC"),
                    "electraproto" => ("Electra Protocol", "XEP"),
                    other => {
                        return Err(crate::Error::Env(format!(
                            "invalid network type {}/{other}",
                            self.kind
                        )))
                    }
                };
                if self.name.is_empty() {
                    self.name = name.to_owned();
                }
                if self.currency_symbol.is_empty() {
                    self.currency_symbol = sym.to_owned();
                }
                return Ok(());
            }
            "solana" => {
                match self.chain_id.as_str() {
                    "mainnet" => {
                        if self.name.is_empty() {
                            self.name = "Solana".to_owned();
                        }
                        if self.currency_symbol.is_empty() {
                            self.currency_symbol = "SOL".to_owned();
                        }
                    }
                    "devnet" => {
                        if self.name.is_empty() {
                            self.name = "Solana Devnet".to_owned();
                        }
                        if self.currency_symbol.is_empty() {
                            self.currency_symbol = "SOL".to_owned();
                        }
                        self.testnet = true;
                    }
                    other => {
                        return Err(crate::Error::Env(format!(
                            "invalid network type {}/{other}",
                            self.kind
                        )))
                    }
                }
                if self.currency_decimals == 0 {
                    self.currency_decimals = 9;
                }
                if self.rpc.is_empty() {
                    self.rpc = "auto".to_owned();
                }
                if self.block_explorer.is_empty() {
                    self.block_explorer = "auto".to_owned();
                }
                return Ok(());
            }
            other => return Err(crate::Error::Env(format!("invalid network type {other}"))),
        }
        // EVM: fill from the chain registry when the chain is known; an unknown
        // id leaves the network as-is (Go ignores the GetChainInfo error).
        let info = match self.chain_info() {
            Some(i) => i,
            None => return Ok(()),
        };
        if parse_chain_id(&self.chain_id) == Some(137) && self.currency_symbol == "MATIC" {
            self.currency_symbol = "POL".to_owned();
        }
        if self.name.is_empty() {
            self.name = info.name.clone();
        }
        if self.rpc.is_empty() {
            self.rpc = "auto".to_owned();
        }
        if self.currency_symbol.is_empty() {
            if let Some(nc) = info.native_currency.as_ref() {
                self.currency_symbol = nc.symbol.clone();
            }
        }
        if self.block_explorer.is_empty() {
            self.block_explorer = "auto".to_owned();
        }
        Ok(())
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
            // Resolve the current selection the same way as a direct fetch:
            // a stored id via by_id, an ephemeral "type.chainId" via the split.
            return fetch(env, &cur);
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

/// Whether a stored network row exists for `id` (best-effort; false on error).
pub fn by_id_opt(env: &Env, id: &str) -> bool {
    matches!(by_id(env, id), Ok(Some(_)))
}

/// The deterministic network id derived from `type`+`chainId` (Go
/// `NetworkIdForTypeAndChainId` = `xuid.FromKeyPrefix(type+"."+chainId, "net")`).
pub fn network_id_for(kind: &str, chain_id: &str) -> String {
    Xuid::from_key_prefix(format!("{kind}.{chain_id}"), "net").to_string()
}

/// Insert or replace a network row (keyed on `Id`). An empty `Id` is computed
/// from `type`+`chainId` first, matching Go `Network.Save`.
pub fn save(env: &Env, n: &Network) -> Result<()> {
    let id = if n.id.is_empty() { network_id_for(&n.kind, &n.chain_id) } else { n.id.clone() };
    env.exec(r#"DELETE FROM "Network" WHERE "Id" = ?1"#, vec![SqlValue::Text(id.clone())])?;
    env.exec(
        &format!(r#"INSERT INTO "Network" ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#),
        vec![
            SqlValue::Text(id),
            SqlValue::Text(n.kind.clone()),
            SqlValue::Text(n.chain_id.clone()),
            SqlValue::Text(n.name.clone()),
            SqlValue::Text(n.rpc.clone()),
            SqlValue::Text(n.currency_symbol.clone()),
            SqlValue::Int(n.currency_decimals),
            SqlValue::Text(n.block_explorer.clone()),
            SqlValue::Int(n.testnet as i64),
            SqlValue::Int(n.priority),
            SqlValue::Text(if n.created.is_empty() { crate::now_rfc3339() } else { n.created.clone() }),
            SqlValue::Text(crate::now_rfc3339()),
        ],
    )?;
    Ok(())
}

pub fn list(env: &Env) -> Result<Vec<Network>> {
    let sql = format!(r#"SELECT {COLS} FROM "Network" ORDER BY "Priority" DESC"#);
    let rows = env.query(&sql, Vec::new())?;
    Ok(rows.iter().map(|r| row_to_network(r)).collect())
}

/// Create a network (port of Go `apiCreateNetwork`): the id is (re)computed
/// from type+chainId, `check()` validates and fills defaults, then the row is
/// persisted. No live RPC probe — Go's create path only validates the URL shape
/// and fills chain-registry defaults, it never dials the node.
pub fn create(env: &Env, mut n: Network) -> Result<Network> {
    // Go sets Id=nil so it is recomputed from type.chainId in Save.
    n.id = String::new();
    n.check()?;
    n.id = network_id_for(&n.kind, &n.chain_id);
    let now = crate::now_rfc3339();
    if n.created.is_empty() {
        n.created = now.clone();
    }
    n.updated = now;
    save(env, &n)?;
    Ok(n)
}

/// Apply the mutable fields Go `Network.ApiUpdate` allows (Name, RPC,
/// CurrencySymbol, TestNet, Priority) from `params` to the stored row, re-run
/// `check()` (so an invalid/internal RPC fails the update rather than being
/// persisted), and save. Returns the updated network. A no-op update (no known
/// fields present) returns the row unchanged.
pub fn update(env: &Env, id: &str, params: &Value) -> Result<Network> {
    let mut n = by_id(env, id)?
        .ok_or_else(|| crate::Error::Env(format!("network not found: {id}")))?;
    let mut updated = false;
    if let Some(v) = params.get("Name").and_then(Value::as_str) {
        n.name = v.to_owned();
        updated = true;
    }
    if let Some(v) = params.get("RPC").and_then(Value::as_str) {
        n.rpc = v.to_owned();
        updated = true;
    }
    if let Some(v) = params.get("CurrencySymbol").and_then(Value::as_str) {
        n.currency_symbol = v.to_owned();
        updated = true;
    }
    if let Some(v) = params.get("TestNet").and_then(Value::as_bool) {
        n.testnet = v;
        updated = true;
    }
    if let Some(v) = params.get("Priority").and_then(Value::as_i64) {
        n.priority = v;
        updated = true;
    }
    if !updated {
        return Ok(n);
    }
    n.check()?;
    n.updated = crate::now_rfc3339();
    save(env, &n)?;
    Ok(n)
}

/// Delete a network by id (port of Go `Network.ApiDelete` — ForceDelete by Id).
pub fn delete(env: &Env, id: &str) -> Result<()> {
    env.exec(r#"DELETE FROM "Network" WHERE "Id" = ?1"#, vec![SqlValue::Text(id.to_owned())])?;
    Ok(())
}

// --- URL guard (port of wltnet/urlguard.go) -------------------------------
//
// A Network.RPC is used verbatim both for read-only queries AND for
// broadcasting signed transactions, so an unvalidated value lets a malicious
// dApp repoint a plausibly-named chain at an attacker endpoint (credential
// relay, tx censorship, balance spoofing) or at an internal service the host
// can reach but the attacker cannot (SSRF / port fingerprinting).

/// Validate a `Network.RPC` value: the sentinels "" and "auto" mean "pick
/// automatically from the chain registry" and are always allowed; a concrete
/// URL must pass [`validate_rpc_url`]. Port of Go `validateNetworkRPC`.
pub fn validate_network_rpc(rpc: &str) -> Result<()> {
    let rpc = rpc.trim();
    if rpc.is_empty() || rpc == "auto" {
        return Ok(());
    }
    validate_rpc_url(rpc)
}

/// Validate a concrete RPC URL before it is used for queries or signed-tx
/// broadcast (port of Go `validateRPCURL`). http is allowed only for an
/// explicit localhost / loopback endpoint; any public host must use https and
/// must not resolve to an internal / mDNS address.
pub fn validate_rpc_url(raw: &str) -> Result<()> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(crate::Error::Env("empty RPC URL".into()));
    }
    let (scheme, host) =
        parse_scheme_host(raw).ok_or_else(|| crate::Error::Env(format!("invalid RPC URL: {raw}")))?;
    if scheme != "http" && scheme != "https" {
        return Err(crate::Error::Env(format!(
            "RPC URL scheme {scheme:?} not allowed (want https)"
        )));
    }
    if host.is_empty() {
        return Err(crate::Error::Env("RPC URL has no host".into()));
    }
    let lhost = host.trim_end_matches('.').to_ascii_lowercase();

    // Development escape hatch: explicit localhost name or loopback literal IP.
    if is_localhost_name(&lhost) {
        return Ok(());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return Ok(());
        }
    }
    if scheme != "https" {
        return Err(crate::Error::Env(
            "RPC URL must use https (http is allowed only for localhost)".into(),
        ));
    }
    if lhost.ends_with(".local") {
        return Err(crate::Error::Env(format!(
            "RPC URL host {host:?} (.local mDNS) not allowed"
        )));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_internal_ip(&ip) {
            return Err(crate::Error::Env(format!(
                "RPC URL points at internal address {ip}"
            )));
        }
    }
    Ok(())
}

/// Extract the (lowercased scheme, host-without-port) from a URL. A minimal
/// parser — enough to gate the URL shape without pulling in the `url` crate.
fn parse_scheme_host(raw: &str) -> Option<(String, String)> {
    let (scheme, rest) = raw.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // Strip any userinfo (`user:pass@`).
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = if let Some(after) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: take up to the closing ']'.
        let close = after.find(']')?;
        after[..close].to_owned()
    } else {
        // Strip a trailing `:port`.
        authority.split(':').next().unwrap_or(authority).to_owned()
    };
    Some((scheme.to_ascii_lowercase(), host))
}

/// Whether `host` is the explicit localhost dev endpoint ("localhost" or a
/// "*.localhost" subname). Go `isLocalhostName`.
fn is_localhost_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost")
}

/// Whether `ip` is in a range that must never be a caller-supplied RPC target
/// (Go `isInternalIP`): loopback, private, link-local, ULA, multicast,
/// unspecified, carrier-grade NAT (100.64/10) or 0.0.0.0/8.
fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
            {
                return true;
            }
            let o = v4.octets();
            // 100.64.0.0/10 carrier-grade NAT
            if o[0] == 100 && (o[1] & 0xc0) == 64 {
                return true;
            }
            // 0.0.0.0/8 "this host on this network"
            o[0] == 0
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
                return true;
            }
            let seg = v6.segments();
            // link-local unicast fe80::/10
            if (seg[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // unique-local fc00::/7
            (seg[0] & 0xfe00) == 0xfc00
        }
    }
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
