//! wltasset — asset/balance rows. Port of the Go `wltasset` package.
//!
//! Read surface only: assets are populated by balance discovery (RPC), which
//! lands with wltnet; there is no create endpoint. Unlike the other models,
//! Asset uses lowercase JSON keys (explicit Go `json:` tags) — except Created/
//! Updated, which have none and stay PascalCase. Amount is stored as its
//! `{v,e,f}` JSON and round-trips through [`crate::Amount`].

use serde::{Deserialize, Serialize};
use crate::{Amount, Env, Result, SqlValue};

const TABLE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "Asset" ("Id" text, "Key" text, "Name" text, "Symbol" text, "Amount" text, "Type" text, "Network" text, "Created" text, "Updated" text, PRIMARY KEY ("Id"));
CREATE UNIQUE INDEX IF NOT EXISTS "Asset_Key" ON "Asset" ("Key");"#;
const COLS: &str = r#""Id", "Key", "Name", "Symbol", "Amount", "Type", "Network", "Created", "Updated""#;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Asset {
    #[serde(rename = "id", default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(rename = "key", default)]
    pub key: String,
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "symbol", default)]
    pub symbol: String,
    #[serde(rename = "amount")]
    pub amount: Amount,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(rename = "network", default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Updated", default)]
    pub updated: String,

    // Computed (never persisted) fiat conversion, matching Go's sql:"-" fields.
    #[serde(rename = "fiat_amount", default, skip_serializing_if = "Option::is_none")]
    pub fiat_amount: Option<Amount>,
    #[serde(rename = "fiat_currency", default, skip_serializing_if = "String::is_empty")]
    pub fiat_currency: String,
    #[serde(rename = "fiat_quote", default, skip_serializing_if = "Option::is_none")]
    pub fiat_quote: Option<crate::quote::CmcQuoteEntry>,
    #[serde(rename = "testnet", default, skip_serializing_if = "std::ops::Not::not")]
    pub testnet: bool,
}

impl Asset {
    /// Native currency? (`.NATIVE` suffix on Key — Go `Asset.IsNative`).
    pub fn is_native(&self) -> bool {
        self.key.ends_with(".NATIVE")
    }

    /// Port of Go `Asset.ConvertTo`: multiply the balance by the token's fiat
    /// price (from the quote table) and populate the fiat_* fields. No-op for
    /// testnet assets. `Ok(false)` when no quote/currency entry exists.
    pub fn convert_to(&mut self, env: &Env, currency: &str) -> Result<bool> {
        if self.testnet {
            return Ok(false);
        }
        let quote = match crate::quote::get_quotes_for_token(env, &self.symbol)? {
            Some(q) => q,
            None => return Ok(false),
        };
        let entry = match quote.quote.get(currency) {
            Some(e) => e.clone(),
            None => return Ok(false),
        };
        // price as an Amount (8 decimals — "more decimals always good"), then
        // fiat = balance * price.
        let price = Amount::from_float64(entry.price, 8);
        let mut fiat = Amount::new(0, 8);
        fiat.mul(&self.amount, &price);
        self.fiat_amount = Some(fiat);
        self.fiat_currency = currency.to_owned();
        self.fiat_quote = Some(entry);
        Ok(true)
    }
}

pub fn init(env: &Env) -> Result<()> {
    env.ensure_table(TABLE_DDL)
}

pub fn fetch(env: &Env, id: &str) -> Result<Option<Asset>> {
    let sql = format!(r#"SELECT {COLS} FROM "Asset" WHERE "Id" = ?1"#);
    let rows = env.query(&sql, vec![SqlValue::Text(id.to_owned())])?;
    Ok(rows.first().map(|r| row_to_asset(r)))
}

pub fn list(env: &Env) -> Result<Vec<Asset>> {
    let sql = format!(r#"SELECT {COLS} FROM "Asset" ORDER BY "Key" ASC"#);
    let rows = env.query(&sql, Vec::new())?;
    let mut assets: Vec<Asset> = rows.iter().map(|r| row_to_asset(r)).collect();
    // The live native-currency asset (SOL/ETH/BTC/TRX) for the current
    // account on the current network, first in the list like Go's
    // `computeAssets`. Skipped if a persisted row already carries its key.
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(native) = current_native_asset(env) {
        if !assets.iter().any(|a| a.key == native.key) {
            assets.insert(0, native);
        }
    }
    // Registered ERC-20 (TRC-20) tokens on the current EVM (Tron) network, with live balances
    // (port of the EVM leg Go `computeAssets` gained in wltbase/asset.go).
    // Appended after the persisted rows; best-effort, so a missing current
    // network/account or an unresolvable RPC simply contributes nothing.
    assets.extend(registered_erc20_assets(env));
    Ok(assets)
}

/// The current account's native asset on the current network (port of the
/// native leg of Go `computeAssets`). Best-effort like the token leg: no
/// current network/account, a chain mismatch, a watch-only "N/A" address or
/// an RPC failure yields `None` rather than failing the whole list.
#[cfg(not(target_arch = "wasm32"))]
fn current_native_asset(env: &Env) -> Option<Asset> {
    let net = crate::models::network::fetch(env, "@").ok()??;
    let account_kind = match net.kind.as_str() {
        "evm" => "ethereum",
        other => other,
    };
    let account = crate::models::account::current(env).ok()??;
    if account.kind != account_kind || account.address.is_empty() || account.address == "N/A" {
        return None;
    }
    let rpc = net.resolved_rpc().ok()?;
    net.native_asset(&rpc, &account.address).ok()
}

/// The current EVM network's registered ERC-20 tokens as live-balance assets
/// (port of the EVM leg of Go `computeAssets`). Unlike Solana — where token
/// accounts are enumerable on-chain — EVM has no cheap owner→tokens query, so
/// the user's Token registry (Token:create / Token:discoverToken / swap
/// EnsureToken) is the source of truth. Zero balances are included on purpose:
/// a token the user explicitly registered shows as "0" rather than vanishing.
/// A per-token RPC failure skips that token instead of failing the whole list.
/// Best-effort throughout — any setup failure yields no rows.
fn registered_erc20_assets(env: &Env) -> Vec<Asset> {
    // Tron works the same way: TRC-20 is ERC-20 behind another address
    // encoding, and holdings are not enumerable from the node either.
    let (net, account_kind, token_kind) = match crate::models::network::fetch(env, "@") {
        Ok(Some(n)) if n.kind == "evm" => (n, "ethereum", "erc20"),
        Ok(Some(n)) if n.kind == "tron" => (n, "tron", "trc20"),
        _ => return Vec::new(),
    };
    let account = match crate::models::account::current(env) {
        Ok(Some(a)) if a.kind == account_kind && !a.address.is_empty() && a.address != "N/A" => a,
        _ => return Vec::new(),
    };
    let rpc = match net.resolved_rpc() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let tokens = match crate::models::token::tokens_by_network(env, &net.id) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for token in tokens {
        if token.kind != token_kind {
            continue;
        }
        let bal = match token_kind {
            "trc20" => crate::tron::trc20_balance(&rpc, &token.address, &account.address),
            _ => crate::erc20::balance_of(&rpc, &token.address, &account.address),
        };
        let bal = match bal {
            Ok(b) => b,
            Err(_) => continue, // per-token RPC failure: skip (Go logs + continues)
        };
        // Fall back to a truncated contract address when the row carries no
        // display metadata (matches Go's name/symbol fallbacks).
        let name = if token.name.is_empty() {
            format!("{}...", &token.address[..token.address.len().min(10)])
        } else {
            token.name.clone()
        };
        let symbol = if token.symbol.is_empty() {
            token.address[..token.address.len().min(8)].to_owned()
        } else {
            token.symbol.clone()
        };
        out.push(Asset {
            id: String::new(),
            key: format!("{}.{}", net.key_prefix(), token.address),
            name,
            symbol,
            amount: Amount::new_raw(bal, token.decimals),
            kind: "fungible".to_owned(),
            network: net.id.clone(),
            created: String::new(),
            updated: String::new(),
            fiat_amount: None,
            fiat_currency: String::new(),
            fiat_quote: None,
            testnet: net.testnet,
        });
    }
    out
}

fn row_to_asset(row: &[SqlValue]) -> Asset {
    let text = |i: usize| row.get(i).and_then(|v| v.as_text()).unwrap_or("").to_owned();
    let amount = row
        .get(4)
        .and_then(|v| v.as_text())
        .and_then(|s| serde_json::from_str::<Amount>(s).ok())
        .unwrap_or_else(|| Amount::new(0, 0));
    Asset {
        id: text(0),
        key: text(1),
        name: text(2),
        symbol: text(3),
        amount,
        kind: text(5),
        network: text(6),
        created: text(7),
        updated: text(8),
        fiat_amount: None,
        fiat_currency: String::new(),
        fiat_quote: None,
        testnet: false,
    }
}
