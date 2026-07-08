//! Transaction-history backfill (port of wltbase/tx_history.go). Sweeps a
//! network's tx-history provider for an account and upserts the results as
//! Transaction rows. Currently the EVM `modchain_historyByAddress` provider
//! (paginated, newest→oldest, stop at the first already-known tx); the Solana
//! `getSignaturesForAddress` provider follows.

use num_bigint::BigInt;
use serde_json::{json, Value};

use crate::models::transaction::Transaction;
use crate::{Amount, Env, Result};

/// Max pages per sweep (modchain returns 25/page → 40 pages ≈ 1000 txs).
const MAX_PAGES: usize = 40;

/// Backfill EVM history for `address` via `modchain_historyByAddress`. Returns
/// the number of newly-stored transactions.
pub fn backfill_evm_modchain(env: &Env, address: &str, net: &crate::models::network::Network, rpc: &str) -> Result<usize> {
    let addr = address.to_lowercase();
    let mut continue_key = String::new();
    let mut total = 0usize;

    for _page in 0..MAX_PAGES {
        let resp = crate::rpc::call(rpc, "modchain_historyByAddress", json!([addr, continue_key]))?;
        let results = match resp.get("results").and_then(Value::as_array) {
            Some(r) if !r.is_empty() => r.clone(),
            _ => break,
        };
        // Newest→oldest: stop once we hit a tx we already have.
        let mut saw_known = false;
        for r in &results {
            let hash = r.get("tx").and_then(Value::as_str).unwrap_or("").to_lowercase();
            if hash.is_empty() {
                continue;
            }
            if existing_tx_by_hash(env, &hash, &net.id)? {
                saw_known = true;
                continue;
            }
            if let Some(tx) = build_evm_history_tx(net, &hash, r.get("data")) {
                crate::models::transaction::persist(env, &tx)?;
                total += 1;
            }
        }
        let ck = resp.get("continueKey").and_then(Value::as_str).unwrap_or("");
        if saw_known || ck.is_empty() {
            break;
        }
        continue_key = ck.to_owned();
    }
    Ok(total)
}

/// Whether a Transaction row already exists for `(hash, network)`.
fn existing_tx_by_hash(env: &Env, hash: &str, network_id: &str) -> Result<bool> {
    let rows = env.query(
        r#"SELECT "Id" FROM "Transaction" WHERE "Hash" = ?1 AND "Network" = ?2 LIMIT 1"#,
        vec![crate::SqlValue::Text(hash.to_owned()), crate::SqlValue::Text(network_id.to_owned())],
    )?;
    Ok(!rows.is_empty())
}

/// Build a history Transaction from a modchain EVM summary (Go
/// `buildEvmHistoryTx`): `{from,to,value,gas,gasPrice,timestamp}`.
fn build_evm_history_tx(net: &crate::models::network::Network, hash: &str, data: Option<&Value>) -> Option<Transaction> {
    let s = data?;
    let str_of = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let decimals = if net.currency_decimals > 0 { net.currency_decimals } else { 18 };
    let value = parse_hex_big(&str_of("value")).unwrap_or_else(|| BigInt::from(0));
    let gas = parse_hex_big(&str_of("gas")).and_then(|n| u64::try_from(n).ok()).unwrap_or(0);
    let created = parse_hex_big(&str_of("timestamp"))
        .and_then(|n| i64::try_from(n).ok())
        .map(|secs| crate::db::unix_to_rfc3339(secs))
        .unwrap_or_default();

    Some(Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: "transfer".into(),
        asset: format!("{}.NATIVE", net.key_prefix()),
        from: str_of("from").to_lowercase(),
        to: str_of("to").to_lowercase(),
        gas,
        gas_price: str_of("gasPrice"),
        hash: hash.to_owned(),
        network: net.id.clone(),
        amount: Some(Amount::new_raw(value, decimals)),
        url: tx_url(net, hash),
        created,
        ..Default::default()
    })
}

fn tx_url(net: &crate::models::network::Network, hash: &str) -> String {
    let base = net.resolved_block_explorer();
    if base.is_empty() {
        String::new()
    } else {
        format!("{}/tx/{hash}", base.trim_end_matches('/'))
    }
}

/// Parse a 0x-hex (or decimal) quantity into a BigInt.
fn parse_hex_big(s: &str) -> Option<BigInt> {
    let t = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if t.is_empty() {
        return Some(BigInt::from(0));
    }
    // Hex first (modchain quantities), else decimal (some timestamps).
    if let Some(n) = BigInt::parse_bytes(t.as_bytes(), 16) {
        // Only treat as hex when it's actually hex digits.
        if t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(n);
        }
    }
    BigInt::parse_bytes(s.as_bytes(), 10)
}
