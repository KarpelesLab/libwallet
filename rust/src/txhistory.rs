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

/// One entry from `getSignaturesForAddress`.
const SOLANA_PAGE_SIZE: u64 = 100;

/// Backfill Solana history for `address` via `getSignaturesForAddress` +
/// per-signature `getTransaction` (jsonParsed) condense. Returns the number of
/// newly-stored transactions.
pub fn backfill_solana_signatures(env: &Env, address: &str, net: &crate::models::network::Network, rpc: &str) -> Result<usize> {
    if address.is_empty() {
        return Err(crate::Error::Env("backfill: empty address".into()));
    }
    let mut before = String::new();
    let mut total = 0usize;

    for _page in 0..MAX_PAGES {
        let mut opts = json!({ "limit": SOLANA_PAGE_SIZE });
        if !before.is_empty() {
            opts["before"] = json!(before);
        }
        let resp = crate::rpc::call(rpc, "getSignaturesForAddress", json!([address, opts]))?;
        let sigs = match resp.as_array() {
            Some(s) if !s.is_empty() => s.clone(),
            _ => break,
        };
        let mut saw_known = false;
        let mut last_sig = String::new();
        for s in &sigs {
            let signature = s.get("signature").and_then(Value::as_str).unwrap_or("");
            if signature.is_empty() {
                continue;
            }
            last_sig = signature.to_owned();
            if existing_tx_by_hash(env, signature, &net.id)? {
                saw_known = true;
                continue;
            }
            let block_time = s.get("blockTime").and_then(Value::as_i64);
            match fetch_and_build_solana_tx(rpc, net, address, signature, block_time) {
                Ok(Some(tx)) => {
                    crate::models::transaction::persist(env, &tx)?;
                    total += 1;
                }
                _ => continue, // per-tx decode failures are skipped, not fatal
            }
        }
        if saw_known || last_sig.is_empty() || last_sig == before {
            break;
        }
        before = last_sig;
    }
    Ok(total)
}

/// Fetch one signature's parsed transaction and condense it into a Transaction
/// row (Go `fetchAndBuildSolanaTx`): prefer an SPL transfer touching `owner`,
/// else a system SOL transfer, else the net SOL balance delta ("other").
fn fetch_and_build_solana_tx(rpc: &str, net: &crate::models::network::Network, owner: &str, signature: &str, block_time: Option<i64>) -> Result<Option<Transaction>> {
    let parsed = crate::rpc::call(rpc, "getTransaction", json!([signature, { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }]))?;
    if parsed.is_null() {
        return Ok(None);
    }
    let message = parsed.get("transaction").and_then(|t| t.get("message"));
    let Some(message) = message else { return Ok(None) };

    let created = block_time
        .or_else(|| parsed.get("blockTime").and_then(Value::as_i64))
        .map(crate::db::unix_to_rfc3339)
        .unwrap_or_default();

    // best = (type, asset, from, to, amount, decimals)
    let mut best: Option<(String, String, String, String, BigInt, i64)> = None;
    if let Some(instructions) = message.get("instructions").and_then(Value::as_array) {
        for inst in instructions {
            let program = inst.get("program").and_then(Value::as_str).unwrap_or("");
            let info = inst.get("parsed").and_then(|p| p.get("info"));
            let itype = inst.get("parsed").and_then(|p| p.get("type")).and_then(Value::as_str).unwrap_or("");
            let Some(info) = info else { continue };
            match program {
                "system" => {
                    if best.as_ref().map(|b| b.0 == "spl-token").unwrap_or(false) {
                        continue; // SPL already wins
                    }
                    if itype != "transfer" && itype != "transferWithSeed" {
                        continue;
                    }
                    let source = info.get("source").and_then(Value::as_str).unwrap_or("");
                    let dest = info.get("destination").and_then(Value::as_str).unwrap_or("");
                    if source != owner && dest != owner {
                        continue;
                    }
                    let lamports = info.get("lamports").and_then(Value::as_u64).unwrap_or(0);
                    best = Some(("transfer".into(), format!("{}.NATIVE", net.key_prefix()), source.into(), dest.into(), BigInt::from(lamports), 9));
                }
                "spl-token" | "spl-token-2022" => {
                    if itype != "transfer" && itype != "transferChecked" {
                        continue;
                    }
                    let authority = info.get("authority").and_then(Value::as_str).unwrap_or("");
                    let source = info.get("source").and_then(Value::as_str).unwrap_or("");
                    let dest = info.get("destination").and_then(Value::as_str).unwrap_or("");
                    if authority != owner && source != owner && dest != owner {
                        continue;
                    }
                    let mint = info.get("mint").and_then(Value::as_str).unwrap_or("");
                    let (amount_str, dec) = match info.get("tokenAmount") {
                        Some(ta) => (
                            ta.get("amount").and_then(Value::as_str).unwrap_or("0").to_owned(),
                            ta.get("decimals").and_then(Value::as_i64).unwrap_or(0),
                        ),
                        None => (info.get("amount").and_then(Value::as_str).unwrap_or("0").to_owned(), 0),
                    };
                    let Some(amt) = BigInt::parse_bytes(amount_str.as_bytes(), 10) else { continue };
                    best = Some(("spl-token".into(), format!("{}.{mint}", net.key_prefix()), source.into(), dest.into(), amt, dec));
                }
                _ => {}
            }
        }
    }

    // Fallback: net SOL balance delta → "other".
    let best = match best {
        Some(b) => b,
        None => match solana_balance_delta(&parsed, owner) {
            Some(delta) => ("other".into(), format!("{}.NATIVE", net.key_prefix()), owner.to_owned(), String::new(), delta, 9),
            None => return Ok(None),
        },
    };

    let (kind, asset, from, to, amount, dec) = best;
    Ok(Some(Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind,
        asset,
        from,
        to,
        hash: signature.to_owned(),
        network: net.id.clone(),
        amount: Some(Amount::new_raw(amount, dec)),
        url: tx_url(net, signature),
        created,
        ..Default::default()
    }))
}

/// The owner's net SOL balance change (post − pre) as an absolute amount, or
/// None if the owner isn't in accountKeys / has no delta.
fn solana_balance_delta(parsed: &Value, owner: &str) -> Option<BigInt> {
    let keys = parsed.get("transaction")?.get("message")?.get("accountKeys")?.as_array()?;
    let idx = keys.iter().position(|k| {
        k.as_str() == Some(owner) || k.get("pubkey").and_then(Value::as_str) == Some(owner)
    })?;
    let meta = parsed.get("meta")?;
    let pre = meta.get("preBalances")?.as_array()?.get(idx)?.as_u64()?;
    let post = meta.get("postBalances")?.as_array()?.get(idx)?.as_u64()?;
    let delta = BigInt::from(post) - BigInt::from(pre);
    match delta.sign() {
        num_bigint::Sign::NoSign => None,
        num_bigint::Sign::Minus => Some(-delta),
        num_bigint::Sign::Plus => Some(delta),
    }
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
