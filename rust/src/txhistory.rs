//! Transaction-history backfill (port of wltbase/tx_history.go). Sweeps a
//! network's tx-history provider for an account and upserts the results as
//! Transaction rows. Providers: `modchain_historyByAddress` for EVM and for the
//! Bitcoin family (paginated, newest→oldest, stop at the first already-known
//! tx), and `getSignaturesForAddress` for Solana.

use std::collections::{HashMap, HashSet};

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

/// Backfill a Bitcoin-family account (BTC, LTC, DOGE, BCH, MONA) via
/// `modchain_historyByAddress` — the same backend as the EVM provider. The
/// account is an xpub, so every used receive/change address (found with
/// `modchain_lookupTxoBIP32`, as `Account:allAddresses` does) is swept and the
/// txids merged. Each confirmed tx becomes one row from the account's point of
/// view: outgoing when it spends one of our outputs (amount = what left the
/// account, fee when every input was ours), incoming otherwise (amount = what
/// our addresses received). Unconfirmed txs are left for a later sweep, so the
/// stop-at-known rule never freezes a row without its block time.
pub fn backfill_bitcoin_modchain(
    env: &Env,
    account: &crate::models::account::Account,
    net: &crate::models::network::Network,
    rpc: &str,
) -> Result<usize> {
    use base64::Engine;
    let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap_or_default();
    let xpub = account.xpub()?;
    let pubkey: [u8; 33] = b64(&account.pubkey)
        .try_into()
        .map_err(|_| crate::Error::Env("account pubkey is not 33 bytes".into()))?;
    let chaincode: [u8; 32] = b64(&account.chaincode)
        .try_into()
        .map_err(|_| crate::Error::Env("account chaincode is not 32 bytes".into()))?;
    let mut addrs = crate::bitcoin::scan_chain(rpc, &xpub, &pubkey, &chaincode, &net.chain_id, false)?;
    addrs.extend(crate::bitcoin::scan_chain(rpc, &xpub, &pubkey, &chaincode, &net.chain_id, true)?);
    let ours: HashSet<String> = addrs.iter().map(|a| norm_btc_addr(&a.address)).collect();

    // Newest→oldest per address; a txid touching several of our addresses is
    // kept once.
    let mut order: Vec<String> = Vec::new();
    let mut fetched: HashMap<String, Value> = HashMap::new();
    for a in &addrs {
        let mut continue_key = String::new();
        for _page in 0..MAX_PAGES {
            let resp = crate::rpc::call(rpc, "modchain_historyByAddress", json!([a.address, continue_key]))?;
            let results = match resp.get("results").and_then(Value::as_array) {
                Some(r) if !r.is_empty() => r.clone(),
                _ => break,
            };
            let mut saw_known = false;
            for r in results {
                let txid = r.get("tx").and_then(Value::as_str).unwrap_or("").to_lowercase();
                if txid.is_empty() || fetched.contains_key(&txid) {
                    continue;
                }
                if existing_tx_by_hash(env, &txid, &net.id)? {
                    saw_known = true;
                    continue;
                }
                if let Some(data) = r.get("data") {
                    order.push(txid.clone());
                    fetched.insert(txid, data.clone());
                }
            }
            let ck = resp.get("continueKey").and_then(Value::as_str).unwrap_or("");
            if saw_known || ck.is_empty() {
                break;
            }
            continue_key = ck.to_owned();
        }
    }

    // Our inputs' values: the funding tx paid one of our addresses, so it is
    // usually among `fetched`; otherwise (already stored, or past the page cap)
    // fetch it once.
    let mut remote: HashMap<String, Option<Value>> = HashMap::new();
    let mut total = 0usize;
    for txid in &order {
        let data = &fetched[txid];
        let mut prevout = |prev: &str, n: u64| -> Option<u64> {
            let prev = prev.to_lowercase();
            let tx = match fetched.get(&prev) {
                Some(t) => Some(t),
                None => remote
                    .entry(prev.clone())
                    .or_insert_with(|| crate::rpc::call(rpc, "getrawtransaction", json!([prev, true])).ok())
                    .as_ref(),
            }?;
            let out = tx.get("vout")?.as_array()?.iter().find(|o| o.get("n").and_then(Value::as_u64) == Some(n))?;
            btc_value_sats(out.get("value")?)
        };
        if let Some(tx) = build_bitcoin_history_tx(net, &account.address, &ours, txid, data, &mut prevout) {
            crate::models::transaction::persist(env, &tx)?;
            total += 1;
        }
    }
    Ok(total)
}

/// One decoded node transaction (`getrawtransaction` verbose form, as modchain
/// returns it) as a history row for the account owning `ours`. `prevout`
/// resolves `(txid, vout)` to satoshi for inputs we spent. None for an
/// unconfirmed tx or one that moved none of our coins.
fn build_bitcoin_history_tx(
    net: &crate::models::network::Network,
    account_address: &str,
    ours: &HashSet<String>,
    txid: &str,
    data: &Value,
    prevout: &mut dyn FnMut(&str, u64) -> Option<u64>,
) -> Option<Transaction> {
    if data.get("confirmations").and_then(Value::as_i64).unwrap_or(0) <= 0 {
        return None;
    }
    let (mut received, mut sent_out, mut total_out) = (0u64, 0u64, 0u64);
    let mut payee: Option<String> = None;
    for o in data.get("vout").and_then(Value::as_array).into_iter().flatten() {
        // Indexer-supplied values: a sum that does not fit is not a real
        // transaction, so the row is dropped rather than wrapped.
        let sats = o.get("value").and_then(btc_value_sats).unwrap_or(0);
        total_out = total_out.checked_add(sats)?;
        match vout_address(o) {
            Some(a) if ours.contains(&norm_btc_addr(&a)) => received = received.checked_add(sats)?,
            other => {
                sent_out = sent_out.checked_add(sats)?;
                if payee.is_none() {
                    payee = other;
                }
            }
        }
    }
    // An input is ours when the key that signed it encodes to one of our
    // addresses (P2WPKH witness / P2PKH scriptSig both carry the pubkey).
    // `all_ours_known`: every input is ours with a known value, so the fee is
    // ours too. `spent_known`: just our own inputs' values are all known.
    let (mut spent, mut all_ours_known, mut spent_known, mut any_ours) = (0u64, true, true, false);
    for i in data.get("vin").and_then(Value::as_array).into_iter().flatten() {
        let mine = input_pubkey(i)
            .and_then(|pk| crate::bitcoin::hd_address(&pk, &net.chain_id).ok())
            .is_some_and(|a| ours.contains(&norm_btc_addr(&a)));
        if !mine {
            all_ours_known = false;
            continue;
        }
        any_ours = true;
        let prev = i.get("txid").and_then(Value::as_str).unwrap_or("");
        match i.get("vout").and_then(Value::as_u64).and_then(|n| prevout(prev, n)) {
            Some(v) => spent = spent.checked_add(v)?,
            None => (all_ours_known, spent_known) = (false, false),
        }
    }
    let decimals = if net.currency_decimals > 0 { net.currency_decimals } else { 8 };
    let (from, to, amount, fee) = if any_ours {
        // Sent: what left for other addresses (0 for a move between our own).
        // When someone else's inputs joined ours, the fee isn't ours to report
        // and the account lost only its own net share: spent − received.
        let fee = all_ours_known.then(|| spent.saturating_sub(total_out));
        let amount = if !all_ours_known && spent_known { sent_out.min(spent.saturating_sub(received)) } else { sent_out };
        (account_address.to_owned(), payee.unwrap_or_else(|| account_address.to_owned()), amount, fee)
    } else if received > 0 {
        (String::new(), account_address.to_owned(), received, None)
    } else {
        return None;
    };
    let created = data
        .get("blocktime")
        .or_else(|| data.get("time"))
        .and_then(Value::as_i64)
        .map(crate::db::unix_to_rfc3339)
        .unwrap_or_default();
    Some(Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: "transfer".into(),
        asset: format!("{}.NATIVE", net.key_prefix()),
        from,
        to,
        fee: fee.map(|f| Amount::new_raw(BigInt::from(f), decimals)),
        hash: txid.to_owned(),
        network: net.id.clone(),
        amount: Some(Amount::new_raw(BigInt::from(amount), decimals)),
        url: net.transaction_url(txid),
        created,
        ..Default::default()
    })
}

/// A vout's address: `scriptPubKey.address`, or the first of the older
/// `addresses` list (Dogecoin's node still uses it).
fn vout_address(o: &Value) -> Option<String> {
    let spk = o.get("scriptPubKey")?;
    spk.get("address")
        .and_then(Value::as_str)
        .or_else(|| spk.get("addresses")?.as_array()?.first()?.as_str())
        .map(str::to_owned)
}

/// Compare addresses without the cashaddr `bitcoincash:` prefix or case.
fn norm_btc_addr(a: &str) -> String {
    let a = a.to_ascii_lowercase();
    a.strip_prefix("bitcoincash:").map(str::to_owned).unwrap_or(a)
}

/// The compressed pubkey that signed an input: the last witness item, else the
/// last push of the scriptSig.
fn input_pubkey(vin: &Value) -> Option<[u8; 33]> {
    let witness_last = vin.get("txinwitness").and_then(Value::as_array).and_then(|w| w.last()).and_then(Value::as_str);
    let script_last = vin
        .get("scriptSig")
        .and_then(|s| s.get("asm"))
        .and_then(Value::as_str)
        .and_then(|asm| asm.split_whitespace().last());
    let hex = witness_last.or(script_last)?;
    if hex.len() != 66 || !(hex.starts_with("02") || hex.starts_with("03")) {
        return None;
    }
    let mut out = [0u8; 33];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A node's coin `value` in satoshi. Exact for decimal literals; a number that
/// serde re-renders in exponent form (1e-8) falls back to rounding.
fn btc_value_sats(v: &Value) -> Option<u64> {
    crate::bitcoin::parse_btc_amount(v)
        .ok()
        .or_else(|| v.as_f64().filter(|f| *f >= 0.0).map(|f| (f * 1e8).round() as u64))
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
        url: net.transaction_url(signature),
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
        url: net.transaction_url(hash),
        created,
        ..Default::default()
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    // Two real mainnet txs (via modchain_historyByAddress for OURS): FUND pays
    // 0.39986357 BTC to OURS, SPEND sends all of it to six other addresses.
    const OURS: &str = "bc1qhd58tkh74e0thtnsnctmhgr3g6ztyu4ucn4aug";
    const FUND: &str = r#"{"txid": "c27a54ea62408d29f62ebb98f3f0aade879ae4e5d4320e9b65770ab7c38674fe", "confirmations": 169, "blocktime": 1793871022, "vin": [{"txid": "85be943fbf9c907d7fdf3680ee0ab4bf772b63f74f255c5647d6c86d1c53e41c", "vout": 5, "txinwitness": ["3045022100ba502d85468b7450260569f58d655f5f8e5cb13eec4519bd8eef35af9a33890002201822d0ae69f9eac032dcb4d85873db1edf60855bbffa8752d0812e272f4e3bcf01", "030b5b61d90b9f0d49fed7c83cc8aff20014b575cd5916495effe40bc2b85be41f"]}], "vout": [{"value": 0.00051045, "n": 0, "scriptPubKey": {"address": "bc1q0xsxl8g39p0vwt288q79qalg2fh5xkxuj35krj"}}, {"value": 0.00032996, "n": 1, "scriptPubKey": {"address": "bc1qmt78msdzdf9y9w6xg2lxe3sf5zflfmrgectj64"}}, {"value": 0.00054676, "n": 2, "scriptPubKey": {"address": "bc1qkjm97hm0tydxv2decedsu5dz4w2smt0pq2c7zz"}}, {"value": 0.00040316, "n": 3, "scriptPubKey": {"address": "bc1qa8cedmldseql3zwpy0x0yh92s88k5pyzzmwt9e"}}, {"value": 0.39986357, "n": 4, "scriptPubKey": {"address": "bc1qhd58tkh74e0thtnsnctmhgr3g6ztyu4ucn4aug"}}]}"#;
    const SPEND: &str = r#"{"txid": "fccba2e8e6edd54fc8fb13347330daa9732b38308630a39718d3729480714ad7", "confirmations": 162, "blocktime": 1793877550, "vin": [{"txid": "c27a54ea62408d29f62ebb98f3f0aade879ae4e5d4320e9b65770ab7c38674fe", "vout": 4, "txinwitness": ["3044022061868ac876b1e299450460f07e70d4b8a1a291226270f5ace1e56bd4729f5d050220392976824262852c3bd86b679895af5666c6e999a033d9e6464f8d54a313324a01", "02979b4911eb3077aa3abc76402f0da211711d7f0fb90d1ef14aeb3dd553f5c038"]}], "vout": [{"value": 0.00056787, "n": 0, "scriptPubKey": {"address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"}}, {"value": 0.00062024, "n": 1, "scriptPubKey": {"address": "bc1quj88k4dc6e39rzutajvuj2a3c268rx20kyeudl"}}, {"value": 0.00088197, "n": 2, "scriptPubKey": {"address": "bc1q8c8g4lv7c2tvltwjhl38ua942nuwkwye8rnhf3"}}, {"value": 0.00017032, "n": 3, "scriptPubKey": {"address": "bc1qjr7kesrjq8ptlwp3ff0frkk0q7yuwxjdgedgj8"}}, {"value": 0.00098093, "n": 4, "scriptPubKey": {"address": "bc1qu7a5c9wlupwcx0gx8e85mury5g8w0dmfnlujqy"}}, {"value": 0.39663908, "n": 5, "scriptPubKey": {"address": "bc1qn2l34ludly8pe0h0dfwpjgysfu65d2ypgsu7ce"}}]}"#;

    fn btc() -> crate::models::network::Network {
        crate::models::network::Network {
            id: "net-btc".into(),
            kind: "bitcoin".into(),
            chain_id: "bitcoin".into(),
            currency_decimals: 8,
            ..Default::default()
        }
    }

    fn row(data: &str, fetched: &[&str]) -> Option<Transaction> {
        let ours: HashSet<String> = [OURS.to_owned()].into();
        let data: Value = serde_json::from_str(data).unwrap();
        let txs: Vec<Value> = fetched.iter().map(|t| serde_json::from_str(t).unwrap()).collect();
        let mut prevout = |prev: &str, n: u64| {
            let tx = txs.iter().find(|t| t["txid"] == prev)?;
            let o = tx["vout"].as_array()?.iter().find(|o| o["n"] == n)?;
            btc_value_sats(&o["value"])
        };
        build_bitcoin_history_tx(&btc(), "acct-addr", &ours, data["txid"].as_str().unwrap(), &data, &mut prevout)
    }

    fn sats(a: &Option<Amount>) -> String {
        serde_json::to_value(a.as_ref().unwrap()).unwrap()["v"].as_str().unwrap().to_owned()
    }

    #[test]
    fn incoming_is_what_our_addresses_received() {
        let tx = row(FUND, &[]).unwrap();
        assert_eq!((tx.from.as_str(), tx.to.as_str()), ("", "acct-addr"));
        assert_eq!(sats(&tx.amount), "39986357");
        assert!(tx.fee.is_none());
        assert_eq!(tx.asset, "bitcoin.bitcoin.NATIVE");
        assert_eq!(tx.created, crate::db::unix_to_rfc3339(1793871022));
    }

    #[test]
    fn outgoing_has_amount_payee_and_fee() {
        let tx = row(SPEND, &[FUND]).unwrap();
        assert_eq!(tx.from, "acct-addr");
        assert_eq!(tx.to, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        assert_eq!(sats(&tx.amount), "39986041");
        assert_eq!(sats(&tx.fee), "316");
        // A stranger's input joining ours: no fee, and only our 0.39986357
        // counts as sent, not the stranger's share of the outputs.
        let mut v: Value = serde_json::from_str(SPEND).unwrap();
        let mut extra = v["vin"][0].clone();
        extra["txid"] = json!("00".repeat(32));
        extra["txinwitness"][1] = json!(format!("03{}", "11".repeat(32)));
        v["vin"].as_array_mut().unwrap().push(extra);
        v["vout"][5]["value"] = json!(1.0);
        let tx = row(&v.to_string(), &[FUND]).unwrap();
        assert_eq!(sats(&tx.amount), "39986357");
        assert!(tx.fee.is_none());
        // Without the funding tx the spend is still recognised, just feeless.
        let tx = row(SPEND, &[]).unwrap();
        assert_eq!((tx.from.as_str(), sats(&tx.amount)), ("acct-addr", "39986041".into()));
        assert!(tx.fee.is_none());
    }

    #[test]
    fn unconfirmed_and_unrelated_are_skipped() {
        let mut v: Value = serde_json::from_str(FUND).unwrap();
        v["confirmations"] = json!(0);
        assert!(row(&v.to_string(), &[]).is_none());
        let mut v: Value = serde_json::from_str(FUND).unwrap();
        v["vout"][4]["scriptPubKey"]["address"] = json!("bc1qn2l34ludly8pe0h0dfwpjgysfu65d2ypgsu7ce");
        assert!(row(&v.to_string(), &[]).is_none());
    }

    #[test]
    fn overflowing_output_values_drop_the_row() {
        // Two outputs of ~1.8e11 BTC each: their satoshi sum does not fit u64.
        let mut v: Value = serde_json::from_str(FUND).unwrap();
        v["vout"][0]["value"] = json!("0xffffffffffffffff");
        v["vout"][1]["value"] = json!("0xffffffffffffffff");
        assert!(row(&v.to_string(), &[]).is_none());
    }

    #[test]
    fn helpers() {
        assert_eq!(btc_value_sats(&json!(0.00000001)), Some(1));
        assert_eq!(btc_value_sats(&json!(0.39986357)), Some(39_986_357));
        assert_eq!(norm_btc_addr("bitcoincash:QQgx34"), norm_btc_addr("qqgx34"));
        let doge = json!({"scriptPubKey": {"addresses": ["DMQK9fybTma5m4SiBcuriq9H55u7SkEShx"]}});
        assert_eq!(vout_address(&doge).as_deref(), Some("DMQK9fybTma5m4SiBcuriq9H55u7SkEShx"));
        let p2pkh = json!({"scriptSig": {"asm": "3044[ALL|FORKID] 02979b4911eb3077aa3abc76402f0da211711d7f0fb90d1ef14aeb3dd553f5c038"}});
        assert_eq!(input_pubkey(&p2pkh).unwrap()[0], 0x02);
    }
}
