//! Transaction object endpoints — read surface (fetch/list) plus the EVM
//! `Transaction:signAndSend` path (build → RPC-backfill nonce/gas/fee → DKLs
//! sign → broadcast → persist). Solana/Bitcoin signAndSend for the Transaction
//! object follows; those chains are already fully covered by
//! `Account:signAndSendTransaction`.

use base64::Engine as _;
use num_bigint::BigInt;
use serde_json::{json, Value};

use crate::sign::KeyDescription;
use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    // Optional best-effort fiat conversion when Currency is supplied.
    let currency = params.get("Currency").and_then(Value::as_str);
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::transaction::fetch(env, id).map_err(ApiError::internal)? {
                Some(mut t) => {
                    if let Some(cur) = currency {
                        let _ = t.convert_to(env, cur);
                    }
                    Ok(serde_json::to_value(t).unwrap())
                }
                None => Err(ApiError::new(404, "transaction not found")),
            },
            None => {
                let mut list =
                    crate::models::transaction::list(env).map_err(ApiError::internal)?;
                if let Some(cur) = currency {
                    for t in &mut list {
                        let _ = t.convert_to(env, cur);
                    }
                }
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => Err(ApiError::new(501, "transaction build/sign not yet ported")),
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Transaction"))),
    }
}

/// `Transaction:validate` — the structural validation of a Transaction (Go
/// `Transaction.Validate`, the type/required-field checks). A positive amount is
/// required for value transfers; erc20/bitcoin also need a recipient; erc20 also
/// an asset. Nonce/gas population needs a live node and is left to signAndSend.
pub fn validate(_env: &Env, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").unwrap_or(params);
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("");
    // Amount is an {v,e,f} object or a decimal string; positive when v != "0".
    let amount_positive = || {
        tx.get("amount")
            .map(|a| match a {
                Value::Object(m) => m.get("v").and_then(|v| v.as_str()).map(|s| s != "0" && !s.is_empty()).unwrap_or(false),
                Value::String(s) => s != "0" && !s.is_empty(),
                _ => false,
            })
            .unwrap_or(false)
    };
    let s = |k: &str| tx.get(k).and_then(Value::as_str).unwrap_or("");
    match typ {
        "transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
            if s("asset").is_empty() {
                return Err(ApiError::new(400, "asset is required"));
            }
        }
        "solana_transfer" | "solana_spl_transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
        }
        "evm" => {} // raw evm tx — no structural requirement
        "erc20_transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
            if s("asset").is_empty() {
                return Err(ApiError::new(400, "asset is required for erc20_transfer"));
            }
            if s("to").is_empty() {
                return Err(ApiError::new(400, "recipient (To) is required for erc20_transfer"));
            }
        }
        "bitcoin_transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
            if s("to").is_empty() {
                return Err(ApiError::new(400, "recipient (To) is required for bitcoin_transfer"));
            }
        }
        other => return Err(ApiError::new(400, format!("unsupported transaction type {other}"))),
    }
    Ok(serde_json::json!({ "valid": true, "type": typ }))
}

/// `Transaction:backfill` — sweep the current account+network's tx-history
/// provider and upsert the results (Go `apiTransactionBackfill`). EVM only for
/// now (modchain_historyByAddress); runs synchronously on the worker thread and
/// emits `tx:history_updated`. Returns `{started, provider, count}`. `RPC` in
/// params overrides the network's resolved RPC (tests / explicit routing).
pub fn backfill(env: &Env, params: &Value) -> ApiResult {
    let account_id = env
        .get_current("account")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "no current account"))?;
    let account = crate::models::account::fetch(env, &account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "current account not found"))?;
    let net = crate::models::network::fetch(env, "@")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "no current network"))?;

    let provider = net.tx_history_provider();
    if !matches!(net.kind.as_str(), "evm" | "solana") || provider.is_empty() {
        // Bitcoin provider not yet ported.
        return Ok(json!({ "started": false, "provider": provider, "reason": format!("no tx-history provider ported for {}", net.kind) }));
    }
    let rpc = match params.get("RPC").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => net.resolved_rpc().map_err(|e| ApiError::new(400, e.to_string()))?,
    };
    let count = match net.kind.as_str() {
        "solana" => crate::txhistory::backfill_solana_signatures(env, &account.address, &net, &rpc),
        _ => crate::txhistory::backfill_evm_modchain(env, &account.address, &net, &rpc),
    }
    .map_err(ApiError::internal)?;
    if count > 0 {
        env.broadcast(&crate::response::event("tx:history_updated", json!({ "account": account.id, "count": count })));
    }
    Ok(json!({ "started": true, "provider": provider, "count": count }))
}

/// `Transaction:signAndSend` — build, sign, broadcast, and persist a
/// transaction (Go `Transaction.SignAndSend`). This ports the EVM path: resolve
/// the `From` account + network, RPC-backfill nonce/gas/fee where absent, sign
/// with the account's DKLs shares, broadcast via `eth_sendRawTransaction`, and
/// save the resulting Transaction row. Solana/Bitcoin are deferred here (use
/// `Account:signAndSendTransaction`, which covers them fully).
pub fn sign_and_send(env: &Env, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").unwrap_or(params);
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("transfer");

    let from = tx
        .get("from")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "from is required"))?;
    let account = crate::models::account::find(env, from)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "from account not found"))?;

    // Resolve the network (tx.network or the current one) and its RPC.
    let net_id = tx.get("network").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("@");
    let net = crate::models::network::fetch(env, net_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "network not found"))?;
    if net.kind != "evm" {
        return Err(ApiError::new(
            501,
            format!("Transaction:signAndSend for {} is not yet ported — use Account:signAndSendTransaction", net.kind),
        ));
    }
    let rpc = match params.get("RPC").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => net.resolved_rpc().map_err(|e| ApiError::new(400, e.to_string()))?,
    };
    let chain_id: u64 = net.chain_id.parse().map_err(|_| ApiError::new(400, "non-numeric EVM chain id"))?;

    // Value (wei) = tx.value else tx.amount significand; erc20/data carries 0.
    let is_erc20 = typ == "erc20_transfer";
    let value = if is_erc20 {
        BigInt::from(0)
    } else {
        amount_significand(tx.get("value")).or_else(|| amount_significand(tx.get("amount"))).unwrap_or_else(|| BigInt::from(0))
    };
    let data = match tx.get("data").and_then(Value::as_str) {
        Some(h) if !h.is_empty() => {
            let h = h.strip_prefix("0x").ok_or_else(|| ApiError::new(400, "data must be 0x-prefixed"))?;
            decode_hex(h)?
        }
        _ => Vec::new(),
    };
    if is_erc20 && data.is_empty() {
        return Err(ApiError::new(400, "erc20_transfer requires encoded Data (0x transfer calldata)"));
    }
    let to = tx.get("to").and_then(Value::as_str).unwrap_or("").to_string();

    // Backfill nonce / gas / fee from the node when the caller didn't pin them.
    let nonce = match tx.get("nonce").and_then(Value::as_u64) {
        Some(n) if n > 0 => n,
        _ => rpc_hex_u64(&rpc, "eth_getTransactionCount", json!([account.address, "pending"]))?,
    };

    let eip1559 = tx.get("format").and_then(Value::as_str) == Some("eip1559")
        || tx.get("maxFeePerGas").is_some();
    let (max_fee, max_priority, format) = if eip1559 {
        let max_fee = tx.get("maxFeePerGas").and_then(Value::as_str).map(str::to_owned);
        let max_fee = match max_fee {
            Some(f) => f,
            None => rpc_hex_bigint_dec(&rpc, "eth_gasPrice", json!([]))?,
        };
        let tip = match tx.get("maxPriorityFeePerGas").and_then(Value::as_str) {
            Some(t) => t.to_owned(),
            None => rpc_hex_bigint_dec(&rpc, "eth_maxPriorityFeePerGas", json!([])).unwrap_or_else(|_| "1500000000".into()),
        };
        (max_fee, tip, "eip1559")
    } else {
        let gp = match tx.get("gasPrice").and_then(Value::as_str) {
            Some(p) if !p.is_empty() => p.to_owned(),
            _ => rpc_hex_bigint_dec(&rpc, "eth_gasPrice", json!([]))?,
        };
        (gp, "0".to_string(), "legacy")
    };

    let value_hex = format!("0x{:x}", value);
    let data_hex = format!("0x{}", data.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let gas = match tx.get("gas").and_then(Value::as_u64) {
        Some(g) if g > 0 => g,
        _ => {
            let call = json!([{ "from": account.address, "to": to, "value": value_hex, "data": data_hex }]);
            rpc_hex_u64(&rpc, "eth_estimateGas", call)?
        }
    };

    // Unlock creds from the Keys descriptors (Password/StoreKey).
    let keys: Vec<KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let unlock: Vec<(String, String)> = keys
        .iter()
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain"))
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();
    if unlock.is_empty() {
        return Err(ApiError::new(400, "Keys are required to sign"));
    }

    let req = crate::evm::EvmTxRequest {
        nonce,
        gas,
        max_fee: max_fee.clone(),
        max_priority: max_priority.clone(),
        to: to.clone(),
        value: value.to_string(),
        data: data.clone(),
        chain_id,
        eip1559,
    };
    let raw = crate::evm::sign_tx(env, &account.id, &unlock, &req).map_err(|e| ApiError::new(400, e.to_string()))?;
    let raw_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let hash = crate::rpc::eth_send_raw_transaction(&rpc, &format!("0x{raw_hex}")).map_err(ApiError::internal)?;

    // Persist the broadcast transaction and return it.
    let fee_wei = &value_fee(gas, &max_fee);
    let mut record = crate::models::transaction::Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: typ.to_string(),
        asset: tx.get("asset").and_then(Value::as_str).unwrap_or("").to_string(),
        from: account.address.clone(),
        to,
        gas,
        gas_price: if eip1559 { String::new() } else { max_fee.clone() },
        max_fee_per_gas: if eip1559 { max_fee.clone() } else { String::new() },
        max_priority_fee_per_gas: if eip1559 { max_priority } else { String::new() },
        fee: fee_wei.clone(),
        nonce,
        format: format.to_string(),
        raw: base64::engine::general_purpose::STANDARD.encode(&raw),
        hash: hash.clone(),
        url: tx_url(&net, &hash),
        network: net.id.clone(),
        amount: amount_significand(tx.get("amount")).map(|v| crate::Amount::new_raw(v, 0)),
        value: Some(crate::Amount::new_raw(value, 0)),
        data: data_hex,
        created: crate::now_rfc3339(),
        fiat_amount: None,
        fiat_currency: String::new(),
        fiat_quote: None,
    };
    crate::models::transaction::persist(env, &record).map_err(ApiError::internal)?;
    record.raw = format!("0x{raw_hex}"); // return 0x-hex raw to the host
    Ok(serde_json::to_value(&record).unwrap())
}

/// The block-explorer URL for a tx hash (Go `Network.TransactionUrl`): append
/// `/tx/<hash>` to the resolved explorer, empty when there is none.
fn tx_url(net: &crate::models::network::Network, hash: &str) -> String {
    let base = net.resolved_block_explorer();
    if base.is_empty() {
        return String::new();
    }
    format!("{}/tx/{hash}", base.trim_end_matches('/'))
}

/// The gas fee (gas × price) as a wei Amount, best-effort.
fn value_fee(gas: u64, price_dec: &str) -> Option<crate::Amount> {
    let price = BigInt::parse_bytes(price_dec.as_bytes(), 10)?;
    Some(crate::Amount::new_raw(BigInt::from(gas) * price, 0))
}

/// The significand of an `Amount`-shaped JSON value ({v,e,f} or decimal string).
fn amount_significand(v: Option<&Value>) -> Option<BigInt> {
    let v = v?;
    if let Some(obj) = v.as_object() {
        return obj.get("v").and_then(|s| s.as_str()).and_then(|s| BigInt::parse_bytes(s.as_bytes(), 10));
    }
    if let Some(s) = v.as_str() {
        return BigInt::parse_bytes(s.as_bytes(), 10);
    }
    None
}

/// Call an RPC returning a 0x-hex quantity and parse it as u64.
fn rpc_hex_u64(rpc: &str, method: &str, params: Value) -> Result<u64, ApiError> {
    let out = crate::rpc::call(rpc, method, params).map_err(ApiError::internal)?;
    let hex = out.as_str().ok_or_else(|| ApiError::new(502, format!("{method}: not a string")))?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16).map_err(|_| ApiError::new(502, format!("{method}: bad hex {hex}")))
}

/// Call an RPC returning a 0x-hex quantity and parse it as a decimal string.
fn rpc_hex_bigint_dec(rpc: &str, method: &str, params: Value) -> Result<String, ApiError> {
    let out = crate::rpc::call(rpc, method, params).map_err(ApiError::internal)?;
    let hex = out.as_str().ok_or_else(|| ApiError::new(502, format!("{method}: not a string")))?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let n = BigInt::parse_bytes(hex.as_bytes(), 16).ok_or_else(|| ApiError::new(502, format!("{method}: bad hex {hex}")))?;
    Ok(n.to_string())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ApiError> {
    if s.len() % 2 != 0 {
        return Err(ApiError::new(400, "odd-length hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ApiError::new(400, "bad hex")))
        .collect()
}
