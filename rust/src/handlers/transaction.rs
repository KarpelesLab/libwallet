//! Transaction object endpoints — read surface (fetch/list) plus the EVM
//! `Transaction:signAndSend` path (build → RPC-backfill nonce/gas/fee → DKLs
//! sign → broadcast → persist), plus the Solana, Bitcoin and Tron paths, which
//! reuse the same chain modules `Account:signAndSendTransaction` does.

use base64::Engine as _;
use num_bigint::BigInt;
use serde_json::{json, Value};

use crate::sign::KeyDescription;
use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    // Optional best-effort fiat conversion when Currency is supplied.
    let currency = super::fiat_currency(params);
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
        // POST on the bare Transaction collection is the pobj `Create` action.
        // The Go registration (wlttx/api.go) wires only Fetch/List/Clear — no
        // Create — so apirouter returns 405 Method Not Allowed here. Building a
        // transaction goes through the `Transaction:signAndSend` static method
        // (and `Transaction:validate`), not a POST create. Matching Go exactly.
        "POST" => Err(ApiError::new(405, "Transaction has no create action; use Transaction:signAndSend")),
        // DELETE with an Id deletes one row and returns it (Go loads the object
        // via Fetch, then calls ApiDelete, and responds with the object). DELETE
        // without an Id is the collection Clear (Go apiClearTransaction), honouring
        // the optional From/Network filters; it responds with null.
        "DELETE" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => {
                let t = crate::models::transaction::fetch(env, id)
                    .map_err(ApiError::internal)?
                    .ok_or_else(|| ApiError::new(404, "transaction not found"))?;
                crate::models::transaction::delete_one(env, id).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(t).unwrap())
            }
            None => {
                let from = params.get("From").and_then(Value::as_str).filter(|s| !s.is_empty());
                let network = params.get("Network").and_then(Value::as_str).filter(|s| !s.is_empty());
                crate::models::transaction::clear(env, from, network).map_err(ApiError::internal)?;
                Ok(Value::Null)
            }
        },
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Transaction"))),
    }
}

/// `Transaction:validate` — the structural validation of a Transaction (Go
/// `Transaction.Validate`, the type/required-field checks). A positive amount is
/// required for value transfers; erc20/bitcoin also need a recipient; erc20 also
/// an asset. Nonce/gas population needs a live node and is left to signAndSend.
///
/// A Solana transfer (by type, `network`, or the `from` account's chain) is
/// also *built*: the unsigned SOL / SPL transfer the shared builder produces
/// comes back Transaction-shaped — resolved `amount`, `fee`, the recent
/// blockhash, and `raw` (base64 wire tx with an empty signature slot).
pub fn validate(env: &Env, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").unwrap_or(params);
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("");
    let np = super::simulate::with_tx_network(env, params, tx);
    let solana = matches!(typ, "transfer" | "solana_transfer" | "solana_spl_transfer")
        && super::simulate::tx_chain(env, &np, tx)? == "solana";
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
            // Solana defaults an empty asset to native SOL.
            if s("asset").is_empty() && !solana {
                return Err(ApiError::new(400, "asset is required"));
            }
        }
        "solana_transfer" | "solana_spl_transfer" | "tron_transfer" => {
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
        "trc20_transfer" => {
            if !amount_positive() {
                return Err(ApiError::new(400, "invalid amount"));
            }
            if s("asset").is_empty() {
                return Err(ApiError::new(400, "asset is required for trc20_transfer"));
            }
            if s("to").is_empty() {
                return Err(ApiError::new(400, "recipient (To) is required for trc20_transfer"));
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
    if solana {
        return validate_solana(env, &np, tx, typ);
    }
    Ok(serde_json::json!({ "valid": true, "type": typ }))
}

/// Build the unsigned Solana transfer for `Transaction:validate`.
fn validate_solana(env: &Env, params: &Value, tx: &Value, typ: &str) -> ApiResult {
    let account = super::simulate::tx_account(env, tx)?;
    let net = super::network_for_kind(env, params, "solana")?;
    let rpc = super::resolve_rpc_for_kind(env, params, "solana")?;
    let built = crate::rt::block_on(super::solana_build::build_unsigned(env, &account, &net, &rpc, tx))?;
    let network = if net.id.is_empty() { format!("{}.{}", net.kind, net.chain_id) } else { net.id.clone() };
    Ok(json!({
        "valid": true,
        "type": typ,
        "asset": tx.get("asset").and_then(Value::as_str).unwrap_or(""),
        "from": account.address,
        "to": built.to,
        "network": network,
        "amount": crate::Amount::new_raw(BigInt::from(built.amount), built.decimals),
        "fee": crate::Amount::new_raw(BigInt::from(built.fee_lamports), 9),
        "recentBlockhash": built.blockhash,
        "raw": base64::engine::general_purpose::STANDARD.encode(built.unsigned_tx()),
    }))
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

    // Resolve the network (tx.network, else the current one when it is on the
    // account's chain, else that chain's default) and its RPC.
    let net = match tx.get("network").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(n) => crate::models::network::fetch(env, &super::network_ref(env, n))
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(400, "network not found"))?,
        None => {
            let kind = if account.kind == "ethereum" { "evm" } else { account.kind.as_str() };
            super::network_for_kind(env, &json!({}), kind)?
        }
    };
    let rpc = match params.get("RPC").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => net.resolved_rpc().map_err(|e| ApiError::new(400, e.to_string()))?,
    };

    // Chain dispatch (Go `SignAndSend` branches on n.Type). EVM falls through to
    // the inline path below; Solana/Bitcoin build+sign+broadcast in their own
    // helpers by reusing the same crate modules Account:signAndSendTransaction uses.
    match net.kind.as_str() {
        "evm" => {}
        "solana" => return sign_and_send_solana(env, tx, params, &account, &net, &rpc),
        "bitcoin" => return sign_and_send_bitcoin(env, tx, params, &account, &net, &rpc),
        "tron" => return sign_and_send_tron(env, tx, params, &account, &net, &rpc),
        other => {
            return Err(ApiError::new(
                501,
                format!("Transaction:signAndSend for {other} is not ported — use Account:signAndSendTransaction"),
            ))
        }
    }
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
        url: net.transaction_url(&hash),
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

/// Solana `Transaction:signAndSend` (Go `signAndSendSolana`): build the unsigned
/// transfer with the shared builder (`solana_build` — the same one validate and
/// simulate use: SystemProgram transfer for SOL, ATA-provisioning
/// TransferChecked for an SPL `asset`, MAX resolved on native), FROST-sign it
/// with the account's shares, broadcast via `sendTransaction`, persist, and
/// return the Transaction row.
///
/// SPL scope: Token-1 and non-fee Token-2022; a Token-2022 mint with an active
/// transfer-fee extension is rejected with 501 by the builder.
fn sign_and_send_solana(
    env: &Env,
    tx: &Value,
    params: &Value,
    account: &crate::models::account::Account,
    net: &crate::models::network::Network,
    rpc: &str,
) -> ApiResult {
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("transfer");
    let asset = tx.get("asset").and_then(Value::as_str).unwrap_or("");
    let built = crate::rt::block_on(super::solana_build::build_unsigned(env, account, net, rpc, tx))?;

    let unlock = unlock_from_params(params)?;
    let sig = crate::models::wallet::sign_ed25519_for_account(env, account, &unlock, &built.message)
        .map_err(ApiError::internal)?;
    let raw = crate::solana::assemble_tx(&built.message, &sig);
    let tx_b58 = bs58::encode(&raw).into_string();
    let hash = crate::rpc::call(rpc, "sendTransaction", json!([tx_b58, { "encoding": "base58" }]))
        .map_err(ApiError::internal)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ApiError::new(502, "sendTransaction did not return a signature"))?;

    let record = crate::models::transaction::Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: typ.to_string(),
        asset: asset.to_string(),
        from: account.address.clone(),
        to: built.to.clone(),
        gas: 0,
        gas_price: String::new(),
        max_fee_per_gas: String::new(),
        max_priority_fee_per_gas: String::new(),
        fee: Some(crate::Amount::new_raw(BigInt::from(built.fee_lamports), 9)),
        nonce: 0,
        format: String::new(),
        raw: base64::engine::general_purpose::STANDARD.encode(&raw),
        hash: hash.clone(),
        url: net.transaction_url(&hash),
        network: net.id.clone(),
        // SPL amounts persist in the token's own base units/decimals; on MAX the
        // resolved concrete lamports (Go rewrites tx.Amount in place) rather
        // than the {"v":"MAX"} sentinel; otherwise the caller's amount verbatim.
        amount: if built.token.is_some() || built.amount_was_max {
            Some(crate::Amount::new_raw(BigInt::from(built.amount), built.decimals))
        } else {
            tx_amount_field(tx.get("amount"))
        },
        value: None,
        data: String::new(),
        created: crate::now_rfc3339(),
        fiat_amount: None,
        fiat_currency: String::new(),
        fiat_quote: None,
    };
    crate::models::transaction::persist(env, &record).map_err(ApiError::internal)?;
    Ok(serde_json::to_value(&record).unwrap())
}

/// Resolve `asset` against the local Token table for a Tron send (port of Go
/// `resolveTokenAsset`). Returns `None` for a native asset (empty / NATIVE /
/// "*.NATIVE"); the token row for a `tok-…` XUID or a canonical
/// "<type>.<chainId>.<contract>" key; and a 400 error when the asset is
/// non-native but not resolvable (a caller mistake we surface at send time).
fn resolve_token_asset(
    env: &Env,
    net: &crate::models::network::Network,
    asset: &str,
) -> Result<Option<crate::models::token::Token>, ApiError> {
    if super::solana_build::is_native_asset(asset) {
        return Ok(None);
    }
    // XUID shape ("tok-…") — look up by id.
    if xuid::Xuid::parse_prefix(asset, "tok").is_ok() {
        return crate::models::token::fetch(env, asset)
            .map_err(ApiError::internal)?
            .map(Some)
            .ok_or_else(|| ApiError::new(400, format!("token {asset} not found")));
    }
    // Canonical "<type>.<chainId>.<addr>" — the part after the second dot is the
    // on-chain contract address.
    let parts: Vec<&str> = asset.splitn(3, '.').collect();
    if parts.len() != 3 || parts[2].is_empty() {
        return Err(ApiError::new(
            400,
            format!("asset {asset:?} is not a recognised key (expected a tok-… XUID or \"<type>.<chainId>.<addr>\")"),
        ));
    }
    crate::models::token::lookup_by_mint(env, &net.id, parts[2])
        .map_err(ApiError::internal)?
        .map(Some)
        .ok_or_else(|| ApiError::new(400, format!("token {} not registered on network {}", parts[2], net.id)))
}

/// Bitcoin `Transaction:signAndSend` (Go `buildBitcoinTx` + `broadcastBitcoinTx`,
/// native transfer): auto-discover + select UTXOs for the account xpub, build and
/// DKLs-sign each input, broadcast via `sendrawtransaction`, persist, and return
/// the Transaction row. Reuses `crate::bitcoin::build_and_sign_auto` (the same
/// builder `Account:signAndSendTransaction` uses). Fee rate comes from
/// `bitcoinFeeRate` when pinned, else `estimatesmartfee` against a target derived
/// from `priorityLevel`.
fn sign_and_send_bitcoin(
    env: &Env,
    tx: &Value,
    params: &Value,
    account: &crate::models::account::Account,
    net: &crate::models::network::Network,
    rpc: &str,
) -> ApiResult {
    let to = tx
        .get("to")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "recipient (to) is required for bitcoin_transfer"))?;
    let sats_bi = amount_significand(tx.get("amount"))
        .ok_or_else(|| ApiError::new(400, "amount is required"))?;
    let sats = bigint_to_u64(&sats_bi)
        .ok_or_else(|| ApiError::new(400, "amount exceeds representable u64 satoshis"))?;
    let fee_rate = bitcoin_fee_rate(rpc, tx);

    let unlock = unlock_from_params(params)?;
    let raw = crate::bitcoin::build_and_sign_auto(
        env, &account.id, &unlock, rpc, &net.chain_id, to, sats, fee_rate,
    )
    .map_err(|e| ApiError::new(400, e.to_string()))?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let hash = crate::rpc::call(rpc, "sendrawtransaction", json!([hex]))
        .map_err(ApiError::internal)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ApiError::new(502, "sendrawtransaction did not return a txid"))?;

    let record = crate::models::transaction::Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: tx.get("type").and_then(Value::as_str).unwrap_or("bitcoin_transfer").to_string(),
        asset: tx.get("asset").and_then(Value::as_str).unwrap_or("").to_string(),
        from: account.address.clone(),
        to: to.to_string(),
        gas: 0,
        gas_price: String::new(),
        max_fee_per_gas: String::new(),
        max_priority_fee_per_gas: String::new(),
        // buildBitcoinTx computes the exact fee from coin selection; the auto
        // builder doesn't surface it, so leave it unset rather than guess.
        fee: None,
        nonce: 0,
        format: String::new(),
        raw: base64::engine::general_purpose::STANDARD.encode(&raw),
        hash: hash.clone(),
        url: net.transaction_url(&hash),
        network: net.id.clone(),
        amount: tx_amount_field(tx.get("amount")),
        value: None,
        data: String::new(),
        created: crate::now_rfc3339(),
        fiat_amount: None,
        fiat_currency: String::new(),
        fiat_quote: None,
    };
    crate::models::transaction::persist(env, &record).map_err(ApiError::internal)?;
    Ok(serde_json::to_value(&record).unwrap())
}

/// Tron `Transaction:signAndSend`: a TRX transfer, or a TRC-20 transfer when
/// the asset resolves to a registered token (the same resolution as Solana's
/// SPL routing). The amount is in base units (sun / token units); MAX resolves
/// for TRX to the balance less the bandwidth and new-account fees. `feeLimit`
/// (sun) caps a TRC-20 transfer's energy burn. Built and signed locally,
/// anchored on the node's current block, broadcast via `broadcasthex`.
fn sign_and_send_tron(
    env: &Env,
    tx: &Value,
    params: &Value,
    account: &crate::models::account::Account,
    net: &crate::models::network::Network,
    rpc: &str,
) -> ApiResult {
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("transfer");
    let asset = tx.get("asset").and_then(Value::as_str).unwrap_or("");
    let to = tx
        .get("to")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "to is required"))?;
    let amount_is_max = tx
        .get("amount")
        .and_then(|v| serde_json::from_value::<crate::Amount>(v.clone()).ok())
        .map(|a| a.is_max())
        .unwrap_or(false);

    let token = resolve_token_asset(env, net, asset)?;
    let (transfer, amount) = match &token {
        Some(token) => {
            if token.kind != "trc20" {
                return Err(ApiError::new(400, format!("token type {} cannot be sent on tron", token.kind)));
            }
            if amount_is_max {
                return Err(ApiError::new(400, "MAX amount is not supported for TRC-20 sends"));
            }
            let units = amount_significand(tx.get("amount")).ok_or_else(|| ApiError::new(400, "amount is required"))?;
            let amount: u128 = units.to_string().parse().map_err(|_| ApiError::new(400, "amount out of range"))?;
            let fee_limit = tx.get("feeLimit").and_then(Value::as_u64).unwrap_or(crate::tron::DEFAULT_TRC20_FEE_LIMIT);
            let transfer = crate::tron::Transfer::Trc20 { contract: token.address.clone(), to: to.to_owned(), amount, fee_limit };
            (transfer, crate::Amount::new_raw(units, token.decimals))
        }
        None => {
            let sun = if amount_is_max {
                let (_, _, max) = crate::tron::max_sendable(rpc, &account.address, to)
                    .map_err(|e| ApiError::new(400, format!("cannot resolve MAX amount: {e}")))?;
                if max == 0 {
                    return Err(ApiError::new(400, "balance does not cover the transfer fees"));
                }
                max
            } else {
                let units = amount_significand(tx.get("amount")).ok_or_else(|| ApiError::new(400, "amount is required"))?;
                bigint_to_u64(&units).ok_or_else(|| ApiError::new(400, "amount exceeds representable u64 sun"))?
            };
            let transfer = crate::tron::Transfer::Trx { to: to.to_owned(), amount: sun };
            (transfer, crate::Amount::new_raw(BigInt::from(sun), crate::tron::TRX_DECIMALS))
        }
    };

    let unlock = unlock_from_params(params)?;
    let (hash, raw) = crate::tron::send(env, account, &unlock, rpc, &transfer).map_err(|e| ApiError::new(400, e.to_string()))?;

    let record = crate::models::transaction::Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: typ.to_string(),
        asset: asset.to_string(),
        from: account.address.clone(),
        to: to.to_string(),
        gas: 0,
        gas_price: String::new(),
        max_fee_per_gas: String::new(),
        max_priority_fee_per_gas: String::new(),
        // Bandwidth/energy are settled by the network after the fact; the
        // receipt (gettransactioninfobyid) carries the real fee.
        fee: None,
        nonce: 0,
        format: String::new(),
        raw: base64::engine::general_purpose::STANDARD.encode(&raw),
        hash: hash.clone(),
        url: net.transaction_url(&hash),
        network: net.id.clone(),
        amount: Some(amount),
        value: None,
        data: String::new(),
        created: crate::now_rfc3339(),
        fiat_amount: None,
        fiat_currency: String::new(),
        fiat_quote: None,
    };
    crate::models::transaction::persist(env, &record).map_err(ApiError::internal)?;
    Ok(serde_json::to_value(&record).unwrap())
}

/// The unlock credentials (id, key) from the request `Keys` descriptors, keeping
/// the Password/StoreKey/Plain kinds the signers understand. Errors when none
/// are usable — every sign path needs at least one.
fn unlock_from_params(params: &Value) -> Result<Vec<(String, String)>, ApiError> {
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
    Ok(unlock)
}

/// The persisted `amount` field: the caller's Amount object verbatim when it
/// deserializes ({v,e,f}), else the significand at 0 decimals (matching the EVM
/// path's fallback for a bare decimal string).
fn tx_amount_field(v: Option<&Value>) -> Option<crate::Amount> {
    let v = v?;
    if let Ok(a) = serde_json::from_value::<crate::Amount>(v.clone()) {
        return Some(a);
    }
    amount_significand(Some(v)).map(|b| crate::Amount::new_raw(b, 0))
}

/// The bitcoin fee rate in sat/vB: the pinned `bitcoinFeeRate` when > 0, else an
/// `estimatesmartfee` lookup against a `priorityLevel`-derived confirmation
/// target, falling back to 10 sat/vB when the node can't estimate.
fn bitcoin_fee_rate(rpc: &str, tx: &Value) -> u64 {
    if let Some(r) = tx.get("bitcoinFeeRate").and_then(Value::as_u64) {
        if r > 0 {
            return r;
        }
    }
    let target = match tx.get("priorityLevel").and_then(Value::as_str).unwrap_or("") {
        "high" => 1,
        "medium" => 3,
        _ => 6,
    };
    if let Ok(v) = crate::rpc::call(rpc, "estimatesmartfee", json!([target])) {
        // estimatesmartfee returns feerate in BTC/kvB; sat/vB = feerate * 1e8 / 1000.
        if let Some(fr) = v.get("feerate").and_then(Value::as_f64) {
            let sat_vb = (fr * 100_000.0).ceil() as u64;
            if sat_vb > 0 {
                return sat_vb;
            }
        }
    }
    10
}

/// Parse a `BigInt` into `u64`, `None` when negative or out of range.
fn bigint_to_u64(b: &BigInt) -> Option<u64> {
    b.to_string().parse::<u64>().ok()
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
