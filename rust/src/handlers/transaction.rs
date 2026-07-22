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

/// Solana `Transaction:signAndSend` (Go `signAndSendSolana`, native path):
/// fetch a recent blockhash, build the SystemProgram transfer message, FROST-sign
/// it with the account's shares, assemble + base58-encode, broadcast via
/// `sendTransaction`, persist, and return the Transaction row. When the tx's
/// asset resolves to a registered SPL token, routes to `sign_and_send_solana_spl`
/// (ATA-provisioning TransferChecked build); otherwise builds the native
/// SystemProgram transfer below.
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

    // Resolve tx.asset against the Token table (Go `resolveTokenAsset`). A
    // non-native asset routes to the SPL build; a native asset (empty / NATIVE /
    // "*.NATIVE") falls through to the SystemProgram transfer.
    if let Some(token) = resolve_token_asset(env, net, asset)? {
        return sign_and_send_solana_spl(env, tx, params, account, net, rpc, typ, &token);
    }

    let to_b58 = tx
        .get("to")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "to is required"))?;

    // Resolve the MAX amount sentinel (`Amount.max(9)`) to a concrete lamport
    // value before building the transfer — balance − fee − rent reserve, the
    // same math as Transaction:maxSendable (Go `preflightSolanaNativeSend`).
    // Without this, MAX reaches the signer with no value and the send fails.
    let amount_is_max = tx
        .get("amount")
        .and_then(|v| serde_json::from_value::<crate::Amount>(v.clone()).ok())
        .map(|a| a.is_max())
        .unwrap_or(false);
    let lamports = if amount_is_max {
        let fee_lamports = solana_fee_lamports(tx);
        crate::transfer::resolve_solana_max_lamports(rpc, &account.address, to_b58, fee_lamports)
            .map_err(|e| ApiError::new(400, e.to_string()))?
    } else {
        let lamports_bi = amount_significand(tx.get("amount"))
            .ok_or_else(|| ApiError::new(400, "amount is required"))?;
        bigint_to_u64(&lamports_bi)
            .ok_or_else(|| ApiError::new(400, "amount exceeds representable u64 lamports"))?
    };

    // Recent blockhash (finalized, matching Go's commitment).
    let bh = crate::rpc::call(rpc, "getLatestBlockhash", json!([{ "commitment": "finalized" }]))
        .map_err(ApiError::internal)?;
    let bh_b58 = bh
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(502, "no blockhash in getLatestBlockhash response"))?;
    let blockhash = b58_32(bh_b58)?;
    let from = crate::solana::pubkey_from_b64url(&account.pubkey)
        .ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    let to = b58_32(to_b58)?;

    let msg = crate::solana::build_transfer_message(&from, &to, lamports, &blockhash);
    let unlock = unlock_from_params(params)?;
    let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &msg)
        .map_err(ApiError::internal)?;
    let raw = crate::solana::assemble_tx(&msg, &sig);
    let tx_b58 = bs58::encode(&raw).into_string();
    let hash = crate::rpc::call(rpc, "sendTransaction", json!([tx_b58, { "encoding": "base58" }]))
        .map_err(ApiError::internal)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ApiError::new(502, "sendTransaction did not return a signature"))?;

    // Solana fee is the 5000-lamport base signature fee (no priority) at 9 decimals.
    let record = crate::models::transaction::Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: typ.to_string(),
        asset: asset.to_string(),
        from: account.address.clone(),
        to: to_b58.to_string(),
        gas: 0,
        gas_price: String::new(),
        max_fee_per_gas: String::new(),
        max_priority_fee_per_gas: String::new(),
        fee: Some(crate::Amount::new_raw(BigInt::from(5000), 9)),
        nonce: 0,
        format: String::new(),
        raw: base64::engine::general_purpose::STANDARD.encode(&raw),
        hash: hash.clone(),
        url: tx_url(net, &hash),
        network: net.id.clone(),
        // On MAX, persist the resolved concrete lamports (Go rewrites tx.Amount
        // in place) rather than round-tripping the {"v":"MAX"} sentinel.
        amount: if amount_is_max {
            Some(crate::Amount::new_raw(BigInt::from(lamports), 9))
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

/// Resolve `asset` against the local Token table for a Solana send (port of Go
/// `resolveTokenAsset`). Returns `None` for a native asset (empty / NATIVE /
/// "*.NATIVE"); the token row for a `tok-…` XUID or a canonical
/// "<type>.<chainId>.<mint>" key; and a 400 error when the asset is non-native
/// but not resolvable (a caller mistake we surface at send time).
fn resolve_token_asset(
    env: &Env,
    net: &crate::models::network::Network,
    asset: &str,
) -> Result<Option<crate::models::token::Token>, ApiError> {
    if is_native_asset(asset) {
        return Ok(None);
    }
    // XUID shape ("tok-…") — look up by id.
    if xuid::Xuid::parse_prefix(asset, "tok").is_ok() {
        return crate::models::token::fetch(env, asset)
            .map_err(ApiError::internal)?
            .map(Some)
            .ok_or_else(|| ApiError::new(400, format!("token {asset} not found")));
    }
    // Canonical "<type>.<chainId>.<mint>" — the part after the second dot is the
    // on-chain mint address.
    let parts: Vec<&str> = asset.splitn(3, '.').collect();
    if parts.len() != 3 || parts[2].is_empty() {
        return Err(ApiError::new(
            400,
            format!("asset {asset:?} is not a recognised key (expected a tok-… XUID or \"<type>.<chainId>.<mint>\")"),
        ));
    }
    crate::models::token::lookup_by_mint(env, &net.id, parts[2])
        .map_err(ApiError::internal)?
        .map(Some)
        .ok_or_else(|| ApiError::new(400, format!("token {} not registered on network {}", parts[2], net.id)))
}

/// Fetch a Solana account's raw data via `getAccountInfo` (base64), returning
/// the decoded bytes (Go `solanaFetchMintAccount`). Used to introspect a
/// Token-2022 mint's extensions before an SPL send.
fn fetch_mint_account(rpc: &str, mint_b58: &str) -> Result<Vec<u8>, ApiError> {
    let resp = crate::rpc::call(
        rpc,
        "getAccountInfo",
        json!([mint_b58, { "encoding": "base64" }]),
    )
    .map_err(ApiError::internal)?;
    let data_b64 = resp
        .get("value")
        .and_then(|v| v.get("data"))
        .and_then(|d| d.get(0))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(502, format!("mint {mint_b58} not found or missing data")))?;
    base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| ApiError::new(502, format!("bad base64 mint data: {e}")))
}

/// Solana SPL-token `Transaction:signAndSend` (Go `signAndSendSolana`, SPL path):
/// derive the sender/recipient ATAs for the mint, build a `TransferChecked`
/// message (prefixed with an idempotent ATA-create so a fresh recipient is
/// provisioned in-tx), FROST-sign, broadcast, persist, and return the row.
///
/// Scope: Token-1 (`spl-token`) and non-fee Token-2022 (`spl-token-2022`).
/// A Token-2022 mint with an active transfer-fee extension is rejected with 501
/// rather than broadcasting a plain TransferChecked the program would revert.
/// Compute-unit sizing is a fixed conservative limit (no simulation).
#[allow(clippy::too_many_arguments)]
fn sign_and_send_solana_spl(
    env: &Env,
    tx: &Value,
    params: &Value,
    account: &crate::models::account::Account,
    net: &crate::models::network::Network,
    rpc: &str,
    typ: &str,
    token: &crate::models::token::Token,
) -> ApiResult {
    use base64::Engine;

    let to_b58 = tx
        .get("to")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "to is required"))?;

    // Amount is the token's base units (e.g. 1_315_764 for 1.315764 USDT @ 6
    // decimals). MAX is native-only — reject it here rather than silently
    // sending zero.
    let amount_is_max = tx
        .get("amount")
        .and_then(|v| serde_json::from_value::<crate::Amount>(v.clone()).ok())
        .map(|a| a.is_max())
        .unwrap_or(false);
    if amount_is_max {
        return Err(ApiError::new(400, "MAX amount is not supported for SPL token sends"));
    }
    let amount_bi = amount_significand(tx.get("amount"))
        .ok_or_else(|| ApiError::new(400, "amount is required"))?;
    let amount = bigint_to_u64(&amount_bi)
        .ok_or_else(|| ApiError::new(400, "amount exceeds representable u64 base units"))?;

    let token_program = crate::solana_spl::token_program_for_type(&token.kind)
        .map_err(|e| ApiError::new(400, e))?;
    let mint = b58_32(&token.address)?;
    if token.decimals < 0 || token.decimals > u8::MAX as i64 {
        return Err(ApiError::new(400, "token decimals out of range"));
    }
    let decimals = token.decimals as u8;

    // Token-2022: introspect the mint. An active transfer-fee extension needs
    // the fee-carrying instruction the Go build emits — out of scope here, so
    // fail closed rather than broadcasting a plain TransferChecked that reverts.
    if token.kind == "spl-token-2022" {
        let data = fetch_mint_account(rpc, &token.address)?;
        if let Some(cfg) = crate::solana_spl::token2022_transfer_fee(&data)
            .map_err(|e| ApiError::new(502, e))?
        {
            if cfg.is_active() {
                return Err(ApiError::new(
                    501,
                    "Token-2022 mints with an active transfer-fee extension are not supported yet",
                ));
            }
        }
    }

    let from = crate::solana::pubkey_from_b64url(&account.pubkey)
        .ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    let to = b58_32(to_b58)?;
    let sender_ata = crate::solana_spl::derive_ata(&from, &mint, &token_program)
        .ok_or_else(|| ApiError::new(500, "failed to derive sender ATA"))?;
    let recipient_ata = crate::solana_spl::derive_ata(&to, &mint, &token_program)
        .ok_or_else(|| ApiError::new(500, "failed to derive recipient ATA"))?;

    // Compute-unit budget: a caller may pin computeUnitLimit / computeUnitPrice;
    // otherwise use the fixed SPL default limit (covers the ATA-create prelude)
    // and no priority price.
    let cu_limit = tx
        .get("computeUnitLimit")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .filter(|v| *v > 0)
        .unwrap_or(crate::solana_spl::SPL_DEFAULT_CU_LIMIT);
    let cu_price = tx.get("computeUnitPrice").and_then(Value::as_u64).unwrap_or(0);

    // Recent blockhash (finalized, matching Go's commitment).
    let bh = crate::rpc::call(rpc, "getLatestBlockhash", json!([{ "commitment": "finalized" }]))
        .map_err(ApiError::internal)?;
    let bh_b58 = bh
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(502, "no blockhash in getLatestBlockhash response"))?;
    let blockhash = b58_32(bh_b58)?;

    let msg = crate::solana_spl::build_spl_transfer_message(
        &from,
        &to,
        &mint,
        &sender_ata,
        &recipient_ata,
        &token_program,
        amount,
        decimals,
        &blockhash,
        cu_limit,
        cu_price,
    );
    let unlock = unlock_from_params(params)?;
    let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &msg)
        .map_err(ApiError::internal)?;
    let raw = crate::solana::assemble_tx(&msg, &sig);
    let tx_b58 = bs58::encode(&raw).into_string();
    let hash = crate::rpc::call(rpc, "sendTransaction", json!([tx_b58, { "encoding": "base58" }]))
        .map_err(ApiError::internal)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ApiError::new(502, "sendTransaction did not return a signature"))?;

    let fee_lamports = crate::solana_spl::fee_lamports(cu_limit, cu_price);
    let record = crate::models::transaction::Transaction {
        id: xuid::Xuid::new("tx").to_string(),
        kind: typ.to_string(),
        asset: tx.get("asset").and_then(Value::as_str).unwrap_or("").to_string(),
        from: account.address.clone(),
        to: to_b58.to_string(),
        gas: 0,
        gas_price: String::new(),
        max_fee_per_gas: String::new(),
        max_priority_fee_per_gas: String::new(),
        fee: Some(crate::Amount::new_raw(BigInt::from(fee_lamports), 9)),
        nonce: 0,
        format: String::new(),
        raw: base64::engine::general_purpose::STANDARD.encode(&raw),
        hash: hash.clone(),
        url: tx_url(net, &hash),
        network: net.id.clone(),
        // Persist the transferred amount in the token's own base units/decimals.
        amount: Some(crate::Amount::new_raw(amount_bi, token.decimals)),
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

/// The fee (in lamports) to reserve when resolving a MAX native-SOL send: the
/// caller's `fee` Amount (9-decimal lamports) when present, else the flat
/// base signature fee. Mirrors Go's use of the priority-inclusive `tx.Fee`
/// with a 5000 fallback.
fn solana_fee_lamports(tx: &Value) -> u64 {
    tx.get("fee")
        .and_then(|v| serde_json::from_value::<crate::Amount>(v.clone()).ok())
        .and_then(|a| a.value().and_then(bigint_to_u64))
        .unwrap_or(crate::transfer::SOLANA_BASE_FEE_LAMPORTS)
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
        url: tx_url(net, &hash),
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

/// Whether an asset id names the chain's native coin (empty / "NATIVE" /
/// "<type>.<chainId>.NATIVE"), mirroring Go `isNativeAsset`.
fn is_native_asset(asset: &str) -> bool {
    asset.is_empty() || asset == "NATIVE" || asset.ends_with(".NATIVE")
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

/// Decode a base58 string into a 32-byte array (Solana pubkey / blockhash).
fn b58_32(s: &str) -> Result<[u8; 32], ApiError> {
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| ApiError::new(400, format!("bad base58 32-byte value: {s}")))
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
