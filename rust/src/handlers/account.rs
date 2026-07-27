//! Account object endpoints — fetch/list and create (ed25519/Solana path).

use base64::Engine;
use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

/// `Account:signMessage` — sign raw bytes with the account's wallet. For a
/// Solana (ed25519) account this is a raw EdDSA signature over the message,
/// returned base58-encoded (matching Go accountSignMessage). `Keys` carries the
/// unlock material (Password shares here).
pub fn sign_message(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let message_b64 = params
        .get("Message")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Message required"))?;
    let msg = base64::engine::general_purpose::STANDARD
        .decode(message_b64)
        .map_err(|e| ApiError::new(400, format!("bad Message base64: {e}")))?;

    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let unlock: Vec<(String, String)> = keys
        .iter()
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain"))
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();

    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;

    match account.kind.as_str() {
        // EIP-191 personal_sign — 65-byte R‖S‖V, hex-encoded.
        "ethereum" => {
            let sig = crate::evm::personal_sign(env, account_id, &unlock, &msg)
                .map_err(ApiError::internal)?;
            let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
            Ok(serde_json::json!({ "signature": format!("0x{hex}") }))
        }
        // Solana / ed25519 — FROST signature, base58 in its canonical encoding.
        _ => {
            // Blind-signing guard: refuse a "message" that is actually a Solana
            // transaction naming this account as a signer (matches Go).
            if let Some(pk) = crate::solana::pubkey_from_b64url(&account.pubkey) {
                if crate::solana::payload_is_signable_tx(&msg, &pk) {
                    return Err(ApiError::new(
                        400,
                        "refusing to sign: message parses as a Solana transaction for this account — use signTransaction",
                    ));
                }
            }
            let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &msg)
                .map_err(ApiError::internal)?;
            Ok(serde_json::json!({ "signature": bs58::encode(&sig).into_string() }))
        }
    }
}

/// `Account:signTransaction` — build and threshold-sign an EVM transaction for
/// the account, returning the signed raw tx as `0x`-hex. Broadcast
/// (signAndSend) layers eth_sendRawTransaction on top once RPC is wired.
/// Extract the local unlock secrets from a request's `Keys` array — the
/// Password/StoreKey/Plain shares the committee signs with. Shared by every
/// chain's signer so the extraction lives in one place.
fn unlock_keys(params: &Value) -> Vec<(String, String)> {
    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    keys.iter()
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain"))
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect()
}

/// `Account:signTransaction` — chain-agnostic offline transaction signing. The
/// caller passes an account `Id` and a `Transaction` object; we dispatch on the
/// account's chain and return a broadcast-ready `raw` (EVM/BTC = `0x`-hex,
/// Solana = base58). There is NO RPC here — every value the signer needs
/// (nonce, blockhash, UTXOs) must be supplied in `Transaction`, which is what
/// lets this build and run on wasm. `Account:signAndSendTransaction` layers the
/// RPC (fee/blockhash/UTXO fetch + broadcast) on top of these same signers.
pub fn sign_transaction(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    match account.kind.as_str() {
        "ethereum" => sign_tx_evm(env, &account, params),
        "solana" => sign_tx_solana(env, &account, params),
        "bitcoin" => sign_tx_bitcoin(env, &account, params),
        other => Err(ApiError::new(400, format!("signTransaction not supported for {other}"))),
    }
}

fn sign_tx_evm(env: &Env, account: &crate::models::account::Account, params: &Value) -> ApiResult {
    let tx = params
        .get("Transaction")
        .ok_or_else(|| ApiError::new(400, "Transaction required"))?;

    let eip1559 =
        tx.get("type").and_then(Value::as_u64) == Some(2) || tx.get("maxFeePerGas").is_some();
    let max_fee = if eip1559 { tx.get("maxFeePerGas") } else { tx.get("gasPrice") }
        .and_then(Value::as_str)
        .unwrap_or("0")
        .to_string();
    let req = crate::evm::EvmTxRequest {
        nonce: tx.get("nonce").and_then(Value::as_u64).unwrap_or(0),
        gas: tx.get("gas").and_then(Value::as_u64).unwrap_or(21000),
        max_fee,
        max_priority: tx.get("maxPriorityFeePerGas").and_then(Value::as_str).unwrap_or("0").to_string(),
        to: tx.get("to").and_then(Value::as_str).unwrap_or("").to_string(),
        value: tx.get("value").and_then(Value::as_str).unwrap_or("0").to_string(),
        data: match tx.get("data").and_then(Value::as_str) {
            Some(h) => decode_hex(h)?,
            None => Vec::new(),
        },
        chain_id: tx.get("chainId").and_then(Value::as_u64).unwrap_or(1),
        eip1559,
    };

    let unlock = unlock_keys(params);
    let raw = crate::evm::sign_tx(env, &account.id, &unlock, &req).map_err(ApiError::internal)?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(serde_json::json!({ "raw": format!("0x{hex}") }))
}

fn sign_tx_solana(env: &Env, account: &crate::models::account::Account, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;
    let to_b58 = tx.get("to").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "to required"))?;
    let lamports: u64 =
        tx.get("value").and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0);
    // Offline signing: the recent blockhash comes from the caller (no RPC here).
    // signAndSend fetches it from the node and injects it before delegating.
    let bh_b58 = tx
        .get("recentBlockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "recentBlockhash required"))?;
    let blockhash = b58_32(bh_b58)?;
    let from = crate::solana::pubkey_from_b64url(&account.pubkey)
        .ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    let to = b58_32(to_b58)?;

    let msg = crate::solana::build_transfer_message(&from, &to, lamports, &blockhash);
    let unlock = unlock_keys(params);
    let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &msg)
        .map_err(ApiError::internal)?;
    let tx_bytes = crate::solana::assemble_tx(&msg, &sig);
    let raw = bs58::encode(&tx_bytes).into_string();
    Ok(serde_json::json!({ "raw": raw }))
}

fn sign_tx_bitcoin(env: &Env, account: &crate::models::account::Account, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;
    let unlock = unlock_keys(params);

    // Offline signing needs explicit inputs — auto UTXO discovery is an RPC
    // concern that lives in signAndSend's bitcoin_send.
    let mut utxos = Vec::new();
    for u in tx.get("UTXOs").and_then(Value::as_array).ok_or_else(|| ApiError::new(400, "UTXOs required"))? {
        let txid_v = decode_hex(u.get("txid").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "utxo txid"))?)?;
        let txid: [u8; 32] = txid_v.try_into().map_err(|_| ApiError::new(400, "txid must be 32 bytes"))?;
        let vout = u.get("vout").and_then(Value::as_u64).unwrap_or(0) as u32;
        let amount = u.get("amount").and_then(Value::as_u64).unwrap_or(0);
        // `script` is optional: an omitted/empty prevout script means a self-spend
        // of the account's own coins — bitcoin::sign_transfer derives the P2WPKH
        // scriptPubKey from the account key, so the browser needs only txid/vout/amount.
        let script = match u.get("script").and_then(Value::as_str) {
            Some(h) if !h.is_empty() => decode_hex(h)?,
            _ => Vec::new(),
        };
        utxos.push(crate::bitcoin::Utxo { txid, vout, amount, script_pubkey: script });
    }
    let mut outputs = Vec::new();
    for o in tx.get("Outputs").and_then(Value::as_array).ok_or_else(|| ApiError::new(400, "Outputs required"))? {
        let address = o.get("address").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "output address"))?;
        let amount = o.get("amount").and_then(Value::as_u64).unwrap_or(0);
        outputs.push((address.to_string(), amount));
    }

    let raw = crate::bitcoin::sign_transfer(env, &account.id, &unlock, &utxos, &outputs).map_err(ApiError::internal)?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(serde_json::json!({ "raw": format!("0x{hex}") }))
}

/// `Account:signAndSendTransaction` — sign the EVM transaction, then broadcast
/// it via the node RPC (eth_sendRawTransaction) and return the tx hash. The RPC
/// endpoint is taken from the `RPC` param (network-resolution lands with wltnet).
#[cfg(not(target_arch = "wasm32"))]
pub fn sign_and_send_transaction(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;

    // Every chain goes through the shared async impl (block_on here, awaited on
    // wasm) so the browser drives sends with no client-side RPC.
    match account.kind.as_str() {
        "ethereum" | "solana" | "bitcoin" => crate::rt::block_on(sign_and_send_impl(env, params)),
        other => Err(ApiError::new(400, format!("signAndSend not supported for {other}"))),
    }
}

/// `Account:signAndSendTransaction` — sign the tx and broadcast it via the node
/// RPC, returning the tx id. One async implementation shared by native
/// (`block_on`) and the browser (awaited in `handle_request_async`); chain I/O
/// runs over `rpc::call_async` and the endpoint is resolved from the Network
/// model, never named by the client. Currently covers ethereum + solana; bitcoin
/// auto-send stays on the native sync path until its builder is made async.
pub async fn sign_and_send_impl(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let url = resolve_rpc(env, params, &account.kind)?;

    match account.kind.as_str() {
        "ethereum" => evm_send_async(env, &account, &url, params).await,
        "solana" => solana_send_async(env, &account, &url, params).await,
        "bitcoin" => bitcoin_send_async(env, &account, &url, params).await,
        other => Err(ApiError::new(400, format!("signAndSend (async) not supported for {other}"))),
    }
}

/// Decode an `0x`-hex quantity into a u64 (JSON-RPC returns hex strings).
fn u64_from_hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

/// EVM signAndSend: fill in any tx fields the caller didn't supply (chainId,
/// nonce, gas, EIP-1559 fees) from the node, sign offline via `sign_tx_evm`,
/// then broadcast. A field already present in `Transaction` is kept as-is, so a
/// fully-specified tx makes no read calls (native/Dart behaviour) while the
/// browser can pass just {to, value} and let Rust fetch the rest.
/// Autofill an EVM `Transaction` from the node (chainId, nonce, gas, EIP-1559
/// fees) for any field the caller omitted, returning the params with a fully
/// populated `Transaction`. Shared by estimate (preview) and send (sign).
async fn evm_fill(account: &crate::models::account::Account, url: &str, params: &Value) -> Result<Value, ApiError> {
    let mut p = params.clone();
    {
        let tx = p
            .get_mut("Transaction")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| ApiError::new(400, "Transaction required"))?;

        if !tx.contains_key("chainId") {
            let cid = crate::rpc::call_async(url, "eth_chainId", serde_json::json!([]))
                .await
                .map_err(ApiError::internal)?;
            tx.insert("chainId".into(), serde_json::json!(u64_from_hex(cid.as_str().unwrap_or("0x1"))));
        }
        if !tx.contains_key("nonce") {
            let n = crate::rpc::call_async(url, "eth_getTransactionCount", serde_json::json!([account.address, "pending"]))
                .await
                .map_err(ApiError::internal)?;
            tx.insert("nonce".into(), serde_json::json!(u64_from_hex(n.as_str().unwrap_or("0x0"))));
        }
        if !tx.contains_key("gas") {
            let to = tx.get("to").and_then(Value::as_str).unwrap_or("").to_owned();
            let value_dec = tx.get("value").and_then(Value::as_str).unwrap_or("0");
            let value_hex = format!("0x{:x}", value_dec.parse::<u128>().unwrap_or(0));
            let est = crate::rpc::call_async(
                url,
                "eth_estimateGas",
                serde_json::json!([{ "from": account.address, "to": to, "value": value_hex }]),
            )
            .await
            .ok()
            .and_then(|g| g.as_str().map(u64_from_hex))
            .unwrap_or(21000);
            tx.insert("gas".into(), serde_json::json!(est));
        }
        // Fees: prefer EIP-1559 (baseFee×2 + tip); fall back to legacy gasPrice.
        if !tx.contains_key("maxFeePerGas") && !tx.contains_key("gasPrice") {
            let base = crate::rpc::call_async(url, "eth_getBlockByNumber", serde_json::json!(["latest", false]))
                .await
                .ok()
                .and_then(|b| b.get("baseFeePerGas").and_then(Value::as_str).map(|s| u128::from(u64_from_hex(s))));
            match base {
                Some(base_fee) => {
                    let tip = crate::rpc::call_async(url, "eth_maxPriorityFeePerGas", serde_json::json!([]))
                        .await
                        .ok()
                        .and_then(|t| t.as_str().map(u64_from_hex))
                        .unwrap_or(1_000_000_000) as u128; // 1 gwei
                    let max_fee = base_fee * 2 + tip;
                    tx.insert("maxFeePerGas".into(), serde_json::json!(max_fee.to_string()));
                    tx.insert("maxPriorityFeePerGas".into(), serde_json::json!(tip.to_string()));
                    tx.insert("type".into(), serde_json::json!(2));
                }
                None => {
                    let gp = crate::rpc::call_async(url, "eth_gasPrice", serde_json::json!([]))
                        .await
                        .ok()
                        .and_then(|g| g.as_str().map(u64_from_hex))
                        .unwrap_or(0);
                    tx.insert("gasPrice".into(), serde_json::json!(gp.to_string()));
                }
            }
        }
    }
    Ok(p)
}

async fn evm_send_async(env: &Env, account: &crate::models::account::Account, url: &str, params: &Value) -> ApiResult {
    let p = evm_fill(account, url, params).await?;
    let signed = sign_tx_evm(env, account, &p)?;
    let raw = signed["raw"].as_str().ok_or_else(|| ApiError::new(500, "no raw tx"))?;
    let hash = crate::rpc::call_async(url, "eth_sendRawTransaction", serde_json::json!([raw]))
        .await
        .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "hash": hash, "raw": raw }))
}

/// Solana signAndSend: fetch the recent blockhash, delegate signing to the
/// shared offline `sign_tx_solana`, then broadcast. Async twin of `solana_send`.
async fn solana_send_async(env: &Env, account: &crate::models::account::Account, url: &str, params: &Value) -> ApiResult {
    let bh = crate::rpc::call_async(url, "getLatestBlockhash", serde_json::json!([]))
        .await
        .map_err(ApiError::internal)?;
    let bh_b58 = bh
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(502, "no blockhash in response"))?;

    let mut p = params.clone();
    p.get_mut("Transaction")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ApiError::new(400, "Transaction required"))?
        .insert("recentBlockhash".to_string(), Value::String(bh_b58.to_string()));

    let signed = sign_tx_solana(env, account, &p)?;
    let tx_b58 = signed["raw"].as_str().ok_or_else(|| ApiError::new(500, "no raw tx"))?;
    let signature = crate::rpc::call_async(url, "sendTransaction", serde_json::json!([tx_b58, {"encoding":"base58"}]))
        .await
        .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "signature": signature, "raw": tx_b58 }))
}

/// Build, DKLs-sign, and broadcast a Bitcoin P2PKH transfer. UTXOs and outputs
/// are supplied in the request (auto-discovery via modchain lands next).
#[cfg(not(target_arch = "wasm32"))]
/// Bitcoin signAndSend (async twin of the old sync path): auto-input
/// {To, Amount} discovers the account's UTXOs via modchain_assets over
/// call_async, builds+signs through the shared offline core, and broadcasts;
/// an explicit-UTXO Transaction goes through the offline sign_tx_bitcoin. One
/// impl for native (block_on) and the browser (await).
async fn bitcoin_send_async(env: &Env, account: &crate::models::account::Account, url: &str, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;
    let unlock = unlock_keys(params);

    let no_utxos = tx.get("UTXOs").and_then(Value::as_array).map(|a| a.is_empty()).unwrap_or(true);
    if no_utxos {
        if let (Some(to), Some(amount)) =
            (tx.get("To").and_then(Value::as_str), tx.get("Amount").and_then(Value::as_u64))
        {
            // Bitcoin-family chain id (for SIGHASH_FORKID + change address);
            // defaults to mainnet "bitcoin", overridable via Transaction.ChainId.
            let chain_id = tx.get("ChainId").and_then(Value::as_str).unwrap_or("bitcoin").to_owned();
            let fee_rate = tx.get("FeeRate").and_then(Value::as_u64).unwrap_or(10);
            let xpub = account.xpub().map_err(ApiError::internal)?;
            let assets = crate::rpc::call_async(url, "modchain_assets", serde_json::json!([xpub]))
                .await
                .map_err(ApiError::internal)?;
            let all = crate::bitcoin::parse_native_utxos(&assets).map_err(ApiError::internal)?;
            let raw = crate::bitcoin::build_and_sign_from_utxos(
                env, &account.id, &unlock, &chain_id, to, amount, fee_rate, &all,
            )
            .map_err(ApiError::internal)?;
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let txid = crate::rpc::call_async(url, "sendrawtransaction", serde_json::json!([hex]))
                .await
                .map_err(ApiError::internal)?;
            return Ok(serde_json::json!({ "txid": txid, "raw": format!("0x{hex}") }));
        }
    }

    // Explicit-UTXO path: the shared offline signer, then broadcast.
    let signed = sign_tx_bitcoin(env, account, params)?;
    let hex = signed["raw"].as_str().unwrap_or("").trim_start_matches("0x").to_string();
    let txid = crate::rpc::call_async(url, "sendrawtransaction", serde_json::json!([hex]))
        .await
        .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "txid": txid, "raw": format!("0x{hex}") }))
}

/// `Account:setCurrent` — mark an account as the active one.
pub fn set_current(env: &Env, params: &Value) -> ApiResult {
    let id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id required"))?;
    // Confirm it exists before selecting it.
    if crate::models::account::fetch(env, id).map_err(ApiError::internal)?.is_none() {
        return Err(ApiError::new(404, "account not found"));
    }
    env.set_current("account", id).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "account": id }))
}

fn b58_32(s: &str) -> Result<[u8; 32], ApiError> {
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::new(400, format!("bad base58 32-byte value: {s}")))
}

/// `Account:balance` — the account's native balance via the node RPC. One async
/// implementation shared by native (driven through `crate::rt::block_on`) and
/// the browser (awaited in `handle_request_async`), so the logic is identical on
/// both. ethereum = eth_getBalance (wei); solana = getBalance (lamports, minus
/// the rent-exempt reserve); bitcoin = modchain_assets NATIVE sum (satoshi).
/// Returned as a decimal string. Chain I/O goes through `rpc::call_async`.
pub async fn balance_impl(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let url = resolve_rpc(env, params, &account.kind)?;

    let bal = match account.kind.as_str() {
        "ethereum" => {
            let hex = crate::rpc::call_async(&url, "eth_getBalance", serde_json::json!([account.address, "latest"]))
                .await
                .map_err(ApiError::internal)?;
            let hex = hex.as_str().ok_or_else(|| ApiError::new(502, "balance not a string"))?;
            let stripped = hex.strip_prefix("0x").unwrap_or(hex);
            num_bigint::BigInt::parse_bytes(stripped.as_bytes(), 16)
                .ok_or_else(|| ApiError::new(502, format!("bad balance hex {hex}")))?
                .to_string()
        }
        "solana" => {
            let res = crate::rpc::call_async(&url, "getBalance", serde_json::json!([account.address]))
                .await
                .map_err(ApiError::internal)?;
            let raw = res
                .get("value")
                .and_then(Value::as_u64)
                .ok_or_else(|| ApiError::new(502, "unexpected getBalance response"))?;
            // Subtract the rent-exempt minimum so the reported balance is what
            // the user can actually spend (matching Go nativeBalance). RPC
            // failure falls back to the canonical 0-byte system-account reserve.
            let rent = crate::rpc::call_async(&url, "getMinimumBalanceForRentExemption", serde_json::json!([0]))
                .await
                .ok()
                .and_then(|v| v.as_u64())
                .unwrap_or(890_880);
            raw.saturating_sub(rent).to_string()
        }
        "bitcoin" => {
            // Prefer the xpub (gap-limit scan across receive+change) when the
            // account has one; fall back to the single address. Matches Go
            // bitcoinBalance, which passes the xpub to modchain_assets.
            let lookup = account.xpub().unwrap_or_else(|_| account.address.clone());
            let raw = crate::rpc::call_async(&url, "modchain_assets", serde_json::json!([lookup]))
                .await
                .map_err(ApiError::internal)?;
            crate::bitcoin::parse_native_balance(&raw).map_err(ApiError::internal)?.to_string()
        }
        other => return Err(ApiError::new(400, format!("balance not supported for {other}"))),
    };
    Ok(serde_json::json!({ "address": account.address, "balance": bal }))
}

/// Native `Account:balance`: drive the shared async impl on the FFI worker.
#[cfg(not(target_arch = "wasm32"))]
pub fn balance(env: &Env, params: &Value) -> ApiResult {
    crate::rt::block_on(balance_impl(env, params))
}

/// `Account:maxSendable` — the maximum native amount an EVM account can send:
/// balance − (21000 × gasPrice) reserved for the fee (Go maxSendableEVM, legacy
/// fee path). {RPC?} — returns {chain, balance, fee, max} as amounts.
#[cfg(not(target_arch = "wasm32"))]
pub fn max_sendable(env: &Env, params: &Value) -> ApiResult {
    use num_bigint::BigInt;
    // "Id" (Account:maxSendable) or "Account" (Transaction:maxSendable).
    let account_id = params
        .get("Id")
        .or_else(|| params.get("Account"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id/Account required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let rpc = resolve_rpc(env, params, &account.kind)?;

    // ERC-20 token max: the whole token balance is spendable (native gas is
    // paid separately), Go maxSendableEVMERC20.
    if let Some(token) = params.get("Token").and_then(Value::as_str) {
        if account.kind != "ethereum" {
            return Err(ApiError::new(400, "Token maxSendable is EVM-only"));
        }
        let balance = crate::erc20::balance_of(&rpc, token, &account.address).map_err(ApiError::internal)?;
        let dec = crate::erc20::decimals(&rpc, token).map_err(ApiError::internal)?;
        let amt = crate::Amount::new_raw(balance, dec);
        return Ok(serde_json::json!({ "chain": "evm", "token": token, "balance": amt, "max": amt }));
    }

    match account.kind.as_str() {
        "ethereum" => {
            let hex_bi = |v: &Value| {
                let s = v.as_str().unwrap_or("0x0");
                BigInt::parse_bytes(s.strip_prefix("0x").unwrap_or(s).as_bytes(), 16)
                    .unwrap_or_else(|| BigInt::from(0))
            };
            let bal_dec = crate::rpc::eth_get_balance(&rpc, &account.address).map_err(ApiError::internal)?;
            let balance = BigInt::parse_bytes(bal_dec.as_bytes(), 10).unwrap_or_else(|| BigInt::from(0));
            // Fee reserve for a 21000-gas transfer. EIP-1559 (when requested):
            // (2*baseFee + tip) * gas; else legacy gasPrice * gas.
            let per_gas = if params.get("Eip1559").and_then(Value::as_bool).unwrap_or(false) {
                let block = crate::rpc::call(&rpc, "eth_getBlockByNumber", serde_json::json!(["latest", false]))
                    .map_err(ApiError::internal)?;
                let base_fee = block.get("baseFeePerGas").map(hex_bi).unwrap_or_else(|| BigInt::from(0));
                let tip = crate::rpc::call(&rpc, "eth_maxPriorityFeePerGas", serde_json::json!([]))
                    .ok()
                    .map(|v| hex_bi(&v))
                    .filter(|t| *t > BigInt::from(0))
                    .unwrap_or_else(|| BigInt::from(1_000_000_000u64)); // 1 gwei fallback
                base_fee * 2 + tip
            } else {
                let gp = crate::rpc::call(&rpc, "eth_gasPrice", serde_json::json!([])).map_err(ApiError::internal)?;
                hex_bi(&gp)
            };
            let fee = BigInt::from(21000) * &per_gas;
            let max = if balance <= fee { BigInt::from(0) } else { &balance - &fee };
            let decimals = crate::models::network::fetch(env, "@")
                .ok().flatten().map(|n| n.native_decimals()).unwrap_or(18);
            let amt = |v: BigInt| crate::Amount::new_raw(v, decimals);
            Ok(serde_json::json!({ "chain": "evm", "balance": amt(balance), "fee": amt(fee), "max": amt(max) }))
        }
        "solana" => {
            // max = balance - 5000 (signature fee) - rent-exempt reserve.
            let res = crate::rpc::call(&rpc, "getBalance", serde_json::json!([account.address]))
                .map_err(ApiError::internal)?;
            let balance = res.get("value").and_then(Value::as_u64).unwrap_or(0);
            const FEE: u64 = 5000;
            let rent = crate::rpc::call(&rpc, "getMinimumBalanceForRentExemption", serde_json::json!([0]))
                .ok().and_then(|v| v.as_u64()).unwrap_or(890_880);
            // If a To is given and that account doesn't exist yet, an extra
            // rent-exempt reserve is held to fund its creation (Go maxSendableSolana).
            let mut recipient_rent = 0u64;
            if let Some(to) = params.get("To").and_then(Value::as_str) {
                let info = crate::rpc::call(&rpc, "getAccountInfo", serde_json::json!([to, {"encoding":"base64"}]));
                let exists = info.ok().map(|v| !v.get("value").map(|x| x.is_null()).unwrap_or(true)).unwrap_or(true);
                if !exists {
                    recipient_rent = rent;
                }
            }
            let reserve = FEE + rent + recipient_rent;
            let max = balance.saturating_sub(reserve);
            let amt = |v: u64| crate::Amount::new_raw(BigInt::from(v), 9);
            let mut reserved = vec![serde_json::json!({ "kind": "sender_rent", "amount": amt(rent) })];
            if recipient_rent > 0 {
                reserved.push(serde_json::json!({ "kind": "recipient_rent", "amount": amt(recipient_rent) }));
            }
            Ok(serde_json::json!({
                "chain": "solana",
                "balance": amt(balance),
                "fee": amt(FEE),
                "reserved": reserved,
                "max": amt(max),
            }))
        }
        "bitcoin" => {
            // max = sum(UTXOs) − fee to spend them all into one output.
            let xpub = account.xpub().map_err(ApiError::internal)?;
            let fee_rate = params.get("FeeRate").and_then(Value::as_u64).unwrap_or(10);
            let (total, fee, max) =
                crate::bitcoin::max_sendable_sats(&rpc, &xpub, fee_rate).map_err(ApiError::internal)?;
            let amt = |v: u64| crate::Amount::new_raw(BigInt::from(v), 8);
            Ok(serde_json::json!({
                "chain": "bitcoin",
                "balance": amt(total),
                "fee": amt(fee),
                "max": amt(max),
                "bitcoinFeeRate": fee_rate,
            }))
        }
        other => Err(ApiError::new(400, format!("maxSendable not supported for {other}"))),
    }
}

/// `Account:tokenBalance` — the ERC-20 balance of an EVM account for a token
/// contract, via eth_call balanceOf. {Token, RPC?} — decimal string base units.
#[cfg(not(target_arch = "wasm32"))]
pub fn token_balance(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let token = params
        .get("Token")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Token (contract address) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    if account.kind != "ethereum" {
        return Err(ApiError::new(400, "tokenBalance is EVM-only"));
    }
    let rpc = resolve_rpc(env, params, &account.kind)?;
    let bal = crate::erc20::balance_of(&rpc, token, &account.address).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "token": token, "owner": account.address, "balance": bal.to_string() }))
}

/// `Account:createView` {Name?, Type, Address|Xpub} — a watch-only account from
/// a bare address or a BIP-32 extended public key (Go `accountCreateView`).
/// Exactly one of `Address` or `Xpub` must be given; `Xpub` is bitcoin-only and
/// yields an account whose pubkey + chaincode drive HD gap-limit scans.
pub fn create_view(env: &Env, params: &Value) -> ApiResult {
    let typ = params.get("Type").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Type required"))?;
    let name = params.get("Name").and_then(Value::as_str).unwrap_or("");
    let address = params.get("Address").and_then(Value::as_str).filter(|s| !s.is_empty());
    let xpub = params.get("Xpub").and_then(Value::as_str).filter(|s| !s.is_empty());
    let a = match (address, xpub) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(ApiError::new(400, "exactly one of address or xpub is required"))
        }
        (Some(addr), None) => {
            crate::models::account::create_view(env, name, typ, addr).map_err(ApiError::internal)?
        }
        (None, Some(xp)) => crate::models::account::create_view_xpub(env, name, typ, xp)
            .map_err(ApiError::internal)?,
    };
    Ok(serde_json::to_value(a).unwrap())
}

/// `Account:xpub` — the BIP-32 extended public key for a bitcoin/ethereum
/// account (Go `Account:xpub`). Used for gap-limit UTXO/history discovery.
pub fn xpub(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let xpub = account.xpub().map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "xpub": xpub }))
}

/// `Account:addressFormats` — every receive-address format (Native SegWit /
/// wrapped / Legacy …) for a bitcoin account on the current chain (Go
/// `accountAddressFormats`). No RPC — pure local derivation.
pub fn address_formats(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    if account.kind != "bitcoin" {
        return Err(ApiError::new(400, "addressFormats is bitcoin-only"));
    }
    let net = crate::models::network::fetch(env, "@")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "no current network"))?;
    if net.kind != "bitcoin" {
        return Err(ApiError::new(400, format!("current network is {}, not bitcoin", net.kind)));
    }
    let pubkey = decode_b64url_33(&account.pubkey)?;
    let chaincode = decode_b64url_32(&account.chaincode)?;
    let formats = crate::bitcoin::address_formats(&pubkey, &chaincode, &net.chain_id)
        .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "chainId": net.chain_id, "formats": formats }))
}

/// `Account:allAddresses` — all used HD addresses (receive + change) plus the
/// next clean address on each chain (Go `accountAllAddresses`).
#[cfg(not(target_arch = "wasm32"))]
pub fn all_addresses(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    if account.kind != "bitcoin" {
        return Err(ApiError::new(400, "allAddresses is bitcoin-only"));
    }
    let net = crate::models::network::fetch(env, "@")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "no current network"))?;
    if net.kind != "bitcoin" {
        return Err(ApiError::new(400, format!("current network is {}, not bitcoin", net.kind)));
    }
    let rpc = resolve_rpc(env, params, &account.kind)?;
    let xpub = account.xpub().map_err(ApiError::internal)?;
    let pubkey = decode_b64url_33(&account.pubkey)?;
    let chaincode = decode_b64url_32(&account.chaincode)?;

    let receive = crate::bitcoin::scan_chain(&rpc, &xpub, &pubkey, &chaincode, &net.chain_id, false)
        .map_err(ApiError::internal)?;
    let change = crate::bitcoin::scan_chain(&rpc, &xpub, &pubkey, &chaincode, &net.chain_id, true)
        .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "receive": receive, "change": change }))
}

/// `Account:utxos` — the account's spendable NATIVE UTXOs (Go
/// `fetchBitcoinUTXOs`), for hosts that build/sign Bitcoin transactions.
#[cfg(not(target_arch = "wasm32"))]
pub fn utxos(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    if account.kind != "bitcoin" {
        return Err(ApiError::new(400, "utxos is bitcoin-only"));
    }
    let rpc = resolve_rpc(env, params, &account.kind)?;
    let xpub = account.xpub().map_err(ApiError::internal)?;
    let utxos = crate::bitcoin::list_utxos(&rpc, &xpub).map_err(ApiError::internal)?;
    let total: u64 = utxos.iter().map(|u| u.amount_sats).sum();
    Ok(serde_json::json!({ "utxos": utxos, "count": utxos.len(), "total_sats": total }))
}

/// `Account:nextAddress` — the next unused HD receive/change address for a
/// bitcoin-family account (Go `accountNextAddress`). Uses the account xpub +
/// modchain_lookupTxoBIP32 to find the highest used index and derives the next.
#[cfg(not(target_arch = "wasm32"))]
pub fn next_address(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    if account.kind != "bitcoin" {
        return Err(ApiError::new(400, "nextAddress is bitcoin-only"));
    }
    let change = params.get("Change").and_then(Value::as_bool).unwrap_or(false);

    // Resolve the current network to get the bitcoin chain id + RPC.
    let net = crate::models::network::fetch(env, "@")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "no current network"))?;
    if net.kind != "bitcoin" {
        return Err(ApiError::new(400, format!("current network is {}, not bitcoin", net.kind)));
    }
    let rpc = resolve_rpc(env, params, &account.kind)?;
    let xpub = account.xpub().map_err(ApiError::internal)?;
    let pubkey = decode_b64url_33(&account.pubkey)?;
    let chaincode = decode_b64url_32(&account.chaincode)?;

    let (address, index, path) =
        crate::bitcoin::next_address(&rpc, &xpub, &pubkey, &chaincode, &net.chain_id, change)
            .map_err(ApiError::internal)?;
    Ok(serde_json::json!({
        "address": address,
        "index": index,
        "path": path,
        "chain": if change { "change" } else { "receive" },
    }))
}

fn decode_b64url_33(s: &str) -> Result<[u8; 33], ApiError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| ApiError::new(400, e.to_string()))?
        .try_into()
        .map_err(|_| ApiError::new(400, "pubkey is not 33 bytes"))
}

fn decode_b64url_32(s: &str) -> Result<[u8; 32], ApiError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| ApiError::new(400, e.to_string()))?
        .try_into()
        .map_err(|_| ApiError::new(400, "chaincode is not 32 bytes"))
}

/// `Account:nativeAsset` — the live native-currency asset for an account:
/// resolve the current network (must match the account chain), fetch the
/// balance, and build the Asset (Key/Name/Symbol/Amount). With an optional
/// `Currency` it is priced into fiat. This is the computed (non-persisted)
/// native asset from Go's asset snapshot.
#[cfg(not(target_arch = "wasm32"))]
pub fn native_asset(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;

    // Resolve the current network and require it to match the account's chain.
    let net = crate::models::network::fetch(env, "@")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "no current network"))?;
    let want = match account.kind.as_str() {
        "ethereum" => "evm",
        other => other,
    };
    if net.kind != want {
        return Err(ApiError::new(
            400,
            format!("current network is {} but account is {}", net.kind, account.kind),
        ));
    }
    let rpc = resolve_rpc(env, params, &account.kind)?;

    let mut asset = net.native_asset(&rpc, &account.address).map_err(ApiError::internal)?;
    if let Some(cur) = params.get("Currency").and_then(Value::as_str) {
        let _ = asset.convert_to(env, cur);
    }
    Ok(serde_json::to_value(asset).unwrap())
}

/// The RPC URL for a request touching an account of `account_kind`: the `RPC`
/// param wins; otherwise resolve it from the Network model (Go resolves RPC from
/// the network). The current network `@` is used when its type matches the
/// account's chain; otherwise we fall back to the seeded DEFAULT network for
/// that chain (evm→1, solana→mainnet, bitcoin→bitcoin). The browser is
/// multi-chain — it has no single `@` that matches every account — so it always
/// takes the default-network path; native keeps its current-network behaviour
/// when `@` matches. Either way the endpoint comes from `Network::resolved_rpc`,
/// the one resolver, never a client-side URL.
fn resolve_rpc(env: &Env, params: &Value, account_kind: &str) -> Result<String, ApiError> {
    // account kind (ethereum/solana/bitcoin) -> network type (evm/solana/bitcoin).
    let want = match account_kind {
        "ethereum" => "evm",
        other => other,
    };
    super::resolve_rpc_for_kind(env, params, want)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(ApiError::new(400, "odd-length hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| ApiError::new(400, e.to_string())))
        .collect()
}

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::account::fetch(env, id).map_err(ApiError::internal)? {
                Some(a) => Ok(serde_json::to_value(a).unwrap()),
                None => Err(ApiError::new(404, "account not found")),
            },
            None => {
                let list = crate::models::account::list(env).map_err(ApiError::internal)?;
                Ok(serde_json::to_value(list).unwrap())
            }
        },
        "POST" => {
            #[derive(serde::Deserialize)]
            struct CreateReq {
                #[serde(rename = "Wallet", default)]
                wallet: String,
                #[serde(rename = "Name", default)]
                name: String,
                #[serde(rename = "Type", default)]
                kind: String,
                #[serde(rename = "Index", default)]
                index: i64,
            }
            let req: CreateReq =
                serde_json::from_value(params.clone()).map_err(|e| ApiError::new(400, e.to_string()))?;
            let a = crate::models::account::create(env, &req.wallet, &req.name, &req.kind, req.index)
                .map_err(ApiError::internal)?;
            Ok(serde_json::to_value(a).unwrap())
        }
        // PATCH Account/<id> — ApiUpdate: only Name is mutable. Returns the
        // updated object.
        "PATCH" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            let name = params.get("Name").and_then(Value::as_str);
            match crate::models::account::update(env, id, name).map_err(ApiError::internal)? {
                Some(a) => Ok(serde_json::to_value(a).unwrap()),
                None => Err(ApiError::new(404, "account not found")),
            }
        }
        // DELETE Account/<id> — ApiDelete: cascade-drops the account's Web3
        // connections, notifies listeners, and returns the deleted object.
        "DELETE" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            let a = crate::models::account::fetch(env, id)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(404, "account not found"))?;
            crate::models::account::delete(env, id).map_err(ApiError::internal)?;
            env.broadcast(&crate::response::event(
                "account:delete",
                serde_json::json!({ "id": a.id }),
            ));
            Ok(serde_json::to_value(a).unwrap())
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Account"))),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod balance_tests {
    use super::*;
    use crate::sign::KeyDescription;
    use crate::Env;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn pw(p: &str) -> KeyDescription {
        KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
    }

    /// One-shot mock JSON-RPC server returning `result_json`.
    fn mock_rpc(result_json: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    // Proves the shared async balance runs through native block_on end to end:
    // block_on → balance_impl → resolve_rpc (RPC override) → call_async →
    // parse_native_balance. Bitcoin's modchain_assets NATIVE sum.
    #[test]
    fn bitcoin_balance_via_block_on() {
        let env = Env::init_memory().unwrap();
        crate::models::wallet::init(&env).unwrap();
        crate::models::account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = crate::models::wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = crate::models::account::create(&env, &w.id, "", "bitcoin", 0).unwrap();

        let url = mock_rpc(r#"{"assets":[{"asset":"NATIVE","balance":"0.00080000"}]}"#.to_string());
        let out = balance(&env, &serde_json::json!({ "Id": a.id, "RPC": url })).unwrap();
        assert_eq!(out["balance"], serde_json::json!("80000"));
        assert_eq!(out["address"], serde_json::json!(a.address));
    }

    // EVM balance decodes the hex wei into a decimal string.
    #[test]
    fn ethereum_balance_via_block_on() {
        let env = Env::init_memory().unwrap();
        crate::models::wallet::init(&env).unwrap();
        crate::models::account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = crate::models::wallet::create(&env, "ETH", "secp256k1", &kds).unwrap();
        let a = crate::models::account::create(&env, &w.id, "", "ethereum", 0).unwrap();

        // 0xde0b6b3a7640000 = 1e18 wei = 1 ETH.
        let url = mock_rpc(r#""0xde0b6b3a7640000""#.to_string());
        let out = balance(&env, &serde_json::json!({ "Id": a.id, "RPC": url })).unwrap();
        assert_eq!(out["balance"], serde_json::json!("1000000000000000000"));
    }

    /// Multi-request mock JSON-RPC server: accepts connections in a loop and
    /// replies to each with the result mapped from the request's `method`
    /// (substring match). Each `call_async` opens a fresh `Connection: close`
    /// socket, so several sequential calls hit this one server.
    fn mock_rpc_dispatch(routes: &'static [(&'static str, &'static str)]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let mut s = match conn {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let reqtxt = String::from_utf8_lossy(&buf[..n]);
                let result = routes
                    .iter()
                    .find(|(m, _)| reqtxt.contains(&format!("\"method\":\"{m}\"")))
                    .map(|(_, r)| *r)
                    .unwrap_or("null");
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    // EVM signAndSend end to end through native block_on: autofill chainId /
    // nonce / gas / EIP-1559 fees from the node, sign offline, broadcast. Proves
    // the browser can pass just {to, value} and Rust does the rest.
    #[test]
    fn ethereum_sign_and_send_autofills_and_broadcasts() {
        let env = Env::init_memory().unwrap();
        crate::models::wallet::init(&env).unwrap();
        crate::models::account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = crate::models::wallet::create(&env, "ETH", "secp256k1", &kds).unwrap();
        let a = crate::models::account::create(&env, &w.id, "", "ethereum", 0).unwrap();

        let url = mock_rpc_dispatch(&[
            ("eth_chainId", r#""0x1""#),
            ("eth_getTransactionCount", r#""0x0""#),
            ("eth_estimateGas", r#""0x5208""#),
            ("eth_getBlockByNumber", r#"{"baseFeePerGas":"0x7"}"#),
            ("eth_maxPriorityFeePerGas", r#""0x3b9aca00""#),
            ("eth_sendRawTransaction", r#""0xabc123""#),
        ]);
        let keys: Vec<_> = w
            .keys
            .iter()
            .zip(["passwordone", "passwordtwo", "passwordthree"])
            .map(|(k, p)| serde_json::json!({ "Type": "Password", "Id": k.id, "Key": p }))
            .collect();

        let out = sign_and_send_transaction(
            &env,
            &serde_json::json!({
                "Id": a.id,
                "RPC": url,
                "Keys": keys,
                "Transaction": { "to": "0x000000000000000000000000000000000000dead", "value": "1000" }
            }),
        )
        .unwrap();
        assert_eq!(out["hash"], serde_json::json!("0xabc123"));
        assert!(out["raw"].as_str().unwrap().starts_with("0x02"), "EIP-1559 typed tx: {out}");
    }

    // Bitcoin signAndSend auto-input end to end: discover the account's UTXOs via
    // modchain_assets (mocked), build+sign through the shared offline core, and
    // broadcast via sendrawtransaction. Exercises the DKLs bitcoin sign path.
    #[test]
    fn bitcoin_sign_and_send_auto_discovers_and_broadcasts() {
        let env = Env::init_memory().unwrap();
        crate::models::wallet::init(&env).unwrap();
        crate::models::account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = crate::models::wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = crate::models::account::create(&env, &w.id, "", "bitcoin", 0).unwrap();

        let url = mock_rpc_dispatch(&[
            (
                "modchain_assets",
                r#"{"assets":[{"asset":"NATIVE","txo":[{"txo":"1111111111111111111111111111111111111111111111111111111111111111:0","amt":"0.00080000","path":"m/0/0","script":"p2wpkh"}]}]}"#,
            ),
            ("sendrawtransaction", r#""btctxid""#),
        ]);
        let keys: Vec<_> = w
            .keys
            .iter()
            .zip(["passwordone", "passwordtwo", "passwordthree"])
            .map(|(k, p)| serde_json::json!({ "Type": "Password", "Id": k.id, "Key": p }))
            .collect();

        let out = sign_and_send_transaction(
            &env,
            &serde_json::json!({
                "Id": a.id,
                "RPC": url,
                "Keys": keys,
                "Transaction": { "To": a.address, "Amount": 50000u64 }
            }),
        )
        .unwrap();
        assert_eq!(out["txid"], serde_json::json!("btctxid"));
        assert!(out["raw"].as_str().unwrap().starts_with("0x"), "{out}");
    }
}
