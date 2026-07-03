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
        .filter(|k| k.kind == "Password")
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();

    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;

    let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &msg)
        .map_err(ApiError::internal)?;

    // Solana signatures are base58 in their canonical chain encoding.
    Ok(serde_json::json!({ "signature": bs58::encode(&sig).into_string() }))
}

/// `Account:signTransaction` — build and threshold-sign an EVM transaction for
/// the account, returning the signed raw tx as `0x`-hex. Broadcast
/// (signAndSend) layers eth_sendRawTransaction on top once RPC is wired.
pub fn sign_transaction(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
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

    let keys: Vec<crate::sign::KeyDescription> = params
        .get("Keys")
        .and_then(|k| serde_json::from_value(k.clone()).ok())
        .unwrap_or_default();
    let unlock: Vec<(String, String)> = keys
        .iter()
        .filter(|k| k.kind == "Password")
        .map(|k| (k.id.clone(), k.key.clone()))
        .collect();

    let raw = crate::evm::sign_tx(env, account_id, &unlock, &req).map_err(ApiError::internal)?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(serde_json::json!({ "raw": format!("0x{hex}") }))
}

/// `Account:signAndSendTransaction` — sign the EVM transaction, then broadcast
/// it via the node RPC (eth_sendRawTransaction) and return the tx hash. The RPC
/// endpoint is taken from the `RPC` param (network-resolution lands with wltnet).
pub fn sign_and_send_transaction(env: &Env, params: &Value) -> ApiResult {
    let rpc_url = params
        .get("RPC")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "RPC endpoint required"))?;
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;

    match account.kind.as_str() {
        "ethereum" => {
            let signed = sign_transaction(env, params)?;
            let raw = signed["raw"].as_str().ok_or_else(|| ApiError::new(500, "no raw tx"))?;
            let hash = crate::rpc::eth_send_raw_transaction(rpc_url, raw).map_err(ApiError::internal)?;
            Ok(serde_json::json!({ "hash": hash, "raw": raw }))
        }
        "solana" => solana_send(env, rpc_url, &account, params),
        "bitcoin" => bitcoin_send(env, rpc_url, &account, params),
        other => Err(ApiError::new(400, format!("signAndSend not supported for {other}"))),
    }
}

/// Build, DKLs-sign, and broadcast a Bitcoin P2PKH transfer. UTXOs and outputs
/// are supplied in the request (auto-discovery via modchain lands next).
fn bitcoin_send(env: &Env, rpc: &str, account: &crate::models::account::Account, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;

    let mut utxos = Vec::new();
    for u in tx.get("UTXOs").and_then(Value::as_array).ok_or_else(|| ApiError::new(400, "UTXOs required"))? {
        let txid_v = decode_hex(u.get("txid").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "utxo txid"))?)?;
        let txid: [u8; 32] = txid_v.try_into().map_err(|_| ApiError::new(400, "txid must be 32 bytes"))?;
        let vout = u.get("vout").and_then(Value::as_u64).unwrap_or(0) as u32;
        let amount = u.get("amount").and_then(Value::as_u64).unwrap_or(0);
        let script = decode_hex(u.get("script").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "utxo script"))?)?;
        utxos.push(crate::bitcoin::Utxo { txid, vout, amount, script_pubkey: script });
    }

    let mut outputs = Vec::new();
    for o in tx.get("Outputs").and_then(Value::as_array).ok_or_else(|| ApiError::new(400, "Outputs required"))? {
        let address = o.get("address").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "output address"))?;
        let amount = o.get("amount").and_then(Value::as_u64).unwrap_or(0);
        outputs.push((address.to_string(), amount));
    }

    let keys: Vec<crate::sign::KeyDescription> =
        params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    let unlock: Vec<(String, String)> =
        keys.iter().filter(|k| k.kind == "Password").map(|k| (k.id.clone(), k.key.clone())).collect();

    let raw = crate::bitcoin::sign_transfer(env, &account.id, &unlock, &utxos, &outputs).map_err(ApiError::internal)?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let txid = crate::rpc::call(rpc, "sendrawtransaction", serde_json::json!([hex])).map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "txid": txid, "raw": format!("0x{hex}") }))
}

/// Build, FROST-sign, and broadcast a Solana transfer: fetch a recent
/// blockhash, serialize the transfer, sign, assemble, base58-encode, and
/// sendTransaction. Returns the transaction signature.
fn solana_send(env: &Env, rpc: &str, account: &crate::models::account::Account, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;
    let to_b58 = tx.get("to").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "to required"))?;
    let lamports: u64 = tx.get("value").and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0);

    // Recent blockhash from the node.
    let bh = crate::rpc::call(rpc, "getLatestBlockhash", serde_json::json!([])).map_err(ApiError::internal)?;
    let bh_b58 = bh
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(502, "no blockhash in response"))?;
    let blockhash = b58_32(bh_b58)?;
    let from = crate::solana::pubkey_from_b64url(&account.pubkey)
        .ok_or_else(|| ApiError::new(500, "bad account pubkey"))?;
    let to = b58_32(to_b58)?;

    let msg = crate::solana::build_transfer_message(&from, &to, lamports, &blockhash);
    let keys: Vec<crate::sign::KeyDescription> =
        params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    let unlock: Vec<(String, String)> =
        keys.iter().filter(|k| k.kind == "Password").map(|k| (k.id.clone(), k.key.clone())).collect();
    let sig = crate::models::wallet::sign_frost_local(env, &account.wallet, &unlock, &msg)
        .map_err(ApiError::internal)?;

    let tx_bytes = crate::solana::assemble_tx(&msg, &sig);
    let tx_b58 = bs58::encode(&tx_bytes).into_string();
    let signature = crate::rpc::call(rpc, "sendTransaction", serde_json::json!([tx_b58, {"encoding":"base58"}]))
        .map_err(ApiError::internal)?;
    Ok(serde_json::json!({ "signature": signature, "raw": tx_b58 }))
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

/// `Account:balance` — the account's native balance via the node RPC. For an
/// ethereum account this is eth_getBalance (wei); solana uses getBalance
/// (lamports). Returned as a decimal string.
pub fn balance(env: &Env, params: &Value) -> ApiResult {
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let rpc = params
        .get("RPC")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "RPC endpoint required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;

    let bal = match account.kind.as_str() {
        "ethereum" => crate::rpc::eth_get_balance(rpc, &account.address).map_err(ApiError::internal)?,
        "solana" => {
            let res = crate::rpc::call(rpc, "getBalance", serde_json::json!([account.address]))
                .map_err(ApiError::internal)?;
            res.get("value")
                .and_then(Value::as_u64)
                .map(|v| v.to_string())
                .ok_or_else(|| ApiError::new(502, "unexpected getBalance response"))?
        }
        other => return Err(ApiError::new(400, format!("balance not supported for {other}"))),
    };
    Ok(serde_json::json!({ "address": account.address, "balance": bal }))
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
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Account"))),
    }
}
