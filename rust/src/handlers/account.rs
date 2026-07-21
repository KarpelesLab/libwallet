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
        .filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain"))
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
    let account_id = params
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Id (account) required"))?;
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let rpc_url = resolve_rpc(env, params, &account.kind)?;
    let rpc_url = rpc_url.as_str();

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

    let keys: Vec<crate::sign::KeyDescription> =
        params.get("Keys").and_then(|k| serde_json::from_value(k.clone()).ok()).unwrap_or_default();
    let unlock: Vec<(String, String)> =
        keys.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain")).map(|k| (k.id.clone(), k.key.clone())).collect();

    // Auto-input path: {To, Amount} with no explicit UTXOs — discover, select,
    // add change, and sign each input under its own HD key.
    let no_utxos = tx.get("UTXOs").and_then(Value::as_array).map(|a| a.is_empty()).unwrap_or(true);
    if no_utxos {
        if let (Some(to), Some(amount)) =
            (tx.get("To").and_then(Value::as_str), tx.get("Amount").and_then(Value::as_u64))
        {
            let net = crate::models::network::fetch(env, "@")
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(400, "no current network"))?;
            if net.kind != "bitcoin" {
                return Err(ApiError::new(400, "current network is not bitcoin"));
            }
            let fee_rate = tx.get("FeeRate").and_then(Value::as_u64).unwrap_or(10);
            let raw = crate::bitcoin::build_and_sign_auto(
                env, &account.id, &unlock, rpc, &net.chain_id, to, amount, fee_rate,
            )
            .map_err(ApiError::internal)?;
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let txid = crate::rpc::call(rpc, "sendrawtransaction", serde_json::json!([hex]))
                .map_err(ApiError::internal)?;
            return Ok(serde_json::json!({ "txid": txid, "raw": format!("0x{hex}") }));
        }
    }

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
        keys.iter().filter(|k| matches!(k.kind.as_str(), "Password" | "StoreKey" | "Plain")).map(|k| (k.id.clone(), k.key.clone())).collect();
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
    let account = crate::models::account::fetch(env, account_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "account not found"))?;
    let rpc = resolve_rpc(env, params, &account.kind)?;
    let rpc = rpc.as_str();

    let bal = match account.kind.as_str() {
        "ethereum" => crate::rpc::eth_get_balance(rpc, &account.address).map_err(ApiError::internal)?,
        "solana" => {
            let res = crate::rpc::call(rpc, "getBalance", serde_json::json!([account.address]))
                .map_err(ApiError::internal)?;
            let raw = res
                .get("value")
                .and_then(Value::as_u64)
                .ok_or_else(|| ApiError::new(502, "unexpected getBalance response"))?;
            // Subtract the rent-exempt minimum so the reported balance is what
            // the user can actually spend (matching Go nativeBalance). RPC
            // failure falls back to the canonical 0-byte system-account reserve.
            let rent = crate::rpc::call(rpc, "getMinimumBalanceForRentExemption", serde_json::json!([0]))
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
            crate::bitcoin::native_balance_satoshi(rpc, &lookup)
                .map_err(ApiError::internal)?
                .to_string()
        }
        other => return Err(ApiError::new(400, format!("balance not supported for {other}"))),
    };
    Ok(serde_json::json!({ "address": account.address, "balance": bal }))
}

/// `Account:maxSendable` — the maximum native amount an EVM account can send:
/// balance − (21000 × gasPrice) reserved for the fee (Go maxSendableEVM, legacy
/// fee path). {RPC?} — returns {chain, balance, fee, max} as amounts.
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
/// param wins; otherwise fall back to the current network's resolved RPC (Go
/// resolves RPC from the network — this covers Solana/Bitcoin, which have
/// endpoint defaults, without the host passing a URL). Errors when neither is
/// available or the current network's type doesn't match the account.
fn resolve_rpc(env: &Env, params: &Value, account_kind: &str) -> Result<String, ApiError> {
    if let Some(url) = params.get("RPC").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        return Ok(url.to_owned());
    }
    let net = crate::models::network::fetch(env, "@")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "RPC endpoint required (no current network)"))?;
    // account kind (ethereum/solana/bitcoin) -> network type (evm/solana/bitcoin).
    let want = match account_kind {
        "ethereum" => "evm",
        other => other,
    };
    if net.kind != want {
        return Err(ApiError::new(
            400,
            format!("current network is {} but account is {account_kind}; pass RPC", net.kind),
        ));
    }
    net.resolved_rpc().map_err(ApiError::internal)
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
