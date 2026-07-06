//! Web3 provider endpoints (port of `wltbase/injection.go` + `web3.go`). The
//! `Web3:injectionScript` builder plus the EIP-1193 `Web3:request` router.
//! Read-only + connect methods are wired here; the signing/send methods
//! (personal_sign, eth_sendTransaction, eth_signTypedData, solana_*, mpurse_*)
//! layer their transaction_sign / message_sign approvals on top and land next.

use num_bigint::BigInt;
use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

/// Object-scoped `Web3/Connection[/<id>]` routing (manage connected dApps).
/// GET (no id) lists (optional Host filter); GET/<id> fetches; POST creates a
/// {Host, Account} link; DELETE/<id> removes one.
pub fn connection_route(env: &Env, verb: &str, id: Option<&str>, params: &Value) -> ApiResult {
    match (verb, id) {
        ("GET", Some(id)) => match crate::models::connected_site::fetch(env, id).map_err(ApiError::internal)? {
            Some(c) => Ok(enrich_connection(env, &c)),
            None => Err(ApiError::new(404, "connection not found")),
        },
        ("GET", None) => {
            let host = params.get("Host").and_then(Value::as_str);
            let list = crate::models::connected_site::list(env, host).map_err(ApiError::internal)?;
            Ok(Value::Array(list.iter().map(|c| enrich_connection(env, c)).collect()))
        }
        ("POST", _) => {
            let host = params.get("Host").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| ApiError::new(400, "host cannot be empty"))?;
            let account = params.get("Account").and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "Account required"))?;
            let acct = crate::models::account::find(env, account).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "account not found"))?;
            crate::models::connected_site::connect(env, host, &acct.id).map_err(ApiError::internal)?;
            let created = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?
                .into_iter().find(|c| c.account == acct.id).ok_or_else(|| ApiError::new(500, "connection not saved"))?;
            Ok(enrich_connection(env, &created))
        }
        ("DELETE", Some(id)) => {
            crate::models::connected_site::delete(env, id).map_err(ApiError::internal)?;
            Ok(json!({ "deleted": true }))
        }
        (other, _) => Err(ApiError::new(405, format!("unsupported verb {other} for Web3/Connection"))),
    }
}

/// Serialize a connection with its joined AccountInfo (Go apiFetch/List).
fn enrich_connection(env: &Env, c: &crate::models::connected_site::ConnectedSite) -> Value {
    let mut v = serde_json::to_value(c).unwrap_or(Value::Null);
    if let Ok(Some(acct)) = crate::models::account::fetch(env, &c.account) {
        v["AccountInfo"] = serde_json::to_value(acct).unwrap_or(Value::Null);
    }
    v
}

/// `Web3:request` {url, query:{method, params}} — the EIP-1193 provider entry.
/// Resolves the requesting site's `scheme://host` key, its connected accounts,
/// and the current network, then dispatches the JSON-RPC method.
pub fn request(env: &Env, params: &Value) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let query = params.get("query").cloned().unwrap_or(Value::Null);
    let method = query.get("method").and_then(Value::as_str).unwrap_or("");
    let q_params = query.get("params").and_then(Value::as_array).cloned().unwrap_or_default();

    let key = host_key(url).ok_or_else(|| ApiError::new(400, "url: host is missing"))?;
    let net = crate::models::network::fetch(env, "@")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(400, "no current network"))?;

    match method {
        "eth_chainId" => {
            let n = BigInt::parse_bytes(net.chain_id.as_bytes(), 10).unwrap_or_else(|| BigInt::from(0));
            Ok(json!(format!("0x{n:x}")))
        }
        "net_version" => Ok(json!(net.chain_id)),
        "web3_clientVersion" => Ok(json!(super::info::web3_client_version())),
        "web3_sha3" => {
            let v = q_params.first().and_then(Value::as_str).and_then(|s| decode_hex_0x(s))
                .ok_or_else(|| ApiError::new(400, "web3_sha3 expects one hex param"))?;
            let h = purecrypto::hash::keccak256(&v);
            Ok(json!(format!("0x{}", h.iter().map(|b| format!("{b:02x}")).collect::<String>())))
        }
        "eth_requestAccounts" => {
            connect_request(env, &key, "eth_requestAccounts", "evm", &[])?;
            let conn = crate::models::connected_site::for_host(env, &key).map_err(ApiError::internal)?;
            Ok(json!(collect_evm_addresses(env, &conn)))
        }
        "eth_accounts" => {
            let conn = crate::models::connected_site::for_host(env, &key).map_err(ApiError::internal)?;
            Ok(json!(collect_evm_addresses(env, &conn)))
        }
        "wallet_requestPermissions" => {
            let perms = extract_requested_perms(&q_params)?;
            if !perms.is_empty() {
                connect_request(env, &key, "wallet_requestPermissions", "evm", &perms)?;
            }
            let conn = crate::models::connected_site::for_host(env, &key).map_err(ApiError::internal)?;
            Ok(json!(eth_accounts_permission(env, &key, &conn)))
        }
        "wallet_getPermissions" => {
            let conn = crate::models::connected_site::for_host(env, &key).map_err(ApiError::internal)?;
            Ok(json!(eth_accounts_permission(env, &key, &conn)))
        }
        "personal_sign" => personal_sign(env, &key, &q_params),
        "personal_ecRecover" => {
            let msg = q_params.first().and_then(Value::as_str).and_then(decode_hex_0x)
                .ok_or_else(|| ApiError::new(400, "personal_ecRecover: message must be 0x-hex"))?;
            let sig = q_params.get(1).and_then(Value::as_str).and_then(decode_hex_0x)
                .ok_or_else(|| ApiError::new(400, "personal_ecRecover: signature must be 0x-hex"))?;
            let addr = crate::evm::personal_ec_recover(&msg, &sig).map_err(|e| ApiError::new(400, e.to_string()))?;
            Ok(json!(addr))
        }
        "eth_signTypedData_v4" | "eth_signTypedData_v3" | "eth_signTypedData" => sign_typed_data(env, &key, method, &q_params),
        "eth_sendTransaction" => eth_send_transaction(env, &key, &q_params),
        "solana_connect" | "solana_requestAccounts" => {
            connect_request(env, &key, method, "solana", &[])?;
            let conn = crate::models::connected_site::for_host(env, &key).map_err(ApiError::internal)?;
            Ok(json!({ "publicKey": connected_addresses(env, &conn) }))
        }
        "solana_accounts" => {
            let conn = crate::models::connected_site::for_host(env, &key).map_err(ApiError::internal)?;
            Ok(json!(connected_addresses(env, &conn)))
        }
        "solana_disconnect" => {
            let conn = crate::models::connected_site::for_host(env, &key).map_err(ApiError::internal)?;
            for c in &conn {
                crate::models::connected_site::delete(env, &c.id).map_err(ApiError::internal)?;
            }
            Ok(Value::Null)
        }
        "solana_signMessage" => solana_sign_message(env, &key, &q_params),
        "solana_signTransaction" | "solana_signAndSendTransaction" => solana_sign_tx(env, &key, method, &q_params),
        "wallet_switchEthereumChain" => wallet_switch_chain(env, &key, &q_params),
        "wallet_addEthereumChain" => wallet_add_chain(env, &key, &q_params),
        "mpurse_getAddress" => mpurse_get_address(env, &key),
        "mpurse_sendRawTransaction" => rpc_passthrough(&net, params, "sendrawtransaction", &q_params),
        "mpurse_sendAsset" => Err(ApiError::new(
            501,
            "mpurse_sendAsset is not implemented; build via counterparty + signRawTransaction",
        )),
        "mpurse_signMessage" | "mpurse_signRawTransaction" => Err(ApiError::new(
            501,
            format!("Web3:request {method} needs Bitcoin message/tx signing (pending)"),
        )),
        // Open relay: forward any other JSON-RPC method to the active network
        // (Go's default — many dApps depend on eth_call / eth_getLogs / etc.).
        other => rpc_passthrough(&net, params, other, &q_params),
    }
}

/// `mpurse_getAddress` — connect a bitcoin-family account (prompting once) and
/// return its address.
fn mpurse_get_address(env: &Env, host: &str) -> ApiResult {
    let mut conn = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?;
    if conn.is_empty() {
        connect_request(env, host, "mpurse_getAddress", "bitcoin", &[])?;
        conn = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?;
    }
    let account = crate::models::account::find(env, &conn.first().ok_or_else(|| ApiError::new(400, "no account connected"))?.account)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "connected account not found"))?;
    Ok(json!(account.address))
}

/// Forward a JSON-RPC call to the current network (the provider's open-relay /
/// broadcast path). The RPC endpoint is the current network's resolved RPC, or
/// a `RPC` param override (for tests / explicit routing).
fn rpc_passthrough(net: &crate::models::network::Network, params: &Value, method: &str, rpc_params: &[Value]) -> ApiResult {
    let rpc = match params.get("RPC").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => net.resolved_rpc().map_err(|e| ApiError::new(400, e.to_string()))?,
    };
    crate::rpc::call(&rpc, method, Value::Array(rpc_params.to_vec())).map_err(ApiError::internal)
}

/// `personal_sign` params [messageHex, signAddr?] — raise a `message_sign`
/// approval; the Request:approve message_sign arm performs the EIP-191 sign and
/// stores the 0x-hex signature in the request Result, which we return.
fn personal_sign(env: &Env, host: &str, q_params: &[Value]) -> ApiResult {
    let msg_hex = q_params.first().and_then(Value::as_str).ok_or_else(|| ApiError::new(400, "personal_sign requires a message"))?;
    if !msg_hex.starts_with("0x") {
        return Err(ApiError::new(400, "personal_sign: value must start with 0x"));
    }
    let message = decode_hex_0x(msg_hex).ok_or_else(|| ApiError::new(400, "personal_sign: invalid value hex"))?;

    let conn = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?;
    if conn.is_empty() {
        return Err(ApiError::new(400, "no addr available"));
    }
    // Choose the account: params[1] address if given, else the first connected.
    let account = match q_params.get(1).and_then(Value::as_str) {
        Some(addr) => {
            let want = addr.to_lowercase();
            conn.iter()
                .filter_map(|c| crate::models::account::find(env, &c.account).ok().flatten())
                .find(|a| a.address.to_lowercase() == want)
                .ok_or_else(|| ApiError::new(400, "requested address not connected"))?
        }
        None => crate::models::account::find(env, &conn[0].account)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(404, "connected account not found"))?,
    };

    use base64::Engine;
    let value = json!({
        "method": "personal_sign",
        "chain": "evm",
        "account": account.address,
        "origin": host,
        "messageBytes": base64::engine::general_purpose::STANDARD.encode(&message),
    });
    let req = crate::models::request::Request {
        kind: "message_sign".into(),
        host: host.to_owned(),
        account: Some(account.id.clone()),
        value: Some(value),
        ..Default::default()
    };
    let out = super::request::run(env, req)?;
    out.result.ok_or_else(|| ApiError::new(500, "sign approval produced no result"))
}

/// `wallet_addEthereumChain` params [AddEthereumChainParameter] — validate the
/// proposed chain, no-op if already registered, else raise an `add_network`
/// approval whose approve arm persists the Network row (Go path).
fn wallet_add_chain(env: &Env, host: &str, q_params: &[Value]) -> ApiResult {
    let p = q_params.first().and_then(Value::as_object).ok_or_else(|| ApiError::new(400, "wallet_addEthereumChain requires 1 parameter"))?;

    let chain_id_hex = p.get("chainId").and_then(Value::as_str).unwrap_or("");
    // EIP-3085: 0x-prefixed, unpadded, non-zero hex.
    let chain_dec = chain_id_hex
        .strip_prefix("0x")
        .and_then(|h| BigInt::parse_bytes(h.as_bytes(), 16))
        .filter(|n| format!("0x{n:x}") == chain_id_hex && n.sign() == num_bigint::Sign::Plus)
        .ok_or_else(|| ApiError::new(-32602, "Expected 0x-prefixed, unpadded, non-zero hexadecimal string 'chainId'."))?
        .to_string();
    let name = p.get("chainName").and_then(Value::as_str).unwrap_or("");
    if name.len() < 3 {
        return Err(ApiError::new(-32602, "Expected chainName"));
    }
    let nc = p.get("nativeCurrency").and_then(Value::as_object);
    let symbol = nc.and_then(|c| c.get("symbol")).and_then(Value::as_str).unwrap_or("");
    if !(2..=6).contains(&symbol.len()) {
        return Err(ApiError::new(-32602, "Expected 2-6 character string 'nativeCurrency.symbol'."));
    }
    let decimals = nc.and_then(|c| c.get("decimals")).and_then(Value::as_i64).unwrap_or(18);
    let rpc = p.get("rpcUrls").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("auto");
    let explorer = p.get("blockExplorerUrls").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("auto");
    // Reject non-http(s) RPC endpoints (SSRF guard, minimal form of Go's check).
    if rpc != "auto" && !rpc.starts_with("https://") && !rpc.starts_with("http://") {
        return Err(ApiError::new(-32602, "Invalid rpcUrls entry: must be http(s)"));
    }

    let net_id = format!("evm.{chain_dec}");
    if crate::models::network::by_id_opt(env, &net_id) {
        return Ok(Value::Null); // already registered — no-op
    }

    let network = json!({
        "Id": net_id, "Type": "evm", "ChainId": chain_dec, "Name": name,
        "RPC": rpc, "CurrencySymbol": symbol, "CurrencyDecimals": decimals,
        "BlockExplorer": explorer,
    });
    let req = crate::models::request::Request {
        kind: "add_network".into(),
        host: host.to_owned(),
        value: Some(json!({ "method": "wallet_addEthereumChain", "network": network })),
        ..Default::default()
    };
    super::request::run(env, req)?;
    Ok(Value::Null)
}

/// `wallet_switchEthereumChain` params [{chainId:"0x…"}] (or a bare hex string) —
/// raise a `chain_switch` approval; the approve arm sets the current network.
/// EVM→EVM only, so the account address is unchanged (no re-derivation needed).
fn wallet_switch_chain(env: &Env, host: &str, q_params: &[Value]) -> ApiResult {
    let p = q_params.first().ok_or_else(|| ApiError::new(400, "wallet_switchEthereumChain requires 1 parameter"))?;
    let chain_hex = match p {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.get("chainId").and_then(Value::as_str).unwrap_or("").to_string(),
        _ => String::new(),
    };
    if chain_hex.is_empty() {
        return Err(ApiError::new(400, r#"wallet_switchEthereumChain: expected { chainId: "0x…" } or a bare hex chainId"#));
    }
    let chain_dec = parse_chain_id_any(&chain_hex).ok_or_else(|| ApiError::new(400, format!("failed to parse chain id {chain_hex}")))?;
    // Known if already stored or present in the static chain registry.
    let target_id = format!("evm.{chain_dec}");
    let known = crate::models::network::by_id_opt(env, &target_id) || chain_dec.parse::<u64>().map(|c| ethrpc_rs::chains::get(c).is_some()).unwrap_or(false);
    if !known {
        return Err(ApiError::new(4902, "Unrecognized chain ID. Try adding the chain using wallet_addEthereumChain first."));
    }
    let value = json!({
        "method": "wallet_switchEthereumChain",
        "chain": "evm",
        "targetNetwork": target_id,
        "chainId": chain_hex,
    });
    let req = crate::models::request::Request {
        kind: "chain_switch".into(),
        host: host.to_owned(),
        value: Some(value),
        ..Default::default()
    };
    super::request::run(env, req)?;
    Ok(Value::Null)
}

/// Parse a chain id given as decimal or 0x-hex into its decimal-string form.
fn parse_chain_id_any(s: &str) -> Option<String> {
    let n = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigInt::parse_bytes(h.as_bytes(), 16)?
    } else {
        BigInt::parse_bytes(s.as_bytes(), 10)?
    };
    Some(n.to_string())
}

/// `solana_signMessage` params [{message: base64, pubkey?: base58}] — raise a
/// `message_sign` approval (solana family); the approve arm FROST-signs and the
/// Result carries {signature, publicKey}.
fn solana_sign_message(env: &Env, host: &str, q_params: &[Value]) -> ApiResult {
    let obj = q_params.first().and_then(Value::as_object).ok_or_else(|| ApiError::new(400, "solana_signMessage param must be an object"))?;
    let msg_b64 = obj.get("message").and_then(Value::as_str).filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, "solana_signMessage: message is required"))?;
    let pubkey = obj.get("pubkey").and_then(Value::as_str).unwrap_or("");

    let conn = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?;
    if conn.is_empty() {
        return Err(ApiError::new(400, "no account connected"));
    }
    let account = if pubkey.is_empty() {
        crate::models::account::find(env, &conn[0].account).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "connected account not found"))?
    } else {
        conn.iter()
            .filter_map(|c| crate::models::account::find(env, &c.account).ok().flatten())
            .find(|a| a.address == pubkey)
            .ok_or_else(|| ApiError::new(400, "requested pubkey not connected"))?
    };

    let value = json!({
        "method": "solana_signMessage",
        "chain": "solana",
        "account": account.address,
        "origin": host,
        "messageBytes": msg_b64, // already base64 from the dApp
    });
    let req = crate::models::request::Request {
        kind: "message_sign".into(),
        host: host.to_owned(),
        account: Some(account.id.clone()),
        value: Some(value),
        ..Default::default()
    };
    let out = super::request::run(env, req)?;
    out.result.ok_or_else(|| ApiError::new(500, "sign approval produced no result"))
}

/// `solana_signTransaction` / `solana_signAndSendTransaction` params
/// [{transaction: base64}] — raise a `transaction_sign` approval; the approve
/// arm FROST-signs the message, splices the signature, and (for the send form)
/// broadcasts. Returns the approval Result.
fn solana_sign_tx(env: &Env, host: &str, method: &str, q_params: &[Value]) -> ApiResult {
    let obj = q_params.first().and_then(Value::as_object).ok_or_else(|| ApiError::new(400, format!("{method} param must be an object")))?;
    let tx_b64 = obj.get("transaction").and_then(Value::as_str).filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(400, format!("{method}: transaction is required")))?;

    let conn = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?;
    if conn.is_empty() {
        return Err(ApiError::new(400, "no account connected"));
    }
    let account = crate::models::account::find(env, &conn[0].account)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "connected account not found"))?;

    let value = json!({ "method": method, "chain": "solana", "raw": tx_b64 });
    let req = crate::models::request::Request {
        kind: "transaction_sign".into(),
        host: host.to_owned(),
        account: Some(account.id.clone()),
        value: Some(value),
        ..Default::default()
    };
    let out = super::request::run(env, req)?;
    out.result.ok_or_else(|| ApiError::new(500, "transaction approval produced no result"))
}

/// Addresses of a host's connected accounts (any curve — used by solana_*).
fn connected_addresses(env: &Env, conn: &[crate::models::connected_site::ConnectedSite]) -> Vec<String> {
    conn.iter()
        .filter_map(|c| crate::models::account::find(env, &c.account).ok().flatten())
        .map(|a| a.address)
        .collect()
}

/// `eth_signTypedData_v3/v4` params [address, typedData] — raise a `message_sign`
/// approval carrying the typed-data JSON; the approve arm EIP-712 hashes + signs.
fn sign_typed_data(env: &Env, host: &str, method: &str, q_params: &[Value]) -> ApiResult {
    if q_params.len() < 2 {
        return Err(ApiError::new(400, format!("{method} requires [address, typedData]")));
    }
    let want = q_params[0].as_str().unwrap_or("").to_lowercase();
    // typedData is a JSON object or a JSON string; normalize to a string.
    let typed_data_str = match &q_params[1] {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    // Validate it up front so a malformed payload fails before the prompt.
    crate::eip712::parse(&typed_data_str).map_err(|e| ApiError::new(400, e))?;

    let conn = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?;
    if conn.is_empty() {
        return Err(ApiError::new(400, "no addr available"));
    }
    let account = if want.is_empty() {
        crate::models::account::find(env, &conn[0].account).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "connected account not found"))?
    } else {
        conn.iter()
            .filter_map(|c| crate::models::account::find(env, &c.account).ok().flatten())
            .find(|a| a.address.to_lowercase() == want)
            .ok_or_else(|| ApiError::new(400, "requested address not connected"))?
    };

    let value = json!({
        "method": method,
        "chain": "evm",
        "account": account.address,
        "origin": host,
        "typedData": typed_data_str,
    });
    let req = crate::models::request::Request {
        kind: "message_sign".into(),
        host: host.to_owned(),
        account: Some(account.id.clone()),
        value: Some(value),
        ..Default::default()
    };
    let out = super::request::run(env, req)?;
    out.result.ok_or_else(|| ApiError::new(500, "sign approval produced no result"))
}

/// `eth_sendTransaction` params [txObject] — normalize the dApp's hex-quantity
/// tx, authorize the sender, raise a `transaction_sign` approval, and return the
/// broadcast tx hash (the approval arm builds/signs/broadcasts + persists).
fn eth_send_transaction(env: &Env, host: &str, q_params: &[Value]) -> ApiResult {
    let raw_tx = q_params.first().and_then(Value::as_object).ok_or_else(|| ApiError::new(400, "eth_sendTransaction requires a transaction object"))?;
    let from = raw_tx.get("from").and_then(Value::as_str).unwrap_or("").to_string();

    // Authorization: `from` must be a connected EVM address for this origin.
    let conn = crate::models::connected_site::for_host(env, host).map_err(ApiError::internal)?;
    let authorized = collect_evm_addresses(env, &conn).iter().any(|a| a.eq_ignore_ascii_case(&from));
    if !authorized {
        return Err(ApiError::new(400, "eth_sendTransaction: from address is not a connected account for this origin"));
    }

    // Normalize hex quantities to the shape transaction::sign_and_send expects.
    let mut tx = json!({ "type": "evm", "from": from });
    if let Some(to) = raw_tx.get("to").and_then(Value::as_str) {
        tx["to"] = json!(to);
    }
    if let Some(d) = raw_tx.get("data").and_then(Value::as_str) {
        tx["data"] = json!(d);
    }
    if let Some(v) = raw_tx.get("value").and_then(Value::as_str).and_then(hex_qty_dec) {
        tx["value"] = json!(v);
    }
    if let Some(g) = raw_tx.get("gas").and_then(Value::as_str).and_then(hex_qty_u64) {
        tx["gas"] = json!(g);
    }
    if let Some(n) = raw_tx.get("nonce").and_then(Value::as_str).and_then(hex_qty_u64) {
        tx["nonce"] = json!(n);
    }
    if let Some(p) = raw_tx.get("gasPrice").and_then(Value::as_str).and_then(hex_qty_dec) {
        tx["gasPrice"] = json!(p);
    }
    if let Some(p) = raw_tx.get("maxFeePerGas").and_then(Value::as_str).and_then(hex_qty_dec) {
        tx["maxFeePerGas"] = json!(p);
    }
    if let Some(p) = raw_tx.get("maxPriorityFeePerGas").and_then(Value::as_str).and_then(hex_qty_dec) {
        tx["maxPriorityFeePerGas"] = json!(p);
    }

    let req = crate::models::request::Request {
        kind: "transaction_sign".into(),
        host: host.to_owned(),
        account: Some(from),
        transaction: Some(tx),
        value: Some(json!({ "method": "eth_sendTransaction", "chain": "evm" })),
        ..Default::default()
    };
    let out = super::request::run(env, req)?;
    out.result.ok_or_else(|| ApiError::new(500, "transaction approval produced no result"))
}

/// Convert a 0x-hex quantity to a decimal string.
fn hex_qty_dec(s: &str) -> Option<String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    Some(BigInt::parse_bytes(s.as_bytes(), 16)?.to_string())
}

/// Convert a 0x-hex quantity to u64.
fn hex_qty_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(s, 16).ok()
}

/// Raise a `connect` approval request and block until the host resolves it. On
/// approval the accounts are persisted by the Request:approve `connect` arm.
fn connect_request(env: &Env, host: &str, method: &str, family: &str, perms: &[String]) -> Result<(), ApiError> {
    let value = build_connect_value(env, host, method, family, perms);
    let req = crate::models::request::Request {
        kind: "connect".into(),
        host: host.to_owned(),
        value: Some(value),
        ..Default::default()
    };
    super::request::run(env, req)?;
    Ok(())
}

/// The `scheme://host` key for a request URL (Go: `url.URL{Scheme,Host}`).
fn host_key(raw: &str) -> Option<String> {
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    // Host is everything up to the first '/', '?' or '#'.
    let host: String = rest.chars().take_while(|&c| c != '/' && c != '?' && c != '#').collect();
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

/// EVM (secp256k1) 0x-addresses among a host's connected accounts.
fn collect_evm_addresses(env: &Env, conn: &[crate::models::connected_site::ConnectedSite]) -> Vec<String> {
    let mut out = Vec::with_capacity(conn.len());
    for c in conn {
        let Ok(Some(a)) = crate::models::account::find(env, &c.account) else { continue };
        if !a.curve.is_empty() && a.curve != "secp256k1" {
            continue;
        }
        if a.address.is_empty() || a.address == "N/A" {
            continue;
        }
        let lower = a.address.to_lowercase();
        if !lower.starts_with("0x") {
            continue;
        }
        out.push(a.address);
    }
    out
}

/// EIP-2255 permission wire shape for wallet_get/requestPermissions: a single
/// `eth_accounts` entry whose caveat carries every authorised EVM address.
fn eth_accounts_permission(env: &Env, host: &str, conn: &[crate::models::connected_site::ConnectedSite]) -> Vec<Value> {
    let addrs = collect_evm_addresses(env, conn);
    if addrs.is_empty() {
        return Vec::new();
    }
    // Stable id derived from the host so the dApp recognises it across calls.
    let id: String = purecrypto::hash::sha256(host.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect();
    vec![json!({
        "id": id,
        "parentCapability": "eth_accounts",
        "invoker": host,
        "caveats": [{ "type": "restrictReturnedAccounts", "value": addrs }],
    })]
}

/// The rich connect-approval Value (Go `buildConnectValue`): the method, family,
/// curve-compatible available accounts, and already-connected account ids.
fn build_connect_value(env: &Env, host: &str, method: &str, family: &str, perms: &[String]) -> Value {
    let curve = match family {
        "evm" | "bitcoin" => "secp256k1",
        "solana" => "ed25519",
        _ => "",
    };
    let available: Vec<Value> = if curve.is_empty() {
        Vec::new()
    } else {
        crate::models::account::list(env)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.curve == curve)
            .map(|a| serde_json::to_value(a).unwrap_or(Value::Null))
            .collect()
    };
    let already: Vec<String> = crate::models::connected_site::for_host(env, host)
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.account)
        .collect();
    let mut v = json!({ "method": method, "family": family });
    if !available.is_empty() {
        v["availableAccounts"] = json!(available);
    }
    if !already.is_empty() {
        v["alreadyConnected"] = json!(already);
    }
    if !perms.is_empty() {
        v["requestedPermissions"] = json!(perms);
    }
    v
}

fn extract_requested_perms(q_params: &[Value]) -> Result<Vec<String>, ApiError> {
    let obj = q_params
        .first()
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::new(400, "wallet_requestPermissions requires one object param"))?;
    let mut perms = Vec::new();
    for k in obj.keys() {
        match k.as_str() {
            "eth_accounts" => perms.push(k.clone()),
            other => return Err(ApiError::new(400, format!("unsupported permission {other}"))),
        }
    }
    Ok(perms)
}

fn decode_hex_0x(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// The webview provider shim, with the config placeholder the Go side rewrites.
const PROVIDER_JS: &str = include_str!("../web3/provider.js");
const CONFIG_PLACEHOLDER: &str = "__LIBWALLET_CONFIG__";

/// `Web3:injectionScript` {Name, Rdns, Uuid, Icon?, Bridge, Host?} — build the
/// JS blob the host runs inside a webview to expose libwallet as an EIP-6963 /
/// window.solana / window.mpurse provider. Substitutes `__LIBWALLET_CONFIG__`
/// with the per-install config, pre-seeding `initialChainId` from the current
/// EVM network so the provider can answer `eth_chainId` on first paint.
pub fn injection_script(env: &Env, params: &Value) -> ApiResult {
    let req = |k: &str| -> Result<String, ApiError> {
        params
            .get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::new(400, format!("{k} is required")))
    };
    let name = req("Name")?;
    let rdns = req("Rdns")?;
    let uuid = req("Uuid")?;
    let bridge = req("Bridge")?;
    let icon = params.get("Icon").and_then(Value::as_str).unwrap_or("");

    let mut cfg = json!({
        "name": name,
        "rdns": rdns,
        "uuid": uuid,
        "icon": icon,
        "bridge": bridge,
    });

    // Initial state — lets the provider answer eth_chainId synchronously on
    // first paint. Best-effort: on any failure we omit it (Go does the same).
    if let Ok(Some(n)) = crate::models::network::fetch(env, "@") {
        if n.kind == "evm" {
            if let Ok(chain) = n.chain_id.parse::<u128>() {
                cfg["initialChainId"] = json!(format!("0x{chain:x}"));
                cfg["initialNetworkVersion"] = json!(n.chain_id);
            }
        }
    }

    // `Host`/`initialAccounts` pre-seeding depends on the connected-site
    // permission store (Web3:request), ported alongside that endpoint.

    let cfg_json = serde_json::to_string(&cfg).map_err(ApiError::internal)?;
    let script = PROVIDER_JS.replace(CONFIG_PLACEHOLDER, &cfg_json);
    Ok(json!({ "script": script }))
}
