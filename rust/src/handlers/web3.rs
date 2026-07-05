//! Web3 provider endpoints (port of `wltbase/injection.go` + `web3.go`). The
//! `Web3:injectionScript` builder plus the EIP-1193 `Web3:request` router.
//! Read-only + connect methods are wired here; the signing/send methods
//! (personal_sign, eth_sendTransaction, eth_signTypedData, solana_*, mpurse_*)
//! layer their transaction_sign / message_sign approvals on top and land next.

use num_bigint::BigInt;
use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

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
        "eth_sendTransaction" => eth_send_transaction(env, &key, &q_params),
        other => Err(ApiError::new(
            501,
            format!("Web3:request method {other} is not yet ported (signing/send methods pending)"),
        )),
    }
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
