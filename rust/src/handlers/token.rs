//! Token object endpoints — full CRUD parity with the Go `wlttoken` object
//! (Fetch/List, Create, ApiUpdate, ApiDelete) plus `discoverToken` metadata
//! read. Create normalizes/validates in the model, reusing the same address
//! normalization and metadata sanitisation `discoverToken` feeds.

use serde_json::Value;

use crate::models::token::Token;
use crate::Env;

use super::{ApiError, ApiResult};

pub fn route(env: &Env, verb: &str, params: &Value) -> ApiResult {
    match verb {
        "GET" => match params.get("Id").and_then(Value::as_str) {
            Some(id) => match crate::models::token::fetch(env, id).map_err(ApiError::internal)? {
                Some(t) => Ok(serde_json::to_value(t).unwrap()),
                None => Err(ApiError::new(404, "token not found")),
            },
            None => Ok(serde_json::to_value(
                crate::models::token::list(env).map_err(ApiError::internal)?,
            )
            .unwrap()),
        },
        "POST" => {
            let t: Token = token_from_params(params);
            let created = crate::models::token::create(env, t)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            Ok(serde_json::to_value(created).unwrap())
        }
        "PATCH" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            let t = crate::models::token::update(env, id, params)
                .map_err(|e| ApiError::new(400, e.to_string()))?;
            Ok(serde_json::to_value(t).unwrap())
        }
        "DELETE" => {
            let id = params
                .get("Id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::new(400, "Id required"))?;
            crate::models::token::delete(env, id).map_err(ApiError::internal)?;
            Ok(serde_json::json!({ "deleted": true }))
        }
        other => Err(ApiError::new(405, format!("unsupported verb {other} for Token"))),
    }
}

/// Build a `Token` from the request params (PascalCase keys, matching the Go
/// wire form). `validate()` normalizes the address and fills the type default.
fn token_from_params(params: &Value) -> Token {
    let s = |k: &str| params.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    Token {
        id: String::new(),
        name: s("Name"),
        symbol: s("Symbol"),
        address: s("Address"),
        decimals: params.get("Decimals").and_then(Value::as_i64).unwrap_or(0),
        kind: s("Type"),
        network: s("Network"),
        logo: s("Logo"),
        memo: s("Memo"),
        created: String::new(),
        updated: String::new(),
    }
}

/// `Token:listCurated` {Network} — the embedded curated token list for a
/// canonical "<type>.<chainId>" chain key (Go apiListCurated). Always a JSON
/// array; the dynamic ChiefStaker (Solana mainnet) feed is not included.
pub fn list_curated(_env: &Env, params: &Value) -> ApiResult {
    let network = params
        .get("Network")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Network required (canonical \"<type>.<chainId>\")"))?;
    Ok(Value::Array(crate::curated::for_chain(network)))
}

use crate::models::token::{
    sanitize_token_text as sanitize_text, MAX_TOKEN_DECIMALS, MAX_TOKEN_NAME_LEN,
    MAX_TOKEN_SYMBOL_LEN,
};

// ERC-20 metadata selectors (keccak256(sig)[:4]).
const SEL_NAME: &str = "0x06fdde03";
const SEL_SYMBOL: &str = "0x95d89b41";
const SEL_DECIMALS: &str = "0x313ce567";
const SEL_TOTAL_SUPPLY: &str = "0x18160ddd";

/// `Token:discoverToken` {Network, Address} — read a token's metadata straight
/// from chain (Go apiDiscoverToken). EVM: name/symbol/decimals/totalSupply via
/// eth_call. Solana: getAccountInfo(jsonParsed) on the mint. Untrusted metadata
/// (decimals) is range-checked before it is trusted.
pub fn discover_token(env: &Env, params: &Value) -> ApiResult {
    let network = params
        .get("Network")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Network required"))?;
    let address = params
        .get("Address")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Address required"))?;

    let net = crate::models::network::fetch(env, network)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(404, "network not found"))?;
    let rpc = net.resolved_rpc().map_err(|e| ApiError::new(400, e.to_string()))?;

    match net.kind.as_str() {
        "evm" => discover_erc20(&rpc, address),
        "solana" => discover_spl(&rpc, address),
        other => Err(ApiError::new(400, format!("token discovery is not supported on {other} networks"))),
    }
}

fn discover_erc20(rpc: &str, address: &str) -> ApiResult {
    let name = eth_call_string(rpc, address, SEL_NAME)
        .map(|s| sanitize_text(&s, MAX_TOKEN_NAME_LEN))
        .unwrap_or_default();
    let symbol = eth_call_string(rpc, address, SEL_SYMBOL)
        .map(|s| sanitize_text(&s, MAX_TOKEN_SYMBOL_LEN))
        .unwrap_or_default();

    let mut decimals = 0i64;
    if let Ok(d) = eth_call_uint256(rpc, address, SEL_DECIMALS) {
        // Reject anything that doesn't fit a small, sane range rather than
        // truncating a uint256 into a (possibly negative) int.
        let di: i64 = (&d).try_into().map_err(|_| ApiError::new(422, format!("address {address} reports an out-of-range decimals value")))?;
        if !(0..=MAX_TOKEN_DECIMALS).contains(&di) {
            return Err(ApiError::new(422, format!("address {address} reports an invalid decimals value {di}")));
        }
        decimals = di;
    }

    let total_supply = eth_call_uint256(rpc, address, SEL_TOTAL_SUPPLY).map(|v| v.to_string()).ok();

    if name.is_empty() && symbol.is_empty() {
        return Err(ApiError::new(422, format!("address {address} does not appear to be an ERC-20 token contract")));
    }

    let mut out = serde_json::json!({
        "name": name, "symbol": symbol, "decimals": decimals,
        "address": address, "type": "erc20",
    });
    if let Some(ts) = total_supply {
        out["total_supply"] = Value::String(ts);
    }
    Ok(out)
}

fn discover_spl(rpc: &str, address: &str) -> ApiResult {
    let resp = crate::rpc::call(rpc, "getAccountInfo", serde_json::json!([address, { "encoding": "jsonParsed" }]))
        .map_err(ApiError::internal)?;
    let value = resp.get("value").filter(|v| !v.is_null())
        .ok_or_else(|| ApiError::new(404, format!("Solana account {address} not found")))?;
    let parsed = value.get("data").and_then(|d| d.get("parsed"));
    let typ = parsed.and_then(|p| p.get("type")).and_then(Value::as_str).unwrap_or("");
    if typ != "mint" {
        return Err(ApiError::new(422, format!("address {address} is not a token mint (type: {typ})")));
    }
    let info = parsed.and_then(|p| p.get("info"));
    let decimals = info.and_then(|i| i.get("decimals")).and_then(Value::as_i64).unwrap_or(0);
    if !(0..=MAX_TOKEN_DECIMALS).contains(&decimals) {
        return Err(ApiError::new(422, format!("address {address} reports an invalid decimals value {decimals}")));
    }
    let supply = info.and_then(|i| i.get("supply")).and_then(Value::as_str).unwrap_or("").to_owned();
    let program = value.get("data").and_then(|d| d.get("program")).and_then(Value::as_str).unwrap_or("");
    let token_type = if program == "spl-token-2022" { "spl-token-2022" } else { "spl-token" };

    let mut out = serde_json::json!({
        "address": address, "type": token_type, "decimals": decimals,
    });
    if !supply.is_empty() {
        out["total_supply"] = Value::String(supply);
    }
    Ok(out)
}

/// `eth_call` and decode an ABI-encoded string result. The offset/length words
/// are attacker-controlled, so every bound is range-checked before slicing
/// (a bogus length would otherwise panic the handler — remote DoS).
fn eth_call_string(rpc: &str, to: &str, selector: &str) -> Result<String, ApiError> {
    let out = crate::rpc::call(rpc, "eth_call", serde_json::json!([{ "to": to, "data": selector }, "latest"]))
        .map_err(ApiError::internal)?;
    let hex = out.as_str().ok_or_else(|| ApiError::new(502, "eth_call result not a string"))?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Err(ApiError::new(502, "empty response"));
    }
    let raw = decode_hex_bytes(hex).ok_or_else(|| ApiError::new(502, "bad hex in eth_call result"))?;

    // ABI string: [offset(32)][length(32)][bytes]. Accept the canonical
    // offset==32 layout with a bounded length; otherwise fall back to raw.
    if raw.len() >= 64 {
        let offset = be_u64(&raw[..32]);
        if offset == Some(32) {
            if let Some(len) = be_u64(&raw[32..64]) {
                let end = 64usize.checked_add(len as usize);
                if let Some(end) = end {
                    if end <= raw.len() {
                        return Ok(String::from_utf8_lossy(&raw[64..end]).trim().to_owned());
                    }
                }
            }
        }
    }
    // Fallback: raw bytes with control chars stripped.
    let s: String = String::from_utf8_lossy(&raw).chars().filter(|c| !c.is_control()).collect();
    Ok(s.trim().to_owned())
}

fn eth_call_uint256(rpc: &str, to: &str, selector: &str) -> Result<num_bigint::BigInt, ApiError> {
    let out = crate::rpc::call(rpc, "eth_call", serde_json::json!([{ "to": to, "data": selector }, "latest"]))
        .map_err(ApiError::internal)?;
    let hex = out.as_str().ok_or_else(|| ApiError::new(502, "eth_call result not a string"))?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let raw = decode_hex_bytes(hex).ok_or_else(|| ApiError::new(502, "bad hex in eth_call result"))?;
    Ok(num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &raw))
}

/// Interpret a 32-byte big-endian word as u64 if it fits (top 24 bytes zero).
fn be_u64(word: &[u8]) -> Option<u64> {
    if word.len() != 32 || word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(word[24..32].try_into().unwrap()))
}

fn decode_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SqlValue;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Serve `results` in order: for each incoming HTTP POST, reply with a
    /// JSON-RPC envelope wrapping the next canned `result`. Returns the URL.
    fn mock_rpc(results: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for result in results {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    /// ABI-encode a string as eth_call would return it: offset(32) + length(32)
    /// + right-padded UTF-8, quoted for the JSON-RPC `result`.
    fn abi_string(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut hex = String::from("0x");
        hex.push_str(&format!("{:064x}", 32)); // offset
        hex.push_str(&format!("{:064x}", bytes.len())); // length
        let mut data: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        while data.len() % 64 != 0 {
            data.push('0');
        }
        hex.push_str(&data);
        format!("\"{hex}\"")
    }

    fn abi_uint(n: u128) -> String {
        format!("\"0x{n:064x}\"")
    }

    fn evm_network(env: &Env, rpc: &str) {
        // network::init now seeds the built-in networks (incl. evm.1), which
        // would collide with this fixture on UNIQUE(Type,ChainId). Clear the
        // table so the test controls the (evm, 1) row and its mock RPC.
        env.exec(r#"DELETE FROM "Network""#, Vec::new()).unwrap();
        env.exec(
            r#"INSERT INTO "Network" ("Id","Type","ChainId","Name","RPC","CurrencySymbol","CurrencyDecimals","BlockExplorer","TestNet","Priority","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            vec![
                SqlValue::Text("net-evm".into()),
                SqlValue::Text("evm".into()),
                SqlValue::Text("1".into()),
                SqlValue::Text("Ethereum".into()),
                SqlValue::Text(rpc.into()),
                SqlValue::Text("ETH".into()),
                SqlValue::Int(18),
                SqlValue::Text("".into()),
                SqlValue::Int(0),
                SqlValue::Int(0),
                SqlValue::Text(crate::now_rfc3339()),
                SqlValue::Text(crate::now_rfc3339()),
            ],
        )
        .unwrap();
    }

    #[test]
    fn discover_erc20_decodes_metadata() {
        let env = Env::init_memory().unwrap();
        crate::models::network::init(&env).unwrap();
        // name, symbol, decimals, totalSupply — served in call order.
        let rpc = mock_rpc(vec![
            abi_string("Test Token"),
            abi_string("TT"),
            abi_uint(18),
            abi_uint(1_000_000),
        ]);
        evm_network(&env, &rpc);

        let out = discover_token(
            &env,
            &serde_json::json!({ "Network": "net-evm", "Address": "0xabc0000000000000000000000000000000000001" }),
        )
        .unwrap();
        assert_eq!(out["name"], "Test Token");
        assert_eq!(out["symbol"], "TT");
        assert_eq!(out["decimals"], 18);
        assert_eq!(out["total_supply"], "1000000");
        assert_eq!(out["type"], "erc20");
    }

    #[test]
    fn discover_erc20_rejects_insane_decimals() {
        let env = Env::init_memory().unwrap();
        crate::models::network::init(&env).unwrap();
        let rpc = mock_rpc(vec![
            abi_string("Bad"),
            abi_string("B"),
            abi_uint(255), // > MAX_TOKEN_DECIMALS (36)
            abi_uint(1),
        ]);
        evm_network(&env, &rpc);
        let err = discover_token(
            &env,
            &serde_json::json!({ "Network": "net-evm", "Address": "0xabc0000000000000000000000000000000000002" }),
        )
        .unwrap_err();
        assert_eq!(err.code, 422);
    }

    #[test]
    fn discover_spl_parses_mint() {
        let env = Env::init_memory().unwrap();
        crate::models::network::init(&env).unwrap();
        // Solana uses an explicit RPC; store it directly on a solana network.
        let account_info = r#"{"value":{"data":{"parsed":{"type":"mint","info":{"decimals":6,"supply":"5000000000","mintAuthority":null}},"program":"spl-token"}}}"#;
        let rpc = mock_rpc(vec![account_info.to_string()]);
        // Clear seeded networks (init now seeds solana.mainnet) so this fixture
        // doesn't collide on UNIQUE(Type,ChainId).
        env.exec(r#"DELETE FROM "Network""#, Vec::new()).unwrap();
        env.exec(
            r#"INSERT INTO "Network" ("Id","Type","ChainId","Name","RPC","CurrencySymbol","CurrencyDecimals","BlockExplorer","TestNet","Priority","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            vec![
                SqlValue::Text("net-sol".into()),
                SqlValue::Text("solana".into()),
                SqlValue::Text("mainnet".into()),
                SqlValue::Text("Solana".into()),
                SqlValue::Text(rpc.clone()),
                SqlValue::Text("SOL".into()),
                SqlValue::Int(9),
                SqlValue::Text("".into()),
                SqlValue::Int(0),
                SqlValue::Int(0),
                SqlValue::Text(crate::now_rfc3339()),
                SqlValue::Text(crate::now_rfc3339()),
            ],
        )
        .unwrap();

        let out = discover_token(
            &env,
            &serde_json::json!({ "Network": "net-sol", "Address": "So11111111111111111111111111111111111111112" }),
        )
        .unwrap();
        assert_eq!(out["type"], "spl-token");
        assert_eq!(out["decimals"], 6);
        assert_eq!(out["total_supply"], "5000000000");
    }
}
