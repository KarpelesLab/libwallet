//! Name resolution endpoint (ENS). `Name:resolve` {Name, RPC} -> {address}.

use serde_json::Value;

use crate::Env;

use super::{ApiError, ApiResult};

pub fn resolve(_env: &Env, params: &Value) -> ApiResult {
    let name = params
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "Name required"))?;
    let rpc = params
        .get("RPC")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(400, "RPC endpoint required"))?;
    // The endpoint is a request parameter: hold it to the same rules as a
    // stored network RPC (https, or http for localhost only; no internal hosts).
    crate::models::network::validate_rpc_url(rpc).map_err(|e| ApiError::new(400, e.to_string()))?;
    // `name` in the reply is the name as it was actually resolved (trimmed,
    // lowercased, and for ENS normalized), so the UI shows what was looked up.
    let (name, address) = if name.trim().to_lowercase().ends_with(".sol") {
        let name = name.trim().to_lowercase();
        let address = crate::names::resolve_sns(rpc, &name).map_err(ApiError::internal)?;
        (name, address)
    } else {
        let name = crate::names::normalize_ens_name(name).map_err(|e| ApiError::new(400, e.to_string()))?;
        let address = crate::names::resolve_ens(rpc, &name).map_err(ApiError::internal)?;
        (name, address)
    };
    Ok(serde_json::json!({ "name": name, "address": address }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Mock node serving `responses` in order (one request each).
    fn mock_multi(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for body in responses {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = s.read(&mut buf);
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                    let _ = s.write_all(resp.as_bytes());
                }
            }
        });
        format!("http://{addr}/")
    }

    #[test]
    fn reply_carries_the_name_as_resolved() {
        let env = Env::init_memory().unwrap();
        let word = |tail: &str| format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}{tail}"}}"#, "0".repeat(24));
        let url = mock_multi(vec![word(&"1".repeat(40)), word("000000000000000000000000000000000000dead")]);
        let out = resolve(&env, &json!({ "Name": "  Foo.ETH ", "RPC": url })).unwrap();
        assert_eq!(out["name"], "foo.eth");
        assert_eq!(out["address"], "0x000000000000000000000000000000000000dead");
    }

    #[test]
    fn refuses_unnormalizable_names_and_bad_rpc_urls() {
        let env = Env::init_memory().unwrap();
        // Zero-width space inside the name: refused before any request.
        let err = resolve(&env, &json!({ "Name": "vita\u{200b}lik.eth", "RPC": "http://127.0.0.1:1/" })).unwrap_err();
        assert_eq!(err.code, 400, "{}", err.message);
        // The RPC override is held to the network RPC rules.
        for rpc in ["http://example.com/rpc", "https://192.168.1.1/", "https://node.local/", "file:///etc/passwd", "ftp://example.com", ""] {
            let err = resolve(&env, &json!({ "Name": "foo.eth", "RPC": rpc })).unwrap_err();
            assert_eq!(err.code, 400, "{rpc}: {}", err.message);
        }
    }
}
