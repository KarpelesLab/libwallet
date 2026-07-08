//! `ClawdWallet:pair` — verify a pairing link against a Clawd agent over Spot.
//! Port of wltwallet/pair.go: parse a `tibane://pair?agent&token` URL, send a
//! single Spot Query to `<agent>/pair` carrying {v, token, mobile_spot_id}, and
//! dispatch the agent's response into a verified identity or a typed error code.
//!
//! The error strings here are the wire-level codes the Go side surfaced to Dart
//! verbatim (plain `errors.New(code)`), so the host dispatcher branches on them.

use serde_json::{json, Value};

use crate::transfer::url_unescape;

pub const PAIR_PROTOCOL_VERSION: i64 = 1;

/// Parse a `tibane://pair?agent=k.<b64url>&token=<tok>` URL → `(agent_spot_id,
/// token)`. Any validation failure collapses to `url_malformed` (Go
/// `parseClawdPairURL` — the Dart side treats all sub-reasons the same).
pub fn parse_clawd_pair_url(raw: &str) -> Result<(String, String), &'static str> {
    if raw.is_empty() {
        return Err("url_malformed");
    }
    let rest = raw.strip_prefix("tibane://").ok_or("url_malformed")?;
    // `tibane://pair?...` → host segment "pair" then query. Accept the path
    // form (`tibane://pair`) too; the target segment must equal "pair".
    let (target_and_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let target = target_and_path.split('/').next().unwrap_or("").trim_start_matches('/');
    if target != "pair" {
        return Err("url_malformed");
    }
    let (mut agent, mut token) = (String::new(), String::new());
    for kv in query.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = url_unescape(v);
        match k {
            "agent" => agent = v,
            "token" => token = v,
            _ => {}
        }
    }
    if agent.is_empty() || token.is_empty() {
        return Err("url_malformed");
    }
    // Spot ids are `k.<base64url>`; reject obvious garbage before the query.
    if !agent.starts_with("k.") || agent.len() < 4 {
        return Err("url_malformed");
    }
    Ok((agent, token))
}

/// Parse the agent's raw Spot response. Success shape is returned as-is (with a
/// normalised `capabilities` object); the error shape maps to its wire code.
/// Anything malformed / wrong-version / mismatched-identity fails closed (Go
/// `dispatchPairResponse`).
pub fn dispatch_pair_response(raw: &[u8], expected_agent_id: &str) -> Result<Value, &'static str> {
    if raw.is_empty() {
        return Err("bad_request");
    }
    let probe: Value = serde_json::from_slice(raw).map_err(|_| "bad_request")?;
    let obj = probe.as_object().ok_or("bad_request")?;

    if let Some(err) = obj.get("error").and_then(Value::as_str) {
        return Err(match err {
            "token_invalid" => "token_invalid",
            "token_expired" => "token_expired",
            "token_consumed" => "token_consumed",
            // bad_request + any unknown code → fail closed.
            _ => "bad_request",
        });
    }

    if obj.get("v").and_then(Value::as_i64) != Some(PAIR_PROTOCOL_VERSION) {
        return Err("bad_request");
    }
    let agent_spot_id = obj.get("agent_spot_id").and_then(Value::as_str).unwrap_or("");
    if agent_spot_id.is_empty() {
        return Err("bad_request");
    }
    if agent_spot_id != expected_agent_id {
        return Err("identity_mismatch");
    }
    // Normalise a nil/absent capabilities map to {} so the host can probe keys.
    let capabilities = match obj.get("capabilities") {
        Some(Value::Object(m)) => Value::Object(m.clone()),
        _ => json!({}),
    };
    let mut out = json!({
        "v": PAIR_PROTOCOL_VERSION,
        "agent_spot_id": agent_spot_id,
        "capabilities": capabilities,
    });
    for k in ["suggested_name", "agent_version"] {
        if let Some(s) = obj.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            out[k] = json!(s);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_ok_and_bad() {
        let (a, t) = parse_clawd_pair_url("tibane://pair?agent=k.abcd&token=xyz%2B123").unwrap();
        assert_eq!(a, "k.abcd");
        assert_eq!(t, "xyz+123");
        assert_eq!(parse_clawd_pair_url("https://x").unwrap_err(), "url_malformed");
        assert_eq!(parse_clawd_pair_url("tibane://nope?agent=k.a&token=t").unwrap_err(), "url_malformed");
        assert_eq!(parse_clawd_pair_url("tibane://pair?token=t").unwrap_err(), "url_malformed");
        assert_eq!(parse_clawd_pair_url("tibane://pair?agent=bad&token=t").unwrap_err(), "url_malformed");
    }

    #[test]
    fn dispatch_success_error_and_mismatch() {
        let ok = dispatch_pair_response(
            br#"{"v":1,"agent_spot_id":"k.agent","suggested_name":"laptop","capabilities":{"sign":true}}"#,
            "k.agent",
        )
        .unwrap();
        assert_eq!(ok["agent_spot_id"], "k.agent");
        assert_eq!(ok["suggested_name"], "laptop");
        assert_eq!(ok["capabilities"]["sign"], true);

        // nil capabilities normalises to {}
        let ok2 = dispatch_pair_response(br#"{"v":1,"agent_spot_id":"k.a"}"#, "k.a").unwrap();
        assert_eq!(ok2["capabilities"], json!({}));

        assert_eq!(
            dispatch_pair_response(br#"{"v":1,"error":"token_expired"}"#, "k.a").unwrap_err(),
            "token_expired",
        );
        assert_eq!(
            dispatch_pair_response(br#"{"v":1,"error":"weird_code"}"#, "k.a").unwrap_err(),
            "bad_request",
        );
        assert_eq!(
            dispatch_pair_response(br#"{"v":1,"agent_spot_id":"k.other"}"#, "k.a").unwrap_err(),
            "identity_mismatch",
        );
        assert_eq!(
            dispatch_pair_response(br#"{"v":2,"agent_spot_id":"k.a"}"#, "k.a").unwrap_err(),
            "bad_request",
        );
        assert_eq!(dispatch_pair_response(b"", "k.a").unwrap_err(), "bad_request");
    }
}
