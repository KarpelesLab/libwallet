//! `Transaction:simulate` — preview a transaction without signing (port of the
//! EVM path of wlttx/simulate.go). Decodes the top-level call, then simulates
//! against the node: prefer `debug_traceCall` (callTracer for the full effect
//! tree + revert, prestateTracer for native balance changes), falling back to
//! `eth_call` + `eth_estimateGas`. Non-blocking approval warnings
//! (recipient-is-contract, unlimited-approve) are appended best-effort.
//!
//! Solana/Bitcoin simulation is deferred (returns `{chain, decodedMethod:
//! "unknown"}`); their raw-tx decoders follow.

use num_bigint::BigInt;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

// keccak256("Transfer(address,address,uint256)") / ("Approval(...)").
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const APPROVAL_TOPIC: &str = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const ERC20_TRANSFER_SELECTOR: &str = "a9059cbb";
const ERC20_APPROVE_SELECTOR: &str = "095ea7b3";

/// `Transaction:simulate` {tx fields, RPC?}. One async implementation shared by
/// native (`crate::rt::block_on`) and the browser (awaited in
/// `handle_request_async`); chain I/O runs over `rpc::call_async`. The target
/// chain comes from the tx `type`, and the endpoint from the Network model —
/// the client never names a URL.
pub async fn simulate_impl(env: &Env, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").unwrap_or(params);
    let kind = sim_kind(env, tx)?;
    if kind == "bitcoin" {
        // Decode-from-raw only (no RPC); the UTXO dry-run preview follows.
        return Ok(simulate_bitcoin(tx));
    }
    let rpc = super::resolve_rpc_for_kind(env, params, kind)?;
    match kind {
        "evm" => Ok(simulate_evm(&rpc, tx).await),
        _ => simulate_solana(&rpc, tx).await,
    }
}

/// Native `Transaction:simulate`: drive the shared async impl on the worker.
#[cfg(not(target_arch = "wasm32"))]
pub fn simulate(env: &Env, params: &Value) -> ApiResult {
    crate::rt::block_on(simulate_impl(env, params))
}

/// The chain a tx targets. A chain-specific tx `type` (solana_*/bitcoin_*/evm/
/// erc20_transfer) decides it directly — this is what the browser relies on
/// (multi-chain, no single current network). Otherwise fall back to the current
/// `@` network's kind (the native/Dart path), defaulting to EVM.
fn sim_kind(env: &Env, tx: &Value) -> Result<&'static str, ApiError> {
    Ok(match tx.get("type").and_then(Value::as_str).unwrap_or("") {
        "solana_transfer" | "solana_spl_transfer" => "solana",
        "bitcoin_transfer" => "bitcoin",
        "evm" | "erc20_transfer" | "transfer" => "evm",
        _ => match crate::models::network::fetch(env, "@")
            .map_err(ApiError::internal)?
            .map(|n| n.kind)
            .as_deref()
        {
            Some("solana") => "solana",
            Some("bitcoin") => "bitcoin",
            _ => "evm",
        },
    })
}

/// Bitcoin simulate: decode the built `raw` tx into its inputs/outputs (Go
/// `simulateBitcoin`, decode-from-raw path). The UTXO dry-run preview (no raw)
/// needs the build machinery and is deferred; here we surface the native
/// transfer decode plus, when `raw` is present, the on-wire shape.
fn simulate_bitcoin(tx: &Value) -> Value {
    let mut out = json!({ "chain": "bitcoin" });
    let to = tx.get("to").and_then(Value::as_str).unwrap_or("");
    if !to.is_empty() {
        if let Some(amt) = amount_bigint(tx.get("amount")) {
            out["decodedMethod"] = json!("native_transfer");
            out["decodedArgs"] = json!({ "to": to, "amount": amount_string(tx.get("amount"), &amt) });
        }
    }

    let raw = tx.get("raw").and_then(Value::as_str).filter(|s| !s.is_empty()).and_then(decode_tx_bytes);
    let Some(raw) = raw else { return out };

    match outscript::btctx::BtcTx::from_bytes(&raw) {
        Ok(btx) => {
            let outputs: Vec<Value> = btx
                .outputs
                .iter()
                .map(|o| json!({ "amount": o.amount.0, "script": hex_lower(&o.script) }))
                .collect();
            let inputs: Vec<Value> = btx
                .inputs
                .iter()
                .map(|i| json!({ "txid": hex_lower(&i.txid), "vout": i.vout }))
                .collect();
            if !outputs.is_empty() {
                out["bitcoinOutputs"] = json!(outputs);
            }
            if !inputs.is_empty() {
                out["bitcoinInputs"] = json!(inputs);
            }
            // Fee is only known when the caller carried it (per-input amounts
            // need a prev-tx lookup we don't do here — matches Go).
            if let Some(fee) = amount_bigint(tx.get("fee")) {
                if let Ok(f) = (&fee).try_into() {
                    let f: i64 = f;
                    out["bitcoinFee"] = json!(f);
                }
            }
            out["bitcoinVSize"] = json!(raw.len());
        }
        Err(e) => {
            out["willRevert"] = json!(true);
            out["revertReason"] = json!(format!("decode btc tx: {e}"));
        }
    }
    out
}

/// Solana simulate: `simulateTransaction` on the already-built `raw` bytes
/// (Go `simulateSolana`). Surfaces logs, unitsConsumed, and revert status.
async fn simulate_solana(rpc: &str, tx: &Value) -> ApiResult {
    let raw = tx.get("raw").and_then(Value::as_str).filter(|s| !s.is_empty());
    let raw = raw.and_then(decode_tx_bytes).ok_or_else(|| {
        ApiError::new(400, "solana tx has no raw bytes; build/validate it first")
    })?;
    let b64 = base64_std(&raw);

    let mut out = json!({ "chain": "solana" });
    let sim = crate::rpc::call_async(
        rpc,
        "simulateTransaction",
        json!([b64, { "sigVerify": false, "encoding": "base64", "commitment": "processed" }]),
    )
    .await;
    match sim {
        Err(e) => {
            out["willRevert"] = json!(true);
            out["revertReason"] = json!(e.to_string());
        }
        Ok(resp) => {
            let value = resp.get("value");
            if let Some(logs) = value.and_then(|v| v.get("logs")).filter(|v| v.is_array()) {
                out["logs"] = logs.clone();
            }
            if let Some(units) = value.and_then(|v| v.get("unitsConsumed")).and_then(Value::as_u64) {
                out["unitsConsumed"] = json!(units);
            }
            let err = value.and_then(|v| v.get("err")).filter(|v| !v.is_null());
            if let Some(err) = err {
                out["willRevert"] = json!(true);
                out["revertReason"] = json!(err.to_string());
            } else {
                out["willRevert"] = json!(false);
            }
        }
    }
    // Decode a native transfer from the tx shape (Go simulateSolana tail).
    if let Some(amt) = amount_bigint(tx.get("amount")).filter(|v| v.sign() == num_bigint::Sign::Plus) {
        out["decodedMethod"] = json!("native_transfer");
        out["decodedArgs"] = json!({
            "to": tx.get("to").and_then(Value::as_str).unwrap_or(""),
            "amount": amount_string(tx.get("amount"), &amt),
        });
    }
    Ok(out)
}

/// Decode a tx `raw` field as base64 (standard) or 0x-hex.
fn decode_tx_bytes(s: &str) -> Option<Vec<u8>> {
    if let Some(h) = s.strip_prefix("0x") {
        return hex_bytes(h);
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn base64_std(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

async fn simulate_evm(rpc: &str, tx: &Value) -> Value {
    let (decoded_method, decoded_args) = decode_evm_call(tx);

    let to = tx.get("to").and_then(Value::as_str).unwrap_or("");
    let from = tx.get("from").and_then(Value::as_str).unwrap_or("");
    let data_hex = strip_hex(tx.get("data").and_then(Value::as_str).unwrap_or(""));

    let mut call = json!({ "to": to, "data": format!("0x{data_hex}") });
    if !from.is_empty() {
        call["from"] = json!(from);
    }
    // eth_call value comes from tx.Value (Go simulateEVM), not tx.Amount.
    if let Some(v) = amount_bigint(tx.get("value")).filter(|v| v.sign() == num_bigint::Sign::Plus) {
        call["value"] = json!(format!("0x{v:x}"));
    }
    if let Some(g) = tx.get("gas").and_then(Value::as_u64).filter(|g| *g > 0) {
        call["gas"] = json!(format!("0x{g:x}"));
    }

    let mut will_revert = false;
    let mut revert_reason = String::new();
    let mut gas_estimate: u64 = 0;
    let mut effects: Vec<Value> = Vec::new();

    // Prefer callTracer for the full effect tree + revert.
    let call_tracer = json!({ "tracer": "callTracer", "tracerConfig": { "withLog": true } });
    let traced = crate::rpc::call_async(rpc, "debug_traceCall", json!([call, "latest", call_tracer])).await;
    if let Ok(raw) = traced {
        if let Ok(frame) = serde_json::from_value::<CallFrame>(raw) {
            if !frame.error.is_empty() {
                will_revert = true;
                revert_reason = decode_revert_hex(&frame.revert_reason);
                if revert_reason.is_empty() {
                    revert_reason = frame.error.clone();
                }
            }
            effects = extract_effects(&frame);
            if let Some(g) = hex_u64(&frame.gas_used) {
                gas_estimate = g;
            }
        }
    } else {
        // Fall back to eth_call + eth_estimateGas.
        match crate::rpc::call_async(rpc, "eth_call", json!([call, "latest"])).await {
            Ok(_) => {
                if let Ok(g) = crate::rpc::call_async(rpc, "eth_estimateGas", json!([call])).await {
                    if let Some(g) = g.as_str().and_then(hex_u64) {
                        gas_estimate = g;
                    }
                }
                if let Some(eff) = effect_from_decoded(from, &decoded_method, &decoded_args) {
                    effects.push(eff);
                }
            }
            Err(e) => {
                will_revert = true;
                revert_reason = decode_evm_revert(&e.to_string());
            }
        }
    }

    // Second pass: native-balance diff via prestateTracer (best-effort).
    let mut balance_changes: Vec<Value> = Vec::new();
    let pre_cfg = json!({ "tracer": "prestateTracer", "tracerConfig": { "diffMode": true } });
    if let Ok(raw) = crate::rpc::call_async(rpc, "debug_traceCall", json!([call, "latest", pre_cfg])).await {
        balance_changes = extract_balance_changes(&raw);
    }

    let warnings = evm_warnings(rpc, tx, &data_hex).await;

    // Assemble the SimulationResult with Go's omitempty semantics.
    let mut out = json!({ "chain": "evm", "willRevert": will_revert });
    if !revert_reason.is_empty() {
        out["revertReason"] = json!(revert_reason);
    }
    if !warnings.is_empty() {
        out["warnings"] = json!(warnings);
    }
    if !decoded_method.is_empty() {
        out["decodedMethod"] = json!(decoded_method);
    }
    if !decoded_args.is_null() {
        out["decodedArgs"] = decoded_args;
    }
    if !effects.is_empty() {
        out["effects"] = json!(effects);
    }
    if !balance_changes.is_empty() {
        out["balanceChanges"] = json!(balance_changes);
    }
    if gas_estimate > 0 {
        out["gasEstimate"] = json!(gas_estimate);
    }
    out
}

#[derive(Deserialize, Default)]
struct CallFrame {
    #[serde(rename = "type", default)]
    typ: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    value: String,
    #[serde(rename = "gasUsed", default)]
    gas_used: String,
    #[serde(default)]
    error: String,
    #[serde(rename = "revertReason", default)]
    revert_reason: String,
    #[serde(default)]
    logs: Vec<CallLog>,
    #[serde(default)]
    calls: Vec<CallFrame>,
}

#[derive(Deserialize, Default)]
struct CallLog {
    #[serde(default)]
    address: String,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    data: String,
}

/// Walk a callTracer frame tree, pulling out every value-carrying CALL/CREATE
/// and every ERC-20 Transfer/Approval log as an Effect.
fn extract_effects(root: &CallFrame) -> Vec<Value> {
    let mut out = Vec::new();
    walk_frame(root, &mut out);
    out
}

fn walk_frame(f: &CallFrame, out: &mut Vec<Value>) {
    if (f.typ == "CALL" || f.typ == "CREATE" || f.typ == "CREATE2")
        && !f.value.is_empty()
        && f.value != "0x"
        && f.value != "0x0"
    {
        if let Some(v) = hex_bigint(&f.value) {
            if v.sign() == num_bigint::Sign::Plus {
                out.push(json!({
                    "type": "native_transfer",
                    "from": f.from.to_lowercase(),
                    "to": f.to.to_lowercase(),
                    "amount": v.to_string(),
                }));
            }
        }
    }
    for lg in &f.logs {
        let Some(topic0) = lg.topics.first() else { continue };
        if topic0 == TRANSFER_TOPIC {
            if let Some(eff) = decode_log(lg, "erc20_transfer") {
                out.push(eff);
            }
        } else if topic0 == APPROVAL_TOPIC {
            if let Some(eff) = decode_log(lg, "erc20_approve") {
                out.push(eff);
            }
        }
    }
    for c in &f.calls {
        walk_frame(c, out);
    }
}

/// Decode a Transfer/Approval log (indexed from/to in topics[1,2], amount in
/// data) into an Effect. `kind` selects the effect type.
fn decode_log(lg: &CallLog, kind: &str) -> Option<Value> {
    if lg.topics.len() < 3 {
        return None;
    }
    let from = format!("0x{}", topic_to_address(&lg.topics[1]));
    let to = format!("0x{}", topic_to_address(&lg.topics[2]));
    let amt = hex_bigint(&lg.data)?;
    Some(json!({
        "type": kind,
        "token": lg.address.to_lowercase(),
        "from": from,
        "to": to,
        "amount": amt.to_string(),
    }))
}

fn topic_to_address(topic: &str) -> String {
    let t = topic.strip_prefix("0x").unwrap_or(topic);
    if t.len() < 40 {
        return t.to_lowercase();
    }
    t[t.len() - 40..].to_lowercase()
}

/// Synthesize a single Effect from the top-level decode when no tracer tree is
/// available.
fn effect_from_decoded(from: &str, method: &str, args: &Value) -> Option<Value> {
    let from = from.to_lowercase();
    let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    match method {
        "native_transfer" => Some(json!({ "type": "native_transfer", "from": from, "to": s("to").to_lowercase(), "amount": s("amount") })),
        "erc20_transfer" => Some(json!({ "type": "erc20_transfer", "token": s("token").to_lowercase(), "from": from, "to": s("to").to_lowercase(), "amount": s("amount") })),
        "erc20_approve" => Some(json!({ "type": "erc20_approve", "token": s("token").to_lowercase(), "from": from, "to": s("spender").to_lowercase(), "amount": s("amount") })),
        _ => None,
    }
}

/// Recognize the ERC-20 transfer/approve shape and a plain native transfer.
/// Returns (decodedMethod, decodedArgs).
fn decode_evm_call(tx: &Value) -> (String, Value) {
    let data = strip_hex(tx.get("data").and_then(Value::as_str).unwrap_or(""));
    let to = tx.get("to").and_then(Value::as_str).unwrap_or("");
    if data.is_empty() {
        if let Some(amt) = amount_bigint(tx.get("amount")).filter(|v| v.sign() == num_bigint::Sign::Plus) {
            return ("native_transfer".into(), json!({ "to": to, "amount": amount_string(tx.get("amount"), &amt) }));
        }
        return (String::new(), Value::Null);
    }
    if data.len() < 8 {
        return ("unknown".into(), json!({ "selector": format!("0x{data}") }));
    }
    let selector = &data[..8];
    if selector == ERC20_TRANSFER_SELECTOR {
        if let Some((addr, amt)) = decode_erc20_args(&data[8..]) {
            return ("erc20_transfer".into(), json!({ "token": to, "to": addr, "amount": amt.to_string() }));
        }
    } else if selector == ERC20_APPROVE_SELECTOR {
        if let Some((addr, amt)) = decode_erc20_args(&data[8..]) {
            return ("erc20_approve".into(), json!({ "token": to, "spender": addr, "amount": amt.to_string() }));
        }
    }
    ("unknown".into(), json!({ "selector": format!("0x{selector}"), "data": format!("0x{data}") }))
}

/// Parse a 64-byte ABI-encoded (address, uint256).
fn decode_erc20_args(hex_args: &str) -> Option<(String, BigInt)> {
    if hex_args.len() < 128 {
        return None;
    }
    let addr_hex = &hex_args[24..64];
    if addr_hex.chars().any(|c| !c.is_ascii_hexdigit()) {
        return None;
    }
    let amt = BigInt::parse_bytes(hex_args[64..128].as_bytes(), 16)?;
    Some((format!("0x{addr_hex}"), amt))
}

/// Decode a callTracer revertReason blob (`Error(string)` = 0x08c379a0).
fn decode_revert_hex(s: &str) -> String {
    let raw = match hex_bytes(s.strip_prefix("0x").unwrap_or(s)) {
        Some(r) if r.len() >= 4 + 64 => r,
        _ => return s.to_owned(),
    };
    if hex_lower(&raw[..4]) != "08c379a0" {
        return s.to_owned();
    }
    let length = BigInt::from_bytes_be(num_bigint::Sign::Plus, &raw[4 + 32..4 + 64]);
    let length: i64 = (&length).try_into().unwrap_or(-1);
    if length <= 0 || (raw.len() as i64) < 4 + 64 + length {
        return s.to_owned();
    }
    String::from_utf8_lossy(&raw[4 + 64..4 + 64 + length as usize]).into_owned()
}

/// Pull a human reason out of an eth_call error string (`Error(string)`).
fn decode_evm_revert(msg: &str) -> String {
    let Some(idx) = msg.find("0x") else { return msg.to_owned() };
    let hex_part = &msg[idx..];
    let mut end = hex_part.len();
    for (i, c) in hex_part.char_indices().skip(2) {
        if !c.is_ascii_hexdigit() {
            end = i;
            break;
        }
    }
    let payload = &hex_part[..end];
    let raw = match hex_bytes(payload.strip_prefix("0x").unwrap_or(payload)) {
        Some(r) if r.len() >= 4 => r,
        _ => return msg.to_owned(),
    };
    if raw.len() >= 4 + 64 && hex_lower(&raw[..4]) == "08c379a0" {
        let length = BigInt::from_bytes_be(num_bigint::Sign::Plus, &raw[4 + 32..4 + 64]);
        let length: i64 = (&length).try_into().unwrap_or(-1);
        if length > 0 && (raw.len() as i64) >= 4 + 64 + length {
            return String::from_utf8_lossy(&raw[4 + 64..4 + 64 + length as usize]).into_owned();
        }
    }
    msg.to_owned()
}

/// prestateTracer diff → per-address native-balance deltas.
fn extract_balance_changes(raw: &Value) -> Vec<Value> {
    #[derive(Deserialize)]
    struct Diff {
        #[serde(default)]
        pre: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Value>>,
        #[serde(default)]
        post: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Value>>,
    }
    let Ok(diff) = serde_json::from_value::<Diff>(raw.clone()) else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (addr, pre) in &diff.pre {
        seen.insert(addr.clone());
        let pre_bal = pre.get("balance").and_then(hex_bigint_val);
        let post_bal = diff.post.get(addr).and_then(|p| p.get("balance")).and_then(hex_bigint_val);
        if pre_bal.is_none() && post_bal.is_none() {
            continue;
        }
        let delta = post_bal.unwrap_or_else(|| BigInt::from(0)) - pre_bal.unwrap_or_else(|| BigInt::from(0));
        if delta.sign() != num_bigint::Sign::NoSign {
            out.push(json!({ "address": addr.to_lowercase(), "delta": delta.to_string() }));
        }
    }
    for (addr, post) in &diff.post {
        if seen.contains(addr) {
            continue;
        }
        if let Some(bal) = post.get("balance").and_then(hex_bigint_val).filter(|b| b.sign() == num_bigint::Sign::Plus) {
            out.push(json!({ "address": addr.to_lowercase(), "delta": bal.to_string() }));
        }
    }
    out
}

/// Non-blocking EVM approval warnings (recipient-is-contract, unlimited-approve).
async fn evm_warnings(rpc: &str, tx: &Value, data_hex: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("");
    let to = tx.get("to").and_then(Value::as_str).unwrap_or("");
    let has_value = amount_bigint(tx.get("amount")).map(|v| v.sign() == num_bigint::Sign::Plus).unwrap_or(false)
        || amount_bigint(tx.get("value")).map(|v| v.sign() == num_bigint::Sign::Plus).unwrap_or(false);

    if (typ == "transfer" || typ == "evm") && !to.is_empty() && has_value && data_hex.is_empty() && is_contract(rpc, to).await {
        out.push(json!({
            "code": "recipient_is_contract",
            "severity": "warn",
            "message": format!("recipient {to} is a contract — plain transfers to contracts without a payable fallback are permanently lost"),
            "field": "to",
        }));
    }

    if data_hex.len() >= 8 + 128 && &data_hex[..8] == ERC20_APPROVE_SELECTOR {
        if let Some((_, amount)) = decode_erc20_args(&data_hex[8..]) {
            // Unlimited = top bit set (> 2^255).
            if amount >= (BigInt::from(1) << 255) {
                out.push(json!({
                    "code": "erc20_approve_unlimited",
                    "severity": "warn",
                    "message": "this transaction grants an unlimited allowance to the spender — a compromised or malicious spender contract can drain the entire token balance at any time",
                    "field": "amount",
                }));
            }
        }
    }
    out
}

async fn is_contract(rpc: &str, addr: &str) -> bool {
    let Ok(v) = crate::rpc::call_async(rpc, "eth_getCode", json!([addr, "latest"])).await else { return false };
    let code = v.as_str().unwrap_or("");
    strip_hex(code).chars().any(|c| c != '0')
}

// ── small helpers ──────────────────────────────────────────────────────────

fn strip_hex(s: &str) -> String {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s).to_owned()
}

fn hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn hex_bigint(s: &str) -> Option<BigInt> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    BigInt::parse_bytes(s.as_bytes(), 16)
}

fn hex_bigint_val(v: &Value) -> Option<BigInt> {
    hex_bigint(v.as_str()?)
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The significand of an Amount-shaped JSON value ({v,e,f} or decimal string).
fn amount_bigint(v: Option<&Value>) -> Option<BigInt> {
    let v = v?;
    if let Some(obj) = v.as_object() {
        return obj.get("v").and_then(Value::as_str).and_then(|s| BigInt::parse_bytes(s.as_bytes(), 10));
    }
    v.as_str().and_then(|s| BigInt::parse_bytes(s.as_bytes(), 10))
}

/// The decimal-point string of an Amount (Go `Amount.String`), used for the
/// native_transfer decodedArgs amount. Falls back to the significand.
fn amount_string(v: Option<&Value>, significand: &BigInt) -> String {
    if let Some(a) = v.and_then(|x| serde_json::from_value::<crate::Amount>(x.clone()).ok()) {
        return a.to_string();
    }
    significand.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SqlValue;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn mock_rpc(result_json: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn simulate_solana_reports_logs_and_units() {
        let env = Env::init_memory().unwrap();
        crate::models::network::init(&env).unwrap();
        env.exec(r#"DELETE FROM "Network""#, vec![]).unwrap(); // drop seeded built-ins; this test controls its own networks
        let rpc = mock_rpc(r#"{"value":{"err":null,"logs":["Program log: ok"],"unitsConsumed":1234}}"#);
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
        env.set_current("network", "net-sol").unwrap();

        // A dummy raw tx (bytes don't matter — the mock ignores them).
        let raw_b64 = base64_std(&[1u8, 2, 3, 4]);
        let params = json!({
            "to": "So11111111111111111111111111111111111111112",
            "amount": { "v": "1000", "e": 0 },
            "raw": raw_b64,
        });
        let out = simulate(&env, &params).unwrap();
        assert_eq!(out["chain"], "solana");
        assert_eq!(out["willRevert"], false);
        assert_eq!(out["unitsConsumed"], 1234);
        assert_eq!(out["logs"][0], "Program log: ok");
        assert_eq!(out["decodedMethod"], "native_transfer");
        assert_eq!(out["decodedArgs"]["amount"], "1000");
    }

    fn insert_network(env: &Env, kind: &str, chain: &str) {
        env.exec(
            r#"INSERT INTO "Network" ("Id","Type","ChainId","Name","RPC","CurrencySymbol","CurrencyDecimals","BlockExplorer","TestNet","Priority","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            vec![
                SqlValue::Text(format!("net-{kind}")),
                SqlValue::Text(kind.into()),
                SqlValue::Text(chain.into()),
                SqlValue::Text(kind.into()),
                SqlValue::Text("https://unused.example".into()),
                SqlValue::Text("X".into()),
                SqlValue::Int(8),
                SqlValue::Text("".into()),
                SqlValue::Int(0),
                SqlValue::Int(0),
                SqlValue::Text(crate::now_rfc3339()),
                SqlValue::Text(crate::now_rfc3339()),
            ],
        )
        .unwrap();
        env.set_current("network", &format!("net-{kind}")).unwrap();
    }

    #[test]
    fn simulate_bitcoin_decodes_raw_tx() {
        let env = Env::init_memory().unwrap();
        crate::models::network::init(&env).unwrap();
        env.exec(r#"DELETE FROM "Network""#, vec![]).unwrap(); // drop seeded built-ins; this test controls its own networks
        insert_network(&env, "bitcoin", "bitcoin");

        // version | 1 input (txid=32×0x11, vout 0, empty scriptsig, seq) |
        // 1 output (1 BTC = 0x05F5E100 sats LE, empty script) | locktime.
        let raw = "0x01000000\
            01\
            1111111111111111111111111111111111111111111111111111111111111111\
            00000000\
            00ffffffff\
            01\
            00e1f50500000000\
            00\
            00000000";
        let params = json!({
            "to": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "amount": { "v": "100000000", "e": 0 },
            "fee": { "v": "1234", "e": 0 },
            "raw": raw,
        });
        let out = simulate(&env, &params).unwrap();
        assert_eq!(out["chain"], "bitcoin");
        assert_eq!(out["decodedMethod"], "native_transfer");
        assert_eq!(out["bitcoinOutputs"][0]["amount"], 100000000u64);
        assert_eq!(out["bitcoinInputs"][0]["txid"], "1111111111111111111111111111111111111111111111111111111111111111");
        assert_eq!(out["bitcoinInputs"][0]["vout"], 0);
        assert_eq!(out["bitcoinFee"], 1234);
        assert_eq!(out["bitcoinVSize"], 60);
    }

    #[test]
    fn simulate_solana_without_raw_errors() {
        let env = Env::init_memory().unwrap();
        crate::models::network::init(&env).unwrap();
        env.exec(r#"DELETE FROM "Network""#, vec![]).unwrap(); // drop seeded built-ins; this test controls its own networks
        env.exec(
            r#"INSERT INTO "Network" ("Id","Type","ChainId","Name","RPC","CurrencySymbol","CurrencyDecimals","BlockExplorer","TestNet","Priority","Created","Updated") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            vec![
                SqlValue::Text("net-sol".into()),
                SqlValue::Text("solana".into()),
                SqlValue::Text("mainnet".into()),
                SqlValue::Text("Solana".into()),
                SqlValue::Text("https://unused.example".into()),
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
        env.set_current("network", "net-sol").unwrap();
        let err = simulate(&env, &json!({ "to": "x", "amount": { "v": "1", "e": 0 } })).unwrap_err();
        assert_eq!(err.code, 400);
    }
}
