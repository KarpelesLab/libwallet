//! `Transaction:simulate` — preview a transaction without signing (port of the
//! EVM path of wlttx/simulate.go). Decodes the top-level call, then simulates
//! against the node: prefer `debug_traceCall` (callTracer for the full effect
//! tree + revert, prestateTracer for native balance changes), falling back to
//! `eth_call` + `eth_estimateGas`. Non-blocking approval warnings
//! (recipient-is-contract, unlimited-approve) are appended best-effort.
//!
//! Solana: a tx carrying built `raw` bytes is simulated as-is; otherwise the
//! unsigned transfer is built server-side from the high-level fields
//! (`from`/`to`/`amount`/`asset`, SOL or SPL — the same builder signAndSend
//! signs) and run through `simulateTransaction`. Bitcoin decodes `raw`.

use num_bigint::BigInt;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

// keccak256("Transfer(address,address,uint256)") / ("Approval(...)").
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const APPROVAL_TOPIC: &str = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
// 4-byte selectors, matched against the decoded calldata.
const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
const ERC20_APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
const ERC20_INCREASE_ALLOWANCE_SELECTOR: [u8; 4] = [0x39, 0x50, 0x93, 0x51]; // increaseAllowance(address,uint256)
const SET_APPROVAL_FOR_ALL_SELECTOR: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65]; // setApprovalForAll(address,bool)

/// `Transaction:simulate` {tx fields, RPC?}. One async implementation shared by
/// native (`crate::rt::block_on`) and the browser (awaited in
/// `handle_request_async`); chain I/O runs over `rpc::call_async`. The target
/// chain comes from the tx (see [`tx_chain`]), and the endpoint from the Network
/// model — the client never names a URL.
pub async fn simulate_impl(env: &Env, params: &Value) -> ApiResult {
    let tx = params.get("Transaction").unwrap_or(params);
    let np = with_tx_network(env, params, tx);
    match tx_chain(env, &np, tx)? {
        // Decode-from-raw only (no RPC); the UTXO dry-run preview follows.
        "bitcoin" => Ok(simulate_bitcoin(tx)),
        "evm" => {
            let rpc = super::resolve_rpc_for_kind(env, &np, "evm")?;
            Ok(simulate_evm(&rpc, tx).await)
        }
        "solana" => simulate_solana(env, &np, tx).await,
        other => Err(ApiError::new(400, format!("Transaction:simulate is not supported for {other}"))),
    }
}

/// Native `Transaction:simulate`: drive the shared async impl on the worker.
#[cfg(not(target_arch = "wasm32"))]
pub fn simulate(env: &Env, params: &Value) -> ApiResult {
    crate::rt::block_on(simulate_impl(env, params))
}

/// `params` with the tx's camelCase `network` (what the Dart
/// `UnsignedTransaction` sends) promoted to the `Network` param the network
/// resolvers read, unless the caller already set one.
pub(crate) fn with_tx_network(env: &Env, params: &Value, tx: &Value) -> Value {
    let mut p = match params {
        Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };
    let has = p.get("Network").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if let (false, Some(n)) = (has, tx.get("network").and_then(Value::as_str).filter(|s| !s.is_empty())) {
        p.insert("Network".into(), json!(super::network_ref(env, n)));
    }
    Value::Object(p)
}

/// The chain a tx targets: "evm" / "solana" / "bitcoin" / "tron". A
/// chain-specific tx `type` (solana_*/bitcoin_*/evm/erc20_*) decides it
/// directly — what the browser relies on (multi-chain, no single current
/// network). A generic `transfer` (or no type) follows the explicit `Network`,
/// then the `from` account's chain, then the current `@` network, defaulting to
/// EVM — so a Solana account's `transfer` never lands on the EVM path.
pub(crate) fn tx_chain(env: &Env, params: &Value, tx: &Value) -> Result<&'static str, ApiError> {
    let chain = |kind: &str| match kind {
        "solana" => "solana",
        "bitcoin" => "bitcoin",
        "tron" => "tron",
        _ => "evm",
    };
    match tx.get("type").and_then(Value::as_str).unwrap_or("") {
        "solana_transfer" | "solana_spl_transfer" => return Ok("solana"),
        "bitcoin_transfer" => return Ok("bitcoin"),
        "tron_transfer" | "trc20_transfer" => return Ok("tron"),
        "evm" | "erc20_transfer" | "erc20_approve" => return Ok("evm"),
        _ => {}
    }
    if let Some(id) = params.get("Network").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let net = crate::models::network::fetch(env, id)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(404, format!("network {id} not found")))?;
        return Ok(chain(&net.kind));
    }
    if let Some(from) = tx.get("from").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        if let Some(a) = crate::models::account::find(env, from).map_err(ApiError::internal)? {
            return Ok(chain(&a.kind));
        }
    }
    Ok(match crate::models::network::fetch(env, "@").map_err(ApiError::internal)? {
        Some(n) => chain(&n.kind),
        None => "evm",
    })
}

/// The account a tx spends from: `from` (an account id or address), else the
/// current account.
pub(crate) fn tx_account(env: &Env, tx: &Value) -> Result<crate::models::account::Account, ApiError> {
    match tx.get("from").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(from) => crate::models::account::find(env, from)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(404, format!("from account {from} not found"))),
        None => crate::models::account::current(env)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::new(400, "from is required (no current account)")),
    }
}

/// Bitcoin simulate: decode the built `raw` tx into its inputs/outputs (Go
/// `simulateBitcoin`, decode-from-raw path). The UTXO dry-run preview (no raw)
/// needs the build machinery and is deferred; here we surface the native
/// transfer decode or, when `raw` is present, the on-wire shape.
///
/// The two are exclusive. `to`/`amount` describe a transfer still to be built;
/// once `raw` is given, the bytes are what would be signed and nothing ties
/// them to those fields — echoing them as `decodedMethod: native_transfer`
/// would label whatever the raw tx does as that benign transfer. With `raw`
/// only what is read from it (inputs, outputs, size) is reported.
fn simulate_bitcoin(tx: &Value) -> Value {
    let mut out = json!({ "chain": "bitcoin" });
    let Some(raw) = tx.get("raw").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        let to = tx.get("to").and_then(Value::as_str).unwrap_or("");
        if !to.is_empty() {
            if let Some(amt) = amount_bigint(tx.get("amount")) {
                out["decodedMethod"] = json!("native_transfer");
                out["decodedArgs"] = json!({ "to": to, "amount": amount_string(tx.get("amount"), &amt) });
            }
        }
        return out;
    };
    let Some(raw) = decode_tx_bytes(raw) else {
        out["willRevert"] = json!(true);
        out["revertReason"] = json!("bitcoin tx raw is not base64 or 0x-hex");
        return out;
    };

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

/// Solana simulate (Go `simulateSolana`). A tx carrying built `raw` bytes is
/// simulated as-is; otherwise the unsigned transfer is built from the tx fields
/// with the shared builder — native SOL or SPL (ATA-create included) — and
/// simulated with `sigVerify: false` + `replaceRecentBlockhash`. Surfaces logs,
/// unitsConsumed and revert status, plus for a built transfer the EVM-shaped
/// preview: `fee`, `effects`, `decodedMethod`/`decodedArgs` and `warnings`.
async fn simulate_solana(env: &Env, params: &Value, tx: &Value) -> ApiResult {
    let rpc = super::resolve_rpc_for_kind(env, params, "solana")?;
    if let Some(raw) = tx.get("raw").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let raw = decode_tx_bytes(raw).ok_or_else(|| ApiError::new(400, "solana tx raw is not base64 or 0x-hex"))?;
        // No decodedMethod/decodedArgs here: the caller's `to`/`amount` are not
        // derived from these bytes, and echoing them would label whatever the
        // raw transaction does as a benign native transfer. The node's
        // simulation of the bytes themselves (logs, units, revert) is the result.
        return Ok(run_solana_simulation(&rpc, &raw, false).await);
    }

    let account = tx_account(env, tx)?;
    let net = super::network_for_kind(env, params, "solana")?;
    let built = super::solana_build::build_unsigned(env, &account, &net, &rpc, tx).await?;
    let mut out = run_solana_simulation(&rpc, &built.unsigned_tx(), true).await;
    out["fee"] = json!(crate::Amount::new_raw(BigInt::from(built.fee_lamports), 9));

    let amount = built.amount.to_string();
    let mut warnings = Vec::new();
    match &built.token {
        None => {
            out["decodedMethod"] = json!("native_transfer");
            out["decodedArgs"] = json!({ "to": built.to, "amount": amount });
            out["effects"] = json!([{
                "type": "native_transfer", "from": account.address, "to": built.to, "amount": amount,
            }]);
            if super::solana_build::account_exists(&rpc, &built.to).await == Some(false) {
                warnings.push(json!({
                    "code": "recipient_new_account",
                    "severity": "info",
                    "message": "The recipient account does not exist yet; this transfer creates it and must cover its rent-exempt minimum.",
                    "field": "to",
                }));
            }
        }
        Some(token) => {
            out["decodedMethod"] = json!("spl_transfer");
            out["decodedArgs"] = json!({ "token": token.mint_b58, "to": built.to, "amount": amount });
            out["effects"] = json!([{
                "type": "spl_transfer", "token": token.mint_b58, "from": account.address, "to": built.to, "amount": amount,
            }]);
            let ata = built.recipient_ata.map(|a| bs58::encode(a).into_string()).unwrap_or_default();
            if super::solana_build::account_exists(&rpc, &ata).await == Some(false) {
                warnings.push(json!({
                    "code": "recipient_new_account",
                    "severity": "info",
                    "message": "The recipient has no token account for this mint yet; this transfer creates it, paying its rent from your SOL.",
                    "field": "to",
                }));
            }
        }
    }
    if !warnings.is_empty() {
        out["warnings"] = json!(warnings);
    }
    Ok(out)
}

/// `simulateTransaction` on wire bytes (signatures unchecked). With
/// `replace_blockhash` the node swaps in its latest blockhash, so a preview
/// never fails on an expired anchor.
async fn run_solana_simulation(rpc: &str, raw: &[u8], replace_blockhash: bool) -> Value {
    let mut cfg = json!({ "sigVerify": false, "encoding": "base64", "commitment": "processed" });
    if replace_blockhash {
        cfg["replaceRecentBlockhash"] = json!(true);
    }
    let mut out = json!({ "chain": "solana" });
    match crate::rpc::call_async(rpc, "simulateTransaction", json!([base64_std(raw), cfg])).await {
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
    out
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
    // (to, value, data) exactly as Transaction:signAndSend derives them — the
    // preview must be of the call that would be signed. A tx the signer would
    // refuse is reported as failing, with the signer's reason.
    let evm_call = match evm_call(tx) {
        Ok(c) => c,
        Err(e) => return json!({ "chain": "evm", "willRevert": true, "revertReason": e.message }),
    };
    let (decoded_method, decoded_args) = decode_evm_call(&evm_call);

    let to = evm_call.to.as_str();
    let from = tx.get("from").and_then(Value::as_str).unwrap_or("");
    let data_hex = hex_lower(&evm_call.data);

    let mut call = json!({ "to": to, "data": format!("0x{data_hex}") });
    if !from.is_empty() {
        call["from"] = json!(from);
    }
    if evm_call.value.sign() == num_bigint::Sign::Plus {
        call["value"] = json!(format!("0x{:x}", evm_call.value));
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

    let warnings = evm_warnings(rpc, tx, &evm_call, &data_hex).await;

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
    // `get` rather than an index: a node can put anything in a topic, and a
    // multi-byte character straddling the cut would panic a plain slice.
    match t.len().checked_sub(40).and_then(|start| t.get(start..)) {
        Some(tail) => tail.to_lowercase(),
        None => t.to_lowercase(),
    }
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
///
/// The selector is matched on the decoded calldata bytes — the same bytes the
/// signer signs — so the spelling of the hex (`0x095EA7B3…`) cannot hide a call.
fn decode_evm_call(call: &EvmCall<'_>) -> (String, Value) {
    let data = call.data.as_slice();
    let to = call.to.as_str();
    if data.is_empty() {
        // The amount shown is the value the call carries (tx.value, else
        // tx.amount — whichever the signer uses), never the other field.
        if call.value.sign() == num_bigint::Sign::Plus {
            return ("native_transfer".into(), json!({ "to": to, "amount": amount_string(call.value_field, &call.value) }));
        }
        return (String::new(), Value::Null);
    }
    let Some((selector, args)) = data.split_first_chunk::<4>() else {
        return ("unknown".into(), json!({ "selector": format!("0x{}", hex_lower(data)) }));
    };
    if *selector == ERC20_TRANSFER_SELECTOR {
        if let Some((addr, amt)) = decode_erc20_args(args) {
            return ("erc20_transfer".into(), json!({ "token": to, "to": addr, "amount": amt.to_string() }));
        }
    } else if *selector == ERC20_APPROVE_SELECTOR {
        if let Some((addr, amt)) = decode_erc20_args(args) {
            return ("erc20_approve".into(), json!({ "token": to, "spender": addr, "amount": amt.to_string() }));
        }
    }
    ("unknown".into(), json!({ "selector": format!("0x{}", hex_lower(selector)), "data": format!("0x{}", hex_lower(data)) }))
}

/// The call an EVM `Transaction` makes: recipient, native value (wei) and
/// calldata. `value_field` is the tx field the value was read from.
/// Lives here rather than in `transaction` (native-only) because simulate is
/// also built for the browser.
pub(crate) struct EvmCall<'a> {
    pub to: String,
    pub value: BigInt,
    pub value_field: Option<&'a Value>,
    pub data: Vec<u8>,
}

/// Derive the `(to, value, data)` an EVM `Transaction` executes. The one place
/// this is decided, shared by `Transaction:signAndSend` (what is signed) and
/// `Transaction:simulate` (what is previewed) so the two cannot disagree:
///   - value (wei) = the `value` significand, else the `amount` significand,
///     else 0; an `erc20_transfer` always carries 0 (its amount is in the
///     calldata);
///   - data = the `0x`-prefixed hex `data`, required for an `erc20_transfer`.
pub(crate) fn evm_call(tx: &Value) -> Result<EvmCall<'_>, ApiError> {
    let is_erc20 = tx.get("type").and_then(Value::as_str) == Some("erc20_transfer");
    let (value, value_field) = match [tx.get("value"), tx.get("amount")]
        .into_iter()
        .flatten()
        .find_map(|f| amount_bigint(Some(f)).map(|v| (v, f)))
    {
        Some((v, f)) if !is_erc20 => (v, Some(f)),
        _ => (BigInt::from(0), None),
    };
    if value.sign() == num_bigint::Sign::Minus {
        return Err(ApiError::new(400, "value must not be negative"));
    }
    let data = match tx.get("data").and_then(Value::as_str) {
        Some(h) if !h.is_empty() => {
            let h = h.strip_prefix("0x").ok_or_else(|| ApiError::new(400, "data must be 0x-prefixed"))?;
            hex_bytes_strict(h)?
        }
        _ => Vec::new(),
    };
    if is_erc20 && data.is_empty() {
        return Err(ApiError::new(400, "erc20_transfer requires encoded Data (0x transfer calldata)"));
    }
    let to = tx.get("to").and_then(Value::as_str).unwrap_or("").to_string();
    Ok(EvmCall { to, value, value_field, data })
}

/// Strict hex decode (no prefix): hex digits only, which also keeps the
/// two-byte slices on character boundaries.
pub(crate) fn hex_bytes_strict(s: &str) -> Result<Vec<u8>, ApiError> {
    if s.len() % 2 != 0 {
        return Err(ApiError::new(400, "odd-length hex"));
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::new(400, "bad hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ApiError::new(400, "bad hex")))
        .collect()
}

/// Parse a 64-byte ABI-encoded (address, uint256): the address as lowercase
/// `0x`-hex, the second word as an unsigned integer.
fn decode_erc20_args(args: &[u8]) -> Option<(String, BigInt)> {
    let addr = args.get(12..32)?;
    let amt = BigInt::from_bytes_be(num_bigint::Sign::Plus, args.get(32..64)?);
    Some((format!("0x{}", hex_lower(addr)), amt))
}

/// Decode a callTracer revertReason blob (`Error(string)` = 0x08c379a0).
fn decode_revert_hex(s: &str) -> String {
    let raw = match hex_bytes(s.strip_prefix("0x").unwrap_or(s)) {
        Some(r) if r.len() >= 4 + 64 => r,
        _ => return s.to_owned(),
    };
    error_string(&raw).unwrap_or_else(|| s.to_owned())
}

/// The message of an ABI-encoded `Error(string)` (selector 0x08c379a0, offset
/// word, length word, bytes). The length is the node's claim: it is bounds-
/// checked against what is actually there, without arithmetic that can
/// overflow (a length near 2^63 used to slip past the check and panic).
fn error_string(raw: &[u8]) -> Option<String> {
    if raw.get(..4)? != [0x08, 0xc3, 0x79, 0xa0] {
        return None;
    }
    let length = BigInt::from_bytes_be(num_bigint::Sign::Plus, raw.get(4 + 32..4 + 64)?);
    let length = usize::try_from(&length).ok().filter(|l| *l > 0)?;
    let text = raw.get(4 + 64..(4usize + 64).checked_add(length)?)?;
    Some(String::from_utf8_lossy(text).into_owned())
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
    error_string(&raw).unwrap_or_else(|| msg.to_owned())
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
async fn evm_warnings(rpc: &str, tx: &Value, call: &EvmCall<'_>, data_hex: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let typ = tx.get("type").and_then(Value::as_str).unwrap_or("");
    let to = call.to.as_str();
    let has_value = call.value.sign() == num_bigint::Sign::Plus;

    if (typ == "transfer" || typ == "evm") && !to.is_empty() && has_value && data_hex.is_empty() && is_contract(rpc, to).await {
        out.push(json!({
            "code": "recipient_is_contract",
            "severity": "warn",
            "message": format!("recipient {to} is a contract — plain transfers to contracts without a payable fallback are permanently lost"),
            "field": "to",
        }));
    }

    // Approval-shaped calls, matched on the calldata bytes. `(address, word)`:
    // approve / increaseAllowance carry an amount, setApprovalForAll a bool.
    let unlimited = json!({
        "code": "erc20_approve_unlimited",
        "severity": "warn",
        "message": "this transaction grants an unlimited allowance to the spender — a compromised or malicious spender contract can drain the entire token balance at any time",
        "field": "amount",
    });
    if let Some((selector, args)) = call.data.split_first_chunk::<4>() {
        if let Some((_, word)) = decode_erc20_args(args) {
            // Unlimited = top bit set (>= 2^255).
            let is_unlimited = word >= (BigInt::from(1) << 255);
            let grants = *selector == ERC20_APPROVE_SELECTOR || *selector == ERC20_INCREASE_ALLOWANCE_SELECTOR;
            if grants && is_unlimited {
                out.push(unlimited);
            } else if *selector == ERC20_INCREASE_ALLOWANCE_SELECTOR {
                out.push(json!({
                    "code": "erc20_increase_allowance",
                    "severity": "warn",
                    "message": "this transaction raises the allowance of the spender — it can move that many more of your tokens at any time",
                    "field": "amount",
                }));
            } else if *selector == SET_APPROVAL_FOR_ALL_SELECTOR && word.sign() == num_bigint::Sign::Plus {
                out.push(json!({
                    "code": "set_approval_for_all",
                    "severity": "warn",
                    "message": "this transaction lets the operator move every token of this collection you hold, now and in the future — a compromised or malicious operator can take them all at any time",
                    "field": "data",
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
    // Hex digits only — which also keeps the two-byte slices below on
    // character boundaries (a non-ASCII string would panic there).
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
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

    /// A node answering every call with `result_json`, recording the requests.
    fn mock_rpc_log(result_json: &'static str) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut s) = conn else { break };
                let mut buf = [0u8; 8192];
                let n = s.read(&mut buf).unwrap_or(0);
                log.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), seen)
    }

    // Audit M5: the simulated call carries the value the signer would send —
    // tx.value, else the tx.amount significand, and 0 for an erc20_transfer.
    #[test]
    fn simulate_evm_previews_the_value_that_gets_signed() {
        let env = Env::init_memory().unwrap();
        let to = "0x00000000000000000000000000000000000000bb";
        let sim = |tx: Value| {
            let (rpc, seen) = mock_rpc_log(r#""0x""#);
            let mut p = tx;
            p["RPC"] = json!(rpc);
            let out = simulate(&env, &p).unwrap();
            let reqs = seen.lock().unwrap().clone();
            (out, reqs)
        };

        // amount only: the signer sends it as the value, so the preview must too.
        let (out, reqs) = sim(json!({ "type": "evm", "to": to, "amount": { "v": "1000", "e": 0 } }));
        assert!(reqs.iter().any(|r| r.contains("debug_traceCall") && r.contains(r#""value":"0x3e8""#)), "{reqs:?}");
        assert_eq!(out["decodedMethod"], "native_transfer");
        assert_eq!(out["decodedArgs"]["amount"], "1000");

        // value wins over amount, in the call and in the decode.
        let (out, reqs) = sim(json!({ "type": "evm", "to": to, "value": "7", "amount": "1000" }));
        assert!(reqs.iter().any(|r| r.contains(r#""value":"0x7""#)), "{reqs:?}");
        assert!(!reqs.iter().any(|r| r.contains("0x3e8")), "{reqs:?}");
        assert_eq!(out["decodedArgs"]["amount"], "7");

        // erc20_transfer: the amount is in the calldata; no native value.
        let data = format!("0xa9059cbb{:0>64}{:0>64}", "aa", "3e8");
        let (out, reqs) = sim(json!({ "type": "erc20_transfer", "to": to, "amount": "1000", "data": data }));
        assert!(!reqs.iter().any(|r| r.contains(r#""value""#)), "{reqs:?}");
        assert_eq!(out["decodedMethod"], "erc20_transfer");

        // What the signer refuses is not previewed as something else.
        let (out, reqs) = sim(json!({ "type": "erc20_transfer", "to": to, "amount": "1000" }));
        assert!(reqs.is_empty(), "{reqs:?}");
        assert_eq!(out["willRevert"], true);
        assert!(out["revertReason"].as_str().unwrap().contains("erc20_transfer requires"), "{out}");
    }

    // Audit M6: selectors are matched on the calldata bytes, so uppercase hex
    // (which the signer accepts) decodes and warns like lowercase; and the
    // other approval-shaped calls warn too.
    #[test]
    fn simulate_evm_matches_selectors_on_bytes_and_warns_on_approvals() {
        let env = Env::init_memory().unwrap();
        let to = "0x00000000000000000000000000000000000000bb";
        let sim = |data: String| {
            let (rpc, _) = mock_rpc_log(r#""0x""#);
            simulate(&env, &json!({ "type": "evm", "to": to, "data": data, "RPC": rpc })).unwrap()
        };
        let codes = |out: &Value| -> Vec<String> {
            out["warnings"].as_array().map(|w| w.iter().map(|x| x["code"].as_str().unwrap().to_owned()).collect()).unwrap_or_default()
        };
        let spender = format!("{:0>64}", "aa");
        let max = "f".repeat(64);
        let word = |hex: &str| format!("{hex:0>64}");

        for approve in ["0x095ea7b3", "0x095EA7B3"] {
            let out = sim(format!("{approve}{spender}{}", max.to_uppercase()));
            assert_eq!(out["decodedMethod"], "erc20_approve", "{out}");
            assert_eq!(out["decodedArgs"]["spender"], "0x00000000000000000000000000000000000000aa");
            assert_eq!(codes(&out), ["erc20_approve_unlimited"], "{out}");
        }
        let out = sim(format!("0xA9059CBB{spender}{}", word("3E8")));
        assert_eq!(out["decodedMethod"], "erc20_transfer", "{out}");
        assert_eq!(out["decodedArgs"]["amount"], "1000");

        // A bounded approve doesn't warn; increaseAllowance always does.
        assert!(codes(&sim(format!("0x095ea7b3{spender}{}", word("3e8")))).is_empty());
        assert_eq!(codes(&sim(format!("0x39509351{spender}{}", word("3e8")))), ["erc20_increase_allowance"]);
        assert_eq!(codes(&sim(format!("0x39509351{spender}{max}"))), ["erc20_approve_unlimited"]);
        // setApprovalForAll(operator, true) warns; revoking (false) doesn't.
        assert_eq!(codes(&sim(format!("0xA22CB465{spender}{}", word("1")))), ["set_approval_for_all"]);
        assert!(codes(&sim(format!("0xa22cb465{spender}{}", word("0")))).is_empty());

        // Short / unknown calldata is "unknown", in canonical lowercase.
        let out = sim("0xDEAD".into());
        assert_eq!(out["decodedMethod"], "unknown");
        assert_eq!(out["decodedArgs"]["selector"], "0xdead");
        let out = sim("0xDEADBEEF00".into());
        assert_eq!(out["decodedArgs"]["selector"], "0xdeadbeef");
        assert_eq!(out["decodedArgs"]["data"], "0xdeadbeef00");
    }

    // Audit L1: strings from the node or the dApp are never byte-sliced blind —
    // non-ASCII input, and lengths the node merely claims, don't panic.
    #[test]
    fn untrusted_strings_do_not_panic() {
        // 39 ASCII bytes + a 2-byte char: the 40-byte cut lands mid-character.
        let topic = format!("0x{}\u{e9}{}", "0".repeat(24), "a".repeat(39));
        let _ = topic_to_address(&topic);
        assert_eq!(topic_to_address(&format!("0x{}{}", "0".repeat(24), "AB".repeat(20))), "ab".repeat(20));
        assert_eq!(topic_to_address("0xAB"), "ab");

        assert_eq!(hex_bytes("\u{e9}\u{e9}"), None);
        assert_eq!(hex_bytes("a\u{e9}b"), None);
        assert_eq!(hex_bytes("+f"), None);
        assert_eq!(hex_bytes("0aFF"), Some(vec![0x0a, 0xff]));

        // Error(string) whose length word claims i64::MAX bytes.
        let huge = format!("0x08c379a0{:0>64}{:0>64}{}", "20", "7fffffffffffffff", "41".repeat(32));
        assert_eq!(decode_revert_hex(&huge), huge);
        assert_eq!(decode_evm_revert(&format!("execution reverted: {huge}")), format!("execution reverted: {huge}"));
        let ok = format!("0x08c379a0{:0>64}{:0>64}{}", "20", "3", "6e6f7065");
        assert_eq!(decode_revert_hex(&ok), "nop");
        assert_eq!(decode_evm_revert(&format!("reverted {ok} \u{e9}")), "nop");
        assert_eq!(decode_revert_hex("0x\u{e9}\u{e9}"), "0x\u{e9}\u{e9}");

        let env = Env::init_memory().unwrap();
        let out = simulate(&env, &json!({ "type": "evm", "to": "0xbb", "data": "0x\u{e9}\u{e9}\u{e9}\u{e9}", "RPC": "http://127.0.0.1:1" })).unwrap();
        assert_eq!(out["willRevert"], true, "{out}");
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
        // Audit L4: the caller's to/amount are not read from `raw`, so they
        // are not presented as its decode.
        assert!(out.get("decodedMethod").is_none(), "{out}");
        assert!(out.get("decodedArgs").is_none(), "{out}");
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
        // Audit L4: with `raw`, only what the bytes say is reported — the
        // caller's to/amount are not echoed as a native_transfer decode.
        assert!(out.get("decodedMethod").is_none(), "{out}");
        assert!(out.get("decodedArgs").is_none(), "{out}");
        assert_eq!(out["bitcoinOutputs"][0]["amount"], 100000000u64);
        assert_eq!(out["bitcoinInputs"][0]["txid"], "1111111111111111111111111111111111111111111111111111111111111111");
        assert_eq!(out["bitcoinInputs"][0]["vout"], 0);
        assert_eq!(out["bitcoinFee"], 1234);
        assert_eq!(out["bitcoinVSize"], 60);

        // Without `raw` the fields describe the transfer to build.
        let out = simulate(&env, &json!({ "to": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "amount": { "v": "100000000", "e": 0 } })).unwrap();
        assert_eq!(out["decodedMethod"], "native_transfer");
        // A `raw` that can't be read is a failure, not a fallback to the fields.
        let out = simulate(&env, &json!({ "to": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "amount": "1", "raw": "0xzz" })).unwrap();
        assert!(out.get("decodedMethod").is_none(), "{out}");
        assert_eq!(out["willRevert"], true);
    }

    #[test]
    fn simulate_solana_without_raw_or_account_errors() {
        // No raw bytes and no from / current account: nothing to build from.
        let env = Env::init_memory().unwrap();
        crate::models::account::init(&env).unwrap();
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
