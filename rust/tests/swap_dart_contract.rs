//! The Dart ↔ Rust swap contract (GitHub issue #3): every `Swap:*` endpoint
//! driven through the FFI request layer with exactly the params
//! `dart/lib/src/api/swap_api.dart` sends (camelCase `tokenIn` / `tokenOut` /
//! `amountIn` / `from` / `quoteId` / `Keys` / `orderId`, no `RPC`), checked
//! against the fields `dart/lib/src/models/swap_quote.dart` parses. A routing
//! mock plays both the OKX proxy (by REST path) and the chain node (by JSON-RPC
//! method), recording every request so the OKX token identifiers can be pinned.

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libwallet::{LibwalletDestroy, LibwalletFree, LibwalletInit, LibwalletRequest, ResponseCallback};
use serde_json::{json, Value};

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL: &str = "So11111111111111111111111111111111111111112";
const OKX_SOL_NATIVE: &str = "11111111111111111111111111111111";

extern "C" fn capture(resp: *const c_char, user_data: usize) {
    let s = unsafe { CStr::from_ptr(resp) }.to_str().unwrap().to_owned();
    LibwalletFree(resp as *mut c_char);
    let tx = unsafe { &*(user_data as *const Sender<String>) };
    let _ = tx.send(s);
}

fn request(h: usize, path: &str, params: Value) -> Value {
    let (tx, rx) = channel::<String>();
    let ud = Box::into_raw(Box::new(tx)) as usize;
    let body = json!({ "path": path, "verb": "POST", "params": params }).to_string();
    let req = CString::new(body).unwrap();
    let cb: ResponseCallback = capture;
    LibwalletRequest(h, req.as_ptr(), Some(cb), ud);
    let value = loop {
        let s = rx.recv_timeout(Duration::from_secs(60)).expect("callback fired");
        let v: Value = serde_json::from_str(&s).unwrap();
        if v["result"] != "progress" {
            break v;
        }
    };
    drop(unsafe { Box::from_raw(ud as *mut Sender<String>) });
    value
}

fn ok(resp: Value) -> Value {
    assert_eq!(resp["result"], "success", "{resp}");
    resp["data"].clone()
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn new_env() -> usize {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("libwallet-swap-dart-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
    let h = LibwalletInit(c_dir.as_ptr());
    assert!(h > 0);
    h
}

// ── routing mock ────────────────────────────────────────────────────────────

/// One recorded request: the REST path (or JSON-RPC method) and its decoded
/// params (the `_` query JSON, the POST body, or the RPC params).
#[derive(Debug, Clone)]
struct Seen {
    route: String,
    params: Value,
}

type Router = dyn Fn(&str, &Value) -> Value + Send + Sync;

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

/// Serve forever: `/_special/rest/<Endpoint>` requests are answered with a KLB
/// envelope around `router(endpoint, params)`; anything else is JSON-RPC and
/// answered with `router(method, params)` as the `result`.
fn mock_server(router: Box<Router>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            // Read headers, then Content-Length bytes of body.
            let (head, body) = loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break (String::from_utf8_lossy(&buf).to_string(), String::new());
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..p]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    while buf.len() < p + 4 + len {
                        let n = s.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    break (head, String::from_utf8_lossy(&buf[p + 4..]).to_string());
                }
            };
            let target = head.split_whitespace().nth(1).unwrap_or("").to_owned();
            let (route, params, rest) = if let Some(i) = target.find("/_special/rest/") {
                let rest_path = &target[i + "/_special/rest/".len()..];
                let (endpoint, query) = rest_path.split_once('?').unwrap_or((rest_path, ""));
                let params = match query.strip_prefix("_=") {
                    Some(q) => serde_json::from_str(&percent_decode(q)).unwrap_or(Value::Null),
                    None => serde_json::from_str(&body).unwrap_or(Value::Null),
                };
                (endpoint.to_owned(), params, true)
            } else {
                let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                (v["method"].as_str().unwrap_or("").to_owned(), v["params"].clone(), false)
            };
            log.lock().unwrap().push(Seen { route: route.clone(), params: params.clone() });
            let data = router(&route, &params);
            let out = if rest {
                json!({ "result": "success", "data": data })
            } else {
                json!({ "jsonrpc": "2.0", "id": 1, "result": data })
            }
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                out.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (format!("http://{addr}"), seen)
}

fn seen_for(seen: &Arc<Mutex<Vec<Seen>>>, route: &str) -> Vec<Value> {
    seen.lock().unwrap().iter().filter(|s| s.route == route).map(|s| s.params.clone()).collect()
}

/// An OKX `/quote` entry echoing the requested amount at `rate` out-per-in.
fn okx_quote_entry(params: &Value, num: u64, den: u64) -> Value {
    let amount: u128 = params["amount"].as_str().unwrap().parse().unwrap();
    let out = amount * num as u128 / den as u128;
    json!([{
        "fromTokenAmount": amount.to_string(),
        "toTokenAmount": out.to_string(),
        "priceImpactPercent": "0.12",
        "estimateGasFee": "5000",
        "dexRouterList": [{
            "dexProtocol": { "dexName": "Raydium", "percent": "100" },
            "fromToken": { "tokenSymbol": "IN" },
            "toToken": { "tokenSymbol": "OUT" },
        }],
        "platformFee": { "side": "from", "percent": "0.5", "amount": (amount / 200).to_string() },
    }])
}

// ── fixtures ────────────────────────────────────────────────────────────────

struct Wallet {
    account_id: String,
    address: String,
    pubkey: String,
    keys: Value,
}

fn create_wallet(h: usize, curve: &str, kind: &str) -> Wallet {
    let w = ok(request(
        h,
        "Wallet",
        json!({ "Name": "W", "Curve": curve, "Keys": [
            { "Type": "Password", "Key": "passwordone" },
            { "Type": "Password", "Key": "passwordtwo" },
            { "Type": "Password", "Key": "passwordthree" },
        ]}),
    ));
    let keys: Vec<Value> = ["passwordone", "passwordtwo", "passwordthree"]
        .iter()
        .enumerate()
        .map(|(i, p)| json!({ "Type": "Password", "Id": w["Keys"][i]["Id"], "Key": p }))
        .collect();
    let a = ok(request(h, "Account", json!({ "Wallet": w["Id"], "Type": kind, "Index": 0 })));
    Wallet {
        account_id: a["Id"].as_str().unwrap().to_owned(),
        address: a["Address"].as_str().unwrap().to_owned(),
        pubkey: a["Pubkey"].as_str().unwrap_or("").to_owned(),
        keys: Value::Array(keys),
    }
}

fn use_network(h: usize, kind: &str, chain_id: &str, rpc: &str) {
    let n = ok(request(h, "Network", json!({ "Type": kind, "ChainId": chain_id, "RPC": rpc })));
    ok(request(h, "Network:setCurrent", json!({ "Id": n["Id"] })));
}

/// A Solana swap tx blob OKX would return: one zeroed signature slot plus a
/// message whose fee payer (signer slot 0) is the account.
fn solana_swap_tx_b58(pubkey_b64url: &str) -> String {
    let from = libwallet::solana::pubkey_from_b64url(pubkey_b64url).unwrap();
    let message = libwallet::solana::build_transfer_message(&from, &[9u8; 32], 500, &[1u8; 32]);
    let mut raw = vec![1u8];
    raw.extend_from_slice(&[0u8; 64]);
    raw.extend_from_slice(&message);
    bs58::encode(&raw).into_string()
}

/// The Solana mock: OKX quote/swap/broadcast/orderStatus plus the node methods
/// maxSpendable needs. Holds 2 SOL, 2.5 USDC, no wSOL account.
fn solana_mock(tx_b58: String) -> (String, Arc<Mutex<Vec<Seen>>>) {
    mock_server(Box::new(move |route, params| match route {
        // 1 SOL (1e9) ≈ 150 USDC (150e6): out = in * 3 / 20 for SOL→USDC, and
        // the inverse for USDC→SOL.
        "Crypto/Okx:quote" => {
            if params["fromTokenAddress"] == OKX_SOL_NATIVE {
                okx_quote_entry(params, 3, 20)
            } else {
                okx_quote_entry(params, 20, 3)
            }
        }
        // minReceiveAmount = the quoted out less 0.5%, as OKX computes it.
        "Crypto/Okx:swap" => {
            let q = if params["fromTokenAddress"] == OKX_SOL_NATIVE {
                okx_quote_entry(params, 3, 20)
            } else {
                okx_quote_entry(params, 20, 3)
            };
            let out: u128 = q[0]["toTokenAmount"].as_str().unwrap().parse().unwrap();
            json!([{ "tx": { "data": tx_b58, "minReceiveAmount": (out * 995 / 1000).to_string() } }])
        }
        "Crypto/Okx:broadcastTransaction" => json!([{ "orderId": "ord-sol" }]),
        "Crypto/Okx:orderStatus" => {
            json!([{ "cursor": "", "orders": [{ "orderId": "ord-sol", "txStatus": "2", "txHash": "5LandedSig" }] }])
        }
        "getBalance" => json!({ "value": 2_000_000_000u64 }),
        "getMinimumBalanceForRentExemption" => {
            if params[0] == 165 { json!(2_039_280u64) } else { json!(890_880u64) }
        }
        "getTokenAccountsByOwner" if params[1]["mint"] == USDC => json!({ "value": [{
            "pubkey": "ata",
            "account": { "data": { "parsed": { "info": { "tokenAmount": { "amount": "2500000", "decimals": 6 } } } } },
        }]}),
        "getTokenAccountsByOwner" => json!({ "value": [] }),
        other => panic!("unexpected mock call {other}"),
    }))
}

/// Assert `q` carries every field `SwapQuote.fromJson` reads, with its type.
fn assert_dart_swap_quote(q: &Value) {
    let amount = |v: &Value| v["v"].is_string() && v["e"].is_i64();
    assert!(q["quoteId"].as_str().unwrap().starts_with("q_"), "{q}");
    for k in ["provider", "providerLabel", "chain", "expiresAt"] {
        assert!(q[k].is_string(), "{k} must be a string: {q}");
    }
    for k in ["tokenIn", "tokenOut"] {
        assert!(q[k]["address"].is_string() && q[k]["decimals"].is_i64(), "{k}: {q}");
    }
    for k in ["amountIn", "amountOut", "minAmountOut"] {
        assert!(amount(&q[k]), "{k} must be an Amount: {q}");
    }
    for k in ["referralFee", "networkFee", "currentAllowance", "neededAllowance"] {
        assert!(q[k].is_null() || amount(&q[k]), "{k} must be null or an Amount: {q}");
    }
    assert!(q["priceImpact"].is_number() && q["feeBps"].is_u64() && q["slippageBps"].is_u64(), "{q}");
    assert!(q["route"].is_array() && q["requiresApproval"].is_boolean(), "{q}");
    // expiresAt is RFC 3339, ~90 s out.
    let exp = chrono::DateTime::parse_from_rfc3339(q["expiresAt"].as_str().unwrap()).unwrap();
    let ttl = exp.with_timezone(&chrono::Utc) - chrono::Utc::now();
    assert!(ttl > chrono::Duration::seconds(80) && ttl <= chrono::Duration::seconds(90), "ttl {ttl}");
}

// ── Solana: SOL → SPL ───────────────────────────────────────────────────────

#[test]
fn sol_to_spl_quote_and_execute_with_dart_params() {
    let h = new_env();
    let w = create_wallet(h, "ed25519", "solana");
    let (mock, seen) = solana_mock(solana_swap_tx_b58(&w.pubkey));
    use_network(h, "solana", "mainnet", &mock);

    // Exactly SwapApi.quote's params (+ the test-only Backend host).
    let q = ok(request(
        h,
        "Swap:quote",
        json!({
            "tokenIn": { "address": "NATIVE", "symbol": "SOL", "decimals": 9 },
            "tokenOut": { "address": USDC, "symbol": "USDC", "decimals": 6 },
            "amountIn": "1000000000",
            "slippageBps": 50,
            "Backend": mock,
        }),
    ));
    assert_dart_swap_quote(&q);
    assert_eq!(q["provider"], "okx_solana");
    assert_eq!(q["providerLabel"], "OKX");
    assert_eq!(q["chain"], "solana");
    assert_eq!(q["tokenIn"]["address"], "NATIVE");
    assert_eq!(q["tokenIn"]["symbol"], "SOL");
    assert_eq!(q["amountIn"]["v"], "1000000000");
    assert_eq!(q["amountIn"]["e"], 9);
    assert_eq!(q["amountOut"]["v"], "150000000");
    assert_eq!(q["amountOut"]["e"], 6);
    assert_eq!(q["minAmountOut"]["v"], "149250000"); // −0.5%
    assert_eq!(q["feeBps"], 50);
    assert_eq!(q["referralFee"]["v"], "5000000");
    assert_eq!(q["networkFee"]["v"], "5000");
    assert_eq!(q["route"][0]["venue"], "Raydium");
    assert_eq!(q["requiresApproval"], false);
    // OKX got the native-SOL identifier (so it wraps), not "NATIVE" / wSOL.
    let okx_q = &seen_for(&seen, "Crypto/Okx:quote")[0];
    assert_eq!(okx_q["chainIndex"], "501");
    assert_eq!(okx_q["fromTokenAddress"], OKX_SOL_NATIVE);
    assert_eq!(okx_q["toTokenAddress"], USDC);

    // Exactly SwapApi.execute's params: quoteId + Keys (no from → the quote's account).
    let quote_id = q["quoteId"].as_str().unwrap().to_owned();
    let r = ok(request(h, "Swap:execute", json!({ "quoteId": quote_id, "Keys": w.keys, "Backend": mock })));
    assert_eq!(r["quoteId"], quote_id.as_str());
    assert_eq!(r["provider"], "okx_solana");
    assert_eq!(r["chain"], "solana");
    assert_eq!(r["hash"], "5LandedSig");
    assert_eq!(r["orderId"], "ord-sol");
    assert!(r["url"].as_str().unwrap().ends_with("/tx/5LandedSig"), "{r}");
    assert_dart_swap_quote(&r["quote"]);
    assert_eq!(r["quote"]["quoteId"], quote_id.as_str());

    let swap = &seen_for(&seen, "Crypto/Okx:swap")[0];
    assert_eq!(swap["fromTokenAddress"], OKX_SOL_NATIVE);
    assert_eq!(swap["toTokenAddress"], USDC);
    assert_eq!(swap["amount"], "1000000000");
    assert_eq!(swap["userWalletAddress"], w.address.as_str());
    assert_eq!(swap["slippagePercent"], "0.5");
    let bcast = &seen_for(&seen, "Crypto/Okx:broadcastTransaction")[0];
    assert_eq!(bcast["quoteId"], quote_id.as_str());
    assert_eq!(bcast["address"], w.address.as_str());

    // orderStatus with SwapApi.orderStatus's params.
    let st = ok(request(h, "Swap:orderStatus", json!({ "orderId": "ord-sol", "Backend": mock })));
    assert_eq!(st["orderId"], "ord-sol");
    assert_eq!(st["chain"], "solana");
    assert_eq!(st["status"], "success");
    assert_eq!(st["txHash"], "5LandedSig");
    LibwalletDestroy(h);
}

// ── Solana: SPL → SOL ───────────────────────────────────────────────────────

#[test]
fn spl_to_sol_quote_and_execute_with_dart_params() {
    let h = new_env();
    let w = create_wallet(h, "ed25519", "solana");
    let (mock, seen) = solana_mock(solana_swap_tx_b58(&w.pubkey));
    use_network(h, "solana", "mainnet", &mock);

    // SOL spelled as the wSOL mint (documented as accepted) and the input as an
    // Asset:list key; `from` names the account explicitly.
    let q = ok(request(
        h,
        "Swap:quote",
        json!({
            "tokenIn": { "address": format!("solana.mainnet.{USDC}"), "symbol": "USDC", "decimals": 6 },
            "tokenOut": { "address": WSOL, "symbol": "SOL", "decimals": 9 },
            "amountIn": "1500000",
            "from": w.account_id,
            "provider": "okx_solana",
            "Backend": mock,
        }),
    ));
    assert_dart_swap_quote(&q);
    assert_eq!(q["tokenIn"]["address"], USDC);
    assert_eq!(q["amountIn"]["v"], "1500000");
    assert_eq!(q["amountOut"]["v"], "10000000"); // 1.5 USDC ≈ 0.01 SOL
    assert_eq!(q["amountOut"]["e"], 9);
    assert_eq!(q["slippageBps"], 50); // default
    let okx_q = &seen_for(&seen, "Crypto/Okx:quote")[0];
    assert_eq!(okx_q["fromTokenAddress"], USDC);
    assert_eq!(okx_q["toTokenAddress"], OKX_SOL_NATIVE, "wSOL output must unwrap to native SOL");

    let r = ok(request(
        h,
        "Swap:execute",
        json!({ "quoteId": q["quoteId"], "Keys": w.keys, "from": w.account_id, "mevProtection": false, "Backend": mock }),
    ));
    assert_eq!(r["hash"], "5LandedSig");
    assert_eq!(r["quote"]["tokenOut"]["address"], WSOL);
    let swap = &seen_for(&seen, "Crypto/Okx:swap")[0];
    assert_eq!(swap["fromTokenAddress"], USDC);
    assert_eq!(swap["toTokenAddress"], OKX_SOL_NATIVE);
    assert_eq!(swap["amount"], "1500000");
    LibwalletDestroy(h);
}

// ── Solana maxSpendable (native + SPL) and "MAX" ────────────────────────────

#[test]
fn solana_max_spendable_native_and_spl() {
    let h = new_env();
    let w = create_wallet(h, "ed25519", "solana");
    let (mock, _seen) = solana_mock(solana_swap_tx_b58(&w.pubkey));
    use_network(h, "solana", "mainnet", &mock);

    // Native SOL in: balance − 5000 fee − 890880 sender rent − 2039280 for the
    // transient wSOL wrap account (the USDC ATA already exists — it holds 2.5).
    let want = 2_000_000_000u64 - 5000 - 890_880 - 2_039_280;
    let q = ok(request(
        h,
        "Swap:maxSpendable",
        json!({
            "tokenIn": { "address": "NATIVE", "decimals": 9 },
            "tokenOut": { "address": USDC, "decimals": 6 },
            "Backend": mock,
        }),
    ));
    assert_dart_swap_quote(&q);
    assert_eq!(q["amountIn"]["v"], want.to_string());
    assert!(q.get("status").is_none(), "executable quote has no status: {q}");

    // SPL in: the full token balance.
    let q = ok(request(
        h,
        "Swap:maxSpendable",
        json!({
            "tokenIn": { "address": USDC, "decimals": 6 },
            "tokenOut": { "address": "NATIVE", "decimals": 9 },
            "Backend": mock,
        }),
    ));
    assert_eq!(q["amountIn"]["v"], "2500000");

    // amountIn "MAX" on Swap:quote resolves the same way.
    let q = ok(request(
        h,
        "Swap:quote",
        json!({
            "tokenIn": { "address": USDC, "decimals": 6 },
            "tokenOut": { "address": "NATIVE", "decimals": 9 },
            "amountIn": "MAX",
            "Backend": mock,
        }),
    ));
    assert_eq!(q["amountIn"]["v"], "2500000");

    // Swap:quotes: one attempt, Dart QuoteAttempt shape, cached quote.
    let r = ok(request(
        h,
        "Swap:quotes",
        json!({
            "tokenIn": { "address": "NATIVE", "decimals": 9 },
            "tokenOut": { "address": USDC, "decimals": 6 },
            "amountIn": "1000000",
            "Backend": mock,
        }),
    ));
    let att = &r["attempts"][0];
    assert_eq!(att["provider"], "okx_solana");
    assert_eq!(att["providerLabel"], "OKX");
    assert_dart_swap_quote(&att["quote"]);
    assert!(att.get("error").is_none());
    LibwalletDestroy(h);
}

// ── errors the Dart docs name ───────────────────────────────────────────────

#[test]
fn swap_errors_carry_dart_codes() {
    let h = new_env();
    let w = create_wallet(h, "ed25519", "solana");
    let (mock, _seen) = solana_mock(solana_swap_tx_b58(&w.pubkey));
    use_network(h, "solana", "mainnet", &mock);

    let r = request(h, "Swap:execute", json!({ "quoteId": "q_nope", "Keys": w.keys, "Backend": mock }));
    assert_eq!(r["result"], "error");
    assert!(r["error"].as_str().unwrap().starts_with("quote_not_found:"), "{r}");

    let r = request(h, "Swap:quote", json!({ "tokenOut": { "address": USDC, "decimals": 6 }, "amountIn": "1" }));
    assert!(r["error"].as_str().unwrap().starts_with("invalid_request:"), "{r}");

    let r = request(
        h,
        "Swap:quote",
        json!({
            "tokenIn": { "address": "NATIVE", "decimals": 9 },
            "tokenOut": { "address": USDC, "decimals": 6 },
            "amountIn": "1000",
            "provider": "okx_evm",
        }),
    );
    assert!(r["error"].as_str().unwrap().starts_with("invalid_request:"), "{r}");

    // Execute without Keys.
    let q = ok(request(
        h,
        "Swap:quote",
        json!({
            "tokenIn": { "address": "NATIVE", "decimals": 9 },
            "tokenOut": { "address": USDC, "decimals": 6 },
            "amountIn": "1000000",
            "Backend": mock,
        }),
    ));
    let r = request(h, "Swap:execute", json!({ "quoteId": q["quoteId"], "Keys": [], "Backend": mock }));
    assert!(r["error"].as_str().unwrap().starts_with("invalid_request:"), "{r}");
    LibwalletDestroy(h);
}

// ── EVM: token-in quote → approval → execute, all by quoteId ────────────────

#[test]
fn evm_token_quote_approval_and_execute_by_quote_id() {
    let token = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let router = "0x1111111111111111111111111111111111111111";
    let h = new_env();
    let w = create_wallet(h, "secp256k1", "ethereum");
    let (mock, seen) = mock_server(Box::new(move |route, params| match route {
        "Crypto/Okx:quote" => okx_quote_entry(params, 1, 2000),
        "Crypto/Okx:supportedChains" => json!([{ "chainIndex": "1", "dexTokenApproveAddress": router }]),
        "Crypto/Okx:swap" => json!([{ "tx": {
            "to": router, "value": "0", "data": "0xabcdef", "gas": "120000", "gasPrice": "20000000000",
            "minReceiveAmount": "4975000000000000",
        }}]),
        "Crypto/Okx:broadcastTransaction" => json!([{ "orderId": "ord-evm" }]),
        "Crypto/Okx:orderStatus" => {
            json!([{ "cursor": "", "orders": [{ "orderId": "ord-evm", "txStatus": "2", "txHash": "0xlanded" }] }])
        }
        "eth_call" => json!(format!("0x{}", "0".repeat(64))), // allowance 0
        "eth_getTransactionCount" => json!("0x7"),
        "eth_gasPrice" => json!("0x4a817c800"),
        "eth_estimateGas" => json!("0xb3b0"),
        other => panic!("unexpected mock call {other}"),
    }));
    use_network(h, "evm", "1", &mock);

    let q = ok(request(
        h,
        "Swap:quote",
        json!({
            "tokenIn": { "address": token, "symbol": "USDC", "decimals": 6 },
            "tokenOut": { "address": "NATIVE", "symbol": "ETH", "decimals": 18 },
            "amountIn": "10000000",
            "Backend": mock,
        }),
    ));
    assert_dart_swap_quote(&q);
    assert_eq!(q["provider"], "okx_evm");
    assert_eq!(q["requiresApproval"], true);
    assert_eq!(q["approvalSpender"], router);
    assert_eq!(q["currentAllowance"]["v"], "0");
    assert_eq!(q["neededAllowance"]["v"], "10000000");

    // SwapApi.buildApproval {quoteId} → ApprovalPreview.
    let p = ok(request(h, "Swap:buildApproval", json!({ "quoteId": q["quoteId"] })));
    assert_eq!(p["token"]["address"], token);
    assert_eq!(p["spender"], router);
    assert_eq!(p["spenderLabel"], "OKX Router");
    assert_eq!(p["amount"]["v"], "10000000");
    assert_eq!(p["isUnlimited"], false);
    assert_eq!(p["currentAllowance"]["v"], "0");
    assert!(p["networkFee"]["v"].is_string());
    let tx = &p["tx"];
    assert_eq!(tx["type"], "evm");
    assert_eq!(tx["from"], w.address.as_str());
    assert_eq!(tx["to"], token);
    assert_eq!(tx["value"]["v"], "0");
    assert_eq!(tx["nonce"], 7);
    assert_eq!(tx["gas"], 46000);
    assert!(tx["data"].as_str().unwrap().starts_with("0x095ea7b3"));
    // "max" → unlimited.
    let p = ok(request(h, "Swap:buildApproval", json!({ "quoteId": q["quoteId"], "approvalAmount": "max" })));
    assert_eq!(p["isUnlimited"], true);

    let r = ok(request(h, "Swap:execute", json!({ "quoteId": q["quoteId"], "Keys": w.keys, "Backend": mock })));
    assert_eq!(r["chain"], "evm");
    assert_eq!(r["hash"], "0xlanded");
    assert_eq!(r["orderId"], "ord-evm");
    let swap = &seen_for(&seen, "Crypto/Okx:swap")[0];
    assert_eq!(swap["fromTokenAddress"], token);
    assert_eq!(swap["toTokenAddress"], "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    assert_eq!(swap["amount"], "10000000");
    assert_eq!(seen_for(&seen, "Crypto/Okx:broadcastTransaction")[0]["enableMevProtection"], true);
    LibwalletDestroy(h);
}

#[test]
fn evm_execute_rejects_swap_tx_to_unapproved_router() {
    let token = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let h = new_env();
    let w = create_wallet(h, "secp256k1", "ethereum");
    let (mock, seen) = mock_server(Box::new(move |route, params| match route {
        "Crypto/Okx:quote" => okx_quote_entry(params, 1, 2000),
        "Crypto/Okx:supportedChains" => {
            json!([{ "chainIndex": "1", "dexTokenApproveAddress": "0x1111111111111111111111111111111111111111" }])
        }
        // A tampered response pointing at another contract.
        "Crypto/Okx:swap" => json!([{ "tx": {
            "to": "0x9999999999999999999999999999999999999999", "value": "0", "data": "0xab", "gas": "1", "gasPrice": "1",
        }}]),
        "eth_call" => json!(format!("0x{}", "f".repeat(64))), // allowance already max
        other => panic!("unexpected mock call {other}"),
    }));
    use_network(h, "evm", "1", &mock);
    let q = ok(request(
        h,
        "Swap:quote",
        json!({
            "tokenIn": { "address": token, "decimals": 6 },
            "tokenOut": { "address": "NATIVE", "decimals": 18 },
            "amountIn": "10000000",
            "Backend": mock,
        }),
    ));
    assert_eq!(q["requiresApproval"], false);
    let r = request(h, "Swap:execute", json!({ "quoteId": q["quoteId"], "Keys": w.keys, "Backend": mock }));
    assert_eq!(r["result"], "error");
    assert!(r["error"].as_str().unwrap().contains("does not match approved spender"), "{r}");
    assert!(seen_for(&seen, "Crypto/Okx:broadcastTransaction").is_empty(), "nothing may be broadcast");
    LibwalletDestroy(h);
}
