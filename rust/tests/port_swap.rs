//! Ports of the wltswap/okx robustness commits (settlement-confirm, orderStatus,
//! native-SOL wrap, retry predicate, MEV opt-out, min-receive tripwire). Mirrors
//! the Go `wltswap/okx_test.go` cases plus the orderStatus wire shapes.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::rest::ApiKey;
use libwallet::swap::{self, OkxOrderStatusEntry, SwapOrderStatus};
use num_bigint::BigInt;

/// Multi-response mock serving `responses` in order (one request each). Used for
/// both KLB REST envelopes and JSON-RPC node calls.
fn mock_multi(responses: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for body in responses {
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
        }
    });
    format!("http://{addr}")
}

/// One-shot KLB envelope mock wrapping `data_json`.
fn mock_klb(data_json: &str) -> String {
    mock_multi(vec![format!(r#"{{"result":"success","data":{data_json}}}"#)])
}

// ── bce9c70: native-SOL identifier makes OKX wrap SOL ───────────────────────

#[test]
fn native_sol_identifier_wraps_native_sol() {
    // Pins OKX's native-SOL identifier to the all-1s System Program address; it
    // must NOT be the wSOL mint (that leaves the source token account
    // uninitialized -> AccountNotInitialized / custom program error 0xb).
    assert_eq!(swap::OKX_SOLANA_NATIVE, "11111111111111111111111111111111");
    assert_eq!(swap::okx_token_addr("solana", "NATIVE"), "11111111111111111111111111111111");
    assert_ne!(swap::okx_token_addr("solana", "NATIVE"), "So11111111111111111111111111111111111111112");
    // EVM native + explicit token addresses are unaffected.
    assert_eq!(swap::okx_token_addr("evm", "NATIVE"), "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    assert_eq!(swap::okx_token_addr("solana", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
}

// ── 2f419bc: min-receive tripwire tolerates quote→execute drift ─────────────

#[test]
fn min_receive_tolerates_drift() {
    let q = |min_out: i64| BigInt::from(min_out);
    // The field report: 0.0136% drift below the approved minimum — inside the
    // 50 bps band, must NOT reject.
    assert!(swap::okx_assert_min_receive(Some(&q(713274)), 50, "713177").is_ok());
    // SlippageBps == 0 normalizes to the 50 bps default.
    assert!(swap::okx_assert_min_receive(Some(&q(713274)), 0, "713177").is_ok());
    // Exactly the approved minimum passes.
    assert!(swap::okx_assert_min_receive(Some(&q(713274)), 50, "713274").is_ok());
    // floor = 713274 * 9950/10000 = 709707; one unit under it rejects.
    assert!(swap::okx_assert_min_receive(Some(&q(713274)), 50, "709706").is_err());
    // Order-of-magnitude shortfall a tampered response would produce.
    assert!(swap::okx_assert_min_receive(Some(&q(713274)), 50, "400000").is_err());
    // Absent / unparseable field is a no-op.
    assert!(swap::okx_assert_min_receive(Some(&q(713274)), 50, "").is_ok());
    assert!(swap::okx_assert_min_receive(Some(&q(713274)), 50, "   ").is_ok());
    // No quote minimum is a no-op.
    assert!(swap::okx_assert_min_receive(None, 50, "1").is_ok());
}

// ── 6fcb1a8: don't retry deterministic reverts ──────────────────────────────

#[test]
fn is_retryable_solana_broadcast_discriminates() {
    let cases: &[(&str, bool)] = &[
        // Original node-lag / stale-blockhash bug — retry helps.
        (r#"{"code":-32002,"message":"Transaction simulation failed: Blockhash not found"}"#, true),
        ("block height exceeded", true),
        ("transaction expired", true),
        ("context deadline exceeded", true),
        // Jeremy's FLASH case: deterministic program revert — must NOT retry.
        (r#"{"code":-32002,"message":"Transaction simulation failed: Error processing Instruction 5: custom program error: 0xb"}"#, false),
        ("insufficient lamports", false),
        ("exceeds desired slippage limit", false),
        ("", false),
        ("some other error", false),
    ];
    for (err, want) in cases {
        assert_eq!(swap::is_retryable_solana_broadcast(err), *want, "err={err:?}");
    }
}

// ── dd8197e: MEV protection opt-out (default on) ────────────────────────────

#[test]
fn mev_protection_defaults_on_and_opts_out() {
    assert!(swap::mev_enabled(None)); // unset -> default on
    assert!(swap::mev_enabled(Some(true)));
    assert!(!swap::mev_enabled(Some(false))); // host opts out
}

// ── f273dec / f9b3715: orderStatus label + fetch + wire shape ───────────────

#[test]
fn okx_tx_status_label_maps_numeric_codes() {
    let mk = |st: &str, hash: &str| OkxOrderStatusEntry {
        order_id: "o1".into(),
        tx_status: st.into(),
        fail_reason: String::new(),
        tx_hash: hash.into(),
    };
    assert_eq!(swap::okx_tx_status_label(None), "pending");
    assert_eq!(swap::okx_tx_status_label(Some(&mk("1", ""))), "pending");
    assert_eq!(swap::okx_tx_status_label(Some(&mk("2", "0xabc"))), "success");
    assert_eq!(swap::okx_tx_status_label(Some(&mk("3", ""))), "failed");
    // Unknown code but a landed tx reads as success; unknown + no hash pending.
    assert_eq!(swap::okx_tx_status_label(Some(&mk("9", "0xdef"))), "success");
    assert_eq!(swap::okx_tx_status_label(Some(&mk("", ""))), "pending");
}

#[test]
fn okx_fetch_order_status_parses_paginated_envelope() {
    let key = ApiKey::from_seed("kid", [4u8; 32]);
    // Orders nested under the paginated envelope: data[0].orders[].
    let base = mock_klb(r#"[{"cursor":"c1","orders":[{"orderId":"o1","txStatus":"2","txHash":"5xHash","failReason":""}]}]"#);
    let e = swap::okx_fetch_order_status(&key, &base, "501", "SoLaNaAddr", "o1").unwrap().unwrap();
    assert_eq!(e.order_id, "o1");
    assert_eq!(e.tx_status, "2");
    assert_eq!(e.tx_hash, "5xHash");
    assert_eq!(swap::okx_tx_status_label(Some(&e)), "success");

    // A failed order surfaces its reason.
    let base = mock_klb(r#"[{"cursor":"","orders":[{"orderId":"o2","txStatus":"3","failReason":"custom program error: 0xb"}]}]"#);
    let e = swap::okx_fetch_order_status(&key, &base, "501", "addr", "o2").unwrap().unwrap();
    assert_eq!(swap::okx_tx_status_label(Some(&e)), "failed");
    assert_eq!(e.fail_reason, "custom program error: 0xb");

    // Order not yet visible to OKX -> Ok(None) -> pending.
    let base = mock_klb("[]");
    assert!(swap::okx_fetch_order_status(&key, &base, "501", "addr", "unknown").unwrap().is_none());
    let base = mock_klb(r#"[{"cursor":"","orders":[]}]"#);
    assert!(swap::okx_fetch_order_status(&key, &base, "501", "addr", "unknown").unwrap().is_none());
}

#[test]
fn swap_order_status_json_shape() {
    // The normalized wire shape: orderId/chain/status always present; txHash and
    // failReason omitted when empty.
    let pending = SwapOrderStatus {
        order_id: "o1".into(),
        chain: "solana".into(),
        status: "pending".into(),
        tx_hash: String::new(),
        fail_reason: String::new(),
    };
    let v = serde_json::to_value(&pending).unwrap();
    assert_eq!(v["orderId"], "o1");
    assert_eq!(v["chain"], "solana");
    assert_eq!(v["status"], "pending");
    assert!(v.get("txHash").is_none(), "empty txHash must be omitted");
    assert!(v.get("failReason").is_none(), "empty failReason must be omitted");

    let failed = SwapOrderStatus {
        order_id: "o2".into(),
        chain: "evm".into(),
        status: "failed".into(),
        tx_hash: "0xabc".into(),
        fail_reason: "reverted".into(),
    };
    let v = serde_json::to_value(&failed).unwrap();
    assert_eq!(v["txHash"], "0xabc");
    assert_eq!(v["failReason"], "reverted");
}

// ── 03ad446: reserve wSOL input-wrap rent on max native-SOL swaps ───────────

#[test]
fn solana_swap_sol_reservation_reserves_wrap_and_ata() {
    let out_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // USDC
    let rent = 2_039_280u64;
    let empty = || r#"{"jsonrpc":"2.0","id":1,"result":{"value":[]}}"#.to_string();
    let held = || r#"{"jsonrpc":"2.0","id":1,"result":{"value":[{"pubkey":"x"}]}}"#.to_string();
    let rent_resp = || format!(r#"{{"jsonrpc":"2.0","id":1,"result":{rent}}}"#);

    // Native SOL in, holds no wSOL, no output ATA -> reserve BOTH accounts.
    // RPC order: rent, wSOL probe, output-mint probe.
    let node = mock_multi(vec![rent_resp(), empty(), empty()]);
    assert_eq!(swap::solana_swap_sol_reservation(&node, "owner", "NATIVE", out_mint), 2 * rent);

    // Already holds wSOL, already has the output ATA -> reserve NOTHING.
    let node = mock_multi(vec![rent_resp(), held(), held()]);
    assert_eq!(swap::solana_swap_sol_reservation(&node, "owner", "NATIVE", out_mint), 0);

    // No wSOL, output IS wSOL -> reserve only the input wrap (no output probe).
    let node = mock_multi(vec![rent_resp(), empty()]);
    assert_eq!(
        swap::solana_swap_sol_reservation(&node, "owner", "NATIVE", "So11111111111111111111111111111111111111112"),
        rent
    );

    // Non-native input -> 0, no RPC at all (unroutable URL proves it).
    assert_eq!(swap::solana_swap_sol_reservation("http://127.0.0.1:1", "owner", out_mint, out_mint), 0);
}

#[test]
fn is_native_token_address_recognizes_forms() {
    assert!(swap::is_native_token_address(""));
    assert!(swap::is_native_token_address("NATIVE"));
    assert!(swap::is_native_token_address("native"));
    assert!(swap::is_native_token_address("So11111111111111111111111111111111111111112"));
    assert!(!swap::is_native_token_address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
}
