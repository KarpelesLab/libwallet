//! MAX amount sentinel resolution for native-SOL sends (port of the MAX branch
//! of Go `wlttx/preflight.go` + `computeSolanaMaxSendable`). Asserts a MAX send
//! resolves to balance − fee − rent reserve, against a local mock Solana RPC —
//! no external network. Mirrors `wlttx/maxsendable_test.go::TestComputeSolanaMaxSendable`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::transfer::{
    compute_solana_max_sendable, resolve_solana_max_lamports, SOLANA_BASE_FEE_LAMPORTS,
    SOLANA_DEFAULT_SENDER_RENT,
};

/// Mock Solana JSON-RPC node dispatching on method: `getBalance` returns
/// `balance` lamports, `getMinimumBalanceForRentExemption` returns `rent`, and
/// `getAccountInfo` returns a present or null account per `recipient_exists`.
fn mock_solana(balance: u64, rent: u64, recipient_exists: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Handle each connection on its own thread so accepting the next
            // request never blocks on finishing the current one.
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let result = if req.contains("getMinimumBalanceForRentExemption") {
                    format!("{rent}")
                } else if req.contains("getBalance") {
                    format!(r#"{{"context":{{"slot":1}},"value":{balance}}}"#)
                } else if req.contains("getAccountInfo") {
                    if recipient_exists {
                        r#"{"context":{"slot":1},"value":{"lamports":1,"data":["","base64"]}}"#.to_string()
                    } else {
                        r#"{"context":{"slot":1},"value":null}"#.to_string()
                    }
                } else {
                    "null".to_string()
                };
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
                let _ = s.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    format!("http://{addr}/")
}

const ADDR: &str = "So11111111111111111111111111111111111111112";

#[test]
fn max_resolves_to_balance_minus_reserve_recipient_exists() {
    // The canonical scenario: 0.01 SOL = 10_000_000 lamports.
    // 10_000_000 − 5000 fee − 890_880 sender rent = 9_104_120 lamports.
    let url = mock_solana(10_000_000, SOLANA_DEFAULT_SENDER_RENT, true);
    let got = resolve_solana_max_lamports(&url, ADDR, ADDR, SOLANA_BASE_FEE_LAMPORTS).unwrap();
    assert_eq!(got, 9_104_120);
}

#[test]
fn max_resolves_reserving_new_recipient_rent() {
    // Funding a brand-new recipient also reserves its rent-exempt minimum:
    // 10_000_000 − 5000 − 890_880 − 890_880 = 8_213_240 lamports.
    let url = mock_solana(10_000_000, SOLANA_DEFAULT_SENDER_RENT, false);
    let got = resolve_solana_max_lamports(&url, ADDR, ADDR, SOLANA_BASE_FEE_LAMPORTS).unwrap();
    assert_eq!(got, 8_213_240);
}

#[test]
fn max_with_empty_recipient_skips_recipient_rent() {
    // No recipient supplied -> only fee + sender rent reserved.
    let url = mock_solana(1_000_000_000, SOLANA_DEFAULT_SENDER_RENT, true);
    let got = resolve_solana_max_lamports(&url, ADDR, "", SOLANA_BASE_FEE_LAMPORTS).unwrap();
    assert_eq!(got, 1_000_000_000 - SOLANA_BASE_FEE_LAMPORTS - SOLANA_DEFAULT_SENDER_RENT);
}

#[test]
fn max_respects_priority_inclusive_fee() {
    // A caller-supplied fee larger than the 5000 base is honoured.
    let url = mock_solana(10_000_000, SOLANA_DEFAULT_SENDER_RENT, true);
    let got = resolve_solana_max_lamports(&url, ADDR, ADDR, 25_000).unwrap();
    assert_eq!(got, 10_000_000 - 25_000 - SOLANA_DEFAULT_SENDER_RENT);
}

#[test]
fn max_fails_when_balance_below_reserve() {
    // Below fee + rent -> nothing sendable, resolution errors loudly.
    let url = mock_solana(100_000, SOLANA_DEFAULT_SENDER_RENT, true);
    let err = resolve_solana_max_lamports(&url, ADDR, ADDR, SOLANA_BASE_FEE_LAMPORTS).unwrap_err();
    assert!(err.to_string().contains("not enough"), "{err}");
}

#[test]
fn compute_matches_go_vectors() {
    // Mirrors wlttx/maxsendable_test.go::TestComputeSolanaMaxSendable.
    let fee = 5000u64;
    let rent = 890_880u64;

    // recipient exists, 0.01 SOL
    let (max, reserved, reason) = compute_solana_max_sendable(10_000_000, fee, rent, 0, true);
    assert_eq!((max, reserved), (9_104_120, 895_880));
    assert!(reason.is_none());
    assert_eq!(max + reserved, 10_000_000); // balance conservation

    // new recipient, 0.01 SOL (recipient rent also reserved)
    let (max, reserved, reason) = compute_solana_max_sendable(10_000_000, fee, rent, rent, false);
    assert_eq!((max, reserved), (8_213_240, 1_786_760));
    assert!(reason.is_none());
    assert_eq!(max + reserved, 10_000_000);

    // exactly fee + rent -> nothing sendable
    let (max, reserved, reason) = compute_solana_max_sendable(fee + rent, fee, rent, 0, true);
    assert_eq!((max, reserved), (0, fee + rent));
    assert!(reason.is_some());

    // below fee + rent
    let (max, _reserved, reason) = compute_solana_max_sendable(100_000, fee, rent, 0, true);
    assert_eq!(max, 0);
    assert!(reason.is_some());

    // large balance fully covers everything
    let (max, reserved, reason) = compute_solana_max_sendable(1_000_000_000, fee, rent, 0, true);
    assert_eq!((max, reserved), (1_000_000_000 - fee - rent, fee + rent));
    assert!(reason.is_none());
}
