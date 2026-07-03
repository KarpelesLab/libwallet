//! ERC-20 read-call encoding + eth_call decoding against a mock node.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::erc20;

#[test]
fn selectors_are_keccak() {
    let sel = |sig: &[u8]| {
        let h = purecrypto::hash::keccak256(sig);
        format!("{:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3])
    };
    assert_eq!(sel(b"balanceOf(address)"), "70a08231");
    assert_eq!(sel(b"allowance(address,address)"), "dd62ed3e");
}

#[test]
fn encode_calldata_is_byte_exact() {
    let bal = erc20::encode_balance_of("0x1111111111111111111111111111111111111111").unwrap();
    assert_eq!(
        bal,
        "0x70a082310000000000000000000000001111111111111111111111111111111111111111"
    );
    assert_eq!(bal.len(), 2 + 8 + 64);

    // Mixed-case address is lowercased and left-padded; two words for allowance.
    let allow = erc20::encode_allowance(
        "0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
        "0x2222222222222222222222222222222222222222",
    )
    .unwrap();
    assert_eq!(
        allow,
        "0xdd62ed3e\
         000000000000000000000000abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd\
         0000000000000000000000002222222222222222222222222222222222222222"
    );

    // Malformed addresses error.
    assert!(erc20::encode_balance_of("1111").is_err());
    assert!(erc20::encode_balance_of("0x1234").is_err());
}

/// One-shot mock returning a single JSON-RPC result.
fn mock(result_json: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
    thread::spawn(move || {
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
    format!("http://{addr}/")
}

#[test]
fn balance_of_decodes_eth_call_uint256() {
    // 0x…0f4240 = 1_000_000 base units.
    let url = mock(r#""0x00000000000000000000000000000000000000000000000000000000000f4240""#);
    let bal = erc20::balance_of(&url, "0xToken", "0x1111111111111111111111111111111111111111").unwrap();
    assert_eq!(bal.to_string(), "1000000");
}

#[test]
fn empty_result_is_zero() {
    let url = mock(r#""0x""#);
    let bal = erc20::balance_of(&url, "0xToken", "0x1111111111111111111111111111111111111111").unwrap();
    assert_eq!(bal.to_string(), "0");
}

#[test]
fn decimals_selector_and_decode() {
    // selector = keccak256("decimals()")[:4].
    let h = purecrypto::hash::keccak256(b"decimals()");
    assert_eq!(format!("{:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3]), "313ce567");
    // eth_call returns the decimals in a uint256 word (6 for USDC).
    let url = mock(r#""0x0000000000000000000000000000000000000000000000000000000000000006""#);
    assert_eq!(erc20::decimals(&url, "0xToken").unwrap(), 6);
}
