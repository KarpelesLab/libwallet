//! ENS: namehash (EIP-137 vectors) + full resolution against a mock node.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::names::{namehash, resolve_ens};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Mock node that serves `responses` in order (one request each).
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
    format!("http://{addr}/")
}

#[test]
fn namehash_eip137_vectors() {
    assert_eq!(hex(&namehash("")), "0".repeat(64));
    assert_eq!(hex(&namehash("eth")), "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae");
    assert_eq!(hex(&namehash("foo.eth")), "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f");
}

#[test]
fn resolve_ens_two_hops() {
    // Hop 1: registry.resolver -> a non-zero resolver address.
    let resolver = format!("{}{}", "0".repeat(24), "1".repeat(40));
    // Hop 2: resolver.addr -> the resolved address (…dead).
    let target = format!("{}000000000000000000000000000000000000dead", "0".repeat(24));
    let url = mock_multi(vec![
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{resolver}"}}"#),
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{target}"}}"#),
    ]);

    let addr = resolve_ens(&url, "foo.eth").unwrap();
    assert_eq!(addr, "0x000000000000000000000000000000000000dead");
}

#[test]
fn resolve_ens_no_resolver_errors() {
    let zero_word = "0".repeat(64);
    let url = mock_multi(vec![format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{zero_word}"}}"#)]);
    assert!(resolve_ens(&url, "nonexistent.eth").is_err());
}
