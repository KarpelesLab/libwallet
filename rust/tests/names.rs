//! ENS: namehash (EIP-137 vectors) + full resolution against a mock node.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::names::{namehash, normalize_ens_name, resolve_ens};

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

#[test]
fn ens_names_are_normalized_before_hashing() {
    // Case and surrounding whitespace fold away; the result is what is hashed.
    assert_eq!(normalize_ens_name("foo.eth").unwrap(), "foo.eth");
    assert_eq!(normalize_ens_name("  Foo.ETH\n").unwrap(), "foo.eth");
    assert_eq!(normalize_ens_name("sub.Vitalik.eth").unwrap(), "sub.vitalik.eth");
    assert_eq!(normalize_ens_name("a-b_c.1.eth").unwrap(), "a-b_c.1.eth");
    // Decomposed input composes (NFC), so both spellings hash alike.
    let composed = normalize_ens_name("caf\u{e9}.eth").unwrap();
    assert_eq!(normalize_ens_name("cafe\u{301}.eth").unwrap(), composed);
    assert_eq!(normalize_ens_name("CAFE\u{301}.ETH").unwrap(), composed);
    assert_eq!(composed, "caf\u{e9}.eth");
    // Ordinary non-Latin names and plain emoji still pass.
    assert_eq!(normalize_ens_name("БАНК.eth").unwrap(), "банк.eth");
    assert_eq!(normalize_ens_name("日本.eth").unwrap(), "日本.eth");
    assert_eq!(normalize_ens_name("\u{1F680}.eth").unwrap(), "\u{1F680}.eth");
    // Normalizing twice changes nothing.
    for n in ["Foo.ETH", "CAFE\u{301}.eth", "БАНК.eth", "ΟΔΟΣ.eth", "İstanbul.eth"] {
        let once = normalize_ens_name(n).unwrap();
        assert_eq!(normalize_ens_name(&once).unwrap(), once, "{n}");
    }
}

#[test]
fn ens_names_that_would_hash_to_someone_elses_node_are_refused() {
    for bad in [
        "",
        "   ",
        ".eth",
        "foo..eth",
        "foo.eth.",
        ".",
        "foo bar.eth",
        "foo\tbar.eth",
        "foo\u{a0}bar.eth",   // no-break space
        "foo\u{3000}.eth",    // ideographic space
        "foo\u{0}.eth",       // control
        "foo\u{7f}.eth",
        "vita\u{200b}lik.eth", // zero width space
        "vita\u{200c}lik.eth", // ZWNJ
        "vita\u{200d}lik.eth", // ZWJ
        "\u{200e}vitalik.eth", // LRM
        "vitalik\u{200f}.eth", // RLM
        "\u{202e}kilativ.eth", // bidi override
        "vita\u{2060}lik.eth", // word joiner
        "vita\u{2063}lik.eth", // invisible separator
        "vita\u{2066}lik.eth", // bidi isolate
        "vitalik\u{feff}.eth", // BOM inside the name
        "vita\u{ad}lik.eth",   // soft hyphen
        "vita\u{61c}lik.eth",  // arabic letter mark
        "vita\u{180e}lik.eth", // mongolian vowel separator
        "\u{2764}\u{fe0f}.eth", // emoji variation selector
        "vita\u{e0061}lik.eth", // tag character
        "\u{ff56}italik.eth",  // fullwidth v
        "\u{fb01}sh.eth",      // fi ligature
        "foo\u{3002}eth",      // ideographic full stop
        "foo\u{ff0e}eth",      // fullwidth full stop
        "foo\u{2024}eth",      // one dot leader
        "\u{1d400}.eth",       // mathematical bold capital A
    ] {
        assert!(normalize_ens_name(bad).is_err(), "{bad:?} must be refused");
        // …and resolution never reaches the node for it (unroutable RPC).
        assert!(resolve_ens("http://127.0.0.1:1/", bad).unwrap_err().to_string().contains("unsupported ENS name"), "{bad:?}");
    }
}

#[test]
fn resolve_ens_hashes_the_normalized_name() {
    // Capture the node asked for: "Foo.ETH" must query namehash("foo.eth").
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen2 = seen.clone();
    let t = thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            *seen2.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#, "0".repeat(64));
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes());
        }
    });
    assert!(resolve_ens(&format!("http://{addr}/"), "  Foo.ETH ").is_err()); // zero resolver
    t.join().unwrap();
    let request = seen.lock().unwrap().clone();
    assert!(request.contains(&hex(&namehash("foo.eth"))), "{request}");
    assert!(!request.contains(&hex(&namehash("Foo.ETH"))));
}
