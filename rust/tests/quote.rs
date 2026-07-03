//! Quote lookup against a local mock of the KLB REST backend — no external
//! network. Verifies the envelope is unwrapped, the record parses, and the
//! result is DB-cached (a second lookup needs no second request).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::quote;
use libwallet::Env;

/// One-shot mock: replies to a single request with the KLB envelope wrapping
/// `data_json`, then closes. Returns the base URL (no trailing slash).
fn mock(data_json: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(r#"{{"result":"success","data":{data_json}}}"#);
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

const QUOTES: &str = r#"[
    {"id":1,"name":"Bitcoin","symbol":"BTC","slug":"bitcoin","date_added":"2013-04-28T00:00:00.000Z",
     "tags":["mineable"],"circulating_supply":19700000.0,"total_supply":21000000.0,
     "last_updated":"2024-07-30T05:43:00.000Z",
     "quote":{"USD":{"price":65000.5,"volume_24h":123.0,"market_cap":1.2e12,"percent_change_24h":-1.5,"last_updated":"2024-07-30T05:43:00.000Z"},
              "EUR":{"price":60000.0,"last_updated":"2024-07-30T05:43:00.000Z"}}},
    {"id":1027,"name":"Ethereum","symbol":"ETH","slug":"ethereum",
     "quote":{"USD":{"price":3200.25}}}
]"#;

#[test]
fn lookup_parses_and_caches() {
    let base = mock(QUOTES);
    let env = Env::init_memory().unwrap();

    // First lookup fetches from the (one-shot) server.
    let btc = quote::get_quotes_for_token_from(&env, &base, "BTC")
        .unwrap()
        .expect("BTC present");
    assert_eq!(btc.name, "Bitcoin");
    assert_eq!(btc.symbol, "BTC");
    assert_eq!(btc.quote.get("USD").unwrap().price, 65000.5);
    assert_eq!(btc.quote.get("EUR").unwrap().price, 60000.0);
    assert_eq!(btc.circulating_supply, 19700000.0);

    // Second lookup (different symbol) must come from the cache — the mock only
    // served one request, so this would fail on a network round-trip.
    let eth = quote::get_quotes_for_token_from(&env, &base, "ETH")
        .unwrap()
        .expect("ETH present");
    assert_eq!(eth.quote.get("USD").unwrap().price, 3200.25);

    // A missing symbol resolves to None (still from cache).
    assert!(quote::get_quotes_for_token_from(&env, &base, "NOPE").unwrap().is_none());

    // The cached bytes live under the Go-compatible key.
    assert!(env.cache_load(quote::CACHE_KEY).unwrap().is_some());
}
