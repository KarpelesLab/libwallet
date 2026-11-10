//! CoinInfo lookup against a local mock of the KLB REST backend — no external
//! network. Verifies envelope unwrap, parse, DB caching, and negative caching.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use libwallet::coininfo;
use libwallet::Env;

/// Mock serving `data_json` inside the KLB envelope, counting requests so a
/// test can assert the cache prevented a second fetch.
fn mock(data_json: &str, hits: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(r#"{{"result":"success","data":{data_json}}}"#);
    thread::spawn(move || {
        for _ in 0..8 {
            if let Ok((mut s, _)) = listener.accept() {
                hits.fetch_add(1, Ordering::SeqCst);
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

#[test]
fn by_symbol_parses_and_caches() {
    let hits = Arc::new(AtomicUsize::new(0));
    let base = mock(
        r#"{"id":825,"name":"Tether","symbol":"USDT","category":"token","logo":"data:image/png;base64,AA","urls":{"website":["https://tether.to"]},"twitter_username":"tether_to"}"#,
        hits.clone(),
    );
    let env = Env::init_memory().unwrap();

    let info = coininfo::by_key(&env, &base, "symbol", "USDT").unwrap().expect("found");
    assert_eq!(info.name, "Tether");
    assert_eq!(info.symbol, "USDT");
    assert_eq!(info.twitter, "tether_to");
    assert_eq!(info.urls.get("website").unwrap()[0], "https://tether.to");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Second lookup is served from the DB cache — no new request.
    let again = coininfo::by_key(&env, &base, "symbol", "USDT").unwrap().expect("cached");
    assert_eq!(again.name, "Tether");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[test]
fn absent_record_is_negative_cached() {
    let hits = Arc::new(AtomicUsize::new(0));
    let base = mock("null", hits.clone());
    let env = Env::init_memory().unwrap();

    assert!(coininfo::by_key(&env, &base, "symbol", "NOPE").unwrap().is_none());
    // A null record is cached negatively: the second call makes no request.
    assert!(coininfo::by_key(&env, &base, "symbol", "NOPE").unwrap().is_none());
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// Audit F8: a lookup against an overridden backend is cached under that
/// backend only — it never lands in (or is served from) the entry the default
/// backend uses, nor another override's.
#[test]
fn overridden_backend_does_not_share_the_default_cache_entry() {
    let hits_a = Arc::new(AtomicUsize::new(0));
    let hits_b = Arc::new(AtomicUsize::new(0));
    let a = mock(r#"{"id":1,"name":"Evil Tether","symbol":"USDT"}"#, hits_a.clone());
    let b = mock(r#"{"id":2,"name":"Other Tether","symbol":"USDT"}"#, hits_b.clone());
    let env = Env::init_memory().unwrap();

    let got = coininfo::by_key(&env, &a, "symbol", "USDT").unwrap().expect("found");
    assert_eq!(got.name, "Evil Tether");
    // The production cache entry is untouched.
    assert!(env.cache_load("rest:ccInfo:symbol:USDT").unwrap().is_none());

    // A different backend is fetched, not answered from the first one's entry.
    let got = coininfo::by_key(&env, &b, "symbol", "USDT").unwrap().expect("found");
    assert_eq!(got.name, "Other Tether");
    assert_eq!((hits_a.load(Ordering::SeqCst), hits_b.load(Ordering::SeqCst)), (1, 1));

    // Each override still caches for itself.
    assert_eq!(coininfo::by_key(&env, &a, "symbol", "USDT").unwrap().unwrap().name, "Evil Tether");
    assert_eq!((hits_a.load(Ordering::SeqCst), hits_b.load(Ordering::SeqCst)), (1, 1));

    // And an entry cached by the default backend is what the default path reads.
    env.cache_store(
        "rest:ccInfo:symbol:USDT",
        br#"{"id":825,"name":"Tether","symbol":"USDT"}"#,
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(coininfo::by_symbol(&env, "USDT").unwrap().unwrap().name, "Tether");
}
