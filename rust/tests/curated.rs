//! Curated token registry — the embedded per-chain lists load and match the Go
//! data files (Token:listCurated).

use libwallet::curated;

#[test]
fn for_chain_returns_embedded_list() {
    // evm.1 (Ethereum) has the full embedded list; first entry matches the
    // Go data file byte-for-byte.
    let eth = curated::for_chain("evm.1");
    assert_eq!(eth.len(), 379, "evm.1 curated count matches Go data");
    assert_eq!(eth[0]["address"], "0x000006c2A22ff4A44ff1f5d0F2ed65F781F55555");
    assert_eq!(eth[0]["chainKey"], "evm.1");
    assert!(eth[0].get("symbol").is_some());

    // Another chain loads too.
    assert!(!curated::for_chain("evm.137").is_empty(), "polygon list present");
    assert!(!curated::for_chain("solana.mainnet").is_empty(), "solana list present");

    // An unknown chain is an empty list (never null).
    assert!(curated::for_chain("evm.999999").is_empty());
    assert!(curated::for_chain("bitcoin.bitcoin").is_empty());
}

/// Every embedded list must parse (`for_chain` swallows parse errors and would
/// silently serve an empty list), carry no duplicate addresses, and use a real
/// boolean for the optional `verified` flag.
#[test]
fn embedded_lists_are_well_formed() {
    let chains = [
        "evm.1", "evm.10", "evm.56", "evm.100", "evm.137", "evm.250", "evm.324",
        "evm.8453", "evm.42161", "evm.43114", "evm.59144", "solana.mainnet",
    ];
    for chain in chains {
        let list = curated::for_chain(chain);
        let mut seen = std::collections::HashSet::new();
        for t in &list {
            assert_eq!(t["chainKey"], chain, "{chain}: wrong chainKey in {t}");
            let addr = t["address"].as_str().unwrap_or_else(|| panic!("{chain}: no address in {t}"));
            assert!(seen.insert(addr.to_ascii_lowercase()), "{chain}: duplicate {addr}");
            if let Some(v) = t.get("verified") {
                assert!(v.is_boolean(), "{chain}: non-boolean verified on {addr}");
            }
        }
    }
    // A hand-edit that breaks the JSON would empty the list instead of failing.
    assert!(curated::for_chain("solana.mainnet").len() >= 693, "solana list parses");
}

#[test]
fn solana_verified_flag_passes_through() {
    let sol = curated::for_chain("solana.mainnet");
    let jup = sol
        .iter()
        .find(|t| t["address"] == "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN")
        .expect("JUP present");
    assert_eq!(jup["verified"], true);
    assert!(sol.iter().filter(|t| t["verified"] == true).count() >= 48);
    assert!(curated::for_chain("evm.1").iter().all(|t| t.get("verified").is_none()));
}
