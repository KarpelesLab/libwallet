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
