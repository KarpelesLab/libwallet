//! Curated token registry (wlttoken/curated) — the embedded, vetted token list
//! served by `Token:listCurated`. Per-chain JSON files are compiled in via
//! `include_str!` (like the contract registry); the dynamic ChiefStaker feed for
//! Solana mainnet needs a live service and is out of scope here.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One curated token entry (Go `CuratedToken`), a pass-through of the embedded
/// JSON so every generator field reaches the host unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuratedToken(pub Value);

/// The embedded per-chain lists, keyed by canonical `<type>.<chainId>`.
fn chain_file(chain_key: &str) -> Option<&'static str> {
    Some(match chain_key {
        "evm.1" => include_str!("token_data/evm-1.json"),
        "evm.10" => include_str!("token_data/evm-10.json"),
        "evm.56" => include_str!("token_data/evm-56.json"),
        "evm.100" => include_str!("token_data/evm-100.json"),
        "evm.137" => include_str!("token_data/evm-137.json"),
        "evm.250" => include_str!("token_data/evm-250.json"),
        "evm.324" => include_str!("token_data/evm-324.json"),
        "evm.8453" => include_str!("token_data/evm-8453.json"),
        "evm.42161" => include_str!("token_data/evm-42161.json"),
        "evm.43114" => include_str!("token_data/evm-43114.json"),
        "evm.59144" => include_str!("token_data/evm-59144.json"),
        "solana.mainnet" => include_str!("token_data/solana-mainnet.json"),
        _ => return None,
    })
}

/// The curated token list for a canonical `<type>.<chainId>` chain key. Returns
/// an empty list for chains with no embedded file (never null, matching Go).
pub fn for_chain(chain_key: &str) -> Vec<Value> {
    match chain_file(chain_key).and_then(|s| serde_json::from_str::<Vec<Value>>(s).ok()) {
        Some(list) => list,
        None => Vec::new(),
    }
}
