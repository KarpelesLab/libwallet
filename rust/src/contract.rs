//! wltcontract — curated smart-contract labels (embedded per-chain registry).
//! Used to show human-readable names ("Uniswap V2: Router") for known
//! addresses in tx effects and approval sheets. Data is embedded at build time.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Contract {
    #[serde(rename = "chainKey", default)]
    pub chain_key: String,
    #[serde(rename = "address", default)]
    pub address: String,
    #[serde(rename = "label", default)]
    pub label: String,
    #[serde(rename = "kind", default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(rename = "project", default, skip_serializing_if = "String::is_empty")]
    pub project: String,
}

/// The embedded per-chain registries (one JSON array per EVM chain).
const REGISTRIES: &[&str] = &[
    include_str!("contract_data/evm-1.json"),
    include_str!("contract_data/evm-10.json"),
    include_str!("contract_data/evm-137.json"),
    include_str!("contract_data/evm-42161.json"),
    include_str!("contract_data/evm-43114.json"),
    include_str!("contract_data/evm-8453.json"),
];

/// Lookup index keyed by "<chainKey>|<lowercase address>".
static INDEX: LazyLock<HashMap<String, Contract>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    for raw in REGISTRIES {
        if let Ok(list) = serde_json::from_str::<Vec<Contract>>(raw) {
            for c in list {
                m.insert(format!("{}|{}", c.chain_key, c.address.to_lowercase()), c);
            }
        }
    }
    m
});

/// Look up a curated label for a contract address on a chain (e.g. chain_key
/// "evm.1"). Address matching is case-insensitive.
pub fn lookup(chain_key: &str, address: &str) -> Option<Contract> {
    INDEX.get(&format!("{}|{}", chain_key, address.to_lowercase())).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_uniswap_router_is_labeled() {
        // Uniswap V2 Router on Ethereum mainnet (from the embedded registry).
        let c = lookup("evm.1", "0x7a250d5630b4cf539739df2c5dacb4c659f2488d").expect("found");
        assert_eq!(c.label, "Uniswap V2: Router");
        assert_eq!(c.project, "uniswap");
        // Case-insensitive on the address.
        assert!(lookup("evm.1", "0x7A250D5630B4CF539739DF2C5DACB4C659F2488D").is_some());
    }

    #[test]
    fn unknown_address_is_none() {
        assert!(lookup("evm.1", "0x0000000000000000000000000000000000000000").is_none());
        assert!(lookup("evm.999", "0x7a250d5630b4cf539739df2c5dacb4c659f2488d").is_none());
    }

    #[test]
    fn registry_loaded_nonempty() {
        assert!(INDEX.len() >= 30, "embedded registry has entries: {}", INDEX.len());
    }
}
