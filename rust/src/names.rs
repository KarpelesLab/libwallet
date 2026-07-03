//! Name resolution (port of wltnames). ENS (Ethereum) resolves a name to an
//! address via two eth_call hops: registry.resolver(namehash) then
//! resolver.addr(namehash). Uses the blocking RPC client.

use purecrypto::hash::keccak256;
use serde_json::json;

use crate::{Error, Result};

/// The canonical ENS registry on Ethereum mainnet.
const ENS_REGISTRY: &str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
/// `resolver(bytes32)` selector.
const SEL_RESOLVER: [u8; 4] = [0x01, 0x78, 0xb8, 0xbf];
/// `addr(bytes32)` selector.
const SEL_ADDR: [u8; 4] = [0x3b, 0x3b, 0x57, 0xde];

/// EIP-137 namehash of a domain.
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if !name.is_empty() {
        for label in name.split('.').rev() {
            let label_hash = keccak256(label.as_bytes());
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&node);
            buf[32..].copy_from_slice(&label_hash);
            node = keccak256(&buf);
        }
    }
    node
}

/// Resolve an ENS name to a lowercase 0x-address, or an error if unregistered.
pub fn resolve_ens(rpc_url: &str, name: &str) -> Result<String> {
    let node = namehash(name);

    // registry.resolver(node) -> resolver address (last 20 bytes of the return).
    let resolver_ret = eth_call(rpc_url, ENS_REGISTRY, &SEL_RESOLVER, &node)?;
    let resolver = addr_from_word(&resolver_ret)?;
    if resolver.iter().all(|&b| b == 0) {
        return Err(Error::Env(format!("no resolver for {name}")));
    }
    let resolver_hex = format!("0x{}", hex(&resolver));

    // resolver.addr(node) -> the resolved address.
    let addr_ret = eth_call(rpc_url, &resolver_hex, &SEL_ADDR, &node)?;
    let addr = addr_from_word(&addr_ret)?;
    if addr.iter().all(|&b| b == 0) {
        return Err(Error::Env(format!("{name} has no address record")));
    }
    Ok(format!("0x{}", hex(&addr)))
}

fn eth_call(url: &str, to: &str, selector: &[u8; 4], node: &[u8; 32]) -> Result<Vec<u8>> {
    let mut data = selector.to_vec();
    data.extend_from_slice(node);
    let res = crate::rpc::call(url, "eth_call", json!([{ "to": to, "data": format!("0x{}", hex(&data)) }, "latest"]))?;
    let s = res.as_str().ok_or_else(|| Error::Env("eth_call result not a string".into()))?;
    hex_decode(s.strip_prefix("0x").unwrap_or(s))
}

/// The 20-byte address in the low bytes of a 32-byte ABI word.
fn addr_from_word(word: &[u8]) -> Result<[u8; 20]> {
    if word.len() < 32 {
        return Err(Error::Env("ABI word shorter than 32 bytes".into()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&word[12..32]);
    Ok(a)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::Env("odd-length hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| Error::Env(e.to_string())))
        .collect()
}
