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

// --- SNS (Solana Name Service) --------------------------------------------

const SNS_PROGRAM: &str = "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX";
const SNS_PARENT: &str = "58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx";
const SNS_PREFIX: &str = "SPL Name Service";

fn sha256(data: &[u8]) -> [u8; 32] {
    purecrypto::hash::sha256(data)
}

/// True if `bytes` decompresses to a valid Ed25519 point (i.e. is on-curve, so
/// not a valid PDA).
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    purecrypto::ec::edwards25519::hazmat::EdwardsPoint::decompress(bytes).is_some()
}

fn b58_32(s: &str) -> Result<[u8; 32]> {
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Env(format!("bad base58 32-byte value: {s}")))
}

/// Solana findProgramAddress over seeds `[name_hash, class(0), parent]`: try
/// bumps 255..0, returning the first off-curve candidate (matching Go
/// createProgramAddress).
fn create_program_address(name_hash: &[u8; 32], parent: &[u8; 32], program: &[u8; 32]) -> Result<[u8; 32]> {
    let class = [0u8; 32];
    let mut seed = Vec::with_capacity(96);
    seed.extend_from_slice(name_hash);
    seed.extend_from_slice(&class);
    seed.extend_from_slice(parent);
    for bump in (0u16..=255).rev() {
        let mut h = seed.clone();
        h.push(bump as u8);
        h.extend_from_slice(program);
        h.extend_from_slice(b"ProgramDerivedAddress");
        let pda = sha256(&h);
        if !is_on_curve(&pda) {
            return Ok(pda);
        }
    }
    Err(Error::Env("unable to derive PDA".into()))
}

/// Resolve a Solana `.sol` name to its owner address (base58), via the SNS
/// domain PDA + getAccountInfo. Port of Go ResolveSNS.
pub fn resolve_sns(rpc_url: &str, name: &str) -> Result<String> {
    let name = name.trim().to_lowercase();
    let label = name.strip_suffix(".sol").ok_or_else(|| Error::Env("SNS names must end with .sol".into()))?;
    if label.is_empty() || label.contains('.') {
        return Err(Error::Env("SNS supports single-label .sol names only".into()));
    }

    let name_hash = sha256(format!("{SNS_PREFIX}{label}").as_bytes());
    let parent = b58_32(SNS_PARENT)?;
    let program = b58_32(SNS_PROGRAM)?;
    let domain = create_program_address(&name_hash, &parent, &program)?;
    let domain_b58 = bs58::encode(&domain).into_string();

    let res = crate::rpc::call(
        rpc_url,
        "getAccountInfo",
        json!([domain_b58, { "encoding": "base64" }]),
    )?;
    let data_b64 = res
        .get("value")
        .and_then(|v| v.get("data"))
        .and_then(|d| d.get(0))
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::Env("SNS domain not found".into()))?;
    let data = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| Error::Env(format!("bad account data: {e}")))?
    };
    if data.len() < 96 {
        return Err(Error::Env(format!("SNS record too short ({} bytes)", data.len())));
    }
    // NameRecordHeader: parent(32) | owner(32) | class(32) | data.
    if data[0..32] != parent {
        return Err(Error::Env("SNS record parent mismatch".into()));
    }
    let owner = &data[32..64];
    if owner.iter().all(|&b| b == 0) {
        return Err(Error::Env("SNS name resolves to zero owner".into()));
    }
    Ok(bs58::encode(owner).into_string())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod sns_tests {
    use super::*;
    use base64::Engine;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn program_address_is_deterministic_and_off_curve() {
        let nh = sha256(b"SPL Name Servicebonfida");
        let parent = b58_32(SNS_PARENT).unwrap();
        let program = b58_32(SNS_PROGRAM).unwrap();
        let a = create_program_address(&nh, &parent, &program).unwrap();
        let b = create_program_address(&nh, &parent, &program).unwrap();
        assert_eq!(a, b);
        assert!(!is_on_curve(&a), "PDA must be off-curve");
    }

    fn mock(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
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
    fn resolve_sns_returns_owner() {
        let parent = b58_32(SNS_PARENT).unwrap();
        let owner = [0x11u8; 32];
        // NameRecordHeader: parent | owner | class(0).
        let mut record = Vec::new();
        record.extend_from_slice(&parent);
        record.extend_from_slice(&owner);
        record.extend_from_slice(&[0u8; 32]);
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&record);
        let url = mock(format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"value":{{"data":["{data_b64}","base64"]}}}}}}"#
        ));

        let got = resolve_sns(&url, "example.sol").unwrap();
        assert_eq!(got, bs58::encode(&owner).into_string());
    }

    #[test]
    fn resolve_sns_rejects_non_sol() {
        assert!(resolve_sns("http://unused", "foo.eth").is_err());
    }
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
