//! `Wallet:probeActivity` core (port of wltwallet/probe.go): derive the
//! canonical addresses for a BIP39 seed across the supported chains and probe
//! each chain's RPC for on-chain activity. Read-only; no wallet state changes.
//!
//! This is the reusable core (seed → candidates → addresses → probe). The FFI
//! endpoint decrypts a mnemonic-keep wallet's share to obtain the seed; that
//! wallet type + handler wiring builds on top of this.

use serde_json::Value;

use crate::{Error, Result};

/// One (chain, BIP variant) address the probe derives + checks.
pub struct Candidate {
    pub network: &'static str,          // "bitcoin" | "ethereum" | "solana" | …
    pub variant: &'static str,          // UI label
    pub curve: &'static str,            // "secp256k1" | "ed25519"
    pub path: &'static str,             // BIP32 path ("" = ed25519 Sollet)
    pub address_chain: &'static str,    // bitcoin::hd_address chain id (secp/bitcoin)
    pub network_type: &'static str,     // "evm" | "bitcoin" | "solana"
    pub network_chain_id: &'static str, // for the probe network
}

/// The baseline candidate list (Go `defaultProbeCandidates`; the P2WPKH/EVM/
/// Solana set — legacy P2PKH variants land with a public P2PKH encoder).
pub fn default_candidates() -> Vec<Candidate> {
    vec![
        Candidate { network: "bitcoin", variant: "P2WPKH (BIP84)", curve: "secp256k1", path: "m/84'/0'/0'/0/0", address_chain: "bitcoin", network_type: "bitcoin", network_chain_id: "bitcoin" },
        Candidate { network: "litecoin", variant: "P2WPKH (BIP84)", curve: "secp256k1", path: "m/84'/2'/0'/0/0", address_chain: "litecoin", network_type: "bitcoin", network_chain_id: "litecoin" },
        Candidate { network: "monacoin", variant: "P2WPKH (BIP84)", curve: "secp256k1", path: "m/84'/22'/0'/0/0", address_chain: "monacoin", network_type: "bitcoin", network_chain_id: "monacoin" },
        Candidate { network: "ethereum", variant: "standard", curve: "secp256k1", path: "m/44'/60'/0'/0/0", address_chain: "", network_type: "evm", network_chain_id: "1" },
        Candidate { network: "solana", variant: "sollet (seed[:32])", curve: "ed25519", path: "", address_chain: "", network_type: "solana", network_chain_id: "mainnet" },
        Candidate { network: "solana", variant: "phantom (m/44'/501'/0'/0')", curve: "ed25519", path: "m/44'/501'/0'/0'", address_chain: "", network_type: "solana", network_chain_id: "mainnet" },
    ]
}

/// Derive `(pubkey_b64url, address)` for a candidate from `seed`.
pub fn derive_address(seed: &[u8], c: &Candidate) -> Result<(String, String)> {
    let pubkey = crate::hdderive::derive_pubkey_for_path(seed, c.curve, c.path)
        .map_err(|e| Error::Env(e.to_string()))?;
    let address = match (c.curve, c.network_type) {
        ("ed25519", _) => bs58::encode(&pubkey).into_string(),
        ("secp256k1", "evm") => crate::hdderive::evm_address(&pubkey).map_err(|e| Error::Env(e.to_string()))?,
        ("secp256k1", "bitcoin") => {
            let p33: [u8; 33] = pubkey.clone().try_into().map_err(|_| Error::Env("secp pubkey not 33 bytes".into()))?;
            crate::bitcoin::hd_address(&p33, c.address_chain)?
        }
        (curve, ty) => return Err(Error::Env(format!("unsupported probe candidate {curve}/{ty}"))),
    };
    use base64::Engine;
    Ok((base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pubkey), address))
}

/// Probe a candidate's chain for activity, returning `(raw_balance, has_activity)`.
/// EVM: eth_getBalance (wei). Solana: getBalance (lamports). Bitcoin: presence
/// of any `modchain_assets` entry.
pub fn probe_balance(rpc: &str, c: &Candidate, address: &str) -> Result<(String, bool)> {
    match c.network_type {
        "evm" => {
            let hex = crate::rpc::call(rpc, "eth_getBalance", serde_json::json!([address, "latest"]))?;
            let hex = hex.as_str().ok_or_else(|| Error::Env("eth_getBalance not a string".into()))?;
            let stripped = hex.strip_prefix("0x").unwrap_or(hex);
            let n = num_bigint::BigInt::parse_bytes(stripped.as_bytes(), 16).ok_or_else(|| Error::Env(format!("bad balance hex {hex}")))?;
            Ok((n.to_string(), n.sign() == num_bigint::Sign::Plus))
        }
        "solana" => {
            let res = crate::rpc::call(rpc, "getBalance", serde_json::json!([address]))?;
            let v = res.get("value").and_then(Value::as_u64).unwrap_or(0);
            Ok((v.to_string(), v > 0))
        }
        "bitcoin" => {
            let res = crate::rpc::call(rpc, "modchain_assets", serde_json::json!([address]))?;
            let empty = res.is_null() || res.as_array().map(|a| a.is_empty()).unwrap_or(false) || res.as_object().map(|o| o.is_empty()).unwrap_or(false);
            Ok((res.to_string(), !empty))
        }
        other => Err(Error::Env(format!("unsupported probe network type {other}"))),
    }
}

/// Full probe of one candidate: derive its address then hit its RPC. Errors are
/// captured on the result (partial data), matching Go `probeOne`.
pub fn probe_one(seed: &[u8], c: &Candidate, rpc: &str) -> Value {
    let mut out = serde_json::json!({
        "network": c.network, "variant": c.variant, "curve": c.curve, "derivationPath": c.path,
    });
    let (pubkey, address) = match derive_address(seed, c) {
        Ok(x) => x,
        Err(e) => {
            out["error"] = Value::String(format!("derive: {e}"));
            return out;
        }
    };
    out["pubkey"] = Value::String(pubkey);
    out["address"] = Value::String(address.clone());
    match probe_balance(rpc, c, &address) {
        Ok((balance, activity)) => {
            out["balance"] = Value::String(balance);
            out["hasActivity"] = Value::Bool(activity);
        }
        Err(e) => out["error"] = Value::String(format!("probe: {e}")),
    }
    out
}

/// Filter the default candidates to a requested network list (empty = all),
/// case-insensitive on the `network` tag (Go probe's Networks filter).
pub fn candidates_for(networks: &[String]) -> Vec<Candidate> {
    if networks.is_empty() {
        return default_candidates();
    }
    let wanted: Vec<String> = networks.iter().map(|n| n.to_lowercase()).collect();
    default_candidates().into_iter().filter(|c| wanted.iter().any(|w| w == &c.network.to_lowercase())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The standard "abandon … about" test mnemonic.
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn ethereum_candidate_matches_bip44_vector() {
        let seed = crate::bip39::mnemonic_to_seed(MNEMONIC, "");
        let eth = default_candidates().into_iter().find(|c| c.network == "ethereum").unwrap();
        let (_pub, addr) = derive_address(&seed, &eth).unwrap();
        // Well-known BIP44 m/44'/60'/0'/0/0 address for this mnemonic.
        assert_eq!(addr, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn solana_and_bitcoin_candidates_derive_addresses() {
        let seed = crate::bip39::mnemonic_to_seed(MNEMONIC, "");
        for c in default_candidates() {
            let (pubkey, addr) = derive_address(&seed, &c).unwrap();
            assert!(!pubkey.is_empty() && !addr.is_empty(), "{}/{}", c.network, c.variant);
            match c.network_type {
                "solana" => assert!(!addr.contains(['0', 'O', 'I', 'l']), "base58 addr {addr}"),
                "bitcoin" if c.address_chain == "bitcoin" => assert!(addr.starts_with("bc1"), "P2WPKH {addr}"),
                "bitcoin" if c.address_chain == "litecoin" => assert!(addr.starts_with("ltc1"), "LTC {addr}"),
                _ => {}
            }
        }
        // The Sollet and Phantom Solana variants differ (different derivation).
        let sollet = default_candidates().into_iter().find(|c| c.variant.starts_with("sollet")).unwrap();
        let phantom = default_candidates().into_iter().find(|c| c.variant.starts_with("phantom")).unwrap();
        assert_ne!(derive_address(&seed, &sollet).unwrap().1, derive_address(&seed, &phantom).unwrap().1);
    }

    #[test]
    fn probe_one_reports_activity() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        // Mock node reporting a 1 ETH balance.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let body = r#"{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}"#;
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let rpc = format!("http://{addr}");

        let seed = crate::bip39::mnemonic_to_seed(MNEMONIC, "");
        let eth = default_candidates().into_iter().find(|c| c.network == "ethereum").unwrap();
        let res = probe_one(&seed, &eth, &rpc);
        assert_eq!(res["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(res["balance"], "1000000000000000000");
        assert_eq!(res["hasActivity"], true);
        assert!(res.get("error").is_none());
    }

    #[test]
    fn candidates_filter_by_network() {
        assert_eq!(candidates_for(&["ethereum".into()]).len(), 1);
        assert_eq!(candidates_for(&["solana".into()]).len(), 2);
        assert_eq!(candidates_for(&[]).len(), default_candidates().len());
    }
}
