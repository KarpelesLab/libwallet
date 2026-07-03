//! ERC-20 read calls (`balanceOf`, `allowance`) — pure calldata encoding plus
//! `eth_call` helpers. Ports the encoding used across wltswap (allowance check)
//! and enables EVM token-balance reads. Values are uint256 big-endian.

use num_bigint::BigInt;
use serde_json::json;

use crate::{Error, Result};

/// `balanceOf(address)` selector = keccak256("balanceOf(address)")[:4].
const BALANCE_OF: &str = "70a08231";
/// `allowance(address,address)` selector (Go `erc20AllowanceSelector`).
const ALLOWANCE: &str = "dd62ed3e";

/// Decode a `0x`-prefixed 20-byte address to bytes (Go `hexAddressBytes`).
fn address_bytes(addr: &str) -> Result<[u8; 20]> {
    let lower = addr.to_lowercase();
    let hexs = lower.strip_prefix("0x").ok_or_else(|| Error::Env("not a 0x-prefixed address".into()))?;
    if hexs.len() != 40 {
        return Err(Error::Env(format!("address must be 20 bytes, got {} hex chars", hexs.len())));
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&hexs[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::Env(format!("invalid hex: {e}")))?;
    }
    Ok(out)
}

/// A 20-byte address left-padded into a 32-byte ABI word, as lowercase hex.
fn padded_address_hex(addr: &[u8; 20]) -> String {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr);
    word.iter().map(|b| format!("{b:02x}")).collect()
}

/// `balanceOf(owner)` calldata (`0x70a08231` + 32-byte owner).
pub fn encode_balance_of(owner: &str) -> Result<String> {
    let o = address_bytes(owner)?;
    Ok(format!("0x{BALANCE_OF}{}", padded_address_hex(&o)))
}

/// `allowance(owner, spender)` calldata (`0xdd62ed3e` + owner + spender).
pub fn encode_allowance(owner: &str, spender: &str) -> Result<String> {
    let o = address_bytes(owner)?;
    let s = address_bytes(spender)?;
    Ok(format!("0x{ALLOWANCE}{}{}", padded_address_hex(&o), padded_address_hex(&s)))
}

/// `eth_call` a token contract and decode the uint256 result.
fn call_uint256(rpc: &str, token: &str, data: &str) -> Result<BigInt> {
    let out = crate::rpc::call(rpc, "eth_call", json!([{ "to": token, "data": data }, "latest"]))?;
    let hex = out.as_str().ok_or_else(|| Error::Env("eth_call result not a string".into()))?;
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    if stripped.is_empty() {
        return Ok(BigInt::from(0));
    }
    BigInt::parse_bytes(stripped.as_bytes(), 16)
        .ok_or_else(|| Error::Env(format!("bad eth_call uint256 {hex}")))
}

/// The ERC-20 balance of `owner` for `token` (base units).
pub fn balance_of(rpc: &str, token: &str, owner: &str) -> Result<BigInt> {
    call_uint256(rpc, token, &encode_balance_of(owner)?)
}

/// The ERC-20 allowance `owner` has granted `spender` for `token` (base units).
pub fn allowance(rpc: &str, token: &str, owner: &str, spender: &str) -> Result<BigInt> {
    call_uint256(rpc, token, &encode_allowance(owner, spender)?)
}

/// `decimals()` selector = keccak256("decimals()")[:4].
const DECIMALS: &str = "313ce567";

/// The ERC-20 token's `decimals()` (0..=255).
pub fn decimals(rpc: &str, token: &str) -> Result<i64> {
    let v = call_uint256(rpc, token, &format!("0x{DECIMALS}"))?;
    v.try_into()
        .ok()
        .and_then(|d: i64| if (0..=255).contains(&d) { Some(d) } else { None })
        .ok_or_else(|| Error::Env("ERC-20 decimals out of range".into()))
}
