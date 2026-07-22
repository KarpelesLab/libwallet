//! Solana address parsing (port of `solana.go`).

use crate::base58;
use crate::out::Out;

/// Parses a Solana base58-encoded address (32 bytes when decoded).
pub fn parse_solana_address(address: &str) -> Result<Out, String> {
    let buf =
        base58::decode(address).map_err(|e| format!("failed to decode solana address: {e}"))?;
    if buf.len() != 32 {
        return Err(format!(
            "invalid solana address: expected 32 bytes, got {}",
            buf.len()
        ));
    }
    Ok(Out::make("solana", buf, &["solana"]))
}
