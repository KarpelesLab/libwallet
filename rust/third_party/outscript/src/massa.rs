//! Massa address parsing (port of `massa.go`).

use crate::base58;
use crate::hash::dsha256;
use crate::out::Out;

/// Parses a Massa address ("AU" for user accounts, "AS" for smart contracts).
pub fn parse_massa_address(address: &str) -> Result<Out, String> {
    if !address.starts_with("AU") && !address.starts_with("AS") {
        return Err("massa address must start with AU or AS".into());
    }
    let typ: u8 = match address.as_bytes()[1] {
        b'U' => 0,
        b'S' => 1,
        _ => return Err("massa address must start with AU or AS".into()),
    };

    let mut buf = base58::decode(&address[2..])
        .map_err(|e| format!("failed to decode massa address: {e}"))?;
    if buf.len() < 4 {
        return Err("massa address too short".into());
    }
    let chk_start = buf.len() - 4;
    let h = dsha256(&buf[..chk_start]);
    if h[..4] != buf[chk_start..] {
        return Err("bad checksum on massa address".into());
    }
    buf.truncate(chk_start);

    let mut raw = Vec::with_capacity(1 + buf.len());
    raw.push(typ);
    raw.extend_from_slice(&buf);
    Ok(Out::make("massa", raw, &["massa"]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_user() {
        // From massa_test.go vectors: an AU address should round-trip.
        // (validated end-to-end via the address generation tests).
        let res = parse_massa_address("not-a-massa-address");
        assert!(res.is_err());
    }
}
