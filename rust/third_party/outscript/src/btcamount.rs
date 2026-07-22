//! Bitcoin amount type (satoshis) with Go-compatible JSON.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A Bitcoin amount in satoshis (1 BTC = 100,000,000 satoshis).
///
/// Serializes to JSON as an unquoted decimal number with 8 decimal places
/// (e.g. `1.00000000`). Deserializes from JSON numbers, decimal strings,
/// integer strings, and `0x`-prefixed hex strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct BtcAmount(pub u64);

impl BtcAmount {
    /// Formats the amount as a decimal string with exactly 8 decimal places.
    pub fn to_decimal_string(self) -> String {
        // Zero-pad to at least 9 digits so there's always an integer part to the
        // left of the 8 fractional digits.
        let s = format!("{:09}", self.0);
        let ln = s.len();
        format!("{}.{}", &s[..ln - 8], &s[ln - 8..])
    }

    /// Parses a textual amount. Accepts decimal strings (e.g. "1.5"), integer
    /// strings (multiplied by 10^8), and `0x`-prefixed hex (treated as raw
    /// satoshis).
    pub fn from_text(s: &str) -> Result<BtcAmount, String> {
        if let Some(hex_part) = s.strip_prefix("0x") {
            let v = u64::from_str_radix(hex_part, 16).map_err(|e| e.to_string())?;
            return Ok(BtcAmount(v));
        }
        match s.find('.') {
            None => {
                let v: u64 = s
                    .parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?;
                Ok(BtcAmount(
                    v.checked_mul(100_000_000).ok_or("amount overflows u64")?,
                ))
            }
            Some(pos) => {
                let ln = s.len();
                let dec_count = ln - pos - 1;
                if dec_count > 8 {
                    return Err("cannot parse amount with more than 8 decimals".into());
                }
                let without_dot = s.replacen('.', "", 1);
                let mut v: u64 = without_dot
                    .parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?;
                for _ in dec_count..8 {
                    v = v.checked_mul(10).ok_or("amount overflows u64")?;
                }
                Ok(BtcAmount(v))
            }
        }
    }
}

impl From<u64> for BtcAmount {
    fn from(v: u64) -> Self {
        BtcAmount(v)
    }
}

impl From<BtcAmount> for u64 {
    fn from(v: BtcAmount) -> Self {
        v.0
    }
}

impl Serialize for BtcAmount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Emit an unquoted JSON number with 8 decimal places, matching Go.
        let raw = serde_json::value::RawValue::from_string(self.to_decimal_string())
            .map_err(serde::ser::Error::custom)?;
        raw.serialize(serializer)
    }
}

struct BtcAmountVisitor;

impl Visitor<'_> for BtcAmountVisitor {
    type Value = BtcAmount;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a bitcoin amount as number or string")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<BtcAmount, E> {
        BtcAmount::from_text(&v.to_string()).map_err(de::Error::custom)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<BtcAmount, E> {
        BtcAmount::from_text(&v.to_string()).map_err(de::Error::custom)
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<BtcAmount, E> {
        // Format with shortest round-trip representation, then parse as decimal.
        BtcAmount::from_text(&format!("{v}")).map_err(de::Error::custom)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<BtcAmount, E> {
        BtcAmount::from_text(v).map_err(de::Error::custom)
    }

    fn visit_unit<E: de::Error>(self) -> Result<BtcAmount, E> {
        Ok(BtcAmount(0))
    }

    fn visit_none<E: de::Error>(self) -> Result<BtcAmount, E> {
        Ok(BtcAmount(0))
    }
}

impl<'de> Deserialize<'de> for BtcAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(BtcAmountVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmarshal_text_decimal() {
        let cases = [
            ("1.5", 150_000_000u64),
            ("0.00000001", 1),
            ("21000000.00000000", 2_100_000_000_000_000),
            ("0.1", 10_000_000),
            ("100", 10_000_000_000),
        ];
        for (input, want) in cases {
            assert_eq!(
                BtcAmount::from_text(input).unwrap().0,
                want,
                "input {input}"
            );
        }
    }

    #[test]
    fn unmarshal_text_hex() {
        assert_eq!(BtcAmount::from_text("0x5f5e100").unwrap().0, 100_000_000);
    }

    #[test]
    fn unmarshal_text_integer() {
        assert_eq!(BtcAmount::from_text("50").unwrap().0, 5_000_000_000);
    }

    #[test]
    fn too_many_decimals() {
        assert!(BtcAmount::from_text("1.123456789").is_err());
    }

    #[test]
    fn overflow_is_rejected() {
        // integer path: v * 1e8 wraps u64
        assert!(BtcAmount::from_text("1000000000000").is_err());
        // decimal-scaling path: v *= 10 wraps u64
        assert!(BtcAmount::from_text("1844674407370955161.5").is_err());
    }

    #[test]
    fn json_roundtrip() {
        let a = BtcAmount(150_000_000);
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, "1.50000000");
        let b: BtcAmount = serde_json::from_str(&j).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn json_from_quoted_and_null() {
        let b: BtcAmount = serde_json::from_str("\"1.5\"").unwrap();
        assert_eq!(b.0, 150_000_000);
        let n: BtcAmount = serde_json::from_str("null").unwrap();
        assert_eq!(n.0, 0);
    }
}
