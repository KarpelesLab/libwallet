//! Amount — arbitrary-precision fixed-point decimal. Port of `wltobj/amount.go`.
//!
//! Stored as a big integer significand plus a decimal exponent: 123.456 is
//! value=123456, exp=3. A MAX sentinel defers "use the maximum sendable" until
//! build time (value is None until resolved).
//!
//! JSON form is `{"v": significand, "e": exp, "f": float}` (all three always
//! present; `f` is 0 for MAX / unset). A bare string or number is also
//! accepted on input, and the string "MAX" round-trips the sentinel.
//!
//! Only the pure-integer surface is ported here (construction, string/JSON/
//! binary serialization, cmp, add/sub/mul/div, set_exp). The `big.Float`
//! helpers (from_float, reciprocal, and decimal-scientific string parsing with
//! a fixed decimals arg) are deferred; [`Amount::from_string`] returns an error
//! rather than silently mis-parsing.

use std::fmt;
use std::str::FromStr;

use num_bigint::{BigInt, Sign};
use num_traits::{ToPrimitive, Zero};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_AMOUNT_STRING_LEN: usize = 128;
const MAX_SENTINEL: &str = "MAX";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountError(pub String);

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse amount: {}", self.0)
    }
}

impl std::error::Error for AmountError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amount {
    /// Significand; None for an unresolved MAX sentinel.
    value: Option<BigInt>,
    /// Decimal exponent (number of fractional digits).
    exp: i64,
    is_max: bool,
}

fn exp10(n: u32) -> BigInt {
    BigInt::from(10u32).pow(n)
}

/// BigInt from an already-integral f64 (NaN/inf -> 0). Handles magnitudes
/// beyond i64 by decomposing the float, matching Go's `big.Float.Int`.
fn bigint_from_f64_trunc(f: f64) -> BigInt {
    if !f.is_finite() {
        return BigInt::from(0);
    }
    num_traits::FromPrimitive::from_f64(f.trunc()).unwrap_or_else(|| BigInt::from(0))
}

impl Amount {
    pub fn new(value: i64, decimals: i64) -> Amount {
        Amount { value: Some(BigInt::from(value)), exp: decimals, is_max: false }
    }

    pub fn new_raw(value: BigInt, decimals: i64) -> Amount {
        Amount { value: Some(value), exp: decimals, is_max: false }
    }

    /// The MAX sentinel with the given decimals (inherited by the resolved
    /// amount). Value is None until [`set_max_resolved`](Amount::set_max_resolved).
    pub fn new_max(decimals: i64) -> Amount {
        Amount { value: None, exp: decimals, is_max: true }
    }

    /// Port of Go `NewAmountFromFloat64(f, exp)`: store `f` with `exp` decimal
    /// places, significand = round-half-away(f * 10^exp). When `exp <= 0` the
    /// scale is taken from `f`'s own decimals (min 5), matching the Go path.
    /// Used for computed (never-persisted) values like a fiat conversion, so
    /// f64's ~53-bit precision — the same precision Go's `big.NewFloat(f)`
    /// starts from — is acceptable.
    pub fn from_float64(f: f64, exp: i64) -> Amount {
        let mut decimals = exp;
        if decimals <= 0 {
            // Count fractional digits of f's shortest decimal form.
            let s = format!("{f}");
            decimals = match s.split_once('.') {
                Some((_, frac)) => frac.len() as i64,
                None => 5,
            };
        }
        if decimals < 5 {
            decimals = 5;
        }
        let scaled = f * 10f64.powi(decimals as i32);
        // Round half away from zero (Go adds 0.5*sign then truncates to int).
        let rounded = if scaled >= 0.0 {
            (scaled + 0.5).trunc()
        } else {
            (scaled - 0.5).trunc()
        };
        let value = bigint_from_f64_trunc(rounded);
        Amount { value: Some(value), exp: decimals, is_max: false }
    }

    /// Parse `s` into an Amount. `decimals == 0` uses the exact integer path
    /// (decimal point and `e`/`E` scientific notation, base 10 only). A
    /// non-zero `decimals` selects the big.Float path, which is not yet ported.
    pub fn from_string(s: &str, decimals: i64) -> Result<Amount, AmountError> {
        if s.len() > MAX_AMOUNT_STRING_LEN {
            return Err(AmountError(format!("input too long ({} > {MAX_AMOUNT_STRING_LEN})", s.len())));
        }
        if decimals != 0 {
            return Err(AmountError("fixed-decimals float parsing not yet ported".into()));
        }

        let mut s = s;
        let mut extra_e: i64 = 0;
        if let Some(pos) = s.find(['e', 'E']) {
            let v = s[pos + 1..]
                .parse::<i64>()
                .map_err(|e| AmountError(e.to_string()))?;
            extra_e = -v;
            s = &s[..pos];
        }

        match s.find('.') {
            None => {
                let mut v = parse_bigint_base10(s)?;
                let mut e = extra_e;
                if e < 0 {
                    v *= exp10((-e) as u32);
                    e = 0;
                }
                Ok(Amount { value: Some(v), exp: e, is_max: false })
            }
            Some(pos) => {
                let mut digits = String::with_capacity(s.len() - 1);
                digits.push_str(&s[..pos]);
                digits.push_str(&s[pos + 1..]);
                let mut v = parse_bigint_base10(&digits)?;
                let mut e = (s.len() - pos - 1) as i64 + extra_e;
                if e < 0 {
                    v *= exp10((-e) as u32);
                    e = 0;
                }
                Ok(Amount { value: Some(v), exp: e, is_max: false })
            }
        }
    }

    pub fn set_max_resolved(&mut self, v: BigInt) -> Result<(), AmountError> {
        if !self.is_max {
            return Err(AmountError("set_max_resolved on a non-MAX Amount".into()));
        }
        self.value = Some(v);
        self.is_max = false;
        Ok(())
    }

    pub fn is_max(&self) -> bool {
        self.is_max
    }

    /// The significand, or None for an unresolved MAX.
    pub fn value(&self) -> Option<&BigInt> {
        self.value.as_ref()
    }

    pub fn exp(&self) -> i64 {
        self.exp
    }

    pub fn sign(&self) -> i32 {
        match &self.value {
            None => 0,
            Some(v) => match v.sign() {
                Sign::Minus => -1,
                Sign::NoSign => 0,
                Sign::Plus => 1,
            },
        }
    }

    pub fn is_zero(&self) -> bool {
        self.value.as_ref().map_or(true, |v| v.is_zero())
    }

    pub fn neg(&self) -> Amount {
        Amount { value: self.value.as_ref().map(|v| -v), exp: self.exp, is_max: false }
    }

    /// Rescale to `e` decimals in place, rounding half away from zero when
    /// reducing precision. Matches Go `SetExp` exactly.
    pub fn set_exp(&mut self, e: i64) -> &mut Amount {
        if self.exp == e {
            return self;
        }
        let value = self.value.as_mut().expect("set_exp on unresolved MAX");
        if e > self.exp {
            let add = (e - self.exp) as u32;
            *value *= exp10(add);
            self.exp = e;
            return self;
        }
        let sub = (self.exp - e) as u32;
        let e10 = exp10(sub);
        let mut half = &e10 / BigInt::from(2); // truncates toward zero (matches big.Int.Quo)
        if value.sign() == Sign::Minus {
            half = -half;
        }
        *value += half;
        *value /= &e10; // truncates toward zero
        self.exp = e;
        self
    }

    /// Compare two amounts of the same exponent. Panics on mismatch, like Go.
    pub fn cmp(&self, other: &Amount) -> std::cmp::Ordering {
        assert_eq!(self.exp, other.exp, "only amounts with same exponent can be compared");
        self.require_value().cmp(other.require_value())
    }

    /// a = x + y (rescaling x and y to a's exponent). Returns self.
    pub fn add(&mut self, x: &Amount, y: &Amount) -> &mut Amount {
        let xv = rescaled(x, self.exp);
        let yv = rescaled(y, self.exp);
        self.value = Some(xv + yv);
        self
    }

    pub fn sub(&mut self, x: &Amount, y: &Amount) -> &mut Amount {
        let xv = rescaled(x, self.exp);
        let yv = rescaled(y, self.exp);
        self.value = Some(xv - yv);
        self
    }

    /// a = x * y (exponents add, then rescale back to a's original exponent).
    pub fn mul(&mut self, x: &Amount, y: &Amount) -> &mut Amount {
        let target = self.exp;
        self.value = Some(x.require_value() * y.require_value());
        self.exp = x.exp + y.exp;
        self.set_exp(target)
    }

    /// a = x / y (integer quotient after rescaling x to y.exp + a.exp).
    pub fn div(&mut self, x: &Amount, y: &Amount) -> &mut Amount {
        let mut xd = x.clone();
        xd.set_exp(y.exp + self.exp);
        self.value = Some(xd.require_value() / y.require_value());
        self
    }

    /// Textual form: the significand with a decimal point inserted at `exp`.
    pub fn to_display_string(&self) -> String {
        let v = match &self.value {
            Some(v) => v,
            None => return "0".to_owned(),
        };
        let s = v.to_str_radix(10);
        if self.exp == 0 {
            return s;
        }
        let (neg, mag) = match s.strip_prefix('-') {
            Some(rest) => ("-", rest),
            None => ("", s.as_str()),
        };
        let exp = self.exp as usize;
        if mag.len() > exp {
            let p = mag.len() - exp;
            format!("{neg}{}.{}", &mag[..p], &mag[p..])
        } else if mag.len() < exp {
            format!("{neg}0.{}{}", "0".repeat(exp - mag.len()), mag)
        } else {
            format!("{neg}0.{mag}")
        }
    }

    /// Lossy float64 of the value, for the JSON `f` field. 0 for MAX / unset.
    fn as_f64(&self) -> f64 {
        match &self.value {
            None => 0.0,
            Some(v) if v.is_zero() => 0.0,
            Some(v) => v.to_f64().unwrap_or(f64::NAN) / 10f64.powi(self.exp as i32),
        }
    }

    fn require_value(&self) -> &BigInt {
        self.value.as_ref().expect("operation on unresolved MAX Amount")
    }

    // --- Versioned binary encoding (matches Amount.Bytes / UnmarshalBinary) --

    pub fn to_bytes(&self) -> Vec<u8> {
        let negative = matches!(&self.value, Some(v) if v.sign() == Sign::Minus);
        if negative {
            // version 0x01: [0x01][varint exp][sign=1][magnitude BE]
            let mut buf = vec![0x01u8];
            put_varint(&mut buf, self.exp);
            buf.push(1);
            let (_, mag) = self.value.as_ref().unwrap().to_bytes_be();
            buf.extend_from_slice(&mag);
            return buf;
        }
        // version 0x00: [0x00][varint exp][magnitude BE] (empty for zero)
        let mut buf = vec![0x00u8];
        put_varint(&mut buf, self.exp);
        if let Some(v) = &self.value {
            if v.sign() != Sign::NoSign {
                let (_, mag) = v.to_bytes_be();
                buf.extend_from_slice(&mag);
            }
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Amount, AmountError> {
        if data.len() < 2 {
            return Err(AmountError("data too short".into()));
        }
        let version = data[0];
        if version != 0x00 && version != 0x01 {
            return Err(AmountError("invalid version".into()));
        }
        let (exp, n) = read_varint(&data[1..]).ok_or_else(|| AmountError("invalid encoding".into()))?;
        let rest = &data[1 + n..];
        let value = if version == 0x00 {
            BigInt::from_bytes_be(Sign::Plus, rest)
        } else {
            if rest.is_empty() {
                return Err(AmountError("missing sign byte".into()));
            }
            let mut v = BigInt::from_bytes_be(Sign::Plus, &rest[1..]);
            if rest[0] == 1 {
                v = -v;
            }
            v
        };
        Ok(Amount { value: Some(value), exp, is_max: false })
    }

    // --- JSON (serde_json::Value bridge) ----------------------------------

    fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        if self.is_max {
            return json!({ "v": MAX_SENTINEL, "e": self.exp, "f": 0.0 });
        }
        match &self.value {
            None => json!({ "v": "0", "e": self.exp, "f": 0.0 }),
            Some(v) => json!({ "v": v.to_str_radix(10), "e": self.exp, "f": self.as_f64() }),
        }
    }

    /// Accept a string, number, or `{v,e,f}` object — the Go `Scan` contract.
    fn from_json(v: &serde_json::Value) -> Result<Amount, AmountError> {
        use serde_json::Value;
        match v {
            Value::String(s) => {
                if s == MAX_SENTINEL {
                    return Ok(Amount { value: None, exp: 0, is_max: true });
                }
                Amount::from_string(s, 0)
            }
            Value::Number(n) => Amount::from_string(&n.to_string(), 0),
            Value::Object(m) => {
                if let (Some(Value::String(vs)), Some(e)) = (m.get("v"), m.get("e")) {
                    let exp = json_to_i64(e)?;
                    if vs == MAX_SENTINEL {
                        return Ok(Amount { value: None, exp, is_max: true });
                    }
                    if vs.len() > MAX_AMOUNT_STRING_LEN {
                        return Err(AmountError("v too long".into()));
                    }
                    let value = parse_bigint_base10(vs)?;
                    return Ok(Amount { value: Some(value), exp, is_max: false });
                }
                if let Some(f) = m.get("f") {
                    let s = match f {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        _ => return Err(AmountError("bad f field".into())),
                    };
                    return Amount::from_string(&s, 0);
                }
                Err(AmountError("object is not an Amount".into()))
            }
            _ => Err(AmountError(format!("unsupported amount value: {v}"))),
        }
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_string())
    }
}

impl FromStr for Amount {
    type Err = AmountError;
    fn from_str(s: &str) -> Result<Amount, AmountError> {
        Amount::from_string(s, 0)
    }
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Amount, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        Amount::from_json(&v).map_err(D::Error::custom)
    }
}

/// Rescale a copy of `a` to exponent `e` and return its significand.
fn rescaled(a: &Amount, e: i64) -> BigInt {
    if a.exp == e {
        return a.require_value().clone();
    }
    let mut c = a.clone();
    c.set_exp(e);
    c.require_value().clone()
}

/// Base-10 big integer parse, rejecting 0x/0o/0b prefixes and `_` separators
/// (untrusted input), matching Go's `big.Int.SetString(s, 10)`.
fn parse_bigint_base10(s: &str) -> Result<BigInt, AmountError> {
    BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| AmountError(format!("not a base-10 integer: {s:?}")))
}

fn json_to_i64(v: &serde_json::Value) -> Result<i64, AmountError> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().ok_or_else(|| AmountError("e not an integer".into())),
        serde_json::Value::String(s) => s.parse().map_err(|_| AmountError("e not an integer".into())),
        _ => Err(AmountError("e has unexpected type".into())),
    }
}

/// Signed varint (zigzag LEB128), matching Go `encoding/binary.PutVarint`.
fn put_varint(buf: &mut Vec<u8>, x: i64) {
    let mut ux = ((x << 1) ^ (x >> 63)) as u64;
    while ux >= 0x80 {
        buf.push((ux as u8) | 0x80);
        ux >>= 7;
    }
    buf.push(ux as u8);
}

/// Decode a signed varint; returns (value, bytes_read). Matches `binary.Varint`.
fn read_varint(data: &[u8]) -> Option<(i64, usize)> {
    let mut ux: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        if i > 9 {
            return None;
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None; // overflow
            }
            ux |= (b as u64) << shift;
            let x = ((ux >> 1) as i64) ^ -((ux & 1) as i64);
            return Some((x, i + 1));
        }
        ux |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    None
}
