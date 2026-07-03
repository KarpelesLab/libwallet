//! TimeId — a sortable timestamp identifier. Port of `wltobj/timeid.go`.
//!
//! Text form is `"<type>:<unix>:<nano>:<index>"`, or `"nil:..."` when the type
//! is empty. Binary form is a fixed 16 bytes: `Unix(u64 BE) | Nano(u32 BE) |
//! Index(u32 BE)` — big-endian so byte order sorts chronologically.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimeId {
    pub type_: String,
    pub unix: u64,
    pub nano: u32,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTimeIdError(pub String);

impl fmt::Display for ParseTimeIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid TimeId: {}", self.0)
    }
}

impl std::error::Error for ParseTimeIdError {}

impl TimeId {
    /// A TimeId for the current instant (Index = 0), like `NewTimeId`.
    pub fn now() -> TimeId {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        TimeId { type_: String::new(), unix: d.as_secs(), nano: d.subsec_nanos(), index: 0 }
    }

    /// 16-byte big-endian encoding: `Unix(u64) | Nano(u32) | Index(u32)`.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.unix.to_be_bytes());
        b[8..12].copy_from_slice(&self.nano.to_be_bytes());
        b[12..16].copy_from_slice(&self.index.to_be_bytes());
        b
    }

    /// Decode the 16-byte form. The type is left empty (it is not carried in
    /// the binary encoding), matching `TimeId.UnmarshalBinary`.
    pub fn from_bytes(v: &[u8]) -> Result<TimeId, ParseTimeIdError> {
        if v.len() != 16 {
            return Err(ParseTimeIdError(format!("bad data length {}", v.len())));
        }
        Ok(TimeId {
            type_: String::new(),
            unix: u64::from_be_bytes(v[0..8].try_into().unwrap()),
            nano: u32::from_be_bytes(v[8..12].try_into().unwrap()),
            index: u32::from_be_bytes(v[12..16].try_into().unwrap()),
        })
    }
}

impl fmt::Display for TimeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Empty type renders as the literal "nil", matching the Go String().
        let ty = if self.type_.is_empty() { "nil" } else { self.type_.as_str() };
        write!(f, "{}:{}:{}:{}", ty, self.unix, self.nano, self.index)
    }
}

impl FromStr for TimeId {
    type Err = ParseTimeIdError;

    fn from_str(s: &str) -> Result<TimeId, ParseTimeIdError> {
        // splitn(4) then, if 4 parts, the first is the type. Mirrors the Go
        // parser exactly — including that "nil:..." yields type "nil".
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        if parts.len() < 3 {
            return Err(ParseTimeIdError(format!("bad format: {s}")));
        }
        let (type_, nums): (&str, &[&str]) = if parts.len() == 4 {
            (parts[0], &parts[1..])
        } else {
            ("", &parts[..])
        };
        let unix = nums[0].parse::<u64>().map_err(|e| ParseTimeIdError(e.to_string()))?;
        let nano = nums[1].parse::<u32>().map_err(|e| ParseTimeIdError(e.to_string()))?;
        let index = nums[2].parse::<u32>().map_err(|e| ParseTimeIdError(e.to_string()))?;
        Ok(TimeId { type_: type_.to_owned(), unix, nano, index })
    }
}

impl Serialize for TimeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TimeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<TimeId, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(D::Error::custom)
    }
}
