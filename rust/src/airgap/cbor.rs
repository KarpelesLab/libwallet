//! Small ciborium conveniences for the UR registry types: integer-keyed maps,
//! tagged items, and the handful of scalar accessors the codecs need.

use ciborium::value::{Integer, Value};

use crate::{Error, Result};

/// Encode a value to CBOR bytes.
pub fn to_bytes(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| Error::Env(format!("cbor encode: {e}")))?;
    Ok(out)
}

/// Decode CBOR bytes to a value (the whole buffer must be one item).
pub fn from_bytes(b: &[u8]) -> Result<Value> {
    ciborium::from_reader(b).map_err(|e| Error::Env(format!("cbor decode: {e}")))
}

/// A map builder with integer keys, in insertion order.
#[derive(Default)]
pub struct MapBuilder(Vec<(Value, Value)>);

impl MapBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put(mut self, key: u64, v: Value) -> Self {
        self.0.push((Value::Integer(Integer::from(key)), v));
        self
    }
    /// Insert only when `Some`.
    pub fn opt(self, key: u64, v: Option<Value>) -> Self {
        match v {
            Some(v) => self.put(key, v),
            None => self,
        }
    }
    pub fn build(self) -> Value {
        Value::Map(self.0)
    }
}

pub fn uint(n: u64) -> Value {
    Value::Integer(Integer::from(n))
}
pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}
pub fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}
pub fn tagged(tag: u64, v: Value) -> Value {
    Value::Tag(tag, Box::new(v))
}

/// Look up integer key `key` in a CBOR map.
pub fn get<'a>(map: &'a Value, key: u64) -> Option<&'a Value> {
    let entries = match map {
        Value::Map(m) => m,
        _ => return None,
    };
    entries.iter().find_map(|(k, v)| match k {
        Value::Integer(i) if u64::try_from(*i).ok() == Some(key) => Some(v),
        _ => None,
    })
}

pub fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}
pub fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}
pub fn as_bytes(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}
pub fn as_text(v: &Value) -> Option<&str> {
    match v {
        Value::Text(s) => Some(s),
        _ => None,
    }
}
pub fn as_array(v: &Value) -> Option<&[Value]> {
    match v {
        Value::Array(a) => Some(a),
        _ => None,
    }
}

/// Strip an expected tag (or none — UR bodies omit the top-level tag since the
/// UR type names it). Returns the inner value and the tag seen, if any.
pub fn untag(v: &Value) -> (&Value, Option<u64>) {
    match v {
        Value::Tag(t, inner) => (inner, Some(*t)),
        other => (other, None),
    }
}

/// Require a map field.
pub fn need<'a>(map: &'a Value, key: u64, what: &str) -> Result<&'a Value> {
    get(map, key).ok_or_else(|| Error::Env(format!("{what}: missing field {key}")))
}

/// Render a CBOR value as JSON for diagnostics / the generic decoder output:
/// byte strings become `"0x…"` hex, tags become `{"tag":n,"value":…}`, and
/// integer map keys become strings.
pub fn to_json(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Integer(i) => match i128::try_from(*i) {
            Ok(n) if n >= 0 && n <= u64::MAX as i128 => J::from(n as u64),
            Ok(n) if n < 0 && n >= i64::MIN as i128 => J::from(n as i64),
            Ok(n) => J::String(n.to_string()),
            Err(_) => J::Null,
        },
        Value::Bytes(b) => J::String(format!("0x{}", super::hex(b))),
        Value::Text(s) => J::String(s.clone()),
        Value::Bool(b) => J::Bool(*b),
        Value::Null => J::Null,
        Value::Float(f) => serde_json::Number::from_f64(*f).map(J::Number).unwrap_or(J::Null),
        Value::Array(a) => J::Array(a.iter().map(to_json).collect()),
        Value::Map(m) => {
            let mut o = serde_json::Map::new();
            for (k, val) in m {
                let key = match k {
                    Value::Text(s) => s.clone(),
                    Value::Integer(i) => i128::try_from(*i).map(|n| n.to_string()).unwrap_or_default(),
                    other => serde_json::to_string(&to_json(other)).unwrap_or_default(),
                };
                o.insert(key, to_json(val));
            }
            J::Object(o)
        }
        Value::Tag(t, inner) => serde_json::json!({ "tag": t, "value": to_json(inner) }),
        _ => J::Null,
    }
}
