//! EIP-712 typed-structured-data hashing (port of `wltbase/eip712.go`). Produces
//! the signable digest `keccak256("\x19\x01" || domainSeparator ||
//! hashStruct(message))` that `eth_signTypedData_v3/v4` signs.

use std::collections::{BTreeSet, HashMap};

use num_bigint::{BigInt, Sign};
use serde::Deserialize;
use serde_json::{Map, Value};

use purecrypto::hash::keccak256;

#[derive(Deserialize, Debug, Clone)]
pub struct TypedData {
    #[serde(default)]
    pub types: HashMap<String, Vec<Field>>,
    #[serde(rename = "primaryType", default)]
    pub primary_type: String,
    #[serde(default)]
    pub domain: Map<String, Value>,
    #[serde(default)]
    pub message: Map<String, Value>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub typ: String,
}

/// Parse a typed-data JSON string (Go `ParseEIP712TypedData`).
pub fn parse(data: &str) -> Result<TypedData, String> {
    let td: TypedData = serde_json::from_str(data).map_err(|e| format!("failed to parse typed data: {e}"))?;
    if td.primary_type.is_empty() {
        return Err("primaryType is required".into());
    }
    if td.types.is_empty() {
        return Err("types is required".into());
    }
    if !td.types.contains_key(&td.primary_type) {
        return Err(format!("primaryType {} not found in types", td.primary_type));
    }
    Ok(td)
}

impl TypedData {
    /// The EIP-712 signable digest: `keccak256("\x19\x01" || domainSep || hashStruct(message))`.
    pub fn hash(&self) -> Result<[u8; 32], String> {
        let domain_sep = self.hash_struct("EIP712Domain", &self.domain)?;
        let msg_hash = self.hash_struct(&self.primary_type, &self.message)?;
        let mut raw = vec![0x19u8, 0x01];
        raw.extend_from_slice(&domain_sep);
        raw.extend_from_slice(&msg_hash);
        Ok(keccak256(&raw))
    }

    /// `keccak256(typeHash || encodeData(value))`.
    fn hash_struct(&self, type_name: &str, data: &Map<String, Value>) -> Result<[u8; 32], String> {
        let type_hash = self.type_hash(type_name)?;
        let encoded = self.encode_data(type_name, data)?;
        let mut raw = Vec::with_capacity(32 + encoded.len());
        raw.extend_from_slice(&type_hash);
        raw.extend_from_slice(&encoded);
        Ok(keccak256(&raw))
    }

    fn type_hash(&self, type_name: &str) -> Result<[u8; 32], String> {
        Ok(keccak256(self.encode_type(type_name)?.as_bytes()))
    }

    /// The type encoding string, e.g. `Mail(address from,...)Person(...)` with
    /// referenced types appended in sorted order.
    fn encode_type(&self, type_name: &str) -> Result<String, String> {
        let fields = self.types.get(type_name).ok_or_else(|| format!("type {type_name} not found"))?;
        let mut deps = BTreeSet::new();
        self.find_deps(type_name, &mut deps);
        deps.remove(type_name); // primary type comes first
        let mut result = format_type(type_name, fields);
        for dep in &deps {
            result.push_str(&format_type(dep, &self.types[dep]));
        }
        Ok(result)
    }

    fn find_deps(&self, type_name: &str, deps: &mut BTreeSet<String>) {
        if deps.contains(type_name) {
            return;
        }
        let Some(fields) = self.types.get(type_name) else { return };
        deps.insert(type_name.to_owned());
        for f in fields {
            let base = strip_array_suffix(&f.typ);
            if self.types.contains_key(base) {
                self.find_deps(base, deps);
            }
        }
    }

    fn encode_data(&self, type_name: &str, data: &Map<String, Value>) -> Result<Vec<u8>, String> {
        let fields = self.types.get(type_name).ok_or_else(|| format!("type {type_name} not found"))?;
        let mut encoded = Vec::new();
        for field in fields {
            let val = data.get(&field.name).unwrap_or(&Value::Null);
            let enc = self
                .encode_value(&field.typ, val)
                .map_err(|e| format!("field {type_name}.{}: {e}", field.name))?;
            encoded.extend_from_slice(&enc);
        }
        Ok(encoded)
    }

    fn encode_value(&self, typ: &str, val: &Value) -> Result<Vec<u8>, String> {
        // Array types (T[] / T[N]) → keccak of concatenated member encodings.
        if let Some((elem, fixed_len)) = array_elem_type(typ) {
            let arr = val.as_array().ok_or_else(|| format!("expected array for {typ}"))?;
            if let Some(n) = fixed_len {
                if arr.len() != n {
                    return Err(format!("{typ} expects {n} elements, got {}", arr.len()));
                }
            }
            let mut inner = Vec::new();
            for item in arr {
                inner.extend_from_slice(&self.encode_value(&elem, item)?);
            }
            return Ok(keccak256(&inner).to_vec());
        }
        // Referenced struct types → hashStruct.
        if self.types.contains_key(typ) {
            let m = val.as_object().ok_or_else(|| format!("expected object for struct type {typ}"))?;
            return Ok(self.hash_struct(typ, m)?.to_vec());
        }
        // Atomic types.
        match typ {
            "string" => Ok(keccak256(val.as_str().unwrap_or("").as_bytes()).to_vec()),
            "bytes" => {
                let s = val.as_str().ok_or("bytes value must be hex string")?;
                Ok(keccak256(&hex_decode(s)?).to_vec())
            }
            "bool" => Ok(pad_left32(&[bool_to_byte(val)])),
            "address" => {
                let s = val.as_str().unwrap_or("");
                Ok(pad_left32(&hex_decode(s)?))
            }
            _ if typ.starts_with("uint") => {
                let n = bigint_from_val(val).ok_or_else(|| format!("invalid value for {typ}"))?;
                if n.sign() == Sign::Minus {
                    return Err(format!("negative value for unsigned {typ}"));
                }
                Ok(encode_uint256(&n))
            }
            _ if typ.starts_with("int") => {
                let n = bigint_from_val(val).ok_or_else(|| format!("invalid value for {typ}"))?;
                Ok(encode_int256(&n))
            }
            _ if typ.starts_with("bytes") => {
                // Fixed-size bytesN — right-padded.
                let s = val.as_str().unwrap_or("");
                Ok(pad_right32(&hex_decode(s)?))
            }
            other => Err(format!("unsupported EIP-712 type: {other}")),
        }
    }
}

fn format_type(name: &str, fields: &[Field]) -> String {
    let parts: Vec<String> = fields.iter().map(|f| format!("{} {}", f.typ, f.name)).collect();
    format!("{name}({})", parts.join(","))
}

fn strip_array_suffix(t: &str) -> &str {
    match t.find('[') {
        Some(i) => &t[..i],
        None => t,
    }
}

/// `(elemType, Some(n)|None)` for a fixed/dynamic array type, else None.
fn array_elem_type(typ: &str) -> Option<(String, Option<usize>)> {
    if !typ.ends_with(']') {
        return None;
    }
    let open = typ.rfind('[')?;
    let inner = &typ[open + 1..typ.len() - 1];
    let base = typ[..open].to_owned();
    if inner.is_empty() {
        return Some((base, None));
    }
    inner.parse::<usize>().ok().map(|n| (base, Some(n)))
}

/// Decode a 0x-prefixed (or bare) hex string, erroring on invalid input.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let s = if s.len() % 2 != 0 { format!("0{s}") } else { s.to_owned() };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Parse an EIP-712 numeric value (decimal/hex string or JSON number).
fn bigint_from_val(val: &Value) -> Option<BigInt> {
    match val {
        Value::String(s) => {
            let s = s.trim();
            let (neg, s) = match s.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, s),
            };
            let n = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                BigInt::parse_bytes(h.as_bytes(), 16)?
            } else {
                BigInt::parse_bytes(s.as_bytes(), 10)?
            };
            Some(if neg { -n } else { n })
        }
        Value::Number(n) => BigInt::parse_bytes(n.to_string().as_bytes(), 10),
        _ => None,
    }
}

fn max_uint256() -> BigInt {
    (BigInt::from(1) << 256) - 1
}

/// The low 256 bits of `n` as big-endian 32 bytes.
fn encode_uint256(n: &BigInt) -> Vec<u8> {
    let masked = n & max_uint256();
    to_be_32(&masked)
}

/// `n` as a 32-byte two's-complement big-endian integer.
fn encode_int256(n: &BigInt) -> Vec<u8> {
    let m = if n.sign() != Sign::Minus {
        n & max_uint256()
    } else {
        ((BigInt::from(1) << 256) + n) & max_uint256()
    };
    to_be_32(&m)
}

/// A non-negative BigInt (< 2^256) as exactly 32 big-endian bytes.
fn to_be_32(n: &BigInt) -> Vec<u8> {
    let (_, mut bytes) = n.to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    let mut out = vec![0u8; 32 - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

fn pad_left32(b: &[u8]) -> Vec<u8> {
    if b.len() >= 32 {
        return b[b.len() - 32..].to_vec();
    }
    let mut out = vec![0u8; 32 - b.len()];
    out.extend_from_slice(b);
    out
}

fn pad_right32(b: &[u8]) -> Vec<u8> {
    let mut out = if b.len() >= 32 { b[..32].to_vec() } else { b.to_vec() };
    out.resize(32, 0);
    out
}

fn bool_to_byte(val: &Value) -> u8 {
    matches!(val, Value::Bool(true)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical EIP-712 spec "Mail" example → its well-known signable digest.
    const MAIL: &str = r#"{
        "types": {
            "EIP712Domain": [
                {"name":"name","type":"string"},
                {"name":"version","type":"string"},
                {"name":"chainId","type":"uint256"},
                {"name":"verifyingContract","type":"address"}
            ],
            "Person": [
                {"name":"name","type":"string"},
                {"name":"wallet","type":"address"}
            ],
            "Mail": [
                {"name":"from","type":"Person"},
                {"name":"to","type":"Person"},
                {"name":"contents","type":"string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    }"#;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn mail_example_digest_matches_spec() {
        let td = parse(MAIL).unwrap();
        // encodeType(Mail) with the sorted Person dependency appended.
        assert_eq!(td.encode_type("Mail").unwrap(), "Mail(Person from,Person to,string contents)Person(string name,address wallet)");
        // The domain separator and message hash are the spec's known values.
        assert_eq!(hex(&td.hash_struct("EIP712Domain", &td.domain).unwrap()), "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
        // The full signable digest.
        assert_eq!(hex(&td.hash().unwrap()), "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
    }

    #[test]
    fn missing_primary_type_errors() {
        assert!(parse(r#"{"types":{"X":[]},"domain":{},"message":{}}"#).is_err());
    }
}
