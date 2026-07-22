//! EVM ABI encoding (port of `evmabi.go`).

use num_bigint::{BigInt, Sign};

use crate::hash::keccak256_once;
use crate::out::Out;

fn two_pow_256() -> BigInt {
    BigInt::from(1) << 256
}

/// A value that can be ABI-encoded.
///
/// Non-exhaustive: more ABI value kinds (fixed bytes, arrays, tuples, …) may be
/// added.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AbiValue {
    /// Unsigned/large integer.
    Uint(BigInt),
    /// Signed 64-bit integer.
    Int(i64),
    /// Unsigned 64-bit integer.
    Uint64(u64),
    /// Boolean.
    Bool(bool),
    /// Dynamic byte string.
    Bytes(Vec<u8>),
    /// UTF-8 string.
    Str(String),
    /// An `Out` (used as an EVM address by `encode_auto`).
    Out(Out),
}

struct AbiString {
    offset: usize,
    data: Vec<u8>,
}

/// A builder for EVM ABI-encoded data.
#[derive(Default)]
pub struct AbiBuffer {
    buf: Vec<u8>,
    str: Vec<AbiString>,
}

impl AbiBuffer {
    /// Creates a new buffer seeded with `buf`.
    pub fn new(buf: Vec<u8>) -> AbiBuffer {
        AbiBuffer {
            buf,
            str: Vec::new(),
        }
    }

    /// Encodes values by inferring their natural ABI representation.
    pub fn encode_auto(&mut self, params: &[AbiValue]) -> Result<(), String> {
        for p in params {
            match p {
                AbiValue::Int(o) => self.append_big_int(&BigInt::from(*o))?,
                AbiValue::Uint64(o) => self.append_big_int(&BigInt::from(*o))?,
                AbiValue::Uint(o) => self.append_big_int(o)?,
                AbiValue::Bool(b) => self.append_big_int(&BigInt::from(*b as u8))?,
                AbiValue::Bytes(o) => self.append_bytes(o),
                AbiValue::Str(s) => self.append_bytes(s.as_bytes()),
                AbiValue::Out(o) => {
                    if o.name == "evm" || o.name == "eth" {
                        self.append_big_int(&BigInt::from_bytes_be(Sign::Plus, o.bytes()))?;
                    } else {
                        return Err(format!("unsupported value type {} for EVM", o.name));
                    }
                }
            }
        }
        Ok(())
    }

    /// Encodes parameters according to an ABI signature like
    /// "transfer(address,uint256)".
    pub fn encode_abi(&mut self, abi: &str, params: &[AbiValue]) -> Result<(), String> {
        let pos = abi
            .find('(')
            .ok_or("invalid abi format (could not locate start of parameters)")?;
        if !abi.ends_with(')') {
            return Err("invalid abi format (does not end with a closing parenthesis)".into());
        }
        let inner = &abi[pos + 1..abi.len() - 1];
        let types: Vec<&str> = if inner.is_empty() {
            Vec::new()
        } else {
            inner.split(',').collect()
        };
        self.encode_types(&types, params)
    }

    /// Encodes parameters according to explicit ABI type strings.
    pub fn encode_types(&mut self, types: &[&str], params: &[AbiValue]) -> Result<(), String> {
        if types.len() != params.len() {
            return Err("wrong number of arguments".into());
        }
        for (t, p) in types.iter().zip(params.iter()) {
            match *t {
                "uint" | "uint8" | "uint16" | "uint32" | "uint64" | "uint256" | "bytes4"
                | "bytes32" => self.append_uint256_any(p)?,
                "address" => self.append_address_any(p)?,
                "bytes" | "string" => self.append_buffer_any(p)?,
                other => return Err(format!("unsupported type: {other}")),
            }
        }
        Ok(())
    }

    fn append_uint256_any(&mut self, v: &AbiValue) -> Result<(), String> {
        match v {
            AbiValue::Bool(b) => self.append_big_int(&BigInt::from(*b as u8)),
            AbiValue::Int(o) => self.append_big_int(&BigInt::from(*o)),
            AbiValue::Uint64(o) => self.append_big_int(&BigInt::from(*o)),
            AbiValue::Uint(o) => self.append_big_int(o),
            other => Err(format!(
                "unsupported type {other:?} for evm abi uint256-style type"
            )),
        }
    }

    /// Validates that `addr` is exactly 20 bytes and appends it as a uint256-style
    /// ABI word (left-padded to 32 bytes).
    fn append_address_bytes(&mut self, addr: &[u8]) -> Result<(), String> {
        if addr.len() != 20 {
            return Err(format!("evm address must be 20 bytes, got {}", addr.len()));
        }
        self.append_big_int(&BigInt::from_bytes_be(Sign::Plus, addr))
    }

    fn append_address_any(&mut self, v: &AbiValue) -> Result<(), String> {
        match v {
            AbiValue::Out(o) => {
                if o.name != "evm" && o.name != "eth" {
                    return Err(format!(
                        "unsupported output type {} for evm abi type address",
                        o.name
                    ));
                }
                self.append_address_bytes(o.bytes())
            }
            AbiValue::Bytes(b) => self.append_address_bytes(b),
            AbiValue::Str(s) => {
                let s = s.strip_prefix("0x").unwrap_or(s);
                let addr = hex::decode(s).map_err(|e| format!("invalid hex address: {e}"))?;
                self.append_address_bytes(&addr)
            }
            other => Err(format!(
                "unsupported type {other:?} for evm abi type address"
            )),
        }
    }

    fn append_buffer_any(&mut self, v: &AbiValue) -> Result<(), String> {
        match v {
            AbiValue::Bytes(o) => {
                self.append_bytes(o);
                Ok(())
            }
            AbiValue::Str(s) => {
                self.append_bytes(s.as_bytes());
                Ok(())
            }
            other => Err(format!(
                "unsupported type {other:?} for evm abi buffer type"
            )),
        }
    }

    /// Appends a 256-bit integer (big-endian, 32 bytes).
    pub fn append_big_int(&mut self, v: &BigInt) -> Result<(), String> {
        let bound = two_pow_256();
        // Only the (rare) negative case allocates; the common path borrows `v`.
        let owned;
        let val: &BigInt = if v.sign() == Sign::Minus {
            // two's complement: 2^256 + v (v is negative). For v == -1 this yields
            // an all-ones 32-byte word.
            owned = &bound + v;
            if owned.sign() != Sign::Plus {
                return Err("big.Int value exceeds negative 256 bits".into());
            }
            &owned
        } else {
            v
        };
        if *val >= bound {
            return Err("big.Int value exceeds 256 bits".into());
        }
        let mut inbuf = [0u8; 32];
        let (_, bytes) = val.to_bytes_be();
        inbuf[32 - bytes.len()..].copy_from_slice(&bytes);
        self.buf.extend_from_slice(&inbuf);
        Ok(())
    }

    /// Appends a dynamic byte buffer (stored as an offset pointer + tail data).
    pub fn append_bytes(&mut self, v: &[u8]) {
        let pos = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 32]);
        let mut len_buf = [0u8; 32];
        let len_bytes = (v.len() as u64).to_be_bytes();
        len_buf[24..].copy_from_slice(&len_bytes);
        let mut data = len_buf.to_vec();
        data.extend_from_slice(v);
        self.str.push(AbiString { offset: pos, data });
    }

    /// Returns the encoded ABI buffer.
    pub fn bytes(&self) -> Vec<u8> {
        let mut res = self.buf.clone();
        for s in &self.str {
            let mut in_ = s.data.clone();
            let x = in_.len() % 32;
            if x != 0 {
                in_.extend(std::iter::repeat_n(0u8, 32 - x));
            }
            let pos = res.len() as u64;
            let mut pos_buf = [0u8; 32];
            pos_buf[24..].copy_from_slice(&pos.to_be_bytes());
            res[s.offset..s.offset + 32].copy_from_slice(&pos_buf);
            res.extend_from_slice(&in_);
        }
        res
    }

    /// Returns the ABI-encoded method call (4-byte selector + encoded args).
    pub fn call(&self, method: &str) -> Vec<u8> {
        let hash = keccak256_once(method.as_bytes());
        let mut out = hash[..4].to_vec();
        out.extend_from_slice(&self.bytes());
        out
    }
}

/// Generates calldata for an EVM call, performing no validation that the
/// parameters match the ABI signature.
pub fn evm_call(method: &str, params: &[AbiValue]) -> Result<Vec<u8>, String> {
    let mut buf = AbiBuffer::default();
    buf.encode_abi(method, params)?;
    Ok(buf.call(method))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::parse_evm_address;

    #[test]
    fn transfer_encode_auto() {
        let mut buf = AbiBuffer::default();
        let addr = parse_evm_address("0x5Fb84129AD9E7818F099966de975ff41213F028d").unwrap();
        buf.encode_auto(&[
            AbiValue::Out(addr),
            AbiValue::Uint(BigInt::from(123456789123456789u64)),
        ])
        .unwrap();
        let call = buf.call("transfer(address,uint256)");
        assert_eq!(
            hex::encode(call),
            "a9059cbb0000000000000000000000005fb84129ad9e7818f099966de975ff41213f028d00000000000000000000000000000000000000000000000001b69b4bacd05f15"
        );
    }

    #[test]
    fn address_abi_type_encodes() {
        // The "address" ABI type must be usable via encode_abi (the evm_call path),
        // not only encode_auto.
        let addr = parse_evm_address("0x5Fb84129AD9E7818F099966de975ff41213F028d").unwrap();
        let mut buf = AbiBuffer::default();
        buf.encode_abi(
            "transfer(address,uint256)",
            &[
                AbiValue::Out(addr),
                AbiValue::Uint(BigInt::from(123456789123456789u64)),
            ],
        )
        .unwrap();
        let call = buf.call("transfer(address,uint256)");
        assert_eq!(
            hex::encode(call),
            "a9059cbb0000000000000000000000005fb84129ad9e7818f099966de975ff41213f028d00000000000000000000000000000000000000000000000001b69b4bacd05f15"
        );

        // a "0x..." string address also works
        let mut buf2 = AbiBuffer::default();
        buf2.encode_types(
            &["address"],
            &[AbiValue::Str(
                "0x5Fb84129AD9E7818F099966de975ff41213F028d".into(),
            )],
        )
        .unwrap();

        // an address that is not 20 bytes is rejected
        let mut buf3 = AbiBuffer::default();
        assert!(
            buf3.encode_types(&["address"], &[AbiValue::Bytes(vec![0u8; 19])])
                .is_err()
        );
    }

    #[test]
    fn negative_two_complement() {
        // -1 must encode as the all-ones 32-byte word, not be rejected.
        let mut buf = AbiBuffer::default();
        buf.append_big_int(&BigInt::from(-1)).unwrap();
        assert_eq!(hex::encode(buf.bytes()), "f".repeat(64));
    }

    #[test]
    fn cast_vote_with_reason() {
        let call = evm_call(
            "castVoteWithReason(uint256,uint8,string)",
            &[
                AbiValue::Int(123456789123456789),
                AbiValue::Int(1),
                AbiValue::Str("this is a test".into()),
            ],
        )
        .unwrap();
        assert_eq!(
            hex::encode(call),
            "7b3c71d300000000000000000000000000000000000000000000000001b69b4bacd05f1500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000e7468697320697320612074657374000000000000000000000000000000000000"
        );
    }
}
