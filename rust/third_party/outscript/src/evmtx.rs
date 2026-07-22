//! EVM transactions: legacy, EIP-2930, EIP-1559, EIP-4844. Build, sign,
//! serialize, parse and recover sender. Port of `evmtx.go`.

use num_bigint::{BigInt, Sign};
use num_traits::{Num, ToPrimitive};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::address::eip55;
use crate::crypto::secp256k1::{SecpPrivateKey, recover_public_key};
use crate::evmabi::{AbiValue, evm_call};
use crate::hash::keccak256_once;
use crate::rlp::{self, RlpItem};

/// EVM transaction type.
///
/// Non-exhaustive: Ethereum continues to define new EIP-2718 transaction types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvmTxType {
    /// Legacy (pre-EIP-2718).
    Legacy,
    /// EIP-2930 access-list transaction.
    Eip2930,
    /// EIP-1559 dynamic-fee transaction.
    Eip1559,
    /// EIP-4844 blob transaction.
    Eip4844,
}

impl EvmTxType {
    fn type_value(self) -> u8 {
        match self {
            EvmTxType::Legacy => 0,
            EvmTxType::Eip2930 => 1,
            EvmTxType::Eip1559 => 2,
            EvmTxType::Eip4844 => 3,
        }
    }
}

/// An EVM transaction.
#[derive(Debug, Clone)]
pub struct EvmTx {
    /// Account nonce.
    pub nonce: u64,
    /// Max priority fee per gas (EIP-1559).
    pub gas_tip_cap: BigInt,
    /// Max fee per gas / gas price (legacy/2930).
    pub gas_fee_cap: BigInt,
    /// Gas limit.
    pub gas: u64,
    /// Destination address, "0x..." (empty "0x" for contract creation).
    pub to: String,
    /// Value in wei.
    pub value: BigInt,
    /// Calldata.
    pub data: Vec<u8>,
    /// Chain id (encoded in v for legacy EIP-155).
    pub chain_id: u64,
    /// Transaction type.
    pub tx_type: EvmTxType,
    /// Whether the transaction has been signed.
    pub signed: bool,
    /// Signature y-parity / v.
    pub y: BigInt,
    /// Signature r.
    pub r: BigInt,
    /// Signature s.
    pub s: BigInt,
}

impl Default for EvmTx {
    fn default() -> Self {
        EvmTx {
            nonce: 0,
            gas_tip_cap: BigInt::from(0),
            gas_fee_cap: BigInt::from(0),
            gas: 0,
            to: String::new(),
            value: BigInt::from(0),
            data: Vec::new(),
            chain_id: 0,
            tx_type: EvmTxType::Legacy,
            signed: false,
            y: BigInt::from(0),
            r: BigInt::from(0),
            s: BigInt::from(0),
        }
    }
}

fn to_item(to: &str) -> Result<RlpItem, String> {
    RlpItem::hex_str(to).map_err(|e| e.to_string())
}

impl EvmTx {
    /// Returns the RLP fields for the transaction (excluding signature fields).
    pub fn rlp_fields(&self) -> Result<Vec<RlpItem>, String> {
        let bi = |v: &BigInt| RlpItem::bigint(v).map_err(|e| e.to_string());
        Ok(match self.tx_type {
            EvmTxType::Legacy => vec![
                RlpItem::uint(self.nonce),
                bi(&self.gas_fee_cap)?,
                RlpItem::uint(self.gas),
                to_item(&self.to)?,
                bi(&self.value)?,
                RlpItem::Bytes(self.data.clone()),
            ],
            EvmTxType::Eip2930 => vec![
                RlpItem::uint(self.chain_id),
                RlpItem::uint(self.nonce),
                bi(&self.gas_fee_cap)?,
                RlpItem::uint(self.gas),
                to_item(&self.to)?,
                bi(&self.value)?,
                RlpItem::Bytes(self.data.clone()),
                RlpItem::List(vec![]),
            ],
            EvmTxType::Eip1559 => vec![
                RlpItem::uint(self.chain_id),
                RlpItem::uint(self.nonce),
                bi(&self.gas_tip_cap)?,
                bi(&self.gas_fee_cap)?,
                RlpItem::uint(self.gas),
                to_item(&self.to)?,
                bi(&self.value)?,
                RlpItem::Bytes(self.data.clone()),
                RlpItem::List(vec![]),
            ],
            EvmTxType::Eip4844 => return Err("EIP-4844 encoding not supported".into()),
        })
    }

    /// Returns the bytes signed to produce the signature.
    pub fn sign_bytes(&self) -> Result<Vec<u8>, String> {
        match self.tx_type {
            EvmTxType::Legacy => {
                let mut f = self.rlp_fields()?;
                if self.chain_id != 0 {
                    f.push(RlpItem::uint(self.chain_id));
                    f.push(RlpItem::uint(0));
                    f.push(RlpItem::uint(0));
                }
                Ok(rlp::encode_list(&f))
            }
            _ => {
                let f = self.rlp_fields()?;
                let mut out = vec![self.tx_type.type_value()];
                out.extend_from_slice(&rlp::encode_list(&f));
                Ok(out)
            }
        }
    }

    /// Serializes the transaction.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        if !self.signed {
            return self.sign_bytes();
        }
        let bi = |v: &BigInt| RlpItem::bigint(v).map_err(|e| e.to_string());
        let mut f = self.rlp_fields()?;
        f.push(bi(&self.y)?);
        f.push(bi(&self.r)?);
        f.push(bi(&self.s)?);
        match self.tx_type {
            EvmTxType::Legacy => Ok(rlp::encode_list(&f)),
            _ => {
                let mut out = vec![self.tx_type.type_value()];
                out.extend_from_slice(&rlp::encode_list(&f));
                Ok(out)
            }
        }
    }

    /// Parses a transaction from its binary encoding.
    pub fn parse_transaction(buf: &[u8]) -> Result<EvmTx, String> {
        if buf.is_empty() {
            return Err("unexpected EOF".into());
        }
        let mut tx = EvmTx::default();
        if buf[0] >= 0x80 {
            // legacy
            let dec = rlp::decode(buf).map_err(|e| e.to_string())?;
            if dec.len() != 1 {
                return Err("invalid rlp data for legacy transaction".into());
            }
            let list = dec[0].as_list().ok_or("expected list")?;
            let ln = list.len();
            if ln != 6 && ln != 9 {
                return Err(format!(
                    "legacy transaction must have 6 or 9 fields, got {ln}"
                ));
            }
            let b = |i: usize| -> &[u8] { list[i].as_bytes().unwrap_or(&[]) };
            tx.tx_type = EvmTxType::Legacy;
            tx.nonce = rlp::decode_uint64_checked(b(0)).map_err(|e| e.to_string())?;
            tx.gas_fee_cap = BigInt::from_bytes_be(Sign::Plus, b(1));
            tx.gas = rlp::decode_uint64_checked(b(2)).map_err(|e| e.to_string())?;
            tx.to = format!("0x{}", hex::encode(b(3)));
            tx.value = BigInt::from_bytes_be(Sign::Plus, b(4));
            tx.data = b(5).to_vec();
            if ln == 9 {
                tx.signed = true;
                tx.y = BigInt::from_bytes_be(Sign::Plus, b(6));
                tx.r = BigInt::from_bytes_be(Sign::Plus, b(7));
                tx.s = BigInt::from_bytes_be(Sign::Plus, b(8));
                // Derive chain id from v (EIP-155) so SignBytes reconstructs
                // the same preimage during sender recovery.
                if let Some(v) = tx.y.to_u64()
                    && v >= 35
                {
                    let bit = 1 - (v & 1);
                    tx.chain_id = (v - 35 - bit) / 2;
                }
            }
            return Ok(tx);
        }
        let payload = &buf[1..];
        match buf[0] {
            1 | 2 => {
                let dec = rlp::decode(payload).map_err(|e| e.to_string())?;
                if dec.len() != 1 {
                    return Err("invalid rlp data for typed transaction".into());
                }
                let list = dec[0].as_list().ok_or("expected list")?;
                let b = |i: usize| -> &[u8] { list[i].as_bytes().unwrap_or(&[]) };
                if buf[0] == 1 {
                    let ln = list.len();
                    if ln != 8 && ln != 11 {
                        return Err(format!("EIP-2930 must have 8 or 11 fields, got {ln}"));
                    }
                    tx.tx_type = EvmTxType::Eip2930;
                    tx.chain_id = rlp::decode_uint64_checked(b(0)).map_err(|e| e.to_string())?;
                    tx.nonce = rlp::decode_uint64_checked(b(1)).map_err(|e| e.to_string())?;
                    tx.gas_fee_cap = BigInt::from_bytes_be(Sign::Plus, b(2));
                    tx.gas = rlp::decode_uint64_checked(b(3)).map_err(|e| e.to_string())?;
                    tx.to = format!("0x{}", hex::encode(b(4)));
                    tx.value = BigInt::from_bytes_be(Sign::Plus, b(5));
                    tx.data = b(6).to_vec();
                    if ln == 11 {
                        tx.signed = true;
                        tx.y = BigInt::from_bytes_be(Sign::Plus, b(8));
                        tx.r = BigInt::from_bytes_be(Sign::Plus, b(9));
                        tx.s = BigInt::from_bytes_be(Sign::Plus, b(10));
                    }
                } else {
                    let ln = list.len();
                    if ln != 9 && ln != 12 {
                        return Err(format!("EIP-1559 must have 9 or 12 fields, got {ln}"));
                    }
                    tx.tx_type = EvmTxType::Eip1559;
                    tx.chain_id = rlp::decode_uint64_checked(b(0)).map_err(|e| e.to_string())?;
                    tx.nonce = rlp::decode_uint64_checked(b(1)).map_err(|e| e.to_string())?;
                    tx.gas_tip_cap = BigInt::from_bytes_be(Sign::Plus, b(2));
                    tx.gas_fee_cap = BigInt::from_bytes_be(Sign::Plus, b(3));
                    tx.gas = rlp::decode_uint64_checked(b(4)).map_err(|e| e.to_string())?;
                    tx.to = format!("0x{}", hex::encode(b(5)));
                    tx.value = BigInt::from_bytes_be(Sign::Plus, b(6));
                    tx.data = b(7).to_vec();
                    if ln == 12 {
                        tx.signed = true;
                        tx.y = BigInt::from_bytes_be(Sign::Plus, b(9));
                        tx.r = BigInt::from_bytes_be(Sign::Plus, b(10));
                        tx.s = BigInt::from_bytes_be(Sign::Plus, b(11));
                    }
                }
                Ok(tx)
            }
            _ => Err("not supported".into()),
        }
    }

    /// Parses from bytes (alias for `parse_transaction`).
    pub fn from_bytes(buf: &[u8]) -> Result<EvmTx, String> {
        Self::parse_transaction(buf)
    }

    /// Returns `(r, s, recovery_id)` for the signed transaction, normalizing the
    /// legacy EIP-155 `v` and setting `chain_id`.
    fn signature_parts(&self) -> Result<([u8; 32], [u8; 32], u8), String> {
        if !self.signed {
            return Err("cannot obtain signature of an unsigned transaction".into());
        }
        let r = bigint_to_32(&self.r)?;
        let s = bigint_to_32(&self.s)?;
        let mut v = self.y.to_u64().ok_or("invalid v")?;
        if self.tx_type == EvmTxType::Legacy {
            if v >= 35 {
                // EIP-155: v = chainId*2 + 35 + recid; recid = 1 - (v & 1).
                v = 1 - (v & 1);
            } else {
                // Pre-EIP-155 legacy: v is the standard 27/28 (map to recovery
                // 0/1), or already a raw 0/1 recovery id. Anything else is invalid
                // and would otherwise be rejected below or panic in recovery.
                v = match v {
                    27 | 28 => v - 27,
                    0 | 1 => v,
                    _ => return Err("invalid pre-EIP-155 signature v value".into()),
                };
            }
        }
        if v > 3 {
            return Err("invalid recovery id".into());
        }
        Ok((r, s, v as u8))
    }

    /// Recovers the sender's public key.
    pub fn sender_pubkey(&self) -> Result<crate::crypto::secp256k1::SecpPublicKey, String> {
        let (r, s, recid) = self.signature_parts()?;
        let buf = self.sign_bytes()?;
        let digest = keccak256_once(&buf);
        recover_public_key(&r, &s, recid, &digest).map_err(|e| e.to_string())
    }

    /// Recovers the EIP-55 checksummed sender address.
    pub fn sender_address(&self) -> Result<String, String> {
        let pubkey = self.sender_pubkey()?;
        let addr = crate::hash::ether_hash(&pubkey.serialize_uncompressed());
        Ok(eip55(&addr))
    }

    /// Signs the transaction with the given key.
    pub fn sign(&mut self, key: &SecpPrivateKey) -> Result<(), String> {
        let buf = self.sign_bytes()?;
        let digest = keccak256_once(&buf);
        let (r, s, recid) = key.sign_recoverable(&digest);
        self.signed = true;
        self.r = BigInt::from_bytes_be(Sign::Plus, &r);
        self.s = BigInt::from_bytes_be(Sign::Plus, &s);
        let v = recid as u64;
        self.y = if self.tx_type == EvmTxType::Legacy {
            if self.chain_id == 0 {
                BigInt::from(27 + v)
            } else {
                BigInt::from(self.chain_id * 2 + 35 + v)
            }
        } else {
            BigInt::from(v)
        };
        Ok(())
    }

    /// Returns the keccak-256 hash of the signed transaction's encoding.
    pub fn hash(&self) -> Result<[u8; 32], String> {
        let data = self.to_bytes()?;
        Ok(keccak256_once(&data))
    }

    /// Sets the transaction's calldata to the ABI-encoded method call.
    pub fn call(&mut self, method: &str, params: &[AbiValue]) -> Result<(), String> {
        self.data = evm_call(method, params)?;
        Ok(())
    }
}

fn bigint_to_32(v: &BigInt) -> Result<[u8; 32], String> {
    let (sign, bytes) = v.to_bytes_be();
    if sign == Sign::Minus {
        return Err("negative signature component".into());
    }
    if bytes.len() > 32 {
        return Err("signature component exceeds 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecpPrivateKey {
        let mut s = [0u8; 32];
        s.copy_from_slice(
            &hex::decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap(),
        );
        SecpPrivateKey::from_bytes(&s).unwrap()
    }

    #[test]
    fn legacy_parse_sender_hash() {
        let bin = hex::decode("f86b1e8507ea8ed4008252089443badf0e63ac147ace611dc1113afe0ea3f8691787d529ae9e8600008026a0cacce90eb140f837a139e5d8acbe73527663aea163d4e4c6e8218681d1d37b0fa07fdb860517234804b71bbc518ecb4dc4bb96c1944ab28d502fc429baac939b3c").unwrap();
        let tx = EvmTx::parse_transaction(&bin).unwrap();
        assert_eq!(
            tx.sender_address().unwrap(),
            "0xebE790E554f30924801B48197DCb6f71de2760BC"
        );
        assert_eq!(
            hex::encode(tx.hash().unwrap()),
            "bac4cb10f95b37dab2c8a78e880d39661cc53f87386ded2fb721ac2304113ea3"
        );
    }

    #[test]
    fn eip1559_parse_sender_hash() {
        let bin = hex::decode("02f87101830bdfbb80850243e1963982798e94e866fecdb429c72c30868d3582192a878298698487d3c0ba13571e2080c080a08032999a5ae9477f5f52134c9dc1690d1e25d0bb78ef0f22b949afd0df73a9e4a07106563a788499eb370a48e7c86c08e357866fcc12867a8c530b5ca22175e784").unwrap();
        let tx = EvmTx::parse_transaction(&bin).unwrap();
        assert_eq!(
            tx.sender_address().unwrap(),
            "0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"
        );
        assert_eq!(
            hex::encode(tx.hash().unwrap()),
            "c0c7f78587ebe1f3b377f9c572fe59f4007c88677a1bbd78349f7356304e06b4"
        );
    }

    #[test]
    fn json_roundtrip() {
        let mut tx = EvmTx {
            chain_id: 1,
            nonce: 42,
            gas_fee_cap: BigInt::from(30_000_000_000u64),
            gas: 21000,
            to: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7".into(),
            value: BigInt::from(10u64).pow(18),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        let j = serde_json::to_string(&tx).unwrap();
        assert!(j.contains("\"from\":\"0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7\""));
        let parsed: EvmTx = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed.nonce, 42);
        assert_eq!(parsed.value, BigInt::from(10u64).pow(18));
    }

    #[test]
    fn sign_and_recover_sender() {
        let mut tx = EvmTx {
            chain_id: 1,
            nonce: 42,
            gas_fee_cap: BigInt::from(30_000_000_000u64),
            gas: 21000,
            to: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7".into(),
            value: BigInt::from(10u64).pow(18),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        assert_eq!(
            tx.sender_address().unwrap(),
            "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7"
        );
    }

    #[test]
    fn pre_eip155_sign_and_recover() {
        // chain_id == 0 produces a pre-EIP-155 legacy signature (v = 27/28).
        // Recovery must not panic and must return the signer.
        let mut tx = EvmTx {
            chain_id: 0,
            nonce: 7,
            gas_fee_cap: BigInt::from(20_000_000_000u64),
            gas: 21000,
            to: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7".into(),
            value: BigInt::from(1u64),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        // v must be the legacy 27/28 form
        let v = tx.y.to_u64().unwrap();
        assert!(v == 27 || v == 28, "expected legacy v 27/28, got {v}");
        assert_eq!(
            tx.sender_address().unwrap(),
            "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7"
        );
    }

    #[test]
    fn parse_rejects_oversized_uint_field() {
        // A legacy tx whose nonce field is 9 bytes is valid RLP but must error
        // (not panic) when decoded as a u64.
        let nine = vec![0x88u8; 9]; // RLP byte string of 9 bytes -> 0x88 prefix
        let fields: Vec<crate::rlp::RlpItem> = vec![
            crate::rlp::RlpItem::Bytes(nine),             // nonce (9 bytes)
            crate::rlp::RlpItem::Bytes(vec![0x01]),       // gas price
            crate::rlp::RlpItem::Bytes(vec![0x52, 0x08]), // gas
            crate::rlp::RlpItem::Bytes(vec![0u8; 20]),    // to
            crate::rlp::RlpItem::Bytes(vec![]),           // value
            crate::rlp::RlpItem::Bytes(vec![]),           // data
        ];
        let encoded = crate::rlp::RlpItem::List(fields).encode();
        assert!(EvmTx::parse_transaction(&encoded).is_err());
    }
}

// --- JSON (serde) ---

fn hex0x_u64(v: u64) -> String {
    format!("0x{v:x}")
}
fn hex0x_big(v: &BigInt) -> String {
    format!("0x{v:x}")
}

fn parse_u64_auto(s: &str) -> Result<u64, String> {
    if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}
fn parse_big_auto(s: &str) -> Result<BigInt, String> {
    if let Some(h) = s.strip_prefix("0x") {
        BigInt::from_str_radix(h, 16).map_err(|e| e.to_string())
    } else {
        BigInt::from_str_radix(s, 10).map_err(|e| e.to_string())
    }
}

#[derive(Serialize, Deserialize, Default)]
struct EvmTxJson {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    from: String,
    #[serde(default)]
    gas: String,
    #[serde(rename = "gasPrice", default, skip_serializing_if = "String::is_empty")]
    gas_price: String,
    #[serde(
        rename = "maxPriorityFeePerGas",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    gas_tip_cap: String,
    #[serde(
        rename = "maxFeePerGas",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    gas_fee_cap: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    hash: String,
    #[serde(default)]
    input: String,
    #[serde(default)]
    nonce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    to: String,
    #[serde(default)]
    value: String,
    #[serde(rename = "chainId", default)]
    chain_id: String,
    #[serde(default)]
    v: String,
    #[serde(default)]
    r: String,
    #[serde(default)]
    s: String,
}

impl Serialize for EvmTx {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut obj = EvmTxJson {
            gas: hex0x_u64(self.gas),
            input: format!("0x{}", hex::encode(&self.data)),
            nonce: hex0x_u64(self.nonce),
            to: self.to.clone(),
            value: hex0x_big(&self.value),
            chain_id: hex0x_u64(self.chain_id),
            ..Default::default()
        };
        if self.tx_type == EvmTxType::Legacy {
            obj.gas_price = hex0x_big(&self.gas_fee_cap);
        } else {
            obj.gas_fee_cap = hex0x_big(&self.gas_fee_cap);
            obj.gas_tip_cap = hex0x_big(&self.gas_tip_cap);
        }
        if self.signed {
            obj.from = self.sender_address().unwrap_or_default();
            obj.v = hex0x_big(&self.y);
            obj.r = hex0x_big(&self.r);
            obj.s = hex0x_big(&self.s);
        }
        obj.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EvmTx {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let o = EvmTxJson::deserialize(deserializer)?;
        let mut tx = EvmTx::default();
        if !o.gas.is_empty() {
            tx.gas = parse_u64_auto(&o.gas).map_err(D::Error::custom)?;
        }
        if !o.gas_fee_cap.is_empty() && !o.gas_tip_cap.is_empty() {
            tx.gas_fee_cap = parse_big_auto(&o.gas_fee_cap).map_err(D::Error::custom)?;
            tx.gas_tip_cap = parse_big_auto(&o.gas_tip_cap).map_err(D::Error::custom)?;
            tx.tx_type = EvmTxType::Eip1559;
        } else if !o.gas_price.is_empty() {
            tx.gas_fee_cap = parse_big_auto(&o.gas_price).map_err(D::Error::custom)?;
        }
        if !o.input.is_empty() {
            let h = o
                .input
                .strip_prefix("0x")
                .ok_or_else(|| D::Error::custom("input must start with 0x"))?;
            tx.data = hex::decode(h).map_err(D::Error::custom)?;
        }
        if !o.nonce.is_empty() {
            tx.nonce = parse_u64_auto(&o.nonce).map_err(D::Error::custom)?;
        }
        if !o.to.is_empty() {
            tx.to = o.to;
        }
        if !o.value.is_empty() {
            tx.value = parse_big_auto(&o.value).map_err(D::Error::custom)?;
        }
        if !o.chain_id.is_empty() {
            tx.chain_id = parse_u64_auto(&o.chain_id).map_err(D::Error::custom)?;
        }
        if !o.v.is_empty() {
            tx.y = parse_big_auto(&o.v).map_err(D::Error::custom)?;
        }
        if !o.r.is_empty() {
            tx.r = parse_big_auto(&o.r).map_err(D::Error::custom)?;
        }
        if !o.s.is_empty() {
            tx.s = parse_big_auto(&o.s).map_err(D::Error::custom)?;
        }
        Ok(tx)
    }
}
