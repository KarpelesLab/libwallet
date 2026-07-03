//! Bitcoin transaction building + threshold signing (port of the wlttx Bitcoin
//! path). Builds a legacy P2PKH spend, computes each input's sighash via
//! outscript, and signs it with the wallet's DKLs shares under the account's HD
//! tweak. Each signature is self-verified as valid ECDSA under the derived key.

use num_bigint::{BigInt, Sign};
use outscript::btctx::{BtcTx, BtcTxInput, BtcTxSign, Signer};
use outscript::crypto::secp256k1::SecpPublicKey;

use crate::{Env, Error, Result};

/// Serialize a BIP-32 extended **public** key (`xpub…`) from a compressed
/// secp256k1 pubkey + 32-byte chain code, as Go `Account.Xpub` does via
/// `ecckd.FromPublicKey`: mainnet version, depth 0, zero parent fingerprint and
/// child number, base58check (double-SHA256 checksum). The account uses the
/// wallet chain code (matching Go), so this reproduces the exact xpub string.
pub fn build_xpub(pubkey_compressed: &[u8; 33], chaincode: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(78 + 4);
    data.extend_from_slice(&[0x04, 0x88, 0xb2, 0x1e]); // BitcoinMainnetPublic
    data.push(0x00); // depth
    data.extend_from_slice(&[0, 0, 0, 0]); // parent fingerprint
    data.extend_from_slice(&[0, 0, 0, 0]); // child number
    data.extend_from_slice(chaincode);
    data.extend_from_slice(pubkey_compressed);
    let h1 = purecrypto::hash::sha256(&data);
    let h2 = purecrypto::hash::sha256(&h1);
    data.extend_from_slice(&h2[..4]);
    bs58::encode(&data).into_string()
}

/// Parse a modchain `balance` value (outscript BtcAmount JSON) into satoshi.
/// Mirrors Go `BtcAmount.UnmarshalText`: a JSON number/string, where a value
/// without a decimal point is whole BTC (×1e8), a decimal value is scaled to
/// 8 places (max 8 decimals), and a `0x`-prefixed string is raw satoshi hex.
pub fn parse_btc_amount(v: &serde_json::Value) -> Result<u64> {
    // Numbers keep their literal form via to_string (no float rounding).
    let s = match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        other => return Err(Error::Env(format!("bad btc amount {other}"))),
    };
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).map_err(|e| Error::Env(format!("btc hex: {e}")));
    }
    match s.split_once('.') {
        None => {
            let v: u64 = s.parse().map_err(|e| Error::Env(format!("btc int: {e}")))?;
            v.checked_mul(100_000_000).ok_or_else(|| Error::Env("btc overflow".into()))
        }
        Some((int_part, frac)) => {
            if frac.len() > 8 {
                return Err(Error::Env("cannot parse amount with more than 8 decimals".into()));
            }
            let digits = format!("{int_part}{frac}");
            let mut v: u64 = digits.parse().map_err(|e| Error::Env(format!("btc dec: {e}")))?;
            for _ in frac.len()..8 {
                v = v.checked_mul(10).ok_or_else(|| Error::Env("btc overflow".into()))?;
            }
            Ok(v)
        }
    }
}

/// The receive/change address type + address-network name for a Bitcoin-family
/// chain (Go `Account.bitcoinAddress`): segwit P2WPKH (bech32) for
/// bitcoin/litecoin/monacoin, P2PKH for bitcoin-cash (cashaddr) and dogecoin.
fn hd_address_kind(chain_id: &str) -> Result<(&'static str, &'static str)> {
    match chain_id {
        "bitcoin" => Ok(("p2wpkh", "bitcoin")),
        "litecoin" => Ok(("p2wpkh", "litecoin")),
        "monacoin" => Ok(("p2wpkh", "monacoin")),
        "bitcoin-cash" => Ok(("p2pkh", "bitcoincash")),
        "dogecoin" => Ok(("p2pkh", "dogecoin")),
        other => Err(Error::Env(format!("unsupported bitcoin-family chainId: {other}"))),
    }
}

/// Encode a compressed secp256k1 pubkey as the HD receive/change address for
/// `chain_id`, via outscript (P2WPKH/P2PKH per [`hd_address_kind`]).
pub fn hd_address(pubkey_compressed: &[u8; 33], chain_id: &str) -> Result<String> {
    let (script_type, network) = hd_address_kind(chain_id)?;
    let pk = SecpPublicKey::from_sec1(pubkey_compressed)
        .map_err(|e| Error::Env(format!("bad pubkey: {e:?}")))?;
    outscript::script::Script::new(pk)
        .address(script_type, &[network])
        .map_err(|e| Error::Env(format!("address encode: {e}")))
}

/// The next unused HD address on the receive (`change=false`) or change chain,
/// found via `modchain_lookupTxoBIP32` (returns the highest used index `lastI`)
/// and derived at `m/<chain>/<lastI+1>` below the account xpub. Port of Go
/// `accountNextAddress`. Returns `(address, index, path)`.
pub fn next_address(
    rpc: &str,
    xpub: &str,
    account_pubkey: &[u8; 33],
    account_chaincode: &[u8; 32],
    chain_id: &str,
    change: bool,
) -> Result<(String, u32, String)> {
    let chain: u32 = if change { 1 } else { 0 };
    let base_path = format!("m/{chain}");
    let raw = crate::rpc::call(rpc, "modchain_lookupTxoBIP32", serde_json::json!([xpub, base_path, true]))?;
    // lastI = highest used index, -1 when the chain is entirely unused.
    let last_i = raw.get("lastI").and_then(|v| v.as_i64()).unwrap_or(-1);
    let next_index = (last_i + 1) as u32;
    let child = crate::hdderive::derive_pub(account_pubkey, account_chaincode, &[chain, next_index])
        .map_err(|e| Error::Env(e.to_string()))?;
    let address = hd_address(&child, chain_id)?;
    Ok((address, next_index, format!("{base_path}/{next_index}")))
}

/// Sum the NATIVE unspent balance (in satoshi) reported by `modchain_assets`
/// for `lookup` (an address or xpub). Port of Go `Network.bitcoinBalance`.
pub fn native_balance_satoshi(rpc: &str, lookup: &str) -> Result<u64> {
    let raw = crate::rpc::call(rpc, "modchain_assets", serde_json::json!([lookup]))?;
    let assets = raw
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| Error::Env("modchain_assets: no assets array".into()))?;
    let mut total: u64 = 0;
    for a in assets {
        if a.get("asset").and_then(|s| s.as_str()) != Some("NATIVE") {
            continue;
        }
        if let Some(bal) = a.get("balance") {
            total = total
                .checked_add(parse_btc_amount(bal)?)
                .ok_or_else(|| Error::Env("btc balance overflow".into()))?;
        }
    }
    Ok(total)
}

/// A UTXO to spend.
pub struct Utxo {
    pub txid: [u8; 32], // display (big-endian) order
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

/// A signer that routes ECDSA signing to the wallet's DKLs shares under a fixed
/// derivation tweak, verifying each signature under the derived public key.
struct TssSigner<'a> {
    pubkey: SecpPublicKey,
    sign_digest: Box<dyn Fn(&[u8; 32]) -> std::result::Result<(Vec<u8>, Vec<u8>), String> + 'a>,
}

impl<'a> Signer for TssSigner<'a> {
    fn ecdsa_public_key(&self) -> Option<SecpPublicKey> {
        SecpPublicKey::from_sec1(&self.pubkey.serialize_compressed()).ok()
    }

    fn sign_ecdsa_der(&self, digest: &[u8; 32]) -> std::result::Result<Vec<u8>, String> {
        let (r, s) = (self.sign_digest)(digest)?;
        let r32 = pad32(&r);
        let s32 = pad32(&s);
        if !self.pubkey.verify(digest, &r32, &s32) {
            return Err("threshold signature failed to verify under the derived key".into());
        }
        Ok(der_encode(&r32, &s32))
    }
}

/// Build and DKLs-sign a legacy P2PKH transaction spending `utxos` to
/// `outputs` (each `(address, sats)`). `unlock` provides the Password creds for
/// all wallet shares. Returns the raw signed transaction bytes.
pub fn sign_transfer(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    utxos: &[Utxo],
    outputs: &[(String, u64)],
) -> Result<Vec<u8>> {
    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    let pub_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&acct.pubkey)
            .map_err(|e| Error::Env(format!("bad account pubkey: {e}")))?
    };
    let pubkey = SecpPublicKey::from_sec1(&pub_bytes).map_err(|e| Error::Env(format!("{e:?}")))?;
    let tweak = il_to_tweak(&acct.il)?;
    let wallet_id = acct.wallet.clone();

    let signer = TssSigner {
        pubkey,
        sign_digest: Box::new(move |digest: &[u8; 32]| {
            let (r, s, v) = crate::models::wallet::dkls_sign_digest(env, &wallet_id, unlock, &tweak, digest)
                .map_err(|e| e.to_string())?;
            let (s, _) = normalize_low_s(s, v);
            Ok((r, s))
        }),
    };

    let mut tx = BtcTx { version: 2, locktime: 0, ..BtcTx::default() };
    for u in utxos {
        tx.inputs.push(BtcTxInput {
            txid: u.txid,
            vout: u.vout,
            script: Vec::new(),
            sequence: 0xffff_ffff,
            witnesses: Vec::new(),
        });
    }
    for (address, sats) in outputs {
        tx.add_output(address, *sats).map_err(Error::Env)?;
    }

    let signs: Vec<BtcTxSign> = utxos
        .iter()
        .map(|u| BtcTxSign::new(&signer, "p2pkh").amount(u.amount).prev_script(u.script_pubkey.clone()))
        .collect();
    tx.sign(&signs).map_err(Error::Env)?;
    Ok(tx.to_bytes())
}

fn il_to_tweak(il: &serde_json::Value) -> Result<[u8; 32]> {
    let dec = il.as_str().ok_or_else(|| Error::Env("account has no IL tweak".into()))?;
    let n = BigInt::parse_bytes(dec.as_bytes(), 10).ok_or_else(|| Error::Env("bad IL".into()))?;
    Ok(pad32(&n.to_bytes_be().1))
}

fn pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = b.len().min(32);
    out[32 - n..].copy_from_slice(&b[b.len() - n..]);
    out
}

fn secp_n() -> BigInt {
    BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}

fn normalize_low_s(s: Vec<u8>, v: u8) -> (Vec<u8>, u8) {
    let n = secp_n();
    let half = &n >> 1;
    let sv = BigInt::from_bytes_be(Sign::Plus, &s);
    if sv > half {
        (pad32(&(&n - &sv).to_bytes_be().1).to_vec(), v ^ 1)
    } else {
        (s, v)
    }
}

/// DER-encode an ECDSA (r, s) pair.
fn der_encode(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let r = der_int(r);
    let s = der_int(s);
    let mut out = Vec::with_capacity(2 + r.len() + s.len());
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

fn der_int(b: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < b.len() && b[i] == 0 {
        i += 1;
    }
    let mag = &b[i..];
    let mut v = vec![0x02];
    if mag[0] & 0x80 != 0 {
        v.push((mag.len() + 1) as u8);
        v.push(0x00);
    } else {
        v.push(mag.len() as u8);
    }
    v.extend_from_slice(mag);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{account, wallet};
    use crate::sign::KeyDescription;
    use crate::Env;
    use base64::Engine;

    fn pw(p: &str) -> KeyDescription {
        KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
    }

    #[test]
    fn btc_transfer_signs_and_self_verifies() {
        let env = Env::init_memory().unwrap();
        wallet::init(&env).unwrap();
        account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = account::create(&env, &w.id, "", "bitcoin", 0).unwrap();

        // The UTXO we spend pays to the account's own P2PKH scriptPubKey.
        let pub_bytes =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&a.pubkey).unwrap();
        let h160 = outscript::hash::hash160(&pub_bytes);
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&h160);
        script.extend_from_slice(&[0x88, 0xac]);

        let utxos = vec![Utxo { txid: [0x11; 32], vout: 0, amount: 100_000, script_pubkey: script }];
        let outputs = vec![(a.address.clone(), 90_000u64)]; // to self, 10k fee

        let unlock: Vec<(String, String)> = vec![
            (w.keys[0].id.clone(), "passwordone".to_string()),
            (w.keys[1].id.clone(), "passwordtwo".to_string()),
            (w.keys[2].id.clone(), "passwordthree".to_string()),
        ];

        // If the DKLs signature didn't verify as valid ECDSA under the derived
        // key, the signer errors and sign_transfer fails.
        let raw = sign_transfer(&env, &a.id, &unlock, &utxos, &outputs).expect("sign+self-verify");
        assert!(!raw.is_empty());

        let parsed = BtcTx::from_bytes(&raw).expect("valid tx");
        assert_eq!(parsed.inputs.len(), 1);
        assert!(!parsed.inputs[0].script.is_empty(), "input scriptSig populated");
    }
}
