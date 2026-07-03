//! Bitcoin transaction building + threshold signing (port of the wlttx Bitcoin
//! path). Builds a legacy P2PKH spend, computes each input's sighash via
//! outscript, and signs it with the wallet's DKLs shares under the account's HD
//! tweak. Each signature is self-verified as valid ECDSA under the derived key.

use num_bigint::{BigInt, Sign};
use outscript::btctx::{BtcTx, BtcTxInput, BtcTxSign, Signer};
use outscript::crypto::secp256k1::SecpPublicKey;

use crate::{Env, Error, Result};

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
