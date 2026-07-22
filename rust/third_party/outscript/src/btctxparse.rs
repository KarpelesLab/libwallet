//! Parsing/extraction of signatures from Bitcoin input scripts and recomputing
//! the sighash they committed to. Port of `btctxparse.go`.

use crate::btcamount::BtcAmount;
use crate::btctx::BtcTx;
use crate::crypto::secp256k1::SecpPublicKey;
use crate::hash::hash160;
use crate::pushbytes::{parse_push_bytes, push_bytes};

/// Parsed signature data for a single recognized spend.
#[derive(Debug, Clone, Default)]
pub struct BtcInputSig {
    /// "p2pkh", "p2wpkh", "p2sh-multisig", "p2tr-keypath", "p2tr-scriptpath".
    pub scheme: String,
    /// 32-byte big-endian r.
    pub r: Vec<u8>,
    /// 32-byte big-endian s.
    pub s: Vec<u8>,
    /// Sighash flag (0 = SIGHASH_DEFAULT for taproot, 1 = SIGHASH_ALL).
    pub sighash_flag: u32,
    /// Signing pubkey (full compressed/uncompressed for ECDSA, x-only for taproot).
    pub pubkey: Vec<u8>,
    /// Redeem script (for p2sh-multisig).
    pub redeem_script: Vec<u8>,
    /// All N pubkeys (for p2sh-multisig).
    pub pubkeys: Vec<Vec<u8>>,
    /// Tapleaf script (p2tr-scriptpath).
    pub leaf_script: Vec<u8>,
    /// BIP-341 control block (p2tr-scriptpath).
    pub control_block: Vec<u8>,
}

/// Extracts signature data from an input's scriptSig and witness. Returns an
/// empty vector when the input does not match a recognized pattern.
pub fn extract_btc_input_sig(
    script_sig: &[u8],
    witness: &[Vec<u8>],
) -> Result<Vec<BtcInputSig>, String> {
    if script_sig.is_empty() && !witness.is_empty() {
        return extract_witness_only(witness);
    }
    if witness.is_empty() && !script_sig.is_empty() {
        return extract_scriptsig_only(script_sig);
    }
    Ok(Vec::new())
}

fn extract_witness_only(witness: &[Vec<u8>]) -> Result<Vec<BtcInputSig>, String> {
    // Annex (BIP-341) not supported.
    if witness.len() >= 2 {
        let last = &witness[witness.len() - 1];
        if !last.is_empty() && last[0] == 0x50 {
            return Ok(Vec::new());
        }
    }
    match witness.len() {
        1 => {
            if let Some(s) = parse_taproot_sig(&witness[0], "p2tr-keypath") {
                return Ok(vec![s]);
            }
            Ok(Vec::new())
        }
        _ => {
            let cb = &witness[witness.len() - 1];
            if is_control_block(cb) {
                return parse_p2tr_script_path(witness);
            }
            if witness.len() == 2 {
                let pubb = &witness[1];
                if !pubb.is_empty() && matches!(pubb[0], 0x02 | 0x03 | 0x04 | 0x06 | 0x07) {
                    let s = parse_ecdsa_sig(&witness[0], Some(pubb.clone()), "p2wpkh")?;
                    return Ok(vec![s]);
                }
            }
            Ok(Vec::new())
        }
    }
}

fn extract_scriptsig_only(script_sig: &[u8]) -> Result<Vec<BtcInputSig>, String> {
    if script_sig[0] == 0x00
        && let Some(out) = parse_p2sh_multisig(script_sig)
    {
        return Ok(out);
    }
    let (sig_b, n) = match parse_push_bytes(script_sig) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    let (pub_b, m) = match parse_push_bytes(&script_sig[n..]) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    if n + m != script_sig.len() {
        return Ok(Vec::new());
    }
    let s = parse_ecdsa_sig(sig_b, Some(pub_b.to_vec()), "p2pkh")?;
    Ok(vec![s])
}

fn is_control_block(b: &[u8]) -> bool {
    if b.len() < 33 || !(b.len() - 33).is_multiple_of(32) {
        return false;
    }
    (b[0] & 0xfe) == 0xc0
}

fn parse_taproot_sig(sig: &[u8], scheme: &str) -> Option<BtcInputSig> {
    if sig.len() != 64 && sig.len() != 65 {
        return None;
    }
    let (flag, rs) = if sig.len() == 65 {
        (sig[64] as u32, &sig[..64])
    } else {
        (0u32, sig)
    };
    Some(BtcInputSig {
        scheme: scheme.to_string(),
        r: rs[..32].to_vec(),
        s: rs[32..].to_vec(),
        sighash_flag: flag,
        ..Default::default()
    })
}

fn parse_p2tr_script_path(witness: &[Vec<u8>]) -> Result<Vec<BtcInputSig>, String> {
    if witness.len() < 3 {
        return Ok(Vec::new());
    }
    let cb = &witness[witness.len() - 1];
    let leaf = &witness[witness.len() - 2];
    let stack = &witness[..witness.len() - 2];

    if leaf.len() != 34 || leaf[0] != 0x20 || leaf[33] != 0xac {
        return Ok(Vec::new());
    }
    if stack.len() != 1 {
        return Ok(Vec::new());
    }
    let mut parsed = match parse_taproot_sig(&stack[0], "p2tr-scriptpath") {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };
    parsed.pubkey = leaf[1..33].to_vec();
    parsed.leaf_script = leaf.clone();
    parsed.control_block = cb.clone();
    Ok(vec![parsed])
}

fn parse_p2sh_multisig(script_sig: &[u8]) -> Option<Vec<BtcInputSig>> {
    if script_sig.len() < 2 || script_sig[0] != 0x00 {
        return None;
    }
    let mut cur = &script_sig[1..];
    let mut pushes: Vec<Vec<u8>> = Vec::new();
    while !cur.is_empty() {
        let (data, n) = parse_push_bytes(cur)?;
        if n == 0 {
            return None;
        }
        pushes.push(data.to_vec());
        cur = &cur[n..];
    }
    if pushes.len() < 2 {
        return None;
    }
    let redeem = pushes.last().unwrap().clone();
    let sig_pushes = &pushes[..pushes.len() - 1];

    let pubkeys = parse_multisig_pubkeys(&redeem)?;

    let mut out = Vec::new();
    for s in sig_pushes {
        if s.is_empty() {
            continue;
        }
        let mut parsed = parse_ecdsa_sig(s, None, "p2sh-multisig").ok()?;
        parsed.redeem_script = redeem.clone();
        parsed.pubkeys = pubkeys.clone();
        out.push(parsed);
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn parse_multisig_pubkeys(rs: &[u8]) -> Option<Vec<Vec<u8>>> {
    if rs.len() < 4 || rs[rs.len() - 1] != 0xae {
        return None;
    }
    if rs[0] < 0x51 || rs[0] > 0x60 {
        return None;
    }
    let n_op = rs[rs.len() - 2];
    if !(0x51..=0x60).contains(&n_op) {
        return None;
    }
    let n = (n_op as usize) - 0x50;
    let mut cur = &rs[1..rs.len() - 2];
    let mut pubkeys = Vec::new();
    while !cur.is_empty() {
        let (data, off) = parse_push_bytes(cur)?;
        if off == 0 {
            return None;
        }
        pubkeys.push(data.to_vec());
        cur = &cur[off..];
    }
    if pubkeys.len() != n {
        return None;
    }
    Some(pubkeys)
}

fn parse_ecdsa_sig(
    sig_with_flag: &[u8],
    pubkey: Option<Vec<u8>>,
    scheme: &str,
) -> Result<BtcInputSig, String> {
    if sig_with_flag.len() < 9 {
        return Err(format!(
            "signature too short: {} bytes",
            sig_with_flag.len()
        ));
    }
    let flag = sig_with_flag[sig_with_flag.len() - 1] as u32;
    let der = &sig_with_flag[..sig_with_flag.len() - 1];
    if der.len() < 8 || der[0] != 0x30 {
        return Err("not a DER signature".into());
    }
    if der[1] as usize != der.len() - 2 {
        return Err("DER length mismatch".into());
    }
    if der[2] != 0x02 {
        return Err("expected INTEGER for r".into());
    }
    let r_len = der[3] as usize;
    if 4 + r_len + 2 > der.len() {
        return Err("DER r overrun".into());
    }
    let r = &der[4..4 + r_len];
    if der[4 + r_len] != 0x02 {
        return Err("expected INTEGER for s".into());
    }
    let s_len = der[4 + r_len + 1] as usize;
    if 4 + r_len + 2 + s_len != der.len() {
        return Err("DER s overrun".into());
    }
    let s = &der[4 + r_len + 2..4 + r_len + 2 + s_len];

    Ok(BtcInputSig {
        scheme: scheme.to_string(),
        r: normalize_32(r)?,
        s: normalize_32(s)?,
        sighash_flag: flag,
        pubkey: pubkey.unwrap_or_default(),
        ..Default::default()
    })
}

fn normalize_32(b: &[u8]) -> Result<Vec<u8>, String> {
    let mut start = 0;
    while start < b.len() && b[start] == 0x00 {
        start += 1;
    }
    let trimmed = &b[start..];
    if trimmed.len() > 32 {
        return Err(format!("value longer than 32 bytes ({})", trimmed.len()));
    }
    let mut out = vec![0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

impl BtcInputSig {
    /// For multisig signatures, finds the pubkey whose ECDSA signature verifies
    /// against `digest`, setting `pubkey` and returning it. No-op for
    /// non-multisig signatures.
    pub fn resolve_multisig_pubkey(&mut self, digest: &[u8; 32]) -> Option<Vec<u8>> {
        if self.scheme != "p2sh-multisig" {
            return Some(self.pubkey.clone());
        }
        if self.pubkeys.is_empty() {
            return None;
        }
        let r: [u8; 32] = self.r[..].try_into().ok()?;
        let s: [u8; 32] = self.s[..].try_into().ok()?;
        for pk in &self.pubkeys {
            if let Ok(pub_) = SecpPublicKey::from_sec1(pk)
                && pub_.verify(digest, &r, &s)
            {
                self.pubkey = pk.clone();
                return Some(pk.clone());
            }
        }
        None
    }
}

impl BtcTx {
    /// Recomputes the 32-byte digest the parsed signature at input `n`
    /// committed to. Supports p2pkh, p2wpkh and p2sh-multisig with SIGHASH_ALL.
    pub fn input_sighash(
        &self,
        n: usize,
        sig: &BtcInputSig,
        prev_script: &[u8],
        amount: BtcAmount,
    ) -> Result<[u8; 32], String> {
        if n >= self.inputs.len() {
            return Err(format!("input index {n} out of range"));
        }
        if sig.sighash_flag != 1 {
            return Err(format!(
                "unsupported sighash flag 0x{:x} (only SIGHASH_ALL=1 supported)",
                sig.sighash_flag
            ));
        }
        match sig.scheme.as_str() {
            "p2pkh" => Ok(self.legacy_sighash(n, prev_script, sig.sighash_flag)),
            "p2sh-multisig" => {
                if sig.redeem_script.is_empty() {
                    return Err("p2sh-multisig requires RedeemScript".into());
                }
                Ok(self.legacy_sighash(n, &sig.redeem_script, sig.sighash_flag))
            }
            "p2wpkh" => {
                let (pfx, sfx) = self.preimage();
                let pk_hash = hash160(&sig.pubkey);
                let mut script_code = vec![0x76, 0xa9];
                script_code.extend_from_slice(&push_bytes(&pk_hash));
                script_code.extend_from_slice(&[0x88, 0xac]);
                let (input, input_seq) = self.inputs[n].preimage_bytes();
                let mut s = Vec::new();
                s.extend_from_slice(&pfx);
                s.extend_from_slice(&input);
                s.extend_from_slice(&push_bytes(&script_code));
                s.extend_from_slice(&amount.0.to_le_bytes());
                s.extend_from_slice(&input_seq);
                s.extend_from_slice(&sfx);
                s.extend_from_slice(&sig.sighash_flag.to_le_bytes());
                Ok(crate::hash::dsha256(&s))
            }
            other => Err(format!("unsupported scheme: {other}")),
        }
    }

    /// Computes the BIP-341 sighash for a parsed taproot input signature, given
    /// the prev_out scripts and amounts of every input. Supports key-path and
    /// single-sig script-path with SIGHASH_DEFAULT.
    pub fn taproot_input_sighash(
        &self,
        n: usize,
        sig: &BtcInputSig,
        prev_scripts: &[Vec<u8>],
        amounts: &[BtcAmount],
    ) -> Result<[u8; 32], String> {
        if n >= self.inputs.len() {
            return Err(format!("input index {n} out of range"));
        }
        if sig.sighash_flag != 0 {
            return Err(format!(
                "taproot: only SIGHASH_DEFAULT (0) supported, got 0x{:x}",
                sig.sighash_flag
            ));
        }
        let amounts_u: Vec<u64> = amounts.iter().map(|a| a.0).collect();
        let parts = self.taproot_sighash_parts_raw(prev_scripts, &amounts_u)?;
        match sig.scheme.as_str() {
            "p2tr-keypath" => Ok(self.taproot_key_spend_sighash(n, 0x00, &parts)),
            "p2tr-scriptpath" => {
                if sig.leaf_script.is_empty() {
                    return Err("p2tr-scriptpath requires LeafScript".into());
                }
                Ok(self.taproot_script_path_sighash(n, &parts, &sig.leaf_script))
            }
            other => Err(format!("not a taproot scheme: {other}")),
        }
    }
}
