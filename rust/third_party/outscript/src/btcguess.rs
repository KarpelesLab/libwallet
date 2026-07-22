//! Heuristics to recover a public-key hash (and possibly the pubkey) from a
//! Bitcoin output or input script (port of `btcguess.go`).

use crate::hash::hash160;
use crate::pushbytes::parse_push_bytes;

/// Result of a guess: an optional full public key and an optional pubkey hash.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuessResult {
    /// The full public key, if it could be recovered directly from the script.
    pub pubkey: Option<Vec<u8>>,
    /// The public-key (or script) hash, if recognized.
    pub pubkey_hash: Option<Vec<u8>>,
}

/// Attempts to guess the pubkey hash (and possibly the pubkey) from an output
/// script.
pub fn guess_by_out_script(script: &[u8]) -> GuessResult {
    // 1) P2PKH: 76 a9 14 <20> 88 ac
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return GuessResult {
            pubkey: None,
            pubkey_hash: Some(script[3..23].to_vec()),
        };
    }

    // 2) P2SH: a9 14 <20> 87
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return GuessResult {
            pubkey: None,
            pubkey_hash: Some(script[2..22].to_vec()),
        };
    }

    // 3) P2PK: 21 <33> ac  OR  41 <65> ac
    if script.len() == 35 && script[0] == 0x21 && script[34] == 0xac {
        let pubkey = script[1..34].to_vec();
        let h = hash160(&pubkey).to_vec();
        return GuessResult {
            pubkey: Some(pubkey),
            pubkey_hash: Some(h),
        };
    }
    if script.len() == 67 && script[0] == 0x41 && script[66] == 0xac {
        let pubkey = script[1..66].to_vec();
        let h = hash160(&pubkey).to_vec();
        return GuessResult {
            pubkey: Some(pubkey),
            pubkey_hash: Some(h),
        };
    }

    // 4) SegWit P2WPKH (22) / P2WSH (34)
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        return GuessResult {
            pubkey: None,
            pubkey_hash: Some(script[2..22].to_vec()),
        };
    }
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        return GuessResult {
            pubkey: None,
            pubkey_hash: Some(script[2..34].to_vec()),
        };
    }

    // 5) P2TR: 51 20 <32>
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return GuessResult {
            pubkey: None,
            pubkey_hash: Some(script[2..34].to_vec()),
        };
    }

    GuessResult::default()
}

/// Attempts to guess the pubkey hash (and pubkey) from an input script.
pub fn guess_by_in_script(script: &[u8]) -> GuessResult {
    let push1 = parse_push_bytes(script);
    if let Some((_, pos1)) = push1
        && let Some((push2, _)) = parse_push_bytes(&script[pos1..])
    {
        let pubkey = push2.to_vec();
        let h = hash160(&pubkey).to_vec();
        return GuessResult {
            pubkey: Some(pubkey),
            pubkey_hash: Some(h),
        };
    }
    GuessResult::default()
}
