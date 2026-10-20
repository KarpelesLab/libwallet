//! Solana transaction building (port of the wlttx Solana path). Serializes a
//! legacy SystemProgram transfer message, which is signed with the wallet's
//! FROST key (Ed25519) and assembled into a wire transaction for
//! sendTransaction.

/// The System Program id (base58 "1111…1111") is 32 zero bytes.
const SYSTEM_PROGRAM: [u8; 32] = [0u8; 32];

/// Append a compact-u16 (shortvec) length prefix.
fn shortvec(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

/// Read a compact-u16 (shortvec) length; returns `(value, bytes_consumed)`.
/// Groups of 7 bits, little-endian, at most 3 bytes.
pub fn read_compact_u16(bytes: &[u8]) -> Option<(u16, usize)> {
    let mut val: u32 = 0;
    let mut i = 0;
    loop {
        let b = *bytes.get(i)?;
        val |= ((b & 0x7f) as u32) << (i * 7);
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        if i >= 3 {
            return None;
        }
    }
    if val > u16::MAX as u32 {
        None
    } else {
        Some((val as u16, i))
    }
}

/// If `pubkey` appears in a serialized Solana message's account-keys within the
/// required-signers range, return its slot (Go `solanaFindSignerSlot`). A
/// versioned message's leading version byte is skipped.
pub fn find_signer_slot(msg: &[u8], pubkey: &[u8; 32]) -> Option<usize> {
    if msg.is_empty() {
        return None;
    }
    let mut pos = if msg[0] & 0x80 != 0 { 1 } else { 0 };
    if msg.len() < pos + 3 {
        return None;
    }
    let num_required_signatures = msg[pos] as usize;
    pos += 3; // numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned

    let (num_keys, consumed) = read_compact_u16(&msg[pos..])?;
    pos += consumed;
    let num_keys = num_keys as usize;
    if pos + num_keys * 32 > msg.len() {
        return None;
    }
    for i in 0..num_keys {
        let start = pos + i * 32;
        if &msg[start..start + 32] == pubkey.as_slice() {
            return if i < num_required_signatures { Some(i) } else { None };
        }
    }
    None
}

/// Strip the signature array from a full serialized transaction, returning the
/// message bytes (Go `solanaExtractMessage`).
pub fn extract_message(tx: &[u8]) -> Option<&[u8]> {
    let (num_sigs, consumed) = read_compact_u16(tx)?;
    let sig_end = consumed + num_sigs as usize * 64;
    if sig_end > tx.len() {
        None
    } else {
        Some(&tx[sig_end..])
    }
}

/// Whether `payload` parses as a Solana transaction (bare message or full tx)
/// naming `pubkey` as a required signer — the blind-signing guard for
/// `signMessage` (Go `solanaPayloadIsSignableTx`). Signing such a payload as a
/// "message" would forge a fund-moving transaction signature.
pub fn payload_is_signable_tx(payload: &[u8], pubkey: &[u8; 32]) -> bool {
    if find_signer_slot(payload, pubkey).is_some() {
        return true;
    }
    if let Some(msg) = extract_message(payload) {
        if find_signer_slot(msg, pubkey).is_some() {
            return true;
        }
    }
    false
}

/// The signature layout of a serialized transaction: `(first_signature_offset,
/// message_start)`. The message (what each signer signs) is `tx[message_start..]`
/// and signature slot 0 lives at `[first_signature_offset .. +64]`.
pub fn tx_sig_layout(raw_tx: &[u8]) -> Option<(usize, usize)> {
    let (num_sigs, consumed) = read_compact_u16(raw_tx)?;
    if num_sigs < 1 {
        return None;
    }
    let sigs_end = consumed + num_sigs as usize * 64;
    if sigs_end > raw_tx.len() {
        return None;
    }
    Some((consumed, sigs_end))
}

/// The message bytes of a serialized transaction (what the fee-payer signs).
pub fn tx_message(raw_tx: &[u8]) -> Option<&[u8]> {
    tx_sig_layout(raw_tx).map(|(_, start)| &raw_tx[start..])
}

/// Splice a 64-byte signature into slot 0 of a serialized transaction (Go
/// `solanaSplicingSignLocal`'s final copy). Returns the fully-signed bytes.
pub fn splice_signature(raw_tx: &[u8], sig: &[u8; 64]) -> Option<Vec<u8>> {
    let (off, _) = tx_sig_layout(raw_tx)?;
    let mut out = raw_tx.to_vec();
    out[off..off + 64].copy_from_slice(sig);
    Some(out)
}

/// Serialize a legacy transfer message: `from` sends `lamports` to `to` at
/// `recent_blockhash`. Account order is [from(signer,writable), to(writable),
/// SystemProgram(readonly)]; the returned bytes are what the signer signs.
pub fn build_transfer_message(
    from: &[u8; 32],
    to: &[u8; 32],
    lamports: u64,
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::new();
    // Message header.
    m.push(1); // numRequiredSignatures
    m.push(0); // numReadonlySignedAccounts
    m.push(1); // numReadonlyUnsignedAccounts (SystemProgram)

    // Account keys.
    shortvec(3, &mut m);
    m.extend_from_slice(from);
    m.extend_from_slice(to);
    m.extend_from_slice(&SYSTEM_PROGRAM);

    // Recent blockhash.
    m.extend_from_slice(recent_blockhash);

    // Instructions: one SystemProgram::Transfer.
    shortvec(1, &mut m);
    m.push(2); // program id index (SystemProgram)
    shortvec(2, &mut m); // account indices
    m.push(0); // from
    m.push(1); // to
    let mut data = vec![2u8, 0, 0, 0]; // Transfer instruction discriminant (u32 LE)
    data.extend_from_slice(&lamports.to_le_bytes());
    shortvec(data.len(), &mut m);
    m.extend_from_slice(&data);
    m
}

/// Decode a base64url (no-pad) 32-byte Ed25519 pubkey (as stored in
/// Account.Pubkey / Wallet.Pubkey).
pub fn pubkey_from_b64url(b64: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .ok()?
        .try_into()
        .ok()
}

/// Assemble a signed wire transaction: `[shortvec(1)][signature(64)][message]`.
pub fn assemble_tx(message: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut tx = Vec::with_capacity(1 + 64 + message.len());
    shortvec(1, &mut tx);
    tx.extend_from_slice(signature);
    tx.extend_from_slice(message);
    tx
}

// --- Native-send MAX resolution ----------------------------------------------
//
// Port of the MAX-sentinel branch of Go `wlttx/preflight.go`
// (`preflightSolanaNativeSend`) plus `computeSolanaMaxSendable` from
// `wlttx/maxsendable.go`. When a native-SOL send carries the MAX amount
// sentinel (`Amount.max(9)` — see `crate::amount`), the concrete lamports must
// be resolved to `balance − fee − rent reserve` at build time so the signer
// sends a real value instead of the sentinel. Async so the unsigned build
// shared with the browser (`Transaction:simulate`) can use it too.

/// Canonical rent-exempt minimum for a 0-byte system account, used as the
/// fallback when `getMinimumBalanceForRentExemption` is unavailable. Matches
/// Go's 890880 fallback.
pub const SOLANA_DEFAULT_SENDER_RENT: u64 = 890_880;

/// Solana native-transfer base signature fee (lamports). Used when the tx
/// carries no explicit (priority-inclusive) fee. Matches Go's flat 5000.
pub const SOLANA_BASE_FEE_LAMPORTS: u64 = 5_000;

/// RPC-free max-sendable math (port of Go `computeSolanaMaxSendable`). All
/// arguments are lamports; `recipient_exists == false` also reserves
/// `recipient_rent`. Returns `(max, reserved, reason)` where `reason` is
/// `Some` (and `max == 0`) when nothing is sendable.
pub fn compute_solana_max_sendable(
    balance: u64,
    fee: u64,
    sender_rent: u64,
    recipient_rent: u64,
    recipient_exists: bool,
) -> (u64, u64, Option<String>) {
    let reserved = if recipient_exists {
        fee + sender_rent
    } else {
        fee + sender_rent + recipient_rent
    };
    if balance <= reserved {
        let mut reason = format!(
            "balance {balance} lamports is not enough to cover fee {fee} + sender rent {sender_rent}"
        );
        if !recipient_exists {
            reason = format!("{reason} + new-recipient rent {recipient_rent}");
        }
        return (0, reserved, Some(reason));
    }
    (balance - reserved, reserved, None)
}

/// Resolve the MAX sentinel on a native-SOL send to a concrete lamport amount:
/// `balance − fee − sender rent (− new-recipient rent)`, using the same
/// balance/rent inputs as `Transaction:maxSendable`. Port of the MAX branch of
/// Go `preflightSolanaNativeSend`. `to` may be empty (no recipient-rent
/// reservation). Fails loudly rather than let an unresolved sentinel reach the
/// signer when the balance lookup fails or nothing is sendable.
pub async fn resolve_max_lamports(
    rpc: &str,
    from_address: &str,
    to: &str,
    fee_lamports: u64,
) -> crate::Result<u64> {
    // Balance (lamports). Without it MAX can't be resolved — fail loudly.
    let bal_res = crate::rpc::call_async(rpc, "getBalance", serde_json::json!([from_address]))
        .await
        .map_err(|e| crate::Error::Env(format!("cannot resolve MAX amount: balance lookup failed: {e}")))?;
    let balance = bal_res
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| crate::Error::Env("cannot resolve MAX amount: unexpected getBalance response".into()))?;

    // Sender rent-exempt minimum (0-byte system account); canonical fallback.
    let sender_rent = crate::rpc::call_async(rpc, "getMinimumBalanceForRentExemption", serde_json::json!([0]))
        .await
        .ok()
        .and_then(|v| v.as_u64())
        .unwrap_or(SOLANA_DEFAULT_SENDER_RENT);

    // A brand-new recipient must be funded to its own rent-exempt minimum,
    // which comes out of the sendable max.
    let mut recipient_exists = true;
    let mut recipient_rent = 0u64;
    if !to.is_empty() {
        if let Ok(info) =
            crate::rpc::call_async(rpc, "getAccountInfo", serde_json::json!([to, { "encoding": "base64" }])).await
        {
            // getAccountInfo returns "value": null for missing accounts.
            let exists = info.get("value").map(|v| !v.is_null()).unwrap_or(false);
            if !exists {
                recipient_exists = false;
                recipient_rent = sender_rent;
            }
        }
    }

    let (max, _reserved, reason) =
        compute_solana_max_sendable(balance, fee_lamports, sender_rent, recipient_rent, recipient_exists);
    if max == 0 {
        return Err(crate::Error::Env(reason.unwrap_or_else(|| "insufficient balance".into())));
    }
    Ok(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_message_layout() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let bh = [3u8; 32];
        let m = build_transfer_message(&from, &to, 1_000_000, &bh);
        // header(3) + shortvec(1) + 3*32 keys + 32 blockhash + shortvec(1) +
        // instr[ programidx(1)+shortvec(1)+2 accts + shortvec(1)+12 data ].
        assert_eq!(&m[0..3], &[1, 0, 1]);
        assert_eq!(m[3], 3); // 3 account keys
        assert_eq!(&m[4..36], &from);
        assert_eq!(&m[100..132], &bh); // 4 + 96 = 100
        // instruction data starts with the transfer discriminant.
        let data_start = m.len() - 12;
        assert_eq!(&m[data_start..data_start + 4], &[2, 0, 0, 0]);
        assert_eq!(&m[data_start + 4..], &1_000_000u64.to_le_bytes());
    }

    #[test]
    fn assemble_prefixes_signature() {
        let tx = assemble_tx(&[0xAB; 10], &[0xCD; 64]);
        assert_eq!(tx[0], 1); // one signature
        assert_eq!(&tx[1..65], &[0xCD; 64]);
        assert_eq!(&tx[65..], &[0xAB; 10]);
    }
}
