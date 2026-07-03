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
