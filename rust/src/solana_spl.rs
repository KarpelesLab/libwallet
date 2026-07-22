//! Solana SPL Token transfer building (port of the wlttx SPL path).
//!
//! Ports Token-1 (`spl-token`) and Token-2022 (`spl-token-2022`) transfers via
//! `TransferChecked` (opcode 12), each prefixed with an idempotent ATA-create so
//! a brand-new recipient is provisioned in the same tx. The Token-2022
//! transfer-fee extension is *detected* here but NOT executed: a mint with an
//! active fee is rejected by the caller (see `token2022_transfer_fee`) rather
//! than broadcasting a plain `TransferChecked` the on-chain program would
//! revert. Compute-unit sizing is a fixed conservative default — the
//! simulation-based tightening in the Go build is out of scope for this pass.

/// SPL Token program (Token-1). TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA.
pub const SPL_TOKEN_PROGRAM_B58: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SPL Token-2022 program. TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb.
pub const TOKEN_2022_PROGRAM_B58: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// Associated Token Account program. ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL.
pub const ATA_PROGRAM_B58: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// ComputeBudget program. ComputeBudget111111111111111111111111111111.
pub const COMPUTE_BUDGET_PROGRAM_B58: &str = "ComputeBudget111111111111111111111111111111";

/// Fixed compute-unit limit for an SPL transfer (Go `solanaSPLDefaultCULimit`).
/// The ATA CreateIdempotent prelude alone burns ~15k CUs; 30k leaves ~2x
/// headroom for a fresh recipient without paying for Solana's 200k default.
pub const SPL_DEFAULT_CU_LIMIT: u32 = 30_000;

/// Decode a canonical base58 program id to its 32-byte form. Panics on a bad
/// constant — these are compile-time ids, so a typo fails loud (matching the Go
/// `init()` panic) rather than silently routing to the wrong program.
pub fn program_id(b58: &str) -> [u8; 32] {
    bs58::decode(b58)
        .into_vec()
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .expect("valid 32-byte SPL program id")
}

/// Resolve a token `Type` to its owning program id: `spl-token` → Token-1,
/// `spl-token-2022` → Token-2022. Errors on any other type (Go
/// `tokenProgramForType`).
pub fn token_program_for_type(token_type: &str) -> Result<[u8; 32], String> {
    match token_type {
        "spl-token" => Ok(program_id(SPL_TOKEN_PROGRAM_B58)),
        "spl-token-2022" => Ok(program_id(TOKEN_2022_PROGRAM_B58)),
        other => Err(format!("unknown SPL token type {other:?}")),
    }
}

/// Append a compact-u16 (shortvec) length prefix (Go `compactU16`).
fn push_compact_u16(v: u16, out: &mut Vec<u8>) {
    if v <= 0x7f {
        out.push(v as u8);
    } else if v <= 0x3fff {
        out.push((v as u8 & 0x7f) | 0x80);
        out.push((v >> 7) as u8);
    } else {
        out.push((v as u8 & 0x7f) | 0x80);
        out.push(((v >> 7) as u8 & 0x7f) | 0x80);
        out.push((v >> 14) as u8);
    }
}

/// Derive the canonical Associated Token Account pubkey for `(owner, mint)` under
/// `token_program` (Go `deriveAssociatedTokenAccount`).
///
/// The ATA is a Program-Derived Address with seeds `[owner, token_program, mint]`
/// under the ATA program id. PDA derivation counts a single-byte bump down from
/// 255 looking for a candidate whose sha256 hash is NOT a valid ed25519 curve
/// point — that off-curve guarantee is what makes the PDA unsignable. Returns
/// `None` only for degenerate seeds where all 256 candidates land on-curve
/// (mathematically possible, astronomically unlikely for a real pair).
pub fn derive_ata(owner: &[u8; 32], mint: &[u8; 32], token_program: &[u8; 32]) -> Option<[u8; 32]> {
    let ata_program = program_id(ATA_PROGRAM_B58);
    for bump in (0u16..=255).rev() {
        let mut h = Vec::with_capacity(32 * 4 + 1 + 21);
        h.extend_from_slice(owner);
        h.extend_from_slice(token_program);
        h.extend_from_slice(mint);
        h.push(bump as u8);
        h.extend_from_slice(&ata_program);
        h.extend_from_slice(b"ProgramDerivedAddress");
        let cand = purecrypto::hash::sha256(&h);
        // Not on curve → valid PDA (the first hit is the canonical bump).
        if purecrypto::ec::edwards25519::hazmat::EdwardsPoint::decompress(&cand).is_none() {
            return Some(cand);
        }
    }
    None
}

/// `SetComputeUnitLimit` instruction body: `[0x02, u32 LE]` (Go `computeBudgetSetLimit`).
fn compute_budget_set_limit(cu: u32) -> Vec<u8> {
    let mut d = vec![0x02u8];
    d.extend_from_slice(&cu.to_le_bytes());
    d
}

/// `SetComputeUnitPrice` instruction body: `[0x03, u64 LE]` microlamports/CU
/// (Go `computeBudgetSetPrice`).
fn compute_budget_set_price(micro_lamports_per_cu: u64) -> Vec<u8> {
    let mut d = vec![0x03u8];
    d.extend_from_slice(&micro_lamports_per_cu.to_le_bytes());
    d
}

/// `TransferChecked` (opcode 12) data: `[12, amount u64 LE, decimals u8]`
/// (Go `splTransferCheckedInstruction`). TransferChecked (not plain Transfer)
/// makes the program verify the supplied decimals against the mint.
fn transfer_checked_instruction(amount: u64, decimals: u8) -> Vec<u8> {
    let mut d = Vec::with_capacity(10);
    d.push(12);
    d.extend_from_slice(&amount.to_le_bytes());
    d.push(decimals);
    d
}

/// Build a legacy Solana message for an SPL Token transfer (Go
/// `buildSPLTransferMessage`). Account layout (signer→writable→readonly) and
/// instruction ordering match the Go builder byte-for-byte:
///
///   0 sender owner (signer+writable) · 1 sender ATA · 2 recipient ATA ·
///   3 recipient owner · 4 mint · 5 token program · 6 system program ·
///   7 ATA program · [8 ComputeBudget, only when a CB instruction is emitted]
///
/// Instructions: optional SetComputeUnitLimit / SetComputeUnitPrice, then
/// ATA CreateIdempotent, then TransferChecked.
#[allow(clippy::too_many_arguments)]
pub fn build_spl_transfer_message(
    sender_owner: &[u8; 32],
    recipient_owner: &[u8; 32],
    mint: &[u8; 32],
    sender_ata: &[u8; 32],
    recipient_ata: &[u8; 32],
    token_program: &[u8; 32],
    amount: u64,
    decimals: u8,
    recent_blockhash: &[u8; 32],
    cu_limit: u32,
    cu_price: u64,
) -> Vec<u8> {
    let system_program = [0u8; 32];
    let ata_program = program_id(ATA_PROGRAM_B58);
    let compute_budget = program_id(COMPUTE_BUDGET_PROGRAM_B58);

    let has_cb_limit = cu_limit > 0;
    let has_cb_price = cu_price > 0;
    let has_cb = has_cb_limit || has_cb_price;

    let mut msg = Vec::new();

    // ── Header ──────────────────────────────────────────────────────────
    msg.push(1); // numRequiredSignatures: sender owner
    msg.push(0); // numReadonlySignedAccounts
                 // Readonly-unsigned tail: recipientOwner, mint, tokenProgram, systemProgram,
                 // ataProgram (5), plus ComputeBudget when used.
    msg.push(if has_cb { 6 } else { 5 });

    // ── Account keys ────────────────────────────────────────────────────
    push_compact_u16(if has_cb { 9 } else { 8 }, &mut msg);
    msg.extend_from_slice(sender_owner); // 0
    msg.extend_from_slice(sender_ata); // 1
    msg.extend_from_slice(recipient_ata); // 2
    msg.extend_from_slice(recipient_owner); // 3
    msg.extend_from_slice(mint); // 4
    msg.extend_from_slice(token_program); // 5
    msg.extend_from_slice(&system_program); // 6
    msg.extend_from_slice(&ata_program); // 7
    if has_cb {
        msg.extend_from_slice(&compute_budget); // 8
    }

    // ── Recent blockhash ────────────────────────────────────────────────
    msg.extend_from_slice(recent_blockhash);

    // ── Instructions ────────────────────────────────────────────────────
    let mut num_instr: u16 = 2; // ATA create + TransferChecked
    if has_cb_limit {
        num_instr += 1;
    }
    if has_cb_price {
        num_instr += 1;
    }
    push_compact_u16(num_instr, &mut msg);

    const IDX_SENDER_OWNER: u8 = 0;
    const IDX_SENDER_ATA: u8 = 1;
    const IDX_RECIPIENT_ATA: u8 = 2;
    const IDX_RECIPIENT_OWNER: u8 = 3;
    const IDX_MINT: u8 = 4;
    const IDX_TOKEN_PROGRAM: u8 = 5;
    const IDX_SYSTEM_PROGRAM: u8 = 6;
    const IDX_ATA_PROGRAM: u8 = 7;
    const IDX_CB: u8 = 8;

    if has_cb_limit {
        msg.push(IDX_CB);
        push_compact_u16(0, &mut msg); // no accounts
        let data = compute_budget_set_limit(cu_limit);
        push_compact_u16(data.len() as u16, &mut msg);
        msg.extend_from_slice(&data);
    }
    if has_cb_price {
        msg.push(IDX_CB);
        push_compact_u16(0, &mut msg);
        let data = compute_budget_set_price(cu_price);
        push_compact_u16(data.len() as u16, &mut msg);
        msg.extend_from_slice(&data);
    }

    // ATA CreateIdempotent: payer, associated_token(new), owner, mint,
    // system_program, token_program.
    msg.push(IDX_ATA_PROGRAM);
    push_compact_u16(6, &mut msg);
    msg.push(IDX_SENDER_OWNER); // payer
    msg.push(IDX_RECIPIENT_ATA); // associated_token (new)
    msg.push(IDX_RECIPIENT_OWNER); // owner
    msg.push(IDX_MINT); // mint
    msg.push(IDX_SYSTEM_PROGRAM);
    msg.push(IDX_TOKEN_PROGRAM);
    let create_data = [1u8]; // CreateIdempotent opcode
    push_compact_u16(create_data.len() as u16, &mut msg);
    msg.extend_from_slice(&create_data);

    // TransferChecked: source, mint, destination, authority(=sender owner).
    msg.push(IDX_TOKEN_PROGRAM);
    push_compact_u16(4, &mut msg);
    msg.push(IDX_SENDER_ATA);
    msg.push(IDX_MINT);
    msg.push(IDX_RECIPIENT_ATA);
    msg.push(IDX_SENDER_OWNER); // authority
    let tc_data = transfer_checked_instruction(amount, decimals);
    push_compact_u16(tc_data.len() as u16, &mut msg);
    msg.extend_from_slice(&tc_data);

    msg
}

/// One epoch's TransferFee (Go `token2022TransferFee`): basis points + max fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFee {
    pub epoch: u64,
    pub maximum_fee: u64,
    pub basis_points: u16,
}

/// The Token-2022 TransferFeeConfig extension (older + newer epoch fees).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFeeConfig {
    pub older: TransferFee,
    pub newer: TransferFee,
}

impl TransferFeeConfig {
    /// Whether either epoch levies a non-zero fee. A config that exists but is
    /// zeroed (bps==0 && max==0 in both epochs) imposes no fee, so a plain
    /// `TransferChecked` is still valid and need not be rejected.
    pub fn is_active(&self) -> bool {
        self.older.basis_points > 0
            || self.older.maximum_fee > 0
            || self.newer.basis_points > 0
            || self.newer.maximum_fee > 0
    }
}

// Token-2022 mint account layout constants (Go solana_token2022.go).
const TOKEN2022_ACCOUNT_TYPE_INDEX: usize = 165;
const TOKEN2022_ACCOUNT_TYPE_MINT: u8 = 1;
const TOKEN2022_EXT_TRANSFER_FEE_CONFIG: u16 = 1;

/// Walk a Token-2022 mint account's extension TLV and return its
/// TransferFeeConfig if present (Go `parseToken2022TransferFeeConfig`).
///
/// Returns `Ok(None)` for a Token-1-style mint (82 bytes) or a mint without the
/// extension. Returns `Err` when the account data is malformed (wrong account
/// type at the discriminator, or a declared extension length running off the
/// end) — the same data would fail on-chain, so surface it loud rather than
/// silently building a transfer.
pub fn token2022_transfer_fee(data: &[u8]) -> Result<Option<TransferFeeConfig>, String> {
    if data.len() <= TOKEN2022_ACCOUNT_TYPE_INDEX {
        // Token-1-style mint or truncated buffer — no extensions.
        return Ok(None);
    }
    if data[TOKEN2022_ACCOUNT_TYPE_INDEX] != TOKEN2022_ACCOUNT_TYPE_MINT {
        return Err(format!(
            "token-2022 mint: account type at offset {TOKEN2022_ACCOUNT_TYPE_INDEX} is {}, expected {TOKEN2022_ACCOUNT_TYPE_MINT} (Mint)",
            data[TOKEN2022_ACCOUNT_TYPE_INDEX]
        ));
    }

    let mut off = TOKEN2022_ACCOUNT_TYPE_INDEX + 1;
    while off + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[off], data[off + 1]]);
        let ext_len = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
        let body_off = off + 4;
        let body_end = body_off + ext_len;
        if body_end > data.len() {
            return Err(format!(
                "token-2022 mint: extension type {ext_type} length {ext_len} runs off end of data (off={off}, len={})",
                data.len()
            ));
        }
        if ext_type == TOKEN2022_EXT_TRANSFER_FEE_CONFIG {
            let body = &data[body_off..body_end];
            if body.len() < 108 {
                return Err(format!(
                    "token-2022 TransferFeeConfig: body length {} < 108",
                    body.len()
                ));
            }
            // Skip 32 + 32 + 8 = 72 bytes (authorities + withheld_amount).
            // Older TransferFee at offset 72, newer at 72 + 18 = 90.
            let le64 = |s: &[u8]| u64::from_le_bytes(s.try_into().unwrap());
            let le16 = |s: &[u8]| u16::from_le_bytes(s.try_into().unwrap());
            let older = TransferFee {
                epoch: le64(&body[72..80]),
                maximum_fee: le64(&body[80..88]),
                basis_points: le16(&body[88..90]),
            };
            let newer = TransferFee {
                epoch: le64(&body[90..98]),
                maximum_fee: le64(&body[98..106]),
                basis_points: le16(&body[106..108]),
            };
            return Ok(Some(TransferFeeConfig { older, newer }));
        }
        off = body_end;
    }
    Ok(None)
}

/// Total fee in lamports: the 5000 base signature fee plus
/// `ceil(cu_limit * cu_price / 1_000_000)` priority lamports (Go
/// `solanaFeeLamports`). Zero limit or price collapses to the flat base fee.
pub fn fee_lamports(cu_limit: u32, cu_price: u64) -> u64 {
    const BASE_FEE: u64 = 5000;
    if cu_limit == 0 || cu_price == 0 {
        return BASE_FEE;
    }
    // ceil(cu_limit*cu_price/1e6) via u128 so the product can't wrap; saturate
    // just below u64::MAX so an absurd caller-pinned product reads as
    // "insufficient balance" downstream rather than waving a ruinous fee through.
    let num = cu_limit as u128 * cu_price as u128 + 999_999;
    let priority = (num / 1_000_000).min((u64::MAX - BASE_FEE) as u128) as u64;
    BASE_FEE + priority
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_ids_decode_to_32_bytes() {
        for b58 in [
            SPL_TOKEN_PROGRAM_B58,
            TOKEN_2022_PROGRAM_B58,
            ATA_PROGRAM_B58,
            COMPUTE_BUDGET_PROGRAM_B58,
        ] {
            assert_eq!(program_id(b58).len(), 32);
        }
    }

    #[test]
    fn token_program_resolves_by_type() {
        assert_eq!(
            token_program_for_type("spl-token").unwrap(),
            program_id(SPL_TOKEN_PROGRAM_B58)
        );
        assert_eq!(
            token_program_for_type("spl-token-2022").unwrap(),
            program_id(TOKEN_2022_PROGRAM_B58)
        );
        assert!(token_program_for_type("erc20").is_err());
    }

    #[test]
    fn ata_is_off_curve_and_deterministic() {
        let owner = [7u8; 32];
        let mint = [9u8; 32];
        let tp = program_id(SPL_TOKEN_PROGRAM_B58);
        let a = derive_ata(&owner, &mint, &tp).expect("ata derives");
        let b = derive_ata(&owner, &mint, &tp).expect("ata derives");
        assert_eq!(a, b, "derivation is deterministic");
        // The whole point of a PDA: not a valid ed25519 point.
        assert!(
            purecrypto::ec::edwards25519::hazmat::EdwardsPoint::decompress(&a).is_none(),
            "ATA must be off-curve"
        );
        // Token-2022 program yields a different ATA than Token-1.
        let tp22 = program_id(TOKEN_2022_PROGRAM_B58);
        assert_ne!(a, derive_ata(&owner, &mint, &tp22).unwrap());
    }

    #[test]
    fn transfer_checked_encodes_opcode_amount_decimals() {
        let d = transfer_checked_instruction(1_315_764, 6);
        assert_eq!(d[0], 12);
        assert_eq!(&d[1..9], &1_315_764u64.to_le_bytes());
        assert_eq!(d[9], 6);
    }

    #[test]
    fn spl_message_layout_no_compute_budget() {
        let owner = [1u8; 32];
        let to = [2u8; 32];
        let mint = [3u8; 32];
        let s_ata = [4u8; 32];
        let r_ata = [5u8; 32];
        let bh = [6u8; 32];
        let tp = program_id(SPL_TOKEN_PROGRAM_B58);
        let m =
            build_spl_transfer_message(&owner, &to, &mint, &s_ata, &r_ata, &tp, 1000, 6, &bh, 0, 0);
        // Header: 1 signer, 0 ro-signed, 5 ro-unsigned (no CB).
        assert_eq!(&m[0..3], &[1, 0, 5]);
        assert_eq!(m[3], 8, "8 account keys without ComputeBudget");
        assert_eq!(&m[4..36], &owner);
        assert_eq!(&m[4 + 32..4 + 64], &s_ata);
    }

    #[test]
    fn spl_message_adds_compute_budget_key_and_ix() {
        let z = [0u8; 32];
        let tp = program_id(SPL_TOKEN_PROGRAM_B58);
        let with = build_spl_transfer_message(&z, &z, &z, &z, &z, &tp, 1, 0, &z, 30_000, 0);
        assert_eq!(with[2], 6, "ro-unsigned bumped to 6 with ComputeBudget");
        assert_eq!(with[3], 9, "9 account keys with ComputeBudget");
        let without = build_spl_transfer_message(&z, &z, &z, &z, &z, &tp, 1, 0, &z, 0, 0);
        assert!(with.len() > without.len(), "CB instruction adds bytes");
    }

    #[test]
    fn token2022_fee_parse_none_for_short_and_token1() {
        assert_eq!(token2022_transfer_fee(&[]).unwrap(), None);
        assert_eq!(token2022_transfer_fee(&[0u8; 82]).unwrap(), None);
    }

    #[test]
    fn token2022_fee_parse_detects_extension() {
        // Build a minimal Token-2022 mint buffer with one TransferFeeConfig ext.
        let mut data = vec![0u8; TOKEN2022_ACCOUNT_TYPE_INDEX + 1];
        data[TOKEN2022_ACCOUNT_TYPE_INDEX] = TOKEN2022_ACCOUNT_TYPE_MINT;
        // TLV header: type=1, len=108.
        data.extend_from_slice(&TOKEN2022_EXT_TRANSFER_FEE_CONFIG.to_le_bytes());
        data.extend_from_slice(&108u16.to_le_bytes());
        let mut body = vec![0u8; 108];
        // newer epoch: bps=50 at offset 72+18+16 = 106..108.
        body[106..108].copy_from_slice(&50u16.to_le_bytes());
        data.extend_from_slice(&body);
        let cfg = token2022_transfer_fee(&data)
            .unwrap()
            .expect("extension present");
        assert_eq!(cfg.newer.basis_points, 50);
        assert!(cfg.is_active());
    }

    #[test]
    fn fee_lamports_base_and_priority() {
        assert_eq!(fee_lamports(0, 0), 5000);
        assert_eq!(fee_lamports(30_000, 0), 5000);
        // ceil(1_000_000 * 1 / 1e6) = 1 priority lamport.
        assert_eq!(fee_lamports(1_000_000, 1), 5001);
        // ceil(30_000 * 1000 / 1e6) = ceil(30) = 30.
        assert_eq!(fee_lamports(30_000, 1000), 5030);
    }
}
