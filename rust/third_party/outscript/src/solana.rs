//! Solana keys, instructions, transactions (legacy + v0), program-derived
//! addresses. Port of `solanatx.go`, `solana_instructions.go`, `solana_pda.go`.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::base58;
use crate::crypto::ed25519;
use purecrypto::hash::{Digest, Sha256};

/// A 32-byte Solana public key / account address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SolanaKey(pub [u8; 32]);

impl SolanaKey {
    /// Parses a base58-encoded key (must decode to 32 bytes).
    pub fn parse(s: &str) -> Result<SolanaKey, String> {
        let buf = base58::decode(s).map_err(|e| format!("failed to decode solana key: {e}"))?;
        if buf.len() != 32 {
            return Err(format!(
                "invalid solana key: expected 32 bytes, got {}",
                buf.len()
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&buf);
        Ok(SolanaKey(k))
    }
    /// Base58 string encoding.
    pub fn to_base58(&self) -> String {
        base58::encode(&self.0)
    }
    /// Whether the key is all zeros.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl core::fmt::Display for SolanaKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

/// Defines a well-known program/sysvar address, decoded once and cached.
macro_rules! well_known_key {
    ($func:ident, $addr:literal, $doc:literal) => {
        #[doc = $doc]
        pub fn $func() -> SolanaKey {
            static KEY: LazyLock<SolanaKey> =
                LazyLock::new(|| SolanaKey::parse($addr).expect("valid well-known key"));
            *KEY
        }
    };
}

well_known_key!(
    system_program,
    "11111111111111111111111111111111",
    "The Solana System Program address."
);
well_known_key!(
    compute_budget_program,
    "ComputeBudget111111111111111111111111111111",
    "The Compute Budget Program address."
);
well_known_key!(
    token_program,
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "The SPL Token Program address."
);
well_known_key!(
    ata_program,
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "The Associated Token Account Program address."
);
well_known_key!(
    recent_blockhashes_sysvar,
    "SysvarRecentB1ockHashes11111111111111111111",
    "The Recent Blockhashes Sysvar address."
);

/// An account referenced by an instruction.
#[derive(Debug, Clone)]
pub struct SolanaAccountMeta {
    /// The account public key.
    pub pubkey: SolanaKey,
    /// Whether the account must sign.
    pub is_signer: bool,
    /// Whether the account is writable.
    pub is_writable: bool,
}

/// A high-level instruction (before account compilation).
#[derive(Debug, Clone)]
pub struct SolanaInstruction {
    /// The program that processes the instruction.
    pub program_id: SolanaKey,
    /// Accounts referenced.
    pub accounts: Vec<SolanaAccountMeta>,
    /// Instruction data.
    pub data: Vec<u8>,
}

/// Builds a System Program transfer instruction.
pub fn transfer_instruction(from: SolanaKey, to: SolanaKey, lamports: u64) -> SolanaInstruction {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    SolanaInstruction {
        program_id: system_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: from,
                is_signer: true,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: to,
                is_signer: false,
                is_writable: true,
            },
        ],
        data,
    }
}

/// Builds a Compute Budget SetComputeUnitLimit instruction.
pub fn set_compute_unit_limit(units: u32) -> SolanaInstruction {
    let mut data = vec![0u8; 5];
    data[0] = 2;
    data[1..5].copy_from_slice(&units.to_le_bytes());
    SolanaInstruction {
        program_id: compute_budget_program(),
        accounts: vec![],
        data,
    }
}

/// Builds a Compute Budget SetComputeUnitPrice instruction.
pub fn set_compute_unit_price(micro_lamports: u64) -> SolanaInstruction {
    let mut data = vec![0u8; 9];
    data[0] = 3;
    data[1..9].copy_from_slice(&micro_lamports.to_le_bytes());
    SolanaInstruction {
        program_id: compute_budget_program(),
        accounts: vec![],
        data,
    }
}

/// Builds an SPL Token transfer instruction.
pub fn spl_transfer_instruction(
    source: SolanaKey,
    destination: SolanaKey,
    owner: SolanaKey,
    amount: u64,
) -> SolanaInstruction {
    let mut data = vec![0u8; 9];
    data[0] = 3;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    SolanaInstruction {
        program_id: token_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: source,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: destination,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: owner,
                is_signer: true,
                is_writable: false,
            },
        ],
        data,
    }
}

/// Derives the Associated Token Account address for a wallet and mint.
pub fn associated_token_address(wallet: SolanaKey, mint: SolanaKey) -> Result<SolanaKey, String> {
    let (addr, _) = find_program_address(
        &[&wallet.0[..], &token_program().0[..], &mint.0[..]],
        ata_program(),
    )?;
    Ok(addr)
}

/// Builds an instruction to create an Associated Token Account.
pub fn create_ata_instruction(
    payer: SolanaKey,
    wallet: SolanaKey,
    mint: SolanaKey,
) -> Result<SolanaInstruction, String> {
    let ata = associated_token_address(wallet, mint)?;
    Ok(SolanaInstruction {
        program_id: ata_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: payer,
                is_signer: true,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: ata,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: wallet,
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: mint,
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: system_program(),
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: token_program(),
                is_signer: false,
                is_writable: false,
            },
        ],
        data: vec![],
    })
}

/// Builds a System Program AdvanceNonceAccount instruction (must be first).
pub fn advance_nonce_instruction(
    nonce_account: SolanaKey,
    nonce_authority: SolanaKey,
) -> SolanaInstruction {
    let mut data = vec![0u8; 4];
    data[0..4].copy_from_slice(&4u32.to_le_bytes());
    SolanaInstruction {
        program_id: system_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: nonce_account,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: recent_blockhashes_sysvar(),
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: nonce_authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data,
    }
}

/// Message header counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SolanaMessageHeader {
    /// Number of required signatures.
    pub num_required_signatures: u8,
    /// Number of read-only signed accounts.
    pub num_readonly_signed: u8,
    /// Number of read-only unsigned accounts.
    pub num_readonly_unsigned: u8,
}

/// An instruction with account references replaced by indices.
#[derive(Debug, Clone, Default)]
pub struct SolanaCompiledInstruction {
    /// Index of the program id in the account key array.
    pub program_id_index: u8,
    /// Indices of the referenced accounts.
    pub account_indices: Vec<u8>,
    /// Instruction data.
    pub data: Vec<u8>,
}

/// A legacy message.
#[derive(Debug, Clone, Default)]
pub struct SolanaMessage {
    /// Header.
    pub header: SolanaMessageHeader,
    /// Static account keys.
    pub account_keys: Vec<SolanaKey>,
    /// Recent blockhash.
    pub recent_blockhash: SolanaKey,
    /// Compiled instructions.
    pub instructions: Vec<SolanaCompiledInstruction>,
}

/// An address lookup table reference (v0).
#[derive(Debug, Clone, Default)]
pub struct SolanaAddressTableLookup {
    /// The lookup table account.
    pub account_key: SolanaKey,
    /// Writable index positions.
    pub writable_indexes: Vec<u8>,
    /// Read-only index positions.
    pub readonly_indexes: Vec<u8>,
}

/// A versioned (v0) message.
#[derive(Debug, Clone, Default)]
pub struct SolanaMessageV0 {
    /// Header.
    pub header: SolanaMessageHeader,
    /// Static account keys.
    pub account_keys: Vec<SolanaKey>,
    /// Recent blockhash.
    pub recent_blockhash: SolanaKey,
    /// Compiled instructions.
    pub instructions: Vec<SolanaCompiledInstruction>,
    /// Address table lookups.
    pub address_table_lookups: Vec<SolanaAddressTableLookup>,
}

/// A Solana transaction (legacy or versioned).
#[derive(Debug, Clone, Default)]
pub struct SolanaTx {
    /// Signatures (64 bytes each; empty = unsigned slot).
    pub signatures: Vec<Vec<u8>>,
    /// Legacy message.
    pub message: SolanaMessage,
    /// v0 message (when present, the transaction is versioned).
    pub message_v0: Option<SolanaMessageV0>,
}

struct AccountInfo {
    key: SolanaKey,
    is_signer: bool,
    is_writable: bool,
}

/// Result of account compilation: ordered keys, key->index map, message header.
type CompiledAccounts = (Vec<SolanaKey>, HashMap<SolanaKey, u8>, SolanaMessageHeader);

fn compile_accounts(
    fee_payer: SolanaKey,
    instructions: &[SolanaInstruction],
) -> Result<CompiledAccounts, String> {
    let mut seen: HashMap<SolanaKey, AccountInfo> = HashMap::new();
    seen.insert(
        fee_payer,
        AccountInfo {
            key: fee_payer,
            is_signer: true,
            is_writable: true,
        },
    );
    for ix in instructions {
        for acc in &ix.accounts {
            if let Some(info) = seen.get_mut(&acc.pubkey) {
                info.is_signer |= acc.is_signer;
                info.is_writable |= acc.is_writable;
            } else {
                seen.insert(
                    acc.pubkey,
                    AccountInfo {
                        key: acc.pubkey,
                        is_signer: acc.is_signer,
                        is_writable: acc.is_writable,
                    },
                );
            }
        }
        seen.entry(ix.program_id).or_insert(AccountInfo {
            key: ix.program_id,
            is_signer: false,
            is_writable: false,
        });
    }

    let (mut sw, mut sr, mut nw, mut nr) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for info in seen.values() {
        if info.key == fee_payer {
            continue;
        }
        match (info.is_signer, info.is_writable) {
            (true, true) => sw.push(info.key),
            (true, false) => sr.push(info.key),
            (false, true) => nw.push(info.key),
            (false, false) => nr.push(info.key),
        }
    }
    let by_key = |v: &mut Vec<SolanaKey>| v.sort_by_key(|a| a.0);
    by_key(&mut sw);
    by_key(&mut sr);
    by_key(&mut nw);
    by_key(&mut nr);

    let mut all = Vec::with_capacity(seen.len());
    all.push(fee_payer);
    all.extend_from_slice(&sw);
    all.extend_from_slice(&sr);
    all.extend_from_slice(&nw);
    all.extend_from_slice(&nr);
    if all.len() > 256 {
        return Err(format!(
            "transaction has {} accounts, maximum is 256",
            all.len()
        ));
    }

    let mut index = HashMap::with_capacity(all.len());
    for (i, k) in all.iter().enumerate() {
        index.insert(*k, i as u8);
    }
    let header = SolanaMessageHeader {
        num_required_signatures: (1 + sw.len() + sr.len()) as u8,
        num_readonly_signed: sr.len() as u8,
        num_readonly_unsigned: nr.len() as u8,
    };
    Ok((all, index, header))
}

fn compile_instructions(
    instructions: &[SolanaInstruction],
    index: &HashMap<SolanaKey, u8>,
) -> Vec<SolanaCompiledInstruction> {
    instructions
        .iter()
        .map(|ix| SolanaCompiledInstruction {
            program_id_index: index[&ix.program_id],
            account_indices: ix.accounts.iter().map(|a| index[&a.pubkey]).collect(),
            data: ix.data.clone(),
        })
        .collect()
}

/// Compiles instructions into a legacy transaction (fee payer first).
pub fn new_solana_tx(
    fee_payer: SolanaKey,
    recent_blockhash: SolanaKey,
    instructions: &[SolanaInstruction],
) -> Result<SolanaTx, String> {
    let (account_keys, index, header) = compile_accounts(fee_payer, instructions)?;
    let compiled = compile_instructions(instructions, &index);
    let num_signers = header.num_required_signatures as usize;
    Ok(SolanaTx {
        signatures: vec![Vec::new(); num_signers],
        message: SolanaMessage {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled,
        },
        message_v0: None,
    })
}

/// Compiles instructions into a v0 versioned transaction.
pub fn new_solana_tx_v0(
    fee_payer: SolanaKey,
    recent_blockhash: SolanaKey,
    lookups: Vec<SolanaAddressTableLookup>,
    instructions: &[SolanaInstruction],
) -> Result<SolanaTx, String> {
    let (account_keys, index, header) = compile_accounts(fee_payer, instructions)?;
    let compiled = compile_instructions(instructions, &index);
    let num_signers = header.num_required_signatures as usize;
    Ok(SolanaTx {
        signatures: vec![Vec::new(); num_signers],
        message: SolanaMessage::default(),
        message_v0: Some(SolanaMessageV0 {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled,
            address_table_lookups: lookups,
        }),
    })
}

impl SolanaTx {
    fn message_bytes(&self) -> Vec<u8> {
        match &self.message_v0 {
            Some(m) => m.to_bytes(),
            None => self.message.to_bytes(),
        }
    }
    fn header(&self) -> SolanaMessageHeader {
        match &self.message_v0 {
            Some(m) => m.header,
            None => self.message.header,
        }
    }
    fn account_keys(&self) -> &[SolanaKey] {
        match &self.message_v0 {
            Some(m) => &m.account_keys,
            None => &self.message.account_keys,
        }
    }

    /// Signs the transaction message with the given Ed25519 seeds, matching each
    /// to its signature slot by public key.
    pub fn sign(&mut self, seeds: &[[u8; 32]]) -> Result<(), String> {
        let msg = self.message_bytes();
        let num_signers = self.header().num_required_signatures as usize;
        let account_keys: Vec<SolanaKey> = self.account_keys().to_vec();
        if num_signers > account_keys.len() {
            return Err(format!(
                "invalid header: {num_signers} required signers but only {} account keys",
                account_keys.len()
            ));
        }
        for seed in seeds {
            let pubkey = SolanaKey(ed25519::public_from_seed(seed));
            let idx = account_keys[..num_signers]
                .iter()
                .position(|k| *k == pubkey);
            let idx = idx.ok_or_else(|| format!("key {pubkey} is not a required signer"))?;
            self.signatures[idx] = ed25519::sign(seed, &msg).to_vec();
        }
        Ok(())
    }

    /// Verifies all required signatures.
    pub fn verify(&self) -> Result<(), String> {
        let msg = self.message_bytes();
        let num_signers = self.header().num_required_signatures as usize;
        if num_signers > self.account_keys().len() {
            return Err(format!(
                "invalid header: {num_signers} required signers but only {} account keys",
                self.account_keys().len()
            ));
        }
        if self.signatures.len() < num_signers {
            return Err(format!(
                "expected {} signatures, got {}",
                num_signers,
                self.signatures.len()
            ));
        }
        for i in 0..num_signers {
            let sig = &self.signatures[i];
            if sig.len() != 64 {
                return Err(format!(
                    "signature {i} is missing or has invalid length {}",
                    sig.len()
                ));
            }
            let pubkey = self.account_keys()[i];
            let mut s = [0u8; 64];
            s.copy_from_slice(sig);
            if !ed25519::verify(&pubkey.0, &msg, &s) {
                return Err(format!(
                    "signature {i} (signer {pubkey}) verification failed"
                ));
            }
        }
        Ok(())
    }

    /// Returns the transaction id (the first signature).
    pub fn hash(&self) -> Result<Vec<u8>, String> {
        if self.signatures.is_empty() || self.signatures[0].is_empty() {
            return Err("transaction has no signature".into());
        }
        Ok(self.signatures[0].clone())
    }

    /// Serializes the transaction.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let msg = self.message_bytes();
        let mut buf = encode_compact_u16(self.signatures.len());
        for sig in &self.signatures {
            if sig.is_empty() {
                buf.extend(std::iter::repeat_n(0u8, 64));
            } else if sig.len() != 64 {
                return Err(format!("invalid signature length: {}", sig.len()));
            } else {
                buf.extend_from_slice(sig);
            }
        }
        buf.extend_from_slice(&msg);
        Ok(buf)
    }

    /// Parses a transaction from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<SolanaTx, String> {
        let mut pos = 0;
        let sig_count = decode_compact_u16(data, &mut pos)?;
        if sig_count > 256 {
            return Err(format!(
                "signature count {sig_count} exceeds maximum of 256"
            ));
        }
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            if data.len() < pos + 64 {
                return Err("unexpected EOF".into());
            }
            signatures.push(data[pos..pos + 64].to_vec());
            pos += 64;
        }
        let rest = &data[pos..];
        let mut tx = SolanaTx {
            signatures,
            ..Default::default()
        };
        if !rest.is_empty() && rest[0] & 0x80 != 0 {
            let version = rest[0] & 0x7f;
            if version != 0 {
                return Err(format!("unsupported transaction version: {version}"));
            }
            tx.message_v0 = Some(SolanaMessageV0::from_bytes(rest)?);
        } else {
            tx.message = SolanaMessage::from_bytes(rest)?;
        }
        Ok(tx)
    }
}

fn write_message_common(
    buf: &mut Vec<u8>,
    header: &SolanaMessageHeader,
    account_keys: &[SolanaKey],
    recent_blockhash: &SolanaKey,
    instructions: &[SolanaCompiledInstruction],
) {
    buf.push(header.num_required_signatures);
    buf.push(header.num_readonly_signed);
    buf.push(header.num_readonly_unsigned);
    buf.extend_from_slice(&encode_compact_u16(account_keys.len()));
    for k in account_keys {
        buf.extend_from_slice(&k.0);
    }
    buf.extend_from_slice(&recent_blockhash.0);
    buf.extend_from_slice(&encode_compact_u16(instructions.len()));
    for ix in instructions {
        buf.push(ix.program_id_index);
        buf.extend_from_slice(&encode_compact_u16(ix.account_indices.len()));
        buf.extend_from_slice(&ix.account_indices);
        buf.extend_from_slice(&encode_compact_u16(ix.data.len()));
        buf.extend_from_slice(&ix.data);
    }
}

/// Checks that the message header account counts are internally consistent with
/// the number of account keys. Prevents out-of-bounds indexing in sign/verify
/// when handling a crafted message.
fn validate_solana_header(h: &SolanaMessageHeader, num_keys: usize) -> Result<(), String> {
    if h.num_required_signatures as usize > num_keys {
        return Err(format!(
            "num_required_signatures {} exceeds account key count {num_keys}",
            h.num_required_signatures
        ));
    }
    if h.num_readonly_signed > h.num_required_signatures {
        return Err(format!(
            "num_readonly_signed {} exceeds num_required_signatures {}",
            h.num_readonly_signed, h.num_required_signatures
        ));
    }
    if h.num_required_signatures as usize + h.num_readonly_unsigned as usize > num_keys {
        return Err(format!(
            "num_required_signatures + num_readonly_unsigned ({}) exceeds account key count {num_keys}",
            h.num_required_signatures as usize + h.num_readonly_unsigned as usize
        ));
    }
    Ok(())
}

/// Validates that every instruction's program id index and account indices
/// reference an addressable account (`< addressable`).
fn validate_instruction_indexes(
    instructions: &[SolanaCompiledInstruction],
    addressable: usize,
) -> Result<(), String> {
    for (i, ix) in instructions.iter().enumerate() {
        if ix.program_id_index as usize >= addressable {
            return Err(format!(
                "instruction {i} program id index {} out of range ({addressable} addressable accounts)",
                ix.program_id_index
            ));
        }
        for &ai in &ix.account_indices {
            if ai as usize >= addressable {
                return Err(format!(
                    "instruction {i} account index {ai} out of range ({addressable} addressable accounts)"
                ));
            }
        }
    }
    Ok(())
}

fn read_message_common(
    data: &[u8],
    pos: &mut usize,
) -> Result<
    (
        SolanaMessageHeader,
        Vec<SolanaKey>,
        SolanaKey,
        Vec<SolanaCompiledInstruction>,
    ),
    String,
> {
    if data.len() < *pos + 3 {
        return Err("unexpected EOF".into());
    }
    let header = SolanaMessageHeader {
        num_required_signatures: data[*pos],
        num_readonly_signed: data[*pos + 1],
        num_readonly_unsigned: data[*pos + 2],
    };
    *pos += 3;
    let key_count = decode_compact_u16(data, pos)?;
    if key_count > 256 {
        return Err(format!(
            "account key count {key_count} exceeds maximum of 256"
        ));
    }
    let mut account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        if data.len() < *pos + 32 {
            return Err("unexpected EOF".into());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&data[*pos..*pos + 32]);
        account_keys.push(SolanaKey(k));
        *pos += 32;
    }
    validate_solana_header(&header, account_keys.len())?;
    if data.len() < *pos + 32 {
        return Err("unexpected EOF".into());
    }
    let mut bh = [0u8; 32];
    bh.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    let ix_count = decode_compact_u16(data, pos)?;
    // Sanity cap: every instruction needs at least one byte (the program id
    // index), so the count cannot exceed the remaining bytes.
    if ix_count > data.len() - *pos {
        return Err(format!(
            "instruction count {ix_count} exceeds remaining bytes {}",
            data.len() - *pos
        ));
    }
    let mut instructions = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        if data.len() < *pos + 1 {
            return Err("unexpected EOF".into());
        }
        let program_id_index = data[*pos];
        *pos += 1;
        let acc_count = decode_compact_u16(data, pos)?;
        if data.len() < *pos + acc_count {
            return Err("unexpected EOF".into());
        }
        let account_indices = data[*pos..*pos + acc_count].to_vec();
        *pos += acc_count;
        let data_len = decode_compact_u16(data, pos)?;
        if data.len() < *pos + data_len {
            return Err("unexpected EOF".into());
        }
        let ix_data = data[*pos..*pos + data_len].to_vec();
        *pos += data_len;
        instructions.push(SolanaCompiledInstruction {
            program_id_index,
            account_indices,
            data: ix_data,
        });
    }
    Ok((header, account_keys, SolanaKey(bh), instructions))
}

impl SolanaMessage {
    /// Serializes the legacy message.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_message_common(
            &mut buf,
            &self.header,
            &self.account_keys,
            &self.recent_blockhash,
            &self.instructions,
        );
        buf
    }
    /// Parses a legacy message.
    pub fn from_bytes(data: &[u8]) -> Result<SolanaMessage, String> {
        let mut pos = 0;
        let (header, account_keys, recent_blockhash, instructions) =
            read_message_common(data, &mut pos)?;
        // For the legacy format the addressable set is exactly the static
        // account key list.
        validate_instruction_indexes(&instructions, account_keys.len())?;
        Ok(SolanaMessage {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        })
    }
}

impl SolanaMessageV0 {
    /// Serializes the v0 message (with version prefix 0x80).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0x80];
        write_message_common(
            &mut buf,
            &self.header,
            &self.account_keys,
            &self.recent_blockhash,
            &self.instructions,
        );
        buf.extend_from_slice(&encode_compact_u16(self.address_table_lookups.len()));
        for lookup in &self.address_table_lookups {
            buf.extend_from_slice(&lookup.account_key.0);
            buf.extend_from_slice(&encode_compact_u16(lookup.writable_indexes.len()));
            buf.extend_from_slice(&lookup.writable_indexes);
            buf.extend_from_slice(&encode_compact_u16(lookup.readonly_indexes.len()));
            buf.extend_from_slice(&lookup.readonly_indexes);
        }
        buf
    }
    /// Parses a v0 message.
    pub fn from_bytes(data: &[u8]) -> Result<SolanaMessageV0, String> {
        if data.is_empty() {
            return Err("unexpected EOF".into());
        }
        if data[0] & 0x80 == 0 {
            return Err("not a versioned message: MSB not set".into());
        }
        let version = data[0] & 0x7f;
        if version != 0 {
            return Err(format!("unsupported message version: {version}"));
        }
        let mut pos = 1;
        let (header, account_keys, recent_blockhash, instructions) =
            read_message_common(data, &mut pos)?;
        let lookup_count = decode_compact_u16(data, &mut pos)?;
        // Sanity cap: every lookup needs at least one byte, so the count cannot
        // exceed the remaining bytes.
        if lookup_count > data.len() - pos {
            return Err(format!(
                "address table lookup count {lookup_count} exceeds remaining bytes {}",
                data.len() - pos
            ));
        }
        let mut lookups = Vec::with_capacity(lookup_count);
        for _ in 0..lookup_count {
            if data.len() < pos + 32 {
                return Err("unexpected EOF".into());
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            let w_count = decode_compact_u16(data, &mut pos)?;
            if data.len() < pos + w_count {
                return Err("unexpected EOF".into());
            }
            let writable_indexes = data[pos..pos + w_count].to_vec();
            pos += w_count;
            let r_count = decode_compact_u16(data, &mut pos)?;
            if data.len() < pos + r_count {
                return Err("unexpected EOF".into());
            }
            let readonly_indexes = data[pos..pos + r_count].to_vec();
            pos += r_count;
            lookups.push(SolanaAddressTableLookup {
                account_key: SolanaKey(k),
                writable_indexes,
                readonly_indexes,
            });
        }
        // For v0 the addressable account set is the static account keys followed
        // by accounts loaded from address lookup tables (all writable indexes,
        // then all readonly indexes). The lookup counts are only known after the
        // lookups are parsed, which is why this validation happens here.
        let addressable = account_keys.len()
            + lookups
                .iter()
                .map(|l| l.writable_indexes.len() + l.readonly_indexes.len())
                .sum::<usize>();
        validate_instruction_indexes(&instructions, addressable)?;
        Ok(SolanaMessageV0 {
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups: lookups,
        })
    }
}

/// Encodes a value in Solana compact-u16 format.
pub fn encode_compact_u16(v: usize) -> Vec<u8> {
    assert!(v <= 0xffff, "compact-u16 value out of range");
    if v < 0x80 {
        vec![v as u8]
    } else if v < 0x4000 {
        vec![(v & 0x7f) as u8 | 0x80, (v >> 7) as u8]
    } else {
        vec![
            (v & 0x7f) as u8 | 0x80,
            ((v >> 7) & 0x7f) as u8 | 0x80,
            (v >> 14) as u8,
        ]
    }
}

/// Decodes a compact-u16, advancing `pos`.
pub fn decode_compact_u16(data: &[u8], pos: &mut usize) -> Result<usize, String> {
    if *pos >= data.len() {
        return Err("unexpected EOF".into());
    }
    let b0 = data[*pos];
    if b0 < 0x80 {
        *pos += 1;
        return Ok(b0 as usize);
    }
    if *pos + 1 >= data.len() {
        return Err("unexpected EOF".into());
    }
    let b1 = data[*pos + 1];
    if b1 < 0x80 {
        // Reject non-canonical encodings: a 2-byte form whose high group is zero
        // should have been encoded in a single byte.
        if b1 == 0 {
            return Err("non-canonical compact-u16".into());
        }
        *pos += 2;
        return Ok((b0 & 0x7f) as usize | (b1 as usize) << 7);
    }
    if *pos + 2 >= data.len() {
        return Err("unexpected EOF".into());
    }
    let b2 = data[*pos + 2];
    if b2 > 3 {
        return Err("compact-u16 overflow".into());
    }
    // Reject non-canonical encodings: a 3-byte form whose high group is zero
    // should have been encoded in two bytes.
    if b2 == 0 {
        return Err("non-canonical compact-u16".into());
    }
    *pos += 3;
    Ok((b0 & 0x7f) as usize | ((b1 & 0x7f) as usize) << 7 | (b2 as usize) << 14)
}

// --- PDA ---

/// Derives a program address from seeds and a program id; errors if the result
/// lies on the Ed25519 curve.
pub fn create_program_address(seeds: &[&[u8]], program_id: SolanaKey) -> Result<SolanaKey, String> {
    if seeds.len() > 16 {
        return Err("too many seeds: maximum 16".into());
    }
    let mut h = Sha256::new();
    for &seed in seeds {
        if seed.len() > 32 {
            return Err("seed too long: maximum 32 bytes".into());
        }
        h.update(seed);
    }
    h.update(&program_id.0);
    h.update(b"ProgramDerivedAddress");
    let hash = h.finalize();

    if ed25519::is_on_curve(&hash) {
        return Err("derived address is on the Ed25519 curve".into());
    }
    Ok(SolanaKey(hash))
}

/// Finds a valid program address by iterating bump seeds from 255 down to 0.
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: SolanaKey,
) -> Result<(SolanaKey, u8), String> {
    for bump in (0..=255u8).rev() {
        // Append the trailing bump byte to the caller's seeds for this attempt.
        let bump_seed = [bump];
        let mut all = Vec::with_capacity(seeds.len() + 1);
        all.extend_from_slice(seeds);
        all.push(&bump_seed[..]);
        if let Ok(addr) = create_program_address(&all, program_id) {
            return Ok((addr, bump));
        }
    }
    Err("could not find valid program address".into())
}
