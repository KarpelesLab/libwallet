//! Ported tests from `solana_test.go` and `solana_pda_test.go`.

use crate::crypto::ed25519::public_from_seed;
use crate::parse_solana_address;
use crate::pubkey::PubKey;
use crate::script::Script;
use crate::solana::*;

fn seed() -> [u8; 32] {
    let v =
        hex::decode("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88").unwrap();
    let mut s = [0u8; 32];
    s.copy_from_slice(&v);
    s
}

#[test]
fn solana_address_roundtrip() {
    let pk = public_from_seed(&seed());
    let s = Script::new(PubKey::Ed25519(pk));
    let sout = s.out("solana").unwrap();
    let addr = sout.address(&["solana"]).unwrap();
    let parsed = parse_solana_address(&addr).unwrap();
    assert_eq!(parsed.script, sout.script);
    assert_eq!(sout.hash().unwrap().len(), 32);
}

#[test]
fn solana_address_parse_system_program() {
    let addr = "11111111111111111111111111111111";
    let out = parse_solana_address(addr).unwrap();
    assert_eq!(out.address(&["solana"]).unwrap(), addr);
    assert!(parse_solana_address("abc").is_err());
    assert!(parse_solana_address("0000000000000000000000000000000O").is_err());
}

#[test]
fn compact_u16_via_tx_roundtrip() {
    let fee_payer = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let blockhash = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let tx = new_solana_tx(fee_payer, blockhash, &[]).unwrap();
    let data = tx.to_bytes().unwrap();
    let tx2 = SolanaTx::from_bytes(&data).unwrap();
    assert_eq!(
        tx2.message.account_keys.len(),
        tx.message.account_keys.len()
    );
}

#[test]
fn solana_transfer_sign() {
    let s = seed();
    let from = SolanaKey(public_from_seed(&s));
    let to = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let blockhash = SolanaKey::parse("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC").unwrap();

    let ix = transfer_instruction(from, to, 1_000_000);
    let mut tx = new_solana_tx(from, blockhash, &[ix]).unwrap();

    assert_eq!(tx.message.header.num_required_signatures, 1);
    assert_eq!(tx.message.account_keys.len(), 3);
    assert_eq!(tx.message.account_keys[0], from);

    tx.sign(&[s]).unwrap();
    let h = tx.hash().unwrap();
    assert_eq!(h.len(), 64);
    assert_eq!(h, tx.signatures[0]);
    tx.verify().unwrap();

    let data = tx.to_bytes().unwrap();
    assert!(data.len() >= 100);
}

#[test]
fn solana_tx_roundtrip() {
    let s = seed();
    let from = SolanaKey(public_from_seed(&s));
    let to = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let blockhash = SolanaKey::parse("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC").unwrap();
    let ix = transfer_instruction(from, to, 500_000);
    let mut tx = new_solana_tx(from, blockhash, &[ix]).unwrap();
    tx.sign(&[s]).unwrap();
    let data = tx.to_bytes().unwrap();

    let tx2 = SolanaTx::from_bytes(&data).unwrap();
    assert_eq!(tx2.signatures, tx.signatures);
    assert_eq!(tx2.message.header, tx.message.header);
    assert_eq!(tx2.message.account_keys, tx.message.account_keys);
    assert_eq!(tx2.message.recent_blockhash, tx.message.recent_blockhash);
    let data2 = tx2.to_bytes().unwrap();
    assert_eq!(data, data2);
}

#[test]
fn pda_create_and_find() {
    let program_id = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let (addr, bump) = find_program_address(&[&b"test"[..]], program_id).unwrap();
    let addr2 = create_program_address(&[&b"test"[..], &[bump]], program_id).unwrap();
    assert_eq!(addr, addr2);
}

#[test]
fn pda_find_deterministic() {
    let program_id = SolanaKey::parse("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
    let (addr, bump) = find_program_address(&[&b"hello"[..]], program_id).unwrap();
    assert!(!addr.is_zero());
    let (addr2, bump2) = find_program_address(&[&b"hello"[..]], program_id).unwrap();
    assert_eq!(addr, addr2);
    assert_eq!(bump, bump2);
}

#[test]
fn pda_validation() {
    let program_id = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let seeds: Vec<Vec<u8>> = (0..17).map(|i| vec![i as u8]).collect();
    let seed_refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    assert!(create_program_address(&seed_refs, program_id).is_err());
    assert!(create_program_address(&[[0u8; 33].as_slice()], program_id).is_err());
}

#[test]
fn pda_multiple_seeds() {
    let program_id = SolanaKey::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let wallet = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let (addr, bump) = find_program_address(&[&wallet.0[..], &b"seed2"[..]], program_id).unwrap();
    let addr2 =
        create_program_address(&[&wallet.0[..], &b"seed2"[..], &[bump]], program_id).unwrap();
    assert_eq!(addr, addr2);
}

// --- Security regression tests (port of solanatx_extra_test.go) ---

/// Assembles a legacy SolanaMessage wire-format body for tests.
fn build_legacy_message(header: &[u8], key_count: &[u8], num_keys: usize, ix: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(header);
    buf.extend_from_slice(key_count);
    buf.extend(std::iter::repeat_n(0u8, num_keys * 32)); // account keys
    buf.extend(std::iter::repeat_n(0u8, 32)); // recent blockhash
    buf.extend_from_slice(ix);
    buf
}

#[test]
fn message_header_count_too_large() {
    // header: num_required_signatures=2, others=0; key_count=1
    let data = build_legacy_message(&[0x02, 0x00, 0x00], &[0x01], 1, &[0x00]);
    assert!(SolanaMessage::from_bytes(&data).is_err());
}

#[test]
fn verify_sign_no_panic_on_bad_header() {
    // header references more signers than keys; must error, not panic.
    let mut tx = SolanaTx {
        signatures: vec![Vec::new(); 3],
        message: SolanaMessage {
            header: SolanaMessageHeader {
                num_required_signatures: 3,
                ..Default::default()
            },
            account_keys: Vec::new(),
            ..Default::default()
        },
        message_v0: None,
    };
    assert!(tx.verify().is_err());
    assert!(tx.sign(&[seed()]).is_err());
}

#[test]
fn non_canonical_compact_u16_rejected() {
    // header valid, then non-canonical compact-u16 ([0x80,0x00]) for key count.
    let data = vec![0x01, 0x00, 0x00, 0x80, 0x00];
    assert!(SolanaMessage::from_bytes(&data).is_err());
}

#[test]
fn instruction_index_out_of_range() {
    // one instruction with program_id_index=5 but only 1 account key
    let ix = [0x01, 0x05, 0x00, 0x00];
    let data = build_legacy_message(&[0x01, 0x00, 0x00], &[0x01], 1, &ix);
    assert!(SolanaMessage::from_bytes(&data).is_err());

    // out-of-range account index
    let ix2 = [0x01, 0x00, 0x01, 0x09, 0x00];
    let data2 = build_legacy_message(&[0x01, 0x00, 0x00], &[0x01], 1, &ix2);
    assert!(SolanaMessage::from_bytes(&data2).is_err());
}
