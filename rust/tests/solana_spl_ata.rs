//! ATA-derivation cross-check: the Rust `derive_ata` must produce byte-identical
//! Associated Token Accounts to the Go `deriveAssociatedTokenAccount`. The USDC
//! vector below is also the canonical Solana-docs example for owner
//! 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM, so this pins both Rust↔Go parity
//! and Rust↔spec correctness for a fund-critical derivation.

use libwallet::solana_spl::{
    derive_ata, program_id, SPL_TOKEN_PROGRAM_B58, TOKEN_2022_PROGRAM_B58,
};

fn b58_32(s: &str) -> [u8; 32] {
    bs58::decode(s).into_vec().unwrap().try_into().unwrap()
}

#[test]
fn usdc_ata_matches_known_vector() {
    let owner = b58_32("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    let usdc = b58_32("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    let ata = derive_ata(&owner, &usdc, &program_id(SPL_TOKEN_PROGRAM_B58)).unwrap();
    assert_eq!(
        bs58::encode(ata).into_string(),
        "FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B"
    );
}

#[test]
fn synthetic_pair_matches_go() {
    let ata = derive_ata(&[0x11; 32], &[0x22; 32], &program_id(SPL_TOKEN_PROGRAM_B58)).unwrap();
    assert_eq!(
        bs58::encode(ata).into_string(),
        "9aiJHPARxbrgMgeMats2yTcSiBc4afhHCf1faikseJar"
    );
}

#[test]
fn token2022_program_yields_distinct_ata() {
    let owner = b58_32("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    let usdc = b58_32("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    let ata = derive_ata(&owner, &usdc, &program_id(TOKEN_2022_PROGRAM_B58)).unwrap();
    assert_eq!(
        bs58::encode(ata).into_string(),
        "GdjpegrtGwU3pgtzPivYVViSA8rmGL248qBVKzsrU3DD"
    );
}
