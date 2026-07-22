//! outscript generates potential output scripts for a given public key.
//!
//! It supports Bitcoin and Bitcoin-like cryptocurrency output script formats
//! (P2PKH, P2SH, P2WPKH, P2WSH, P2PK, P2TR, etc.), EVM-based networks (Ethereum
//! and compatible chains), and other blockchains such as Litecoin, Dogecoin,
//! Namecoin, Monacoin, Electraproto, Dash, Bitcoin Cash, Massa, Solana and
//! Cardano.
//!
//! This is a Rust port of the Go library `github.com/KarpelesLab/outscript`. All
//! cryptography is provided by the `purecrypto` crate.

pub mod base58;
pub mod bech32;
pub mod cbor;
pub mod crypto;
pub mod hash;
pub mod pushbytes;
pub mod rlp;

pub mod address;
pub mod btcguess;
pub mod btctx;
pub mod btctxparse;
pub mod cardano;
pub mod cardano_derive;
pub mod cardanotx;
pub mod evmabi;
pub mod evmtx;
pub mod insertable;
pub mod massa;
pub mod out;
pub mod pubkey;
pub mod reward;
pub mod script;
pub mod solana;
pub mod solana_addr;

mod btcamount;
mod btcvarint;

pub use address::{eip55, encode_base58_addr, parse_bitcoin_based_address, parse_evm_address};
pub use btcamount::BtcAmount;
pub use btcguess::{GuessResult, guess_by_in_script, guess_by_out_script};
pub use btctx::{BtcTx, BtcTxInput, BtcTxOutput, BtcTxSign, Signer};
pub use btctxparse::{BtcInputSig, extract_btc_input_sig};
pub use btcvarint::BtcVarInt;
pub use cardano::{
    cardano_base_address, cardano_enterprise_address, cardano_key_hash, cardano_reward_address,
    parse_cardano_address,
};
pub use cardano_derive::{
    CARDANO_HARDENED, CardanoExtendedKey, CardanoExtendedPubKey, cardano_harden,
    cardano_icarus_master_key,
};
pub use cardanotx::{
    CardanoAsset, CardanoInput, CardanoOutput, CardanoSigner, CardanoTx, CardanoVkeyWitness,
};
pub use evmabi::{AbiBuffer, AbiValue, evm_call};
pub use evmtx::{EvmTx, EvmTxType};
pub use insertable::{Format, Insertable};
pub use massa::parse_massa_address;
pub use out::{Out, get_outs, guess_out};
pub use pubkey::PubKey;
pub use pushbytes::{parse_push_bytes, push_bytes};
pub use reward::{block_reward, cumulative_reward};
pub use script::{Script, format_def, formats_per_network};
pub use solana_addr::parse_solana_address;

#[cfg(test)]
mod address_tests;
#[cfg(test)]
mod btctx_tests;
#[cfg(test)]
mod cardano_tests;
#[cfg(test)]
mod solana_tests;
