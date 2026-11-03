//! Bitfi key derivation, for recovering funds from a Bitfi salt and secret
//! phrase. Nothing here stores anything: see `handlers::bitfi`.
//!
//! The scheme, from Bitfi's published wallet source (`WalletLibrary/Core`):
//!
//! ```text
//! seed   = scrypt(secret, salt, N = 32768, r = 8, p = 4, 64 bytes)
//! I      = HMAC-SHA512(key = SHA-256(salt), seed)
//! master = BIP32 node (I[..32], chain code I[32..])
//! coin   = master / coin_index(symbol)'
//! key    = coin / position
//! ```
//!
//! Addresses differ from what the rest of libwallet derives: a legacy address
//! hashes the **uncompressed** public key, and only the SegWit address uses the
//! compressed one. Monero treats `key` as a standard Monero seed.

use outscript::btctx::{BtcTx, BtcTxInput, BtcTxSign};
use outscript::crypto::secp256k1::SecpPrivateKey;
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar as EdScalar};
use purecrypto::ec::secp256k1::{ProjectivePoint, Scalar};
use purecrypto::hash::{keccak256, sha256};
use purecrypto::zeroize::zero_bulk;

use crate::hdderive::{ckd_priv, hmac_master};

/// scrypt cost: `log2(N)`, `r` and `p`.
const SCRYPT: (u8, u32, u32) = (15, 8, 4);

/// How a Bitfi coin's addresses work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `outscript` network tag, and whether the coin has SegWit addresses.
    Bitcoin { network: &'static str, segwit: bool, wif: u8 },
    Ethereum,
    Monero,
}

/// A coin both Bitfi and our servers support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coin {
    pub symbol: &'static str,
    /// The chain's name on our RPC servers, and in `outscript` network checks.
    pub chain: &'static str,
    pub family: Family,
}

pub const COINS: [Coin; 7] = [
    Coin { symbol: "btc", chain: "bitcoin", family: Family::Bitcoin { network: "bitcoin", segwit: true, wif: 0x80 } },
    Coin { symbol: "ltc", chain: "litecoin", family: Family::Bitcoin { network: "litecoin", segwit: true, wif: 0xb0 } },
    Coin { symbol: "doge", chain: "dogecoin", family: Family::Bitcoin { network: "dogecoin", segwit: false, wif: 0x9e } },
    Coin { symbol: "bch", chain: "bitcoin-cash", family: Family::Bitcoin { network: "bitcoincash", segwit: false, wif: 0x80 } },
    Coin { symbol: "mona", chain: "monacoin", family: Family::Bitcoin { network: "monacoin", segwit: true, wif: 0xb0 } },
    Coin { symbol: "eth", chain: "ethereum", family: Family::Ethereum },
    Coin { symbol: "xmr", chain: "monero", family: Family::Monero },
];

/// The coin with this symbol, in any case.
pub fn coin(symbol: &str) -> Option<&'static Coin> {
    COINS.iter().find(|c| c.symbol.eq_ignore_ascii_case(symbol))
}

/// A BIP32 private node. Its bytes are wiped when it's dropped.
pub struct Node {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl Drop for Node {
    fn drop(&mut self) {
        zero_bulk(&mut self.key);
        zero_bulk(&mut self.chain_code);
    }
}

/// A coin's account number: each letter's position in the alphabet, written out
/// and joined, so `btc` is 2, 20, 3 and becomes 2203.
pub fn coin_index(symbol: &str) -> u32 {
    let digits: String = symbol.chars().map(|c| (c.to_ascii_uppercase() as u32 - 64).to_string()).collect();
    digits.parse().expect("symbols are short enough for a u32")
}

/// The master node for a salt and secret. This is the slow step, at around 128
/// MiB of work in total. Bitfi hashes these as ASCII, and its calculator turns
/// anything else into `?`, so non-ASCII input is refused rather than guessed at.
pub fn master(salt: &str, secret: &str) -> Result<Node, String> {
    if !salt.is_ascii() || !secret.is_ascii() {
        return Err("salt and secret must be ASCII characters".into());
    }
    if salt.is_empty() || secret.is_empty() {
        return Err("salt and secret are required".into());
    }
    let (log_n, r, p) = SCRYPT;
    let mut seed = [0u8; 64];
    purecrypto::kdf::scrypt::scrypt(secret.as_bytes(), salt.as_bytes(), log_n, r, p, &mut seed)
        .map_err(|e| format!("scrypt: {e:?}"))?;
    let (key, chain_code) = hmac_master(&sha256(salt.as_bytes()), &seed);
    zero_bulk(&mut seed);
    Ok(Node { key, chain_code })
}

impl Node {
    /// The private key for a coin at a position (a non-hardened child).
    pub fn derive(&self, symbol: &str, position: u32) -> Result<PrivateKey, String> {
        if position >= 0x8000_0000 {
            return Err("position out of range".into());
        }
        let hardened = coin_index(symbol) | 0x8000_0000;
        let (mut coin_key, mut coin_chain) = ckd_priv(&self.key, &self.chain_code, hardened).map_err(|e| e.to_string())?;
        let child = ckd_priv(&coin_key, &coin_chain, position).map_err(|e| e.to_string());
        zero_bulk(&mut coin_key);
        zero_bulk(&mut coin_chain);
        let (key, mut chain_code) = child?;
        zero_bulk(&mut chain_code);
        Ok(PrivateKey(key))
    }
}

/// A derived 32-byte private key. Wiped when it's dropped.
pub struct PrivateKey(pub(crate) [u8; 32]);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        zero_bulk(&mut self.0);
    }
}

impl PrivateKey {
    fn compressed_pub(&self) -> Result<[u8; 33], String> {
        let d = Scalar::from_bytes_be(&self.0).map_err(|_| "key out of range".to_string())?;
        let point = ProjectivePoint::mul_generator(&d).to_affine().ok_or("key is zero")?;
        Ok(point.to_sec1_compressed())
    }

    /// The key as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Wallet Import Format for a coin: `compressed` for its SegWit address,
    /// uncompressed for the legacy one.
    pub fn to_wif(&self, version: u8, compressed: bool) -> String {
        let mut body = vec![version];
        body.extend_from_slice(&self.0);
        if compressed {
            body.push(1);
        }
        let checksum = sha256(&sha256(&body));
        body.extend_from_slice(&checksum[..4]);
        let wif = bs58::encode(&body).into_string();
        zero_bulk(&mut body);
        wif
    }

    /// The Monero keys this key seeds, taking it as a standard Monero seed.
    pub fn monero(&self) -> MoneroKeys {
        let spend = reduce32(&self.0);
        let view = reduce32(&keccak256(&spend.to_bytes()));
        let spend_public = EdwardsPoint::mul_base(&spend).compress();
        let view_public = EdwardsPoint::mul_base(&view).compress();
        MoneroKeys { spend: spend.to_bytes(), view: view.to_bytes(), spend_public, view_public }
    }
}

/// A Monero wallet's keys. Private ones are wiped when it's dropped.
pub struct MoneroKeys {
    pub spend: [u8; 32],
    pub view: [u8; 32],
    pub spend_public: [u8; 32],
    pub view_public: [u8; 32],
}

impl Drop for MoneroKeys {
    fn drop(&mut self) {
        zero_bulk(&mut self.spend);
        zero_bulk(&mut self.view);
    }
}

impl MoneroKeys {
    /// The wallet's mainnet primary address.
    pub fn address(&self) -> String {
        let mut body = vec![18u8];
        body.extend_from_slice(&self.spend_public);
        body.extend_from_slice(&self.view_public);
        let checksum = keccak256(&body);
        body.extend_from_slice(&checksum[..4]);
        monero_base58(&body)
    }
}

/// `sc_reduce32`: 32 little-endian bytes, reduced modulo the curve order.
fn reduce32(bytes: &[u8; 32]) -> EdScalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes);
    let scalar = EdScalar::from_bytes_mod_order(&wide);
    zero_bulk(&mut wide);
    scalar
}

/// Monero's base58: each 8-byte block is encoded separately, at a fixed length.
fn monero_base58(data: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const ENCODED_LENGTH: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    let mut out = String::new();
    for block in data.chunks(8) {
        let mut value = block.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b));
        let mut chars = vec![b'1'; ENCODED_LENGTH[block.len()]];
        for c in chars.iter_mut().rev() {
            *c = ALPHABET[(value % 58) as usize];
            value /= 58;
        }
        out.extend(chars.iter().map(|&c| c as char));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One address a key can hold funds at.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Address {
    /// `legacy`, `segwit`, `ethereum` or `monero`.
    pub kind: &'static str,
    pub address: String,
}

/// Every address Bitfi uses for this key on this coin.
pub fn addresses(coin: &Coin, key: &PrivateKey) -> Result<Vec<Address>, String> {
    let public = key.compressed_pub()?;
    match coin.family {
        Family::Bitcoin { network, segwit, .. } => {
            let mut found = vec![Address { kind: "legacy", address: bitcoin_address(&public, "p2pukh", network)? }];
            if segwit {
                found.push(Address { kind: "segwit", address: bitcoin_address(&public, "p2wpkh", network)? });
            }
            Ok(found)
        }
        Family::Ethereum => {
            let address = crate::hdderive::evm_address(&public).map_err(|e| e.to_string())?;
            Ok(vec![Address { kind: "ethereum", address }])
        }
        Family::Monero => Ok(vec![Address { kind: "monero", address: key.monero().address() }]),
    }
}

fn bitcoin_address(public: &[u8; 33], script: &str, network: &str) -> Result<String, String> {
    crate::bitcoin::address_for(public, script, network).map_err(|e| e.to_string())
}

/// How much a send should move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amount {
    /// Everything at the address, less the fee.
    Max,
    Exact(u64),
}

/// A signed transaction that hasn't been broadcast, and what it does.
#[derive(Debug)]
pub struct Spend {
    pub raw: Vec<u8>,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
}

/// Base units as a decimal amount, without trailing zeros.
pub fn format_units(value: &str, decimals: usize) -> String {
    let digits = format!("{value:0>width$}", width = decimals + 1);
    let (whole, fraction) = digits.split_at(digits.len() - decimals);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() { whole.to_owned() } else { format!("{whole}.{fraction}") }
}

/// The smallest output a coin's nodes relay.
fn dust(coin: &Coin) -> u64 {
    if coin.symbol == "doge" { 1_000_000 } else { 546 }
}

/// An upper estimate of a transaction's virtual size. An uncompressed key makes
/// a legacy input far larger than the 148 bytes usually assumed, and outputs are
/// sized for the largest address type the recipient could have.
fn estimate_vsize(kind: &str, inputs: u64, outputs: u64) -> u64 {
    let (overhead, input) = if kind == "segwit" { (11, 68) } else { (10, 180) };
    overhead + inputs * input + outputs * 43
}

/// Build and sign, without broadcasting, a transaction sending every given
/// output of `key`'s `kind` address to `to`. Any change goes back to that same
/// address. `to` must be an address on this coin's own chain.
pub fn spend_bitcoin(
    coin: &Coin,
    key: &PrivateKey,
    kind: &str,
    utxos: &[crate::bitcoin::DiscoveredUtxo],
    to: &str,
    amount: Amount,
    fee_rate: u64,
) -> Result<Spend, String> {
    let Family::Bitcoin { network, segwit, .. } = coin.family else {
        return Err(format!("{} is not a Bitcoin-family coin", coin.symbol));
    };
    let (scheme, sighash) = match kind {
        "legacy" => ("p2pukh", if coin.symbol == "bch" { 0x41 } else { 0 }),
        "segwit" if segwit => ("p2wpkh", 0),
        _ => return Err(format!("{} has no {kind} address", coin.symbol)),
    };
    if utxos.is_empty() {
        return Err("This address has nothing to spend.".into());
    }
    let total = utxos.iter().try_fold(0u64, |sum, u| sum.checked_add(u.amount_sats)).ok_or("amount overflow")?;
    let count = utxos.len() as u64;
    let fee_for = |outputs: u64| estimate_vsize(kind, count, outputs).saturating_mul(fee_rate);
    let show = |sats: u64| format!("{} {}", format_units(&sats.to_string(), 8), coin.symbol.to_uppercase());

    let (sent, change) = match amount {
        Amount::Max => {
            let fee = fee_for(1);
            (total.checked_sub(fee).ok_or(format!("This address holds {}, which doesn't cover a network fee of {}.", show(total), show(fee)))?, 0)
        }
        Amount::Exact(sent) => {
            let fee = fee_for(2);
            let spare = sent
                .checked_add(fee)
                .and_then(|needed| total.checked_sub(needed))
                .ok_or(format!("This address holds {}, which doesn't cover {} plus a network fee of {}.", show(total), show(sent), show(fee)))?;
            // Change too small to relay goes to the miners instead.
            (sent, if spare > dust(coin) { spare } else { 0 })
        }
    };
    if sent <= dust(coin) {
        return Err(format!("{} is too small to send: the network won't relay it.", show(sent)));
    }

    let signer = SecpPrivateKey::from_bytes(&key.0).map_err(|e| format!("bad key: {e:?}"))?;
    let public = key.compressed_pub()?;
    let mut tx = BtcTx { version: 2, locktime: 0, ..BtcTx::default() };
    for u in utxos {
        let (txid, vout) = crate::bitcoin::parse_txo_ref(&u.txo).map_err(|e| e.to_string())?;
        tx.inputs.push(BtcTxInput { txid, vout, script: Vec::new(), sequence: 0xffff_ffff, witnesses: Vec::new() });
    }
    tx.add_net_output(coin.chain, to.trim(), sent).map_err(|_| format!("That isn't a {} address. Sending to another network's address would lose the funds.", coin.symbol.to_uppercase()))?;
    if change > 0 {
        let back = bitcoin_address(&public, scheme, network)?;
        tx.add_net_output(coin.chain, &back, change).map_err(|e| e.to_string())?;
    }
    let previous = outscript::script::Script::new(signer.public_key()).out(scheme).map_err(|e| e.to_string())?.bytes().to_vec();
    let signs: Vec<BtcTxSign> = utxos
        .iter()
        .map(|u| BtcTxSign::new(&signer, scheme).amount(u.amount_sats).sighash(sighash).prev_script(previous.clone()))
        .collect();
    tx.sign(&signs).map_err(|e| format!("signing failed: {e}"))?;
    Ok(Spend { raw: tx.to_bytes(), amount: sent, fee: total - sent - change, change })
}

/// Sign an Ethereum transaction with `key`, without broadcasting it.
pub fn sign_ethereum(key: &PrivateKey, request: &crate::evm::EvmTxRequest) -> Result<Vec<u8>, String> {
    let signer = SecpPrivateKey::from_bytes(&key.0).map_err(|e| format!("bad key: {e:?}"))?;
    let mut tx = crate::evm::build_unsigned(request).map_err(|e| e.to_string())?;
    tx.sign(&signer).map_err(|e| format!("signing failed: {e}"))?;
    tx.to_bytes().map_err(|e| e.to_string())
}

/// Fee rate in satoshi per virtual byte, rounded up, from a node's rate per
/// kilobyte in satoshi.
pub fn fee_rate_from_per_kb(per_kb: u64) -> u64 {
    per_kb.div_ceil(1000).max(1)
}
