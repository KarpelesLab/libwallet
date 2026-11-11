//! Bitcoin transaction building + threshold signing (port of the wlttx Bitcoin
//! path). Builds a legacy P2PKH spend, computes each input's sighash via
//! outscript, and signs it with the wallet's DKLs shares under the account's HD
//! tweak. Each signature is self-verified as valid ECDSA under the derived key.

use std::cell::RefCell;

use num_bigint::{BigInt, Sign};
use outscript::btctx::{BtcTx, BtcTxInput, BtcTxSign, Signer};
use outscript::crypto::SignerError;
use outscript::crypto::secp256k1::{DerSignature, SecpPublicKey};

use crate::{Env, Error, Result};

/// outscript 0.2 reports a structured `outscript::Error` where it used to hand
/// back a `String`, so the conversion into our own error needs a step.
fn oserr(e: outscript::Error) -> Error {
    Error::Env(e.to_string())
}

/// Serialize a BIP-32 extended **public** key (`xpub…`) from a compressed
/// secp256k1 pubkey + 32-byte chain code, as Go `Account.Xpub` does via
/// `ecckd.FromPublicKey`: mainnet version, depth 0, zero parent fingerprint and
/// child number, base58check (double-SHA256 checksum). The account uses the
/// wallet chain code (matching Go), so this reproduces the exact xpub string.
pub fn build_xpub(pubkey_compressed: &[u8; 33], chaincode: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(78 + 4);
    data.extend_from_slice(&[0x04, 0x88, 0xb2, 0x1e]); // BitcoinMainnetPublic
    data.push(0x00); // depth
    data.extend_from_slice(&[0, 0, 0, 0]); // parent fingerprint
    data.extend_from_slice(&[0, 0, 0, 0]); // child number
    data.extend_from_slice(chaincode);
    data.extend_from_slice(pubkey_compressed);
    let h1 = purecrypto::hash::sha256(&data);
    let h2 = purecrypto::hash::sha256(&h1);
    data.extend_from_slice(&h2[..4]);
    bs58::encode(&data).into_string()
}

/// Decode a BIP-32 extended **public** key (`xpub…`) into its compressed
/// secp256k1 pubkey + 32-byte chain code — the inverse of [`build_xpub`], and
/// the Rust equivalent of Go `ecckd.FromString` restricted to public keys.
/// Rejects a malformed base58check payload, a bad checksum, a non-public
/// version, or a private (`xprv…`) key.
pub fn parse_xpub(xpub: &str) -> Result<([u8; 33], [u8; 32])> {
    let data = bs58::decode(xpub)
        .into_vec()
        .map_err(|e| Error::Env(format!("parse xpub: {e}")))?;
    if data.len() != 82 {
        return Err(Error::Env(format!("parse xpub: expected 82 bytes, got {}", data.len())));
    }
    // base58check trailer: first 4 bytes of double-SHA256 over the first 78.
    let (payload, checksum) = data.split_at(78);
    let h1 = purecrypto::hash::sha256(payload);
    let h2 = purecrypto::hash::sha256(&h1);
    if h2[..4] != *checksum {
        return Err(Error::Env("parse xpub: bad checksum".into()));
    }
    // BitcoinMainnetPublic version (0x0488B21E). Private keys carry the pubkey
    // slot as 0x00‖<32-byte scalar>; reject them (Go disallows xpriv here).
    if payload[..4] != [0x04, 0x88, 0xb2, 0x1e] {
        return Err(Error::Env("parse xpub: not a bitcoin mainnet public key".into()));
    }
    let mut chaincode = [0u8; 32];
    chaincode.copy_from_slice(&payload[13..45]);
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&payload[45..78]);
    if !matches!(pubkey[0], 0x02 | 0x03) {
        return Err(Error::Env("parse xpub: not a compressed public key (expected xpub, not xprv)".into()));
    }
    Ok((pubkey, chaincode))
}

/// Parse a modchain `balance` value (outscript BtcAmount JSON) into satoshi.
/// Mirrors Go `BtcAmount.UnmarshalText`: a JSON number/string, where a value
/// without a decimal point is whole BTC (×1e8), a decimal value is scaled to
/// 8 places (max 8 decimals), and a `0x`-prefixed string is raw satoshi hex.
pub fn parse_btc_amount(v: &serde_json::Value) -> Result<u64> {
    // Numbers keep their literal form via to_string (no float rounding).
    let s = match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        other => return Err(Error::Env(format!("bad btc amount {other}"))),
    };
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).map_err(|e| Error::Env(format!("btc hex: {e}")));
    }
    match s.split_once('.') {
        None => {
            let v: u64 = s.parse().map_err(|e| Error::Env(format!("btc int: {e}")))?;
            v.checked_mul(100_000_000).ok_or_else(|| Error::Env("btc overflow".into()))
        }
        Some((int_part, frac)) => {
            if frac.len() > 8 {
                return Err(Error::Env("cannot parse amount with more than 8 decimals".into()));
            }
            let digits = format!("{int_part}{frac}");
            let mut v: u64 = digits.parse().map_err(|e| Error::Env(format!("btc dec: {e}")))?;
            for _ in frac.len()..8 {
                v = v.checked_mul(10).ok_or_else(|| Error::Env("btc overflow".into()))?;
            }
            Ok(v)
        }
    }
}

/// The receive/change address type + address-network name for a Bitcoin-family
/// chain (Go `Account.bitcoinAddress`): segwit P2WPKH (bech32) for
/// bitcoin/litecoin/monacoin, P2PKH for bitcoin-cash (cashaddr) and dogecoin.
fn hd_address_kind(chain_id: &str) -> Result<(&'static str, &'static str)> {
    match chain_id {
        "bitcoin" => Ok(("p2wpkh", "bitcoin")),
        "litecoin" => Ok(("p2wpkh", "litecoin")),
        "monacoin" => Ok(("p2wpkh", "monacoin")),
        "bitcoin-cash" => Ok(("p2pkh", "bitcoincash")),
        "dogecoin" => Ok(("p2pkh", "dogecoin")),
        other => Err(Error::Env(format!("unsupported bitcoin-family chainId: {other}"))),
    }
}

/// The outscript network tag an OUTPUT address must parse under when spending
/// on `chain_id`. outscript's plain `add_output` auto-detects the network from
/// the address, so an `ltc1q…`/`tb1…`/Dogecoin address would be accepted on a
/// BTC send (and vice versa) and the coins would go to the same hash on the
/// wrong chain. Every Bitcoin-family chain the wallet supports has a tag, so an
/// unknown chain is refused rather than falling back to auto-detection.
/// (`bitcoin-cash` accepts cashaddr with or without its prefix and the legacy
/// base58 form, which shares Bitcoin's version bytes.)
pub(crate) fn output_network(chain_id: &str) -> Result<&'static str> {
    match chain_id {
        "bitcoin" => Ok("bitcoin"),
        "litecoin" => Ok("litecoin"),
        "monacoin" => Ok("monacoin"),
        "dogecoin" => Ok("dogecoin"),
        "bitcoin-cash" | "bitcoincash" => Ok("bitcoin-cash"),
        other => Err(Error::Env(format!("unsupported bitcoin-family chainId: {other}"))),
    }
}

/// Add an output paying `address`, which must be an address of `chain_id`.
fn add_chain_output(tx: &mut BtcTx, chain_id: &str, address: &str, sats: u64) -> Result<()> {
    let network = output_network(chain_id)?;
    tx.add_net_output(network, address, sats)
        .map_err(|e| Error::Env(format!("invalid {chain_id} address {address:?}: {e}")))
}

/// Encode a compressed secp256k1 pubkey as the HD receive/change address for
/// `chain_id`, via outscript (P2WPKH/P2PKH per [`hd_address_kind`]).
pub fn hd_address(pubkey_compressed: &[u8; 33], chain_id: &str) -> Result<String> {
    let (script_type, network) = hd_address_kind(chain_id)?;
    address_for(pubkey_compressed, script_type, network)
}

/// Encode `pubkey` as the address of a given `script_type` (e.g. "p2wpkh",
/// "p2sh:p2wpkh", "p2pkh") on the outscript `network` tag.
pub(crate) fn address_for(pubkey_compressed: &[u8; 33], script_type: &str, network: &str) -> Result<String> {
    let pk = SecpPublicKey::from_sec1(pubkey_compressed)
        .map_err(|e| Error::Env(format!("bad pubkey: {e:?}")))?;
    outscript::script::Script::new(pk)
        .address(script_type, &[network])
        .map_err(|e| Error::Env(format!("address encode: {e}")))
}

/// One receive-address format (Go `AddressFormat`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AddressFormat {
    pub kind: String,
    pub name: String,
    pub address: String,
    pub path: String,
    #[serde(rename = "default")]
    pub is_default: bool,
}

/// The address-format catalog per chain (Go `bitcoinFormatCatalog`), ordered by
/// display preference (modern first). The first entry is the account's default.
fn format_catalog(chain_id: &str) -> Option<&'static [(&'static str, &'static str)]> {
    match chain_id {
        "bitcoin" | "litecoin" => Some(&[
            ("p2wpkh", "Native SegWit"),
            ("p2sh:p2wpkh", "SegWit (legacy-compatible)"),
            ("p2pkh", "Legacy"),
        ]),
        "monacoin" => Some(&[("p2wpkh", "Native SegWit"), ("p2pkh", "Legacy")]),
        "bitcoin-cash" => Some(&[("p2pkh", "CashAddr")]),
        "dogecoin" => Some(&[("p2pkh", "Standard")]),
        _ => None,
    }
}

/// Every receive-address format available for this account on `chain_id` (Go
/// `Account.AddressFormats`), all derived from `m/0/0` below the account xpub.
/// Formats a pubkey can't render are skipped rather than failing the list.
pub fn address_formats(
    account_pubkey: &[u8; 33],
    account_chaincode: &[u8; 32],
    chain_id: &str,
) -> Result<Vec<AddressFormat>> {
    let catalog = format_catalog(chain_id)
        .ok_or_else(|| Error::Env(format!("unsupported bitcoin-family chainId: {chain_id}")))?;
    let tag = if chain_id == "bitcoin-cash" { "bitcoincash" } else { chain_id };
    let child = crate::hdderive::derive_pub(account_pubkey, account_chaincode, &[0, 0])
        .map_err(|e| Error::Env(e.to_string()))?;

    let mut out = Vec::with_capacity(catalog.len());
    for (i, (kind, name)) in catalog.iter().enumerate() {
        if let Ok(address) = address_for(&child, kind, tag) {
            out.push(AddressFormat {
                kind: (*kind).to_owned(),
                name: (*name).to_owned(),
                address,
                path: "m/0/0".to_owned(),
                is_default: i == 0,
            });
        }
    }
    Ok(out)
}

/// One derived HD address on a receive/change chain (Go `scanChain` entry).
#[derive(Debug, Clone, serde::Serialize)]
pub struct HdAddress {
    pub index: u32,
    pub address: String,
    pub path: String,
    /// True for the first unused (clean) index past the highest used one.
    pub clean: bool,
}

/// The highest HD child index the wallet accepts from a node, for both the
/// `lastI` of `modchain_lookupTxoBIP32` and the index in a UTXO's `path`. The
/// node is untrusted: an unbounded `lastI` would have [`scan_chain`] derive
/// billions of addresses, or hand out a receive/change address at an index no
/// later scan reaches. Far above any real wallet's usage, far below 2^31.
pub const MAX_HD_INDEX: u32 = 100_000;

/// The `lastI` (highest used index, -1 for an unused chain) of a
/// `modchain_lookupTxoBIP32` reply. Absent means unused; anything that is not
/// an integer in `-1..=MAX_HD_INDEX` is refused.
fn parse_last_index(raw: &serde_json::Value) -> Result<i64> {
    match raw.get("lastI") {
        None | Some(serde_json::Value::Null) => Ok(-1),
        Some(v) => v
            .as_i64()
            .filter(|i| (-1..=i64::from(MAX_HD_INDEX)).contains(i))
            .ok_or_else(|| Error::Env(format!("modchain_lookupTxoBIP32: lastI {v} out of range (-1..={MAX_HD_INDEX})"))),
    }
}

/// Parse an account-relative HD path `m/<chain>/<index>` as modchain reports it
/// for a UTXO: `chain` must be 0 (receive) or 1 (change) and `index` at most
/// [`MAX_HD_INDEX`], both plain decimal.
fn parse_hd_path(path: &str) -> Result<(u32, u32)> {
    let bad = || Error::Env(format!("invalid UTXO path {path:?} (want m/<0|1>/<index up to {MAX_HD_INDEX}>)"));
    let mut parts = path.split('/');
    let (Some("m"), Some(chain), Some(index), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    let chain: u32 = match chain {
        "0" => 0,
        "1" => 1,
        _ => return Err(bad()),
    };
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let index: u32 = index.parse().ok().filter(|i| *i <= MAX_HD_INDEX).ok_or_else(bad)?;
    Ok((chain, index))
}

/// Derive addresses `0..=lastI+1` on the receive (`change=false`) or change
/// chain (Go `scanChain`): `modchain_lookupTxoBIP32` gives `lastI` (the highest
/// used index, bounded by [`MAX_HD_INDEX`]), and each index is derived +
/// encoded, the last marked `clean`.
#[cfg(not(target_arch = "wasm32"))]
pub fn scan_chain(
    rpc: &str,
    xpub: &str,
    account_pubkey: &[u8; 33],
    account_chaincode: &[u8; 32],
    chain_id: &str,
    change: bool,
) -> Result<Vec<HdAddress>> {
    let chain: u32 = if change { 1 } else { 0 };
    let base_path = format!("m/{chain}");
    let raw = crate::rpc::call(rpc, "modchain_lookupTxoBIP32", serde_json::json!([xpub, base_path, false]))?;
    let last_i = parse_last_index(&raw)?;
    let mut out = Vec::new();
    for i in 0..=(last_i + 1) {
        let index = i as u32;
        let child = crate::hdderive::derive_pub(account_pubkey, account_chaincode, &[chain, index])
            .map_err(|e| Error::Env(e.to_string()))?;
        out.push(HdAddress {
            index,
            address: hd_address(&child, chain_id)?,
            path: format!("{base_path}/{index}"),
            clean: i > last_i,
        });
    }
    Ok(out)
}

/// The next unused HD address on the receive (`change=false`) or change chain,
/// found via `modchain_lookupTxoBIP32` (returns the highest used index `lastI`)
/// and derived at `m/<chain>/<lastI+1>` below the account xpub. Port of Go
/// `accountNextAddress`. Returns `(address, index, path)`.
#[cfg(not(target_arch = "wasm32"))]
pub fn next_address(
    rpc: &str,
    xpub: &str,
    account_pubkey: &[u8; 33],
    account_chaincode: &[u8; 32],
    chain_id: &str,
    change: bool,
) -> Result<(String, u32, String)> {
    let chain: u32 = if change { 1 } else { 0 };
    let base_path = format!("m/{chain}");
    let raw = crate::rpc::call(rpc, "modchain_lookupTxoBIP32", serde_json::json!([xpub, base_path, true]))?;
    // lastI = highest used index, -1 when the chain is entirely unused.
    let last_i = parse_last_index(&raw)?;
    let next_index = (last_i + 1) as u32; // 0..=MAX_HD_INDEX+1
    let child = crate::hdderive::derive_pub(account_pubkey, account_chaincode, &[chain, next_index])
        .map_err(|e| Error::Env(e.to_string()))?;
    let address = hd_address(&child, chain_id)?;
    Ok((address, next_index, format!("{base_path}/{next_index}")))
}

/// A spendable output discovered via `modchain_assets` (Go `bitcoinTxo`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredUtxo {
    /// `"<txid>:<vout>"`.
    pub txo: String,
    /// Value in satoshi.
    pub amount_sats: u64,
    /// Block height (0 when unconfirmed).
    pub height: i64,
    /// Full HD path (`"m/0/0"`) — how the spending key is derived.
    pub path: String,
    /// Script flavor (`p2pkh`, `p2wpkh`, …).
    pub script: String,
}

/// Parse spendable NATIVE UTXOs from a decoded `modchain_assets` response
/// (RPC-free half of [`list_utxos`], shared with the async browser path). Skips
/// entries modchain marked spent; amounts decode via the BtcAmount rules.
pub fn parse_native_utxos(raw: &serde_json::Value) -> Result<Vec<DiscoveredUtxo>> {
    let assets = raw
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| Error::Env("modchain_assets: no assets array".into()))?;
    let mut out = Vec::new();
    for a in assets {
        if a.get("asset").and_then(|s| s.as_str()) != Some("NATIVE") {
            continue;
        }
        let txos = match a.get("txo").and_then(|t| t.as_array()) {
            Some(t) => t,
            None => continue,
        };
        for t in txos {
            // Spent when the "spent" field is present and non-null.
            let spent = t.get("spent").map(|s| !s.is_null()).unwrap_or(false);
            if spent {
                continue;
            }
            let txo = t.get("txo").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            if txo.is_empty() {
                continue;
            }
            let amount_sats = t.get("amt").map(parse_btc_amount).transpose()?.unwrap_or(0);
            // The path drives key derivation and the next change index, and it
            // comes from the node: refuse one that isn't m/<0|1>/<bounded index>
            // (a single-address lookup carries none).
            let path = t.get("path").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            if !path.is_empty() {
                parse_hd_path(&path).map_err(|e| Error::Env(format!("modchain_assets: {txo}: {e}")))?;
            }
            out.push(DiscoveredUtxo {
                txo,
                amount_sats,
                height: t.get("height").and_then(|v| v.as_i64()).unwrap_or(0),
                path,
                script: t.get("script").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            });
        }
    }
    Ok(out)
}

/// List the account's spendable NATIVE UTXOs from `modchain_assets(xpub)` (Go
/// `fetchBitcoinUTXOs`). Does not apply the in-memory just-spent tracker (that
/// lands with the auto-input tx builder).
#[cfg(not(target_arch = "wasm32"))]
pub fn list_utxos(rpc: &str, xpub: &str) -> Result<Vec<DiscoveredUtxo>> {
    let raw = crate::rpc::call(rpc, "modchain_assets", serde_json::json!([xpub]))?;
    parse_native_utxos(&raw)
}

/// The maximum sendable satoshi for `xpub`: sum all UTXOs and subtract the fee
/// to spend them all into a single output (Go `maxSendableBitcoin`, one output,
/// no change). Returns `(total, fee, max, inputs)` in satoshi, `inputs` being
/// the `"<txid>:<vout>"` refs spent — what a pinned max send passes back.
#[cfg(not(target_arch = "wasm32"))]
pub fn max_sendable_sats(rpc: &str, xpub: &str, fee_rate: u64) -> Result<(u64, u64, u64, Vec<String>)> {
    let utxos = list_utxos(rpc, xpub)?;
    let total = utxos
        .iter()
        .try_fold(0u64, |acc, u| acc.checked_add(u.amount_sats))
        .ok_or_else(|| Error::Env("utxo total overflows".into()))?;
    let fee = fee_sats(&utxos, 1, fee_rate)?; // one recipient, no change
    let max = total.saturating_sub(fee);
    Ok((total, fee, max, utxos.into_iter().map(|u| u.txo).collect()))
}

/// Sum the NATIVE unspent balance (satoshi) from a decoded `modchain_assets`
/// response. RPC-free half of [`native_balance_satoshi`], shared with the async
/// (browser) balance path which fetches `raw` via `rpc::call_async`.
pub fn parse_native_balance(raw: &serde_json::Value) -> Result<u64> {
    let assets = raw
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| Error::Env("modchain_assets: no assets array".into()))?;
    let mut total: u64 = 0;
    for a in assets {
        if a.get("asset").and_then(|s| s.as_str()) != Some("NATIVE") {
            continue;
        }
        if let Some(bal) = a.get("balance") {
            total = total
                .checked_add(parse_btc_amount(bal)?)
                .ok_or_else(|| Error::Env("btc balance overflow".into()))?;
        }
    }
    Ok(total)
}

/// Sum the NATIVE unspent balance (in satoshi) reported by `modchain_assets`
/// for `lookup` (an address or xpub). Port of Go `Network.bitcoinBalance`.
#[cfg(not(target_arch = "wasm32"))]
pub fn native_balance_satoshi(rpc: &str, lookup: &str) -> Result<u64> {
    let raw = crate::rpc::call(rpc, "modchain_assets", serde_json::json!([lookup]))?;
    parse_native_balance(&raw)
}

impl DiscoveredUtxo {
    /// The `(chain, index)` this UTXO's key is derived at below the account
    /// xpub. A UTXO without a path (single-address lookup) is the account's
    /// first receive address `m/0/0`; a path that isn't `m/<0|1>/<index up to
    /// MAX_HD_INDEX>` is an error.
    pub(crate) fn hd_path(&self) -> Result<(u32, u32)> {
        if self.path.is_empty() {
            return Ok((0, 0));
        }
        parse_hd_path(&self.path)
    }
    /// The HD chain (0=receive, 1=change) from the UTXO's path. An invalid
    /// path reads as `m/0/0` — [`parse_native_utxos`] never yields one; code
    /// that must not guess uses [`Self::hd_path`].
    pub(crate) fn chain(&self) -> u32 {
        self.hd_path().map(|(chain, _)| chain).unwrap_or(0)
    }
    /// The HD child index from the UTXO's path (last segment); see
    /// [`Self::chain`] for an invalid path.
    pub(crate) fn child_index(&self) -> u32 {
        self.hd_path().map(|(_, index)| index).unwrap_or(0)
    }
    /// Per-input virtual size (Go `bitcoinTxo.vsize`) for fee estimation.
    fn vsize(&self) -> u64 {
        match self.script.as_str() {
            "p2wpkh" | "p2wsh" => 68,
            "p2sh:p2wpkh" | "p2sh-p2wpkh" => 91,
            _ => 148, // p2pkh and unknown (over-estimate rather than under-pay)
        }
    }
}

/// Estimated vsize of a tx with `ins` inputs and `outs` outputs (Go
/// `estimateMixedTxVSize`): 11 overhead + 31/output + per-input vsize.
pub(crate) fn estimate_vsize(ins: &[DiscoveredUtxo], outs: u64) -> u64 {
    ins.iter().fold(outs.saturating_mul(31).saturating_add(11), |acc, u| acc.saturating_add(u.vsize()))
}

/// The fee (satoshi) for a tx of `ins` and `outs` outputs at `fee_rate` sat/vB.
/// The rate is caller-supplied (ultimately a node's estimate), so a product
/// that does not fit is an error rather than a wrapped, tiny fee.
pub(crate) fn fee_sats(ins: &[DiscoveredUtxo], outs: u64, fee_rate: u64) -> Result<u64> {
    estimate_vsize(ins, outs)
        .checked_mul(fee_rate)
        .ok_or_else(|| Error::Env(format!("fee overflows at {fee_rate} sat/vB")))
}

/// Greedy largest-first coin selection (Go `selectUTXOs`): add UTXOs until the
/// total covers `want_sats` + the size-based fee. Returns (selected, total_in).
pub(crate) fn select_utxos(all: &[DiscoveredUtxo], want_sats: u64, fee_rate: u64) -> Result<(Vec<DiscoveredUtxo>, u64)> {
    let mut sorted = all.to_vec();
    sorted.sort_by(|a, b| b.amount_sats.cmp(&a.amount_sats)); // largest first
    let mut total: u64 = 0;
    let mut out: Vec<DiscoveredUtxo> = Vec::new();
    for u in sorted {
        // Amounts come from the node and the rate from the caller: no wrapping.
        total = total.checked_add(u.amount_sats).ok_or_else(|| Error::Env("utxo total overflows".into()))?;
        out.push(u);
        let fee = fee_sats(&out, 2, fee_rate)?;
        let need = want_sats.checked_add(fee).ok_or_else(|| Error::Env("amount + fee overflows".into()))?;
        if total >= need {
            return Ok((out, total));
        }
    }
    Err(Error::Env(format!("insufficient funds: have {total} sats across {} utxos", out.len())))
}

/// The next change (m/1) index (Go `nextChangeIndex`): highest used m/1 index +1.
pub(crate) fn next_change_index(all: &[DiscoveredUtxo]) -> u32 {
    // Only a valid m/1/<index ≤ MAX_HD_INDEX> path counts, so a node cannot
    // push the change address to an index the wallet won't rediscover.
    let mut max: i64 = -1;
    for u in all {
        if let Ok((1, index)) = u.hd_path() {
            max = max.max(i64::from(index));
        }
    }
    (max + 1) as u32
}

/// A UTXO to spend.
pub struct Utxo {
    pub txid: [u8; 32], // display (big-endian) order
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

/// The known Bitcoin-family signed-message prefix `[len][magic]` for a chain,
/// or None for an unrecognized chain (Go `BitcoinMessagePrefix` + allow-list).
pub fn message_prefix(chain_id: &str) -> Option<Vec<u8>> {
    let magic = match chain_id {
        "bitcoin" | "bitcoin-cash" | "bitcoincash" => "Bitcoin Signed Message:\n",
        "litecoin" => "Litecoin Signed Message:\n",
        "dogecoin" => "Dogecoin Signed Message:\n",
        "monacoin" => "Monacoin Signed Message:\n",
        _ => return None,
    };
    let mut buf = Vec::with_capacity(1 + magic.len());
    buf.push(magic.len() as u8);
    buf.extend_from_slice(magic.as_bytes());
    Some(buf)
}

/// The digest a Bitcoin-family signed message is made over:
/// `double_sha256(prefix || varint(len(message)) || message)`. None for a chain
/// with no known prefix.
pub(crate) fn message_digest(chain_id: &str, message: &[u8]) -> Option<[u8; 32]> {
    let mut full = message_prefix(chain_id)?;
    append_varint(&mut full, message.len() as u64);
    full.extend_from_slice(message);
    Some(outscript::hash::dsha256(&full))
}

/// Sign a Bitcoin-family message (Go `Account.SignBitcoinMessage`): the digest
/// is `double_sha256(prefix || varint(len(message)) || message)`, DKLs-signed;
/// the recovery id is brute-forced against the account's pubkey and the result
/// packed as the 65-byte compact form `[31+recid][r][s]` (compressed-address
/// header offset).
pub fn sign_message(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    chain_id: &str,
    message: &[u8],
) -> Result<Vec<u8>> {
    let digest = message_digest(chain_id, message)
        .ok_or_else(|| Error::Env("unknown Bitcoin-family message prefix (chain not in allow-list)".into()))?;

    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    let pub_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&acct.pubkey).map_err(|e| Error::Env(format!("bad account pubkey: {e}")))?
    };
    let tweak = il_to_tweak(&acct.il)?;
    let (r, s, _v) = crate::models::wallet::dkls_sign_digest_at(env, &acct.wallet, unlock, &acct.path, &tweak, &digest)?;
    let r32 = pad32(&r);
    let s32 = pad32(&s);

    // Brute-force the recovery id (the TSS→DER path drops it): pick the recid
    // whose recovered pubkey matches the account's compressed key.
    let recid = (0u8..4)
        .find(|&rid| recover_compressed(&digest, &r32, &s32, rid).map(|c| c[..] == pub_bytes[..]).unwrap_or(false))
        .ok_or_else(|| Error::Env("could not determine signature recovery code".into()))?;

    let mut compact = Vec::with_capacity(65);
    compact.push(31 + recid);
    compact.extend_from_slice(&r32);
    compact.extend_from_slice(&s32);
    Ok(compact)
}

/// Whether `sig` — a 65-byte compact (BIP-137) signature, `[header][r][s]` —
/// is `pubkey`'s (33-byte compressed) over `message` on `chain_id`. The
/// header's address-type bits are ignored: only the key matters.
pub fn verify_message_compact(chain_id: &str, message: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    let (Some(digest), true) = (message_digest(chain_id, message), sig.len() == 65 && (27..=42).contains(&sig[0])) else { return false };
    let recid = (sig[0] - 27) & 3;
    let (Ok(r), Ok(s)) = (<[u8; 32]>::try_from(&sig[1..33]), <[u8; 32]>::try_from(&sig[33..65])) else { return false };
    recover_compressed(&digest, &r, &s, recid).is_some_and(|c| c[..] == pubkey[..])
}

/// Recover the compressed signer pubkey from `(r, s, recid)` over `digest`.
fn recover_compressed(digest: &[u8; 32], r32: &[u8; 32], s32: &[u8; 32], recid: u8) -> Option<[u8; 33]> {
    use purecrypto::bignum::BoxedUint;
    use purecrypto::ec::boxed::BoxedEcdsaSignature;
    use purecrypto::ec::CurveId;
    let sig = BoxedEcdsaSignature::from_components(BoxedUint::from_be_bytes(r32), BoxedUint::from_be_bytes(s32));
    let pk = sig.recover_prehash(CurveId::Secp256k1, digest, recid).ok()?;
    purecrypto::ec::secp256k1::AffinePoint::from_sec1(&pk.to_sec1()).ok().map(|p| p.to_sec1_compressed())
}

/// Append a Bitcoin-style variable-length integer.
fn append_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// A signer that routes ECDSA signing to the wallet's DKLs shares under a fixed
/// derivation tweak, verifying each signature under the derived public key.
struct TssSigner<'a> {
    pubkey: SecpPublicKey,
    sign_digest: Box<dyn Fn(&[u8; 32]) -> std::result::Result<(Vec<u8>, Vec<u8>), String> + 'a>,
    /// Why this signer last refused. outscript's `SignerError` is a unit struct
    /// carrying no message, so without this a threshold-verification failure
    /// would reach the caller as a bare "signer failed" — see [`sign_failed`].
    last_error: RefCell<Option<String>>,
}

impl<'a> TssSigner<'a> {
    /// Record `msg` and refuse.
    fn fail(&self, msg: String) -> SignerError {
        *self.last_error.borrow_mut() = Some(msg);
        SignerError
    }
}

impl<'a> Signer for TssSigner<'a> {
    fn ecdsa_public_key(&self) -> Option<SecpPublicKey> {
        SecpPublicKey::from_sec1(&self.pubkey.serialize_compressed()).ok()
    }

    fn sign_ecdsa_der(&self, digest: &[u8; 32]) -> std::result::Result<DerSignature, SignerError> {
        let (r, s) = (self.sign_digest)(digest).map_err(|e| self.fail(e))?;
        let r32 = pad32(&r);
        let s32 = pad32(&s);
        if !self.pubkey.verify(digest, &r32, &s32) {
            return Err(self.fail("threshold signature failed to verify under the derived key".into()));
        }
        // outscript owns the DER encoding as of 0.2.5 (`der_encode` here was its
        // twin). The trait's contract is a low-S signature; tsslib normalizes it
        // for both DKLs and GG18 and every sign_digest closure re-applies
        // normalize_low_s, so the low-S step is a no-op — it just keeps the
        // guarantee enforced at the boundary rather than assumed.
        DerSignature::from_rs_low_s(&r32, &s32).map_err(|e| self.fail(format!("DER encode: {e}")))
    }
}

/// Turn a `BtcTx::sign` failure back into the signer's own diagnosis: outscript
/// reports every refusal as `Error::Signer`, so recover the message the
/// [`TssSigner`] recorded and fall back to the generic mapping otherwise.
fn sign_failed(signers: &[TssSigner], e: outscript::Error) -> Error {
    for s in signers {
        if let Some(msg) = s.last_error.borrow().clone() {
            return Error::Env(msg);
        }
    }
    oserr(e)
}

/// Build and DKLs-sign a transaction spending `utxos` to `outputs` (each
/// `(address, sats)`). `unlock` provides the Password creds for all wallet
/// shares. Returns the raw signed transaction bytes.
///
/// Each UTXO's spend flavor follows its `script_pubkey`: a supplied script is
/// spent as legacy P2PKH (the caller vouches for the prevout); an EMPTY script
/// means "a self-spend of the account's own coins", so we derive the account's
/// native-SegWit (P2WPKH) scriptPubKey from its key — this is the offline path
/// the browser drives with only `{txid, vout, amount}` (no RPC, no script
/// lookup), matching how `build_and_sign_auto` treats the account's own UTXOs.
///
/// This entry point has no chain context, so output addresses are parsed with
/// outscript's network auto-detection: an address of ANOTHER Bitcoin-family
/// chain is accepted. Callers that know the chain being spent must use
/// [`sign_transfer_on_chain`], which refuses such an address.
pub fn sign_transfer(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    utxos: &[Utxo],
    outputs: &[(String, u64)],
) -> Result<Vec<u8>> {
    sign_transfer_inner(env, account_id, unlock, None, utxos, outputs)
}

/// [`sign_transfer`] for a known chain: every output address must be an address
/// of `chain_id` (`bitcoin`, `litecoin`, `dogecoin`, `monacoin`,
/// `bitcoin-cash`), so a send cannot be pointed at another chain's address.
pub fn sign_transfer_on_chain(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    chain_id: &str,
    utxos: &[Utxo],
    outputs: &[(String, u64)],
) -> Result<Vec<u8>> {
    sign_transfer_inner(env, account_id, unlock, Some(chain_id), utxos, outputs)
}

fn sign_transfer_inner(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    chain_id: Option<&str>,
    utxos: &[Utxo],
    outputs: &[(String, u64)],
) -> Result<Vec<u8>> {
    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    let pub_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&acct.pubkey)
            .map_err(|e| Error::Env(format!("bad account pubkey: {e}")))?
    };
    let pubkey = SecpPublicKey::from_sec1(&pub_bytes).map_err(|e| Error::Env(format!("{e:?}")))?;
    let tweak = il_to_tweak(&acct.il)?;
    let wallet_id = acct.wallet.clone();
    let key_path = acct.path.clone(); // mnemonic wallets derive the account node here

    let signer = TssSigner {
        pubkey,
        last_error: RefCell::new(None),
        sign_digest: Box::new(move |digest: &[u8; 32]| {
            let (r, s, v) = crate::models::wallet::dkls_sign_digest_at(env, &wallet_id, unlock, &key_path, &tweak, digest)
                .map_err(|e| e.to_string())?;
            let (s, _) = normalize_low_s(s, v);
            Ok((r, s))
        }),
    };

    let mut tx = BtcTx { version: 2, locktime: 0, ..BtcTx::default() };
    for u in utxos {
        tx.inputs.push(BtcTxInput {
            txid: u.txid,
            vout: u.vout,
            script: Vec::new(),
            sequence: 0xffff_ffff,
            witnesses: Vec::new(),
        });
    }
    for (address, sats) in outputs {
        match chain_id {
            Some(chain_id) => add_chain_output(&mut tx, chain_id, address, *sats)?,
            None => tx.add_output(address, *sats).map_err(oserr)?,
        }
    }

    // The account's own P2WPKH scriptPubKey, derived once for self-spend inputs
    // (UTXOs with an empty script). Same construction as build_and_sign_auto.
    let p2wpkh_script = {
        let pk = SecpPublicKey::from_sec1(&pub_bytes).map_err(|e| Error::Env(format!("{e:?}")))?;
        outscript::script::Script::new(pk).out("p2wpkh").map_err(oserr)?.bytes().to_vec()
    };
    let signs: Vec<BtcTxSign> = utxos
        .iter()
        .map(|u| {
            if u.script_pubkey.is_empty() {
                BtcTxSign::new(&signer, "p2wpkh").amount(u.amount).prev_script(p2wpkh_script.clone())
            } else {
                BtcTxSign::new(&signer, "p2pkh").amount(u.amount).prev_script(u.script_pubkey.clone())
            }
        })
        .collect();
    tx.sign(&signs).map_err(|e| sign_failed(std::slice::from_ref(&signer), e))?;
    Ok(tx.to_bytes())
}

/// Parse a `"<txid>:<vout>"` ref into (32-byte big-endian display txid, vout).
/// outscript reverses to wire order itself, so we keep display order here.
pub(crate) fn parse_txo_ref(ref_: &str) -> Result<([u8; 32], u32)> {
    let (txid_hex, vout_s) = ref_
        .split_once(':')
        .ok_or_else(|| Error::Env(format!("invalid txo ref {ref_}")))?;
    let bytes = (0..txid_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(txid_hex.get(i..i + 2).unwrap_or(""), 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|e| Error::Env(format!("bad txid hex: {e}")))?;
    let txid: [u8; 32] = bytes.try_into().map_err(|_| Error::Env("txid must be 32 bytes".into()))?;
    let vout: u32 = vout_s.parse().map_err(|_| Error::Env("bad vout".into()))?;
    Ok((txid, vout))
}

/// Reduce (account_il + child_tweak) mod n into a 32-byte tweak — the total
/// derivation from the wallet root to an input's key (Go `finalIL`).
fn combine_tweak(account_il: &BigInt, child_tweak: &[u8; 32]) -> [u8; 32] {
    let child = BigInt::from_bytes_be(Sign::Plus, child_tweak);
    let sum = ((account_il + child) % secp_n() + secp_n()) % secp_n();
    pad32(&sum.to_bytes_be().1)
}

/// Discover UTXOs, select inputs, build change/fee, and DKLs-sign a full Bitcoin
/// transaction to `recipient` for `want_sats` (Go `wlttx` bitcoin send path).
/// Each input is signed under its own HD-derived key (m/chain/index below the
/// account xpub) with the combined wallet-root tweak; TssSigner self-verifies
/// every signature. `fee_rate_sat_vb` is the pinned rate (or a caller default).
/// Returns the raw signed transaction bytes.
/// Native auto-input path: discover the account's UTXOs via modchain, then hand
/// off to the offline core. The browser drives the same core over call_async
/// (see [`build_and_sign_from_utxos`]).
#[allow(clippy::too_many_arguments)]
#[cfg(not(target_arch = "wasm32"))]
pub fn build_and_sign_auto(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    rpc: &str,
    chain_id: &str,
    recipient: &str,
    want_sats: u64,
    fee_rate_sat_vb: u64,
) -> Result<Vec<u8>> {
    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    let xpub = acct.xpub()?;
    let all = list_utxos(rpc, &xpub)?;
    build_and_sign_from_utxos(env, account_id, unlock, chain_id, recipient, want_sats, fee_rate_sat_vb, &all)
}

/// Offline core of the auto-input send: given the account's discovered UTXOs
/// `all`, select inputs, add change/fee, derive each input's HD key, DKLs-sign
/// (TssSigner self-verifies), and return the raw signed tx. NO RPC — the browser
/// fetches `all` via `modchain_assets`/`call_async` and calls this, so native
/// and wasm share one Bitcoin builder. `fee_rate_sat_vb` is the pinned rate.
#[allow(clippy::too_many_arguments)]
pub fn build_and_sign_from_utxos(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    chain_id: &str,
    recipient: &str,
    want_sats: u64,
    fee_rate_sat_vb: u64,
    all: &[DiscoveredUtxo],
) -> Result<Vec<u8>> {
    use base64::Engine;
    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    if acct.kind != "bitcoin" {
        return Err(Error::Env("account is not bitcoin".into()));
    }
    let account_pub: [u8; 33] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&acct.pubkey)
        .map_err(|e| Error::Env(format!("bad account pubkey: {e}")))?
        .try_into()
        .map_err(|_| Error::Env("account pubkey not 33 bytes".into()))?;
    let account_cc: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&acct.chaincode)
        .map_err(|e| Error::Env(format!("bad chaincode: {e}")))?
        .try_into()
        .map_err(|_| Error::Env("chaincode not 32 bytes".into()))?;
    let account_il = {
        let s = acct.il.as_str().unwrap_or("0");
        BigInt::parse_bytes(s.as_bytes(), 10).unwrap_or_else(|| BigInt::from(0))
    };
    let wallet_id = acct.wallet.clone();
    let key_path = acct.path.clone(); // mnemonic wallets derive the account node here

    // 1. Select inputs from the discovered UTXOs.
    if all.is_empty() {
        return Err(Error::Env("no spendable UTXOs".into()));
    }
    let (selected, total_in) = select_utxos(all, want_sats, fee_rate_sat_vb)?;

    // 2. Fee + change (dust threshold 546 sat), 2-output size estimate.
    let fee = fee_sats(&selected, 2, fee_rate_sat_vb)?;
    let change = want_sats
        .checked_add(fee)
        .and_then(|need| total_in.checked_sub(need))
        .ok_or_else(|| Error::Env(format!("insufficient funds: {total_in} < {want_sats} + fee {fee}")))?;

    // 3. Per-input signer: derive each input's key + combined tweak.
    struct InputPlan {
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        scheme: String,
        child_pub: [u8; 33],
        tweak: [u8; 32],
    }
    let mut plans = Vec::with_capacity(selected.len());
    for u in &selected {
        let (txid, vout) = parse_txo_ref(&u.txo)?;
        let (chain, index) = u.hd_path()?;
        let (child_pub, child_tweak) =
            crate::hdderive::derive_pub_tweak(&account_pub, &account_cc, &[chain, index])
                .map_err(|e| Error::Env(e.to_string()))?;
        let scheme = if u.script.is_empty() { "p2wpkh".to_owned() } else { u.script.clone() };
        plans.push(InputPlan {
            txid,
            vout,
            amount: u.amount_sats,
            scheme,
            child_pub,
            tweak: combine_tweak(&account_il, &child_tweak),
        });
    }

    // bitcoin-cash requires SIGHASH_FORKID.
    let sighash: u32 = if chain_id == "bitcoin-cash" { 0x41 } else { 0 };

    // Build the signers (self-verifying) and their prev scripts.
    let signers: Vec<TssSigner> = plans
        .iter()
        .map(|p| {
            let pubkey = SecpPublicKey::from_sec1(&p.child_pub)
                .map_err(|e| Error::Env(format!("bad child pubkey: {e:?}")))?;
            let wid = wallet_id.clone();
            let kpath = key_path.clone();
            let tweak = p.tweak;
            Ok(TssSigner {
                pubkey,
                last_error: RefCell::new(None),
                sign_digest: Box::new(move |digest: &[u8; 32]| {
                    let (r, s, v) = crate::models::wallet::dkls_sign_digest_at(env, &wid, unlock, &kpath, &tweak, digest)
                        .map_err(|e| e.to_string())?;
                    let (s, _) = normalize_low_s(s, v);
                    Ok((r, s))
                }),
            })
        })
        .collect::<Result<_>>()?;

    // 4. Assemble the tx.
    let mut tx = BtcTx { version: 2, locktime: 0, ..BtcTx::default() };
    for p in &plans {
        tx.inputs.push(BtcTxInput {
            txid: p.txid,
            vout: p.vout,
            script: Vec::new(),
            sequence: 0xffff_fffd, // RBF
            witnesses: Vec::new(),
        });
    }
    // The recipient must be an address of the chain being spent (not merely a
    // parseable Bitcoin-family address); the change address is our own.
    add_chain_output(&mut tx, chain_id, recipient, want_sats)?;
    if change > 546 {
        let change_addr = {
            let idx = next_change_index(all);
            let (child, _) = crate::hdderive::derive_pub_tweak(&account_pub, &account_cc, &[1, idx])
                .map_err(|e| Error::Env(e.to_string()))?;
            hd_address(&child, chain_id)?
        };
        add_chain_output(&mut tx, chain_id, &change_addr, change)?;
    }

    // 5. Sign every input under its own key + scheme.
    let signs: Vec<BtcTxSign> = plans
        .iter()
        .zip(&signers)
        .map(|(p, signer)| {
            let prev_script = outscript::script::Script::new(
                SecpPublicKey::from_sec1(&p.child_pub).map_err(|e| Error::Env(format!("{e:?}")))?,
            )
            .out(&p.scheme)
            .map_err(oserr)?
            .bytes()
            .to_vec();
            let mut s = BtcTxSign::new(signer, &p.scheme).amount(p.amount).prev_script(prev_script);
            s.sighash = sighash;
            Ok(s)
        })
        .collect::<Result<_>>()?;
    tx.sign(&signs).map_err(|e| sign_failed(&signers, e))?;
    Ok(tx.to_bytes())
}

/// Sign a caller-provided raw Bitcoin transaction (Go `SignRawBitcoinTx`, behind
/// mpurse_signRawTransaction): parse it, fetch the account's UTXOs to resolve
/// each input's derivation path + amount + script, sign every input under its
/// own derived key, and return the signed raw bytes. Every input must be a UTXO
/// owned by `account_id`.
#[cfg(not(target_arch = "wasm32"))]
pub fn sign_raw_tx(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    rpc: &str,
    chain_id: &str,
    raw_tx: &[u8],
) -> Result<Vec<u8>> {
    use base64::Engine;
    let mut btx = BtcTx::from_bytes(raw_tx).map_err(oserr)?;
    if btx.inputs.is_empty() {
        return Err(Error::Env("tx has no inputs".into()));
    }
    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    if acct.kind != "bitcoin" {
        return Err(Error::Env("account is not bitcoin".into()));
    }
    let account_pub: [u8; 33] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&acct.pubkey).map_err(|e| Error::Env(format!("bad account pubkey: {e}")))?
        .try_into().map_err(|_| Error::Env("account pubkey not 33 bytes".into()))?;
    let account_cc: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&acct.chaincode).map_err(|e| Error::Env(format!("bad chaincode: {e}")))?
        .try_into().map_err(|_| Error::Env("chaincode not 32 bytes".into()))?;
    let account_il = BigInt::parse_bytes(acct.il.as_str().unwrap_or("0").as_bytes(), 10).unwrap_or_else(|| BigInt::from(0));
    let wallet_id = acct.wallet.clone();
    let key_path = acct.path.clone(); // mnemonic wallets derive the account node here

    // UTXO set → txo ref → derivation/amount/script.
    let xpub = build_xpub(&account_pub, &account_cc);
    let utxos = list_utxos(rpc, &xpub)?;
    let owned: std::collections::HashMap<String, &DiscoveredUtxo> = utxos.iter().map(|u| (u.txo.clone(), u)).collect();
    let sighash: u32 = if chain_id == "bitcoin-cash" { 0x41 } else { 0 };

    struct Plan {
        child_pub: [u8; 33],
        tweak: [u8; 32],
        amount: u64,
        scheme: String,
    }
    let mut plans = Vec::with_capacity(btx.inputs.len());
    for inp in &btx.inputs {
        let txid_hex: String = inp.txid.iter().map(|b| format!("{b:02x}")).collect();
        let reference = format!("{txid_hex}:{}", inp.vout);
        let u = owned.get(&reference).ok_or_else(|| Error::Env(format!("input {reference} is not owned by this account")))?;
        let (chain, index) = u.hd_path()?;
        let (child_pub, child_tweak) = crate::hdderive::derive_pub_tweak(&account_pub, &account_cc, &[chain, index])
            .map_err(|e| Error::Env(e.to_string()))?;
        let scheme = if u.script.is_empty() { "p2wpkh".to_owned() } else { u.script.clone() };
        plans.push(Plan { child_pub, tweak: combine_tweak(&account_il, &child_tweak), amount: u.amount_sats, scheme });
    }

    let signers: Vec<TssSigner> = plans
        .iter()
        .map(|p| {
            let pubkey = SecpPublicKey::from_sec1(&p.child_pub).map_err(|e| Error::Env(format!("bad child pubkey: {e:?}")))?;
            let wid = wallet_id.clone();
            let kpath = key_path.clone();
            let tweak = p.tweak;
            Ok(TssSigner {
                pubkey,
                last_error: RefCell::new(None),
                sign_digest: Box::new(move |digest: &[u8; 32]| {
                    let (r, s, v) = crate::models::wallet::dkls_sign_digest_at(env, &wid, unlock, &kpath, &tweak, digest).map_err(|e| e.to_string())?;
                    let (s, _) = normalize_low_s(s, v);
                    Ok((r, s))
                }),
            })
        })
        .collect::<Result<_>>()?;

    let signs: Vec<BtcTxSign> = plans
        .iter()
        .zip(&signers)
        .map(|(p, signer)| {
            let prev_script = outscript::script::Script::new(SecpPublicKey::from_sec1(&p.child_pub).map_err(|e| Error::Env(format!("{e:?}")))?)
                .out(&p.scheme).map_err(oserr)?.bytes().to_vec();
            let mut s = BtcTxSign::new(signer, &p.scheme).amount(p.amount).prev_script(prev_script);
            s.sighash = sighash;
            Ok(s)
        })
        .collect::<Result<_>>()?;
    btx.sign(&signs).map_err(|e| sign_failed(&signers, e))?;
    Ok(btx.to_bytes())
}

fn il_to_tweak(il: &serde_json::Value) -> Result<[u8; 32]> {
    // Null/absent IL = null derivation: the account IS the group key, so the
    // tweak is zero (child at tweak 0 == the group key).
    let Some(dec) = il.as_str() else { return Ok([0u8; 32]) };
    let n = BigInt::parse_bytes(dec.as_bytes(), 10).ok_or_else(|| Error::Env("bad IL".into()))?;
    Ok(pad32(&n.to_bytes_be().1))
}

fn pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = b.len().min(32);
    out[32 - n..].copy_from_slice(&b[b.len() - n..]);
    out
}

fn secp_n() -> BigInt {
    BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}

fn normalize_low_s(s: Vec<u8>, v: u8) -> (Vec<u8>, u8) {
    let n = secp_n();
    let half = &n >> 1;
    let sv = BigInt::from_bytes_be(Sign::Plus, &s);
    if sv > half {
        (pad32(&(&n - &sv).to_bytes_be().1).to_vec(), v ^ 1)
    } else {
        (s, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{account, wallet};
    use crate::sign::KeyDescription;
    use crate::Env;
    use base64::Engine;

    fn pw(p: &str) -> KeyDescription {
        KeyDescription { kind: "Password".into(), key: p.into(), id: String::new() }
    }

    #[test]
    fn btc_transfer_signs_and_self_verifies() {
        let env = Env::init_memory().unwrap();
        wallet::init(&env).unwrap();
        account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = account::create(&env, &w.id, "", "bitcoin", 0).unwrap();

        // The UTXO we spend pays to the account's own P2PKH scriptPubKey.
        let pub_bytes =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&a.pubkey).unwrap();
        let h160 = outscript::hash::hash160(&pub_bytes);
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&h160);
        script.extend_from_slice(&[0x88, 0xac]);

        let utxos = vec![Utxo { txid: [0x11; 32], vout: 0, amount: 100_000, script_pubkey: script }];
        let outputs = vec![(a.address.clone(), 90_000u64)]; // to self, 10k fee

        let unlock: Vec<(String, String)> = vec![
            (w.keys[0].id.clone(), "passwordone".to_string()),
            (w.keys[1].id.clone(), "passwordtwo".to_string()),
            (w.keys[2].id.clone(), "passwordthree".to_string()),
        ];

        // If the DKLs signature didn't verify as valid ECDSA under the derived
        // key, the signer errors and sign_transfer fails.
        let raw = sign_transfer(&env, &a.id, &unlock, &utxos, &outputs).expect("sign+self-verify");
        assert!(!raw.is_empty());

        let parsed = BtcTx::from_bytes(&raw).expect("valid tx");
        assert_eq!(parsed.inputs.len(), 1);
        assert!(!parsed.inputs[0].script.is_empty(), "input scriptSig populated");
    }

    #[test]
    fn btc_transfer_p2wpkh_self_spend_signs() {
        // A UTXO with an EMPTY prevout script is a self-spend of the account's
        // own coins: sign_transfer derives the account's P2WPKH scriptPubKey from
        // its key (the offline path the browser drives with only txid/vout/amount).
        // The signed input carries a SegWit witness, not a scriptSig.
        let env = Env::init_memory().unwrap();
        wallet::init(&env).unwrap();
        account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = account::create(&env, &w.id, "", "bitcoin", 0).unwrap();

        let utxos = vec![Utxo { txid: [0x22; 32], vout: 0, amount: 100_000, script_pubkey: Vec::new() }];
        let outputs = vec![(a.address.clone(), 90_000u64)]; // to self, 10k fee
        let unlock: Vec<(String, String)> = vec![
            (w.keys[0].id.clone(), "passwordone".to_string()),
            (w.keys[1].id.clone(), "passwordtwo".to_string()),
            (w.keys[2].id.clone(), "passwordthree".to_string()),
        ];

        let raw = sign_transfer(&env, &a.id, &unlock, &utxos, &outputs).expect("p2wpkh sign+self-verify");
        let parsed = BtcTx::from_bytes(&raw).expect("valid tx");
        assert_eq!(parsed.inputs.len(), 1);
        assert!(parsed.inputs[0].script.is_empty(), "p2wpkh input has empty scriptSig");
        assert!(!parsed.inputs[0].witnesses.is_empty(), "p2wpkh input carries a witness");
    }

    /// One-shot mock serving a single modchain_assets JSON-RPC result.
    fn mock_rpc(result_json: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}/")
    }

    #[test]
    fn btc_auto_build_signs_all_inputs_and_self_verifies() {
        // Full auto-input path: discover UTXOs at their HD paths, select, build
        // change, and sign each input under its own derived key. Each TssSigner
        // self-verifies, so success proves the per-input combined-tweak signing.
        let env = Env::init_memory().unwrap();
        wallet::init(&env).unwrap();
        account::init(&env).unwrap();
        crate::models::network::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = account::create(&env, &w.id, "", "bitcoin", 0).unwrap();

        // Two UTXOs on different HD paths (receive m/0/0 and change m/1/2), so
        // both the multi-path key derivation and change-index logic are used.
        let rpc = mock_rpc(
            r#"{"assets":[{"asset":"NATIVE","txo":[
                {"txo":"1111111111111111111111111111111111111111111111111111111111111111:0","amt":"0.00080000","path":"m/0/0","script":"p2wpkh"},
                {"txo":"2222222222222222222222222222222222222222222222222222222222222222:1","amt":"0.00050000","path":"m/1/2","script":"p2wpkh"}
            ]}]}"#,
        );

        let unlock: Vec<(String, String)> = vec![
            (w.keys[0].id.clone(), "passwordone".to_string()),
            (w.keys[1].id.clone(), "passwordtwo".to_string()),
            (w.keys[2].id.clone(), "passwordthree".to_string()),
        ];

        // Send 0.001 BTC to the account's own address; forces both UTXOs in.
        let raw = build_and_sign_auto(&env, &a.id, &unlock, &rpc, "bitcoin", &a.address, 100_000, 5)
            .expect("auto build + sign + self-verify");
        assert!(!raw.is_empty());

        let parsed = BtcTx::from_bytes(&raw).expect("valid tx");
        assert_eq!(parsed.inputs.len(), 2, "both UTXOs selected");
        // recipient + change outputs.
        assert_eq!(parsed.outputs.len(), 2, "recipient + change");
        // Every input got a witness (p2wpkh) — signed successfully.
        assert!(parsed.inputs.iter().all(|i| !i.witnesses.is_empty()), "witnesses populated");
    }

    /// A valid compressed pubkey to encode addresses of every chain from.
    fn any_pubkey() -> [u8; 33] {
        crate::hdderive::derive_pubkey_for_path(&[7u8; 64], "secp256k1", "m/44'/0'/0'/0/0")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn outputs_must_be_addresses_of_the_chain_being_spent() {
        // (chain id, an address of that chain) for every supported chain, in
        // each address format the wallet hands out, plus a testnet address.
        let pk = any_pubkey();
        let own: Vec<(&str, String)> = vec![
            ("bitcoin", address_for(&pk, "p2wpkh", "bitcoin").unwrap()),
            ("bitcoin", address_for(&pk, "p2sh:p2wpkh", "bitcoin").unwrap()),
            ("bitcoin", address_for(&pk, "p2pkh", "bitcoin").unwrap()),
            ("litecoin", address_for(&pk, "p2wpkh", "litecoin").unwrap()),
            ("litecoin", address_for(&pk, "p2pkh", "litecoin").unwrap()),
            ("monacoin", address_for(&pk, "p2wpkh", "monacoin").unwrap()),
            ("dogecoin", address_for(&pk, "p2pkh", "dogecoin").unwrap()),
            ("bitcoin-cash", address_for(&pk, "p2pkh", "bitcoincash").unwrap()),
        ];
        for (chain, addr) in &own {
            let mut tx = BtcTx::default();
            add_chain_output(&mut tx, chain, addr, 1000).unwrap_or_else(|e| panic!("{chain} {addr}: {e}"));
            // The HD address the wallet derives for a chain is always spendable to.
            let hd = hd_address(&pk, chain).unwrap();
            add_chain_output(&mut tx, chain, &hd, 1000).unwrap_or_else(|e| panic!("{chain} {hd}: {e}"));
            assert_eq!(tx.outputs.len(), 2);
        }
        // An address of another chain is refused, whatever its script type.
        // (bitcoin-cash legitimately shares Bitcoin's legacy base58 addresses.)
        for (chain, _) in &own {
            for (other, addr) in &own {
                let shared_legacy = *chain == "bitcoin-cash" && *other == "bitcoin" && !addr.starts_with("bc1");
                if chain == other || shared_legacy {
                    continue;
                }
                let mut tx = BtcTx::default();
                assert!(add_chain_output(&mut tx, chain, addr, 1000).is_err(), "{chain} send accepted {other} address {addr}");
                assert!(tx.outputs.is_empty());
            }
        }
        let testnet = address_for(&pk, "p2wpkh", "bitcoin-testnet").unwrap();
        assert!(testnet.starts_with("tb1"));
        for chain in ["bitcoin", "litecoin", "monacoin", "dogecoin", "bitcoin-cash"] {
            assert!(add_chain_output(&mut BtcTx::default(), chain, &testnet, 1000).is_err(), "{chain} accepted {testnet}");
        }
        // No silent fallback to auto-detection for a chain we don't know.
        let btc = &own[0].1;
        assert!(add_chain_output(&mut BtcTx::default(), "bitcoin-testnet", btc, 1000).is_err());
        assert!(add_chain_output(&mut BtcTx::default(), "", btc, 1000).is_err());
    }

    #[test]
    fn btc_send_refuses_another_chains_recipient() {
        let env = Env::init_memory().unwrap();
        wallet::init(&env).unwrap();
        account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = account::create(&env, &w.id, "", "bitcoin", 0).unwrap();
        let unlock: Vec<(String, String)> = vec![
            (w.keys[0].id.clone(), "passwordone".to_string()),
            (w.keys[1].id.clone(), "passwordtwo".to_string()),
            (w.keys[2].id.clone(), "passwordthree".to_string()),
        ];
        let all = vec![DiscoveredUtxo {
            txo: format!("{}:0", "11".repeat(32)),
            amount_sats: 100_000,
            height: 1,
            path: "m/0/0".into(),
            script: "p2wpkh".into(),
        }];
        let ltc = address_for(&any_pubkey(), "p2wpkh", "litecoin").unwrap();
        assert!(ltc.starts_with("ltc1"));

        // Auto-input path: an LTC address on a BTC send (and a BTC one on LTC).
        let err = build_and_sign_from_utxos(&env, &a.id, &unlock, "bitcoin", &ltc, 50_000, 5, &all).unwrap_err();
        assert!(err.to_string().contains("invalid bitcoin address"), "{err}");
        assert!(build_and_sign_from_utxos(&env, &a.id, &unlock, "litecoin", &a.address, 50_000, 5, &all).is_err());
        build_and_sign_from_utxos(&env, &a.id, &unlock, "bitcoin", &a.address, 50_000, 5, &all).expect("own-chain send");

        // Explicit-UTXO path with a chain.
        let utxos = vec![Utxo { txid: [0x22; 32], vout: 0, amount: 100_000, script_pubkey: Vec::new() }];
        assert!(sign_transfer_on_chain(&env, &a.id, &unlock, "bitcoin", &utxos, &[(ltc.clone(), 90_000)]).is_err());
        assert!(sign_transfer_on_chain(&env, &a.id, &unlock, "nonsense", &utxos, &[(a.address.clone(), 90_000)]).is_err());
        sign_transfer_on_chain(&env, &a.id, &unlock, "bitcoin", &utxos, &[(a.address.clone(), 90_000)]).expect("own-chain send");
    }

    #[test]
    fn node_supplied_hd_indexes_are_bounded() {
        let j = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        // lastI: absent/null = unused chain; otherwise an integer in -1..=MAX.
        assert_eq!(parse_last_index(&j("{}")).unwrap(), -1);
        assert_eq!(parse_last_index(&j(r#"{"lastI":null}"#)).unwrap(), -1);
        assert_eq!(parse_last_index(&j(r#"{"lastI":-1}"#)).unwrap(), -1);
        assert_eq!(parse_last_index(&j(r#"{"lastI":4}"#)).unwrap(), 4);
        assert_eq!(parse_last_index(&j(r#"{"lastI":100000}"#)).unwrap(), 100_000);
        for bad in ["100001", "3000000000", "-2", "18446744073709551615", "1.5", "\"7\"", "[1]"] {
            assert!(parse_last_index(&j(&format!(r#"{{"lastI":{bad}}}"#))).is_err(), "lastI {bad}");
        }

        // UTXO paths: m/<0|1>/<index ≤ MAX>, nothing else.
        assert_eq!(parse_hd_path("m/0/0").unwrap(), (0, 0));
        assert_eq!(parse_hd_path("m/1/100000").unwrap(), (1, 100_000));
        for bad in [
            "m/1/100001", "m/1/2000000000", "m/1/4294967296", "m/2/0", "m/2147483648/0", "m/0'/0", "m/0/0'",
            "m/0", "m/0/0/0", "0/0", "m//0", "m/0/", "m/0/+1", "m/0/ 1", "m/0/-1", "M/0/0", "m/0/é", "",
        ] {
            assert!(parse_hd_path(bad).is_err(), "path {bad:?}");
        }

        // A hostile path fails the whole modchain_assets reply rather than
        // steering key derivation or the change index.
        let assets = |path: &str| {
            j(&format!(r#"{{"assets":[{{"asset":"NATIVE","txo":[{{"txo":"aa:0","amt":"0.001","path":"{path}","script":"p2wpkh"}}]}}]}}"#))
        };
        assert_eq!(parse_native_utxos(&assets("m/1/7")).unwrap()[0].hd_path().unwrap(), (1, 7));
        assert!(parse_native_utxos(&assets("m/1/2000000000")).is_err());
        assert!(parse_native_utxos(&assets("m/5/1")).is_err());
        // No path at all (single-address lookup) is still the account's m/0/0.
        let no_path = parse_native_utxos(&assets("")).unwrap();
        assert_eq!(no_path[0].hd_path().unwrap(), (0, 0));

        // A hand-built UTXO with a bad path never moves the change index, and
        // the accessors don't hand its numbers out.
        let utxo = |path: &str| DiscoveredUtxo { txo: "aa:0".into(), amount_sats: 1, height: 0, path: path.into(), script: String::new() };
        assert_eq!(next_change_index(&[utxo("m/1/2"), utxo("m/0/9")]), 3);
        assert_eq!(next_change_index(&[utxo("m/1/2"), utxo("m/1/2000000000"), utxo("m/1/4294967295")]), 3);
        assert_eq!(next_change_index(&[]), 0);
        let hostile = utxo("m/1/2000000000");
        assert!(hostile.hd_path().is_err());
        assert_eq!((hostile.chain(), hostile.child_index()), (0, 0));
    }

    #[test]
    fn scan_and_next_address_refuse_an_absurd_last_index() {
        let pk = any_pubkey();
        let cc = [9u8; 32];
        // Would otherwise loop over three billion derivations.
        let rpc = mock_rpc(r#"{"lastI":3000000000}"#);
        assert!(scan_chain(&rpc, "xpub", &pk, &cc, "bitcoin", false).is_err());
        let rpc = mock_rpc(r#"{"lastI":3000000000}"#);
        assert!(next_address(&rpc, "xpub", &pk, &cc, "bitcoin", false).is_err());
        let rpc = mock_rpc(r#"{"lastI":100001}"#);
        assert!(next_address(&rpc, "xpub", &pk, &cc, "bitcoin", true).is_err());
        // In range still works.
        let rpc = mock_rpc(r#"{"lastI":2}"#);
        let (_, index, path) = next_address(&rpc, "xpub", &pk, &cc, "bitcoin", true).unwrap();
        assert_eq!((index, path.as_str()), (3, "m/1/3"));
        let rpc = mock_rpc(r#"{"lastI":1}"#);
        assert_eq!(scan_chain(&rpc, "xpub", &pk, &cc, "bitcoin", false).unwrap().len(), 3);
    }

    #[test]
    fn fee_and_amount_arithmetic_does_not_wrap() {
        let utxo = |sats: u64| DiscoveredUtxo { txo: format!("{}:0", "11".repeat(32)), amount_sats: sats, height: 1, path: "m/0/0".into(), script: "p2wpkh".into() };
        // A fee rate whose product with the vsize wraps u64 to something small.
        assert!(fee_sats(&[utxo(1)], 2, u64::MAX / 2).is_err());
        assert_eq!(fee_sats(&[utxo(1)], 2, 5).unwrap(), (11 + 62 + 68) * 5);
        assert!(select_utxos(&[utxo(100_000)], 1_000, u64::MAX / 2).is_err());
        // want + fee wrapping past zero must not look affordable.
        assert!(select_utxos(&[utxo(100_000)], u64::MAX - 10, 5).is_err());
        // Node-reported amounts whose sum wraps.
        assert!(select_utxos(&[utxo(u64::MAX - 5), utxo(100)], u64::MAX - 1, 0).is_err());
        // The ordinary case is unchanged.
        let (sel, total) = select_utxos(&[utxo(100_000), utxo(5_000)], 50_000, 5).unwrap();
        assert_eq!((sel.len(), total), (1, 100_000));
        assert_eq!(estimate_vsize(&[], u64::MAX), u64::MAX);
    }

    #[test]
    fn btc_auto_build_insufficient_funds_errors() {
        let env = Env::init_memory().unwrap();
        wallet::init(&env).unwrap();
        account::init(&env).unwrap();
        let kds = vec![pw("passwordone"), pw("passwordtwo"), pw("passwordthree")];
        let w = wallet::create(&env, "BTC", "secp256k1", &kds).unwrap();
        let a = account::create(&env, &w.id, "", "bitcoin", 0).unwrap();
        let rpc = mock_rpc(
            r#"{"assets":[{"asset":"NATIVE","txo":[
                {"txo":"1111111111111111111111111111111111111111111111111111111111111111:0","amt":"0.00001000","path":"m/0/0","script":"p2wpkh"}
            ]}]}"#,
        );
        let unlock: Vec<(String, String)> =
            vec![(w.keys[0].id.clone(), "passwordone".to_string())];
        // Want more than the single tiny UTXO holds.
        let err = build_and_sign_auto(&env, &a.id, &unlock, &rpc, "bitcoin", &a.address, 100_000, 5);
        assert!(err.is_err(), "insufficient funds must error");
    }
}
