//! Bitcoin transaction building + threshold signing (port of the wlttx Bitcoin
//! path). Builds a legacy P2PKH spend, computes each input's sighash via
//! outscript, and signs it with the wallet's DKLs shares under the account's HD
//! tweak. Each signature is self-verified as valid ECDSA under the derived key.

use num_bigint::{BigInt, Sign};
use outscript::btctx::{BtcTx, BtcTxInput, BtcTxSign, Signer};
use outscript::crypto::secp256k1::SecpPublicKey;

use crate::{Env, Error, Result};

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

/// Encode a compressed secp256k1 pubkey as the HD receive/change address for
/// `chain_id`, via outscript (P2WPKH/P2PKH per [`hd_address_kind`]).
pub fn hd_address(pubkey_compressed: &[u8; 33], chain_id: &str) -> Result<String> {
    let (script_type, network) = hd_address_kind(chain_id)?;
    address_for(pubkey_compressed, script_type, network)
}

/// Encode `pubkey` as the address of a given `script_type` (e.g. "p2wpkh",
/// "p2sh:p2wpkh", "p2pkh") on the outscript `network` tag.
fn address_for(pubkey_compressed: &[u8; 33], script_type: &str, network: &str) -> Result<String> {
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

/// Derive addresses `0..=lastI+1` on the receive (`change=false`) or change
/// chain (Go `scanChain`): `modchain_lookupTxoBIP32` gives `lastI` (the highest
/// used index), and each index is derived + encoded, the last marked `clean`.
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
    let last_i = raw.get("lastI").and_then(|v| v.as_i64()).unwrap_or(-1);
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
    let last_i = raw.get("lastI").and_then(|v| v.as_i64()).unwrap_or(-1);
    let next_index = (last_i + 1) as u32;
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

/// List the account's spendable NATIVE UTXOs from `modchain_assets(xpub)` (Go
/// `fetchBitcoinUTXOs`). Skips entries modchain marked spent. Amounts decode via
/// the BtcAmount rules. Does not apply the in-memory just-spent tracker (that
/// lands with the auto-input tx builder).
pub fn list_utxos(rpc: &str, xpub: &str) -> Result<Vec<DiscoveredUtxo>> {
    let raw = crate::rpc::call(rpc, "modchain_assets", serde_json::json!([xpub]))?;
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
            out.push(DiscoveredUtxo {
                txo,
                amount_sats,
                height: t.get("height").and_then(|v| v.as_i64()).unwrap_or(0),
                path: t.get("path").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                script: t.get("script").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            });
        }
    }
    Ok(out)
}

/// The maximum sendable satoshi for `xpub`: sum all UTXOs and subtract the fee
/// to spend them all into a single output (Go `maxSendableBitcoin`, one output,
/// no change). Returns `(total, fee, max)` in satoshi.
pub fn max_sendable_sats(rpc: &str, xpub: &str, fee_rate: u64) -> Result<(u64, u64, u64)> {
    let utxos = list_utxos(rpc, xpub)?;
    let total: u64 = utxos.iter().map(|u| u.amount_sats).sum();
    // Convert discovered UTXOs to the vsize estimator's shape.
    let inputs: Vec<DiscoveredUtxo> = utxos;
    let fee = estimate_vsize(&inputs, 1) * fee_rate; // one recipient, no change
    let max = total.saturating_sub(fee);
    Ok((total, fee, max))
}

/// Sum the NATIVE unspent balance (in satoshi) reported by `modchain_assets`
/// for `lookup` (an address or xpub). Port of Go `Network.bitcoinBalance`.
pub fn native_balance_satoshi(rpc: &str, lookup: &str) -> Result<u64> {
    let raw = crate::rpc::call(rpc, "modchain_assets", serde_json::json!([lookup]))?;
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

impl DiscoveredUtxo {
    /// The HD chain (0=receive, 1=change) from the UTXO's path.
    fn chain(&self) -> u32 {
        self.path.split('/').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
    }
    /// The HD child index from the UTXO's path (last segment).
    fn child_index(&self) -> u32 {
        self.path.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0)
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
fn estimate_vsize(ins: &[DiscoveredUtxo], outs: u64) -> u64 {
    11 + outs * 31 + ins.iter().map(|u| u.vsize()).sum::<u64>()
}

/// Greedy largest-first coin selection (Go `selectUTXOs`): add UTXOs until the
/// total covers `want_sats` + the size-based fee. Returns (selected, total_in).
fn select_utxos(all: &[DiscoveredUtxo], want_sats: u64, fee_rate: u64) -> Result<(Vec<DiscoveredUtxo>, u64)> {
    let mut sorted = all.to_vec();
    sorted.sort_by(|a, b| b.amount_sats.cmp(&a.amount_sats)); // largest first
    let mut total: u64 = 0;
    let mut out: Vec<DiscoveredUtxo> = Vec::new();
    for u in sorted {
        total += u.amount_sats;
        out.push(u);
        let fee = estimate_vsize(&out, 2) * fee_rate;
        if total >= want_sats + fee {
            return Ok((out, total));
        }
    }
    Err(Error::Env(format!("insufficient funds: have {total} sats across {} utxos", out.len())))
}

/// The next change (m/1) index (Go `nextChangeIndex`): highest used m/1 index +1.
fn next_change_index(all: &[DiscoveredUtxo]) -> u32 {
    let mut max: i64 = -1;
    for u in all {
        if u.chain() == 1 {
            max = max.max(u.child_index() as i64);
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
    let prefix = message_prefix(chain_id)
        .ok_or_else(|| Error::Env("unknown Bitcoin-family message prefix (chain not in allow-list)".into()))?;
    let mut full = prefix;
    append_varint(&mut full, message.len() as u64);
    full.extend_from_slice(message);
    let digest = outscript::hash::dsha256(&full);

    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    let pub_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&acct.pubkey).map_err(|e| Error::Env(format!("bad account pubkey: {e}")))?
    };
    let tweak = il_to_tweak(&acct.il)?;
    let (r, s, _v) = crate::models::wallet::dkls_sign_digest(env, &acct.wallet, unlock, &tweak, &digest)?;
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
}

impl<'a> Signer for TssSigner<'a> {
    fn ecdsa_public_key(&self) -> Option<SecpPublicKey> {
        SecpPublicKey::from_sec1(&self.pubkey.serialize_compressed()).ok()
    }

    fn sign_ecdsa_der(&self, digest: &[u8; 32]) -> std::result::Result<Vec<u8>, String> {
        let (r, s) = (self.sign_digest)(digest)?;
        let r32 = pad32(&r);
        let s32 = pad32(&s);
        if !self.pubkey.verify(digest, &r32, &s32) {
            return Err("threshold signature failed to verify under the derived key".into());
        }
        Ok(der_encode(&r32, &s32))
    }
}

/// Build and DKLs-sign a legacy P2PKH transaction spending `utxos` to
/// `outputs` (each `(address, sats)`). `unlock` provides the Password creds for
/// all wallet shares. Returns the raw signed transaction bytes.
pub fn sign_transfer(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
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

    let signer = TssSigner {
        pubkey,
        sign_digest: Box::new(move |digest: &[u8; 32]| {
            let (r, s, v) = crate::models::wallet::dkls_sign_digest(env, &wallet_id, unlock, &tweak, digest)
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
        tx.add_output(address, *sats).map_err(Error::Env)?;
    }

    let signs: Vec<BtcTxSign> = utxos
        .iter()
        .map(|u| BtcTxSign::new(&signer, "p2pkh").amount(u.amount).prev_script(u.script_pubkey.clone()))
        .collect();
    tx.sign(&signs).map_err(Error::Env)?;
    Ok(tx.to_bytes())
}

/// Parse a `"<txid>:<vout>"` ref into (32-byte big-endian display txid, vout).
/// outscript reverses to wire order itself, so we keep display order here.
fn parse_txo_ref(ref_: &str) -> Result<([u8; 32], u32)> {
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
#[allow(clippy::too_many_arguments)]
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

    // 1. Discover + select UTXOs.
    let xpub = build_xpub(&account_pub, &account_cc);
    let all = list_utxos(rpc, &xpub)?;
    if all.is_empty() {
        return Err(Error::Env("no spendable UTXOs".into()));
    }
    let (selected, total_in) = select_utxos(&all, want_sats, fee_rate_sat_vb)?;

    // 2. Fee + change (dust threshold 546 sat), 2-output size estimate.
    let fee = estimate_vsize(&selected, 2) * fee_rate_sat_vb;
    if total_in < want_sats + fee {
        return Err(Error::Env(format!("insufficient funds: {total_in} < {want_sats} + fee {fee}")));
    }
    let change = total_in - want_sats - fee;

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
        let (child_pub, child_tweak) =
            crate::hdderive::derive_pub_tweak(&account_pub, &account_cc, &[u.chain(), u.child_index()])
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
            let tweak = p.tweak;
            Ok(TssSigner {
                pubkey,
                sign_digest: Box::new(move |digest: &[u8; 32]| {
                    let (r, s, v) = crate::models::wallet::dkls_sign_digest(env, &wid, unlock, &tweak, digest)
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
    tx.add_output(recipient, want_sats).map_err(Error::Env)?;
    if change > 546 {
        let change_addr = {
            let idx = next_change_index(&all);
            let (child, _) = crate::hdderive::derive_pub_tweak(&account_pub, &account_cc, &[1, idx])
                .map_err(|e| Error::Env(e.to_string()))?;
            hd_address(&child, chain_id)?
        };
        tx.add_output(&change_addr, change).map_err(Error::Env)?;
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
            .map_err(Error::Env)?
            .bytes()
            .to_vec();
            let mut s = BtcTxSign::new(signer, &p.scheme).amount(p.amount).prev_script(prev_script);
            s.sighash = sighash;
            Ok(s)
        })
        .collect::<Result<_>>()?;
    tx.sign(&signs).map_err(Error::Env)?;
    Ok(tx.to_bytes())
}

fn il_to_tweak(il: &serde_json::Value) -> Result<[u8; 32]> {
    let dec = il.as_str().ok_or_else(|| Error::Env("account has no IL tweak".into()))?;
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

/// DER-encode an ECDSA (r, s) pair.
fn der_encode(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let r = der_int(r);
    let s = der_int(s);
    let mut out = Vec::with_capacity(2 + r.len() + s.len());
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

fn der_int(b: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < b.len() && b[i] == 0 {
        i += 1;
    }
    let mag = &b[i..];
    let mut v = vec![0x02];
    if mag[0] & 0x80 != 0 {
        v.push((mag.len() + 1) as u8);
        v.push(0x00);
    } else {
        v.push(mag.len() as u8);
    }
    v.extend_from_slice(mag);
    v
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
