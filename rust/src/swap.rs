//! Token-swap quotes via OKX DEX (port of `wltswap` — the quote path). Quotes
//! come from the platform's `Crypto/Okx:quote` proxy, an authenticated REST
//! endpoint ([`crate::rest::ApiKey`]). Only the quote flow is ported here;
//! execution (`Crypto/Okx:swap` + on-chain broadcast) and ERC-20 approval need
//! the live proxy + credentials and land with the execute pass.

use base64::Engine as _;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::rest::ApiKey;
use crate::{Amount, Env, Error, Result};

/// Default platform fee (bps), matching Go `DefaultFeeBps`.
pub const DEFAULT_FEE_BPS: u16 = 50;
/// Default slippage (bps), matching Go `DefaultSlippageBps`.
pub const DEFAULT_SLIPPAGE_BPS: u16 = 50;
/// Max accepted slippage (bps), matching Go `MaxSlippageBps`.
pub const MAX_SLIPPAGE_BPS: u16 = 5000;

const OKX_EVM_NATIVE: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const WRAPPED_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// OKX's identifier for NATIVE SOL on its DEX quote/swap endpoints: the all-1s
/// System Program address (the 32-byte zero pubkey), NOT the wSOL mint (Go
/// `okxSolanaNativeSentinel`, commit bce9c70).
///
/// Load-bearing. Passing the wSOL mint (`So111…112`) makes OKX treat the input
/// as "spend the user's existing wSOL SPL token" and build a tx that does NOT
/// wrap native SOL — so the swap's source token account is uninitialized for
/// any wallet that doesn't already hold wSOL and the swap reverts on-chain
/// (AnchorError AccountNotInitialized / "custom program error: 0xb"). The
/// all-1s form makes OKX include the SOL→wSOL wrap (and the wSOL→SOL unwrap when
/// SOL is the output).
pub const OKX_SOLANA_NATIVE: &str = "11111111111111111111111111111111";

/// A token reference (Go `TokenRef`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRef {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub decimals: i64,
}

/// The core of a swap quote (subset of Go `Quote` — the quote-time fields).
#[derive(Debug, Clone, Serialize)]
pub struct Quote {
    pub provider: String,
    pub chain: String,
    #[serde(rename = "tokenIn")]
    pub token_in: TokenRef,
    #[serde(rename = "tokenOut")]
    pub token_out: TokenRef,
    #[serde(rename = "amountIn")]
    pub amount_in: Amount,
    #[serde(rename = "amountOut")]
    pub amount_out: Amount,
    #[serde(rename = "minAmountOut")]
    pub min_amount_out: Amount,
    #[serde(rename = "priceImpact")]
    pub price_impact: f64,
    #[serde(rename = "slippageBps")]
    pub slippage_bps: u16,
    #[serde(rename = "feeBps")]
    pub fee_bps: u16,
    #[serde(rename = "networkFee", skip_serializing_if = "Option::is_none")]
    pub network_fee: Option<Amount>,
}

/// The OKX `/quote` response entry we consume.
#[derive(Debug, Deserialize, Default)]
struct OkxQuoteEntry {
    #[serde(default, rename = "fromTokenAmount")]
    from_token_amount: String,
    #[serde(default, rename = "toTokenAmount")]
    to_token_amount: String,
    #[serde(default, rename = "priceImpactPercent")]
    price_impact_percent: String,
    #[serde(default, rename = "estimateGasFee")]
    estimate_gas_fee: String,
}

/// Strip a `<type>.<chainId>.` address prefix (Go `stripChainPrefix`).
fn strip_chain_prefix(addr: &str) -> &str {
    match addr.rfind('.') {
        Some(i) => &addr[i + 1..],
        None => addr,
    }
}

/// The OKX chain index for a network (Go `okxChainIndexFor`): EVM chain id,
/// Solana 501/103 by cluster.
pub fn okx_chain_index(kind: &str, chain_id: &str) -> Result<String> {
    match kind {
        "evm" => {
            if chain_id.is_empty() {
                Err(Error::Env("okx: evm network missing ChainId".into()))
            } else {
                Ok(chain_id.to_owned())
            }
        }
        "solana" => match chain_id {
            "" | "mainnet" | "mainnet-beta" => Ok("501".into()),
            "devnet" => Ok("103".into()),
            "testnet" => Err(Error::Env("okx: solana testnet is not supported".into())),
            other => Ok(other.to_owned()),
        },
        other => Err(Error::Env(format!("okx: unsupported network type {other}"))),
    }
}

/// Map a token address for OKX (Go `okxTokenAddrFor`): native → the chain's
/// sentinel (EVM 0xeee…, Solana wrapped-SOL mint), else the stripped address.
pub fn okx_token_addr(kind: &str, addr: &str) -> String {
    let addr = strip_chain_prefix(addr);
    if addr.is_empty() || addr.eq_ignore_ascii_case("NATIVE") {
        return if kind == "solana" { OKX_SOLANA_NATIVE } else { OKX_EVM_NATIVE }.to_owned();
    }
    addr.to_owned()
}

/// Clamp slippage to `[1, MAX]`, defaulting 0 (Go `normalizeSlippageBps`).
pub fn normalize_slippage(bps: u16) -> u16 {
    if bps == 0 {
        DEFAULT_SLIPPAGE_BPS
    } else if bps > MAX_SLIPPAGE_BPS {
        MAX_SLIPPAGE_BPS
    } else {
        bps
    }
}

/// Whether OKX offers swaps in a country (ISO 3166-1 alpha-2), Go
/// `okxAvailableCountries` — the exact 121-country allow-list.
pub fn okx_available_country(code: &str) -> bool {
    matches!(
        code,
        "AE" | "AG" | "AI" | "AM" | "AR" | "AT" | "AU" | "AZ" | "BB" | "BE" | "BG" | "BH" | "BM"
            | "BO" | "BR" | "BS" | "BW" | "BY" | "BZ" | "CA" | "CF" | "CH" | "CI" | "CL" | "CM"
            | "CO" | "CR" | "CZ" | "DE" | "DK" | "DM" | "DO" | "EC" | "EE" | "ES" | "FI" | "FR"
            | "GB" | "GD" | "GE" | "GN" | "GQ" | "GR" | "GT" | "GW" | "GY" | "HK" | "HN" | "HR"
            | "HU" | "IE" | "IL" | "IT" | "JM" | "JO" | "JP" | "KE" | "KG" | "KN" | "KR" | "KW"
            | "KY" | "KZ" | "LC" | "LI" | "LT" | "LU" | "LV" | "MA" | "MD" | "ME" | "MG" | "MK"
            | "ML" | "MO" | "MT" | "MU" | "MX" | "MY" | "MZ" | "NE" | "NG" | "NI" | "NL" | "NO"
            | "NZ" | "OM" | "PA" | "PE" | "PL" | "PR" | "PT" | "PY" | "QA" | "RO" | "RU" | "SA"
            | "SE" | "SG" | "SI" | "SK" | "SN" | "SR" | "SV" | "TC" | "TJ" | "TM" | "TN" | "TR"
            | "TT" | "TW" | "UA" | "UG" | "US" | "UY" | "UZ" | "VC" | "VE" | "VG" | "VN" | "ZA"
    )
}

/// A country-availability verdict (Go `CountryAvailabilityResult`).
#[derive(Debug, Clone, Serialize)]
pub struct CountryAvailability {
    pub available: bool,
    pub country: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Whether swaps are offered in a country (Go `swapCountryAvailability`). A
/// malformed code (not two ASCII letters) is `invalid_country`; a well-formed
/// but non-allow-listed code is `country_not_supported`. (Go additionally
/// validates against a full ISO 3166-1 table; that country DB isn't ported, so
/// a well-formed but non-existent code reads as `country_not_supported` here.)
pub fn country_availability(country: &str) -> CountryAvailability {
    let code = country.trim().to_uppercase();
    let well_formed = code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase());
    if !well_formed {
        return CountryAvailability { available: false, country: code, reason: "invalid_country".into() };
    }
    if okx_available_country(&code) {
        CountryAvailability { available: true, country: code, reason: String::new() }
    } else {
        CountryAvailability { available: false, country: code, reason: "country_not_supported".into() }
    }
}

/// Whether OKX routes swaps on this EVM chain id (Go `okxSupportedEVMChains`).
pub fn okx_supported_evm_chain(chain_id: &str) -> bool {
    matches!(
        chain_id,
        "1" | "10" | "25" | "56" | "100" | "137" | "169" | "196" | "250" | "324" | "480"
            | "1101" | "5000" | "8217" | "8453" | "34443" | "42161" | "42220" | "43114"
            | "59144" | "81457" | "534352"
    )
}

/// Whether swaps are available on a network + the eligible providers (Go
/// `computeAvailability`). OKX is the only routed provider; EVM is gated per
/// chain id, Solana to mainnet.
#[derive(Debug, Clone, Serialize)]
pub struct Availability {
    pub available: bool,
    pub network: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Compute swap availability for `kind`.`chain_id`.
pub fn availability(kind: &str, chain_id: &str) -> Availability {
    let network = format!("{kind}.{chain_id}");
    let (providers, reason): (Vec<String>, &str) = match kind {
        "solana" if chain_id == "mainnet" => (vec!["okx_solana".into()], ""),
        "evm" if okx_supported_evm_chain(chain_id) => (vec!["okx_evm".into()], ""),
        _ => (vec![], "unsupported_chain"),
    };
    Availability {
        available: !providers.is_empty(),
        network,
        providers,
        reason: reason.to_owned(),
    }
}

/// OKX slippage in percent units (Go `okxSlippagePercent`): bps/100, e.g.
/// 50 bps -> "0.5".
fn okx_slippage_percent(bps: u16) -> String {
    let bps = normalize_slippage(bps);
    let whole = bps / 100;
    let frac = bps % 100;
    if frac == 0 {
        format!("{whole}")
    } else if frac % 10 == 0 {
        format!("{whole}.{}", frac / 10)
    } else {
        format!("{whole}.{frac:02}")
    }
}

/// Execute an EVM swap (Go `okxExecuteEVM`): fetch the swap transaction from the
/// OKX proxy, build a legacy EVM tx (gas raised 50% per OKX guidance), DKLs-sign
/// it locally, and broadcast via the node. Returns `{hash, raw}`.
#[allow(clippy::too_many_arguments)]
pub fn execute_evm(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    key: &ApiKey,
    base: &str,
    rpc: &str,
    chain_id: &str,
    token_in: &TokenRef,
    token_out: &TokenRef,
    amount_in: &str,
    slippage_bps: u16,
) -> Result<serde_json::Value> {
    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    if acct.kind != "ethereum" {
        return Err(Error::Env("swap execute is EVM-only here".into()));
    }
    let chain_index = okx_chain_index("evm", chain_id)?;

    // 1. Fetch the swap tx from the authenticated OKX proxy.
    let params = json!({
        "chainIndex": chain_index,
        "fromTokenAddress": okx_token_addr("evm", &token_in.address),
        "toTokenAddress": okx_token_addr("evm", &token_out.address),
        "amount": amount_in,
        "userWalletAddress": acct.address,
        "slippagePercent": okx_slippage_percent(slippage_bps),
    });
    let data = key.apply_get(base, "Crypto/Okx:swap", &params)?;
    let entry = match &data {
        Value::Array(a) => a.first().cloned().unwrap_or(Value::Null),
        _ => data.clone(),
    };
    let tx = entry.get("tx").ok_or_else(|| Error::Env("okx swap: no tx".into()))?;
    let to = tx.get("to").and_then(Value::as_str).unwrap_or("");
    let tx_data = tx.get("data").and_then(Value::as_str).unwrap_or("");
    if to.is_empty() || tx_data.is_empty() {
        return Err(Error::Env("okx: evm swap returned empty tx".into()));
    }
    let value = tx.get("value").and_then(Value::as_str).unwrap_or("0").to_owned();
    let gas_price = tx.get("gasPrice").and_then(Value::as_str).unwrap_or("0").to_owned();
    let gas: u64 = tx.get("gas").and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0);
    let gas = gas * 3 / 2; // +50% headroom (OKX guidance)

    // 2. Nonce.
    let nonce_hex = crate::rpc::call(rpc, "eth_getTransactionCount", json!([acct.address, "pending"]))?;
    let nonce_hex = nonce_hex.as_str().unwrap_or("0x0");
    let nonce = u64::from_str_radix(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex), 16).unwrap_or(0);

    // 3. Build + sign a legacy tx.
    let data_hex = tx_data.strip_prefix("0x").unwrap_or(tx_data);
    let call_data = (0..data_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(data_hex.get(i..i + 2).unwrap_or(""), 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|e| Error::Env(format!("bad tx data hex: {e}")))?;
    let req = crate::evm::EvmTxRequest {
        nonce,
        gas,
        max_fee: gas_price,
        max_priority: "0".into(),
        to: to.to_owned(),
        value,
        data: call_data,
        chain_id: chain_id.parse().unwrap_or(1),
        eip1559: false,
    };
    let raw = crate::evm::sign_tx(env, account_id, unlock, &req)?;
    let raw_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    // 4. Broadcast via the node.
    let hash = crate::rpc::eth_send_raw_transaction(rpc, &format!("0x{raw_hex}"))?;
    Ok(json!({ "hash": hash, "raw": format!("0x{raw_hex}") }))
}

/// Decode an OKX Solana `tx.data` blob (Go `okxDecodeSolanaTxData`): try base58
/// (the documented encoding) then base64/base64url, preferring the candidate
/// that parses as a transaction whose fee-payer is `signer`.
pub fn decode_solana_tx_data(s: &str, signer: &[u8; 32]) -> Result<Vec<u8>> {
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    if let Ok(raw) = bs58::decode(s).into_vec() {
        if !raw.is_empty() {
            candidates.push(raw);
        }
    }
    let mut b = s.replace('-', "+").replace('_', "/");
    while b.len() % 4 != 0 {
        b.push('=');
    }
    if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(&b) {
        candidates.push(raw);
    }
    // Prefer one whose message names `signer` as a required signer.
    for raw in &candidates {
        if let Some(msg) = crate::solana::tx_message(raw) {
            if crate::solana::find_signer_slot(msg, signer).is_some() {
                return Ok(raw.clone());
            }
        }
    }
    // Fall back to the first structurally-valid candidate.
    for raw in &candidates {
        if crate::solana::tx_sig_layout(raw).is_some() {
            return Ok(raw.clone());
        }
    }
    Err(Error::Env("tx.data is neither valid base58 nor base64 transaction".into()))
}

/// Execute a Solana swap (Go `okxExecuteSolana`): fetch the swap tx from the OKX
/// proxy, FROST-sign its message, splice the signature into slot 0 (self-verified
/// under the fee-payer key), and broadcast via `sendTransaction`. Returns
/// `{signature}`.
#[allow(clippy::too_many_arguments)]
pub fn execute_solana(
    env: &Env,
    account_id: &str,
    unlock: &[(String, String)],
    key: &ApiKey,
    base: &str,
    rpc: &str,
    chain_id: &str,
    token_in: &TokenRef,
    token_out: &TokenRef,
    amount_in: &str,
    slippage_bps: u16,
) -> Result<serde_json::Value> {
    let acct = crate::models::account::fetch(env, account_id)?
        .ok_or_else(|| Error::Env("account not found".into()))?;
    if acct.kind != "solana" {
        return Err(Error::Env("solana swap execute requires a solana account".into()));
    }
    let signer = crate::solana::pubkey_from_b64url(&acct.pubkey)
        .ok_or_else(|| Error::Env("bad account pubkey".into()))?;
    let chain_index = okx_chain_index("solana", chain_id)?;

    let params = json!({
        "chainIndex": chain_index,
        "fromTokenAddress": okx_token_addr("solana", &token_in.address),
        "toTokenAddress": okx_token_addr("solana", &token_out.address),
        "amount": amount_in,
        "userWalletAddress": acct.address,
        "slippagePercent": okx_slippage_percent(slippage_bps),
    });
    let data = key.apply_get(base, "Crypto/Okx:swap", &params)?;
    let entry = match &data {
        Value::Array(a) => a.first().cloned().unwrap_or(Value::Null),
        _ => data.clone(),
    };
    let tx_data = entry
        .get("tx")
        .and_then(|t| t.get("data"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Env("okx: solana swap returned empty tx.data".into()))?;

    let raw_tx = decode_solana_tx_data(tx_data, &signer)?;
    let message = crate::solana::tx_message(&raw_tx)
        .ok_or_else(|| Error::Env("okx solana tx: no message".into()))?
        .to_vec();

    // FROST-sign the message and self-verify under the fee-payer key.
    let sig = crate::models::wallet::sign_frost_local(env, &acct.wallet, unlock, &message)?;
    let sig64: [u8; 64] = sig
        .clone()
        .try_into()
        .map_err(|_| Error::Env("unexpected signature length".into()))?;
    if !crate::tss::ed25519_verify(&signer, &message, &sig64) {
        return Err(Error::Env("signature does not verify under fee-payer pubkey".into()));
    }
    let signed = crate::solana::splice_signature(&raw_tx, &sig64)
        .ok_or_else(|| Error::Env("failed to splice signature".into()))?;

    // Broadcast (base64 wire form).
    let signed_b64 = base64::engine::general_purpose::STANDARD.encode(&signed);
    let res = crate::rpc::call(rpc, "sendTransaction", json!([signed_b64, { "encoding": "base64" }]))?;
    let signature = res.as_str().unwrap_or_default().to_owned();
    Ok(json!({ "signature": signature }))
}

/// The unlimited-approval amount (uint256 max, 2^256 − 1).
pub fn max_uint256() -> BigInt {
    (BigInt::from(1) << 256) - 1
}

/// True when an approval amount has the top bit set (≥ 2^255) — the "unlimited"
/// threshold, matching Go `isUnlimitedApprovalAmount`.
pub fn is_unlimited_approval(amount: &BigInt) -> bool {
    *amount >= (BigInt::from(1) << 255)
}

/// Encode ERC-20 `approve(spender, amount)` calldata (Go `encodeERC20Approve`):
/// `0x` + selector `095ea7b3` + the 32-byte left-padded spender + the 32-byte
/// left-padded amount. Errors on a malformed address or an out-of-range amount.
pub fn encode_erc20_approve(spender: &str, amount: &BigInt) -> Result<String> {
    let lower = spender.to_lowercase();
    let hexs = lower
        .strip_prefix("0x")
        .ok_or_else(|| Error::Env("erc20 approve spender must be a 0x-prefixed address".into()))?;
    if hexs.len() != 40 {
        return Err(Error::Env(format!(
            "erc20 approve spender must be 20 bytes (40 hex chars), got {}",
            hexs.len()
        )));
    }
    let addr = (0..40)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|e| Error::Env(format!("erc20 approve spender: {e}")))?;
    if amount.sign() == num_bigint::Sign::Minus {
        return Err(Error::Env("erc20 approve amount must be non-negative".into()));
    }
    if amount.bits() > 256 {
        return Err(Error::Env("erc20 approve amount overflows uint256".into()));
    }

    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let amt = amount.to_bytes_be().1; // big-endian magnitude
    let mut out = String::from("0x095ea7b3");
    out.push_str(&"00".repeat(12)); // address left-pad
    out.push_str(&hex(&addr));
    out.push_str(&"00".repeat(32 - amt.len())); // amount left-pad
    out.push_str(&hex(&amt));
    Ok(out)
}

fn native_decimals(kind: &str) -> i64 {
    if kind == "solana" {
        9
    } else {
        18
    }
}

/// Fetch a swap quote from the OKX proxy (Go `okxQuote`). `base` is the REST
/// backend, `key` the platform API credential. Returns a [`Quote`] with the
/// out amount, slippage-adjusted minimum, price impact, and network fee.
#[allow(clippy::too_many_arguments)]
pub fn get_quote(
    key: &ApiKey,
    base: &str,
    kind: &str,
    chain_id: &str,
    token_in: TokenRef,
    token_out: TokenRef,
    amount_in: &str,
    slippage_bps: u16,
) -> Result<Quote> {
    let chain_index = okx_chain_index(kind, chain_id)?;
    let from_addr = okx_token_addr(kind, &token_in.address);
    let to_addr = okx_token_addr(kind, &token_out.address);
    if amount_in.is_empty() || amount_in == "0" {
        return Err(Error::Env("okx: amountIn is required and non-zero".into()));
    }

    let params = json!({
        "chainIndex": chain_index,
        "fromTokenAddress": from_addr,
        "toTokenAddress": to_addr,
        "amount": amount_in,
    });
    let data = key.apply_get(base, "Crypto/Okx:quote", &params)?;
    // The proxy returns the OKX entry (or a `[{}]`/`[entry]` array form).
    let entry_val = match &data {
        Value::Array(a) => a.first().cloned().unwrap_or(Value::Null),
        _ => data.clone(),
    };
    let entry: OkxQuoteEntry = serde_json::from_value(entry_val).unwrap_or_default();

    let amount_in_bi = BigInt::parse_bytes(entry.from_token_amount.as_bytes(), 10)
        .or_else(|| BigInt::parse_bytes(amount_in.as_bytes(), 10))
        .ok_or_else(|| Error::Env("okx: bad amountIn".into()))?;
    if entry.to_token_amount.is_empty() || entry.to_token_amount == "0" {
        return Err(Error::Env(format!(
            "okx: no route for {amount_in} {from_addr} -> {to_addr} on chain {chain_index}"
        )));
    }
    let amount_out_bi = BigInt::parse_bytes(entry.to_token_amount.as_bytes(), 10)
        .ok_or_else(|| Error::Env(format!("okx: parse toTokenAmount {}", entry.to_token_amount)))?;

    // minReceive = amountOut * (10000 - slippage) / 10000.
    let slippage = normalize_slippage(slippage_bps);
    let min_out_bi = (&amount_out_bi * BigInt::from(10_000 - slippage as i64)) / BigInt::from(10_000);

    // priceImpact: percent string -> fraction.
    let price_impact = entry
        .price_impact_percent
        .parse::<f64>()
        .map(|p| p / 100.0)
        .unwrap_or(0.0);

    let network_fee = BigInt::parse_bytes(entry.estimate_gas_fee.as_bytes(), 10)
        .map(|g| Amount::new_raw(g, native_decimals(kind)));

    Ok(Quote {
        provider: if kind == "solana" { "okx_solana" } else { "okx_evm" }.to_owned(),
        chain: kind.to_owned(),
        amount_in: Amount::new_raw(amount_in_bi, token_in.decimals),
        amount_out: Amount::new_raw(amount_out_bi, token_out.decimals),
        min_amount_out: Amount::new_raw(min_out_bi, token_out.decimals),
        price_impact,
        slippage_bps: slippage,
        fee_bps: DEFAULT_FEE_BPS,
        network_fee,
        token_in,
        token_out,
    })
}

// ── OKX settlement robustness (ports of wltswap/okx.go) ─────────────────────

/// True when `addr` refers to native SOL (Go `isNativeTokenAddress`): the empty
/// string, the case-insensitive "NATIVE" sentinel, or the on-chain wSOL mint.
/// Does NOT strip a chain prefix (matches Go — it keys off the host sentinel).
pub fn is_native_token_address(addr: &str) -> bool {
    addr.is_empty() || addr.eq_ignore_ascii_case("NATIVE") || addr == WRAPPED_SOL_MINT
}

/// Resolve an output-token address to its on-chain mint (Go
/// `solanaNativeMintOrAddr`): strips a `<type>.<chainId>.` prefix and maps
/// native/empty to the real wSOL mint.
pub fn solana_native_mint_or_addr(addr: &str) -> String {
    let a = strip_chain_prefix(addr);
    if a == "NATIVE" || a.is_empty() {
        WRAPPED_SOL_MINT.to_owned()
    } else {
        a.to_owned()
    }
}

/// Client-side min-receive tripwire (Go `okxAssertMinReceive`, commit 2f419bc).
/// Rejects a swap whose provider-returned `min_receive` (OKX's execute-time
/// `minReceiveAmount`) falls grossly below the approved `min_amount_out` — a
/// tamper / gross-underpayment guard, NOT the user's real slippage protection
/// (that is `minReceiveAmount` itself, enforced on-chain against the current
/// price).
///
/// The comparison can't be exact: `min_amount_out` is a stale snapshot
/// (amountOut at quote time × the user's slippage) while OKX recomputes
/// `minReceiveAmount` from a FRESH quote at execute time, so normal downward
/// price drift in the seconds between quote and execute leaves it a hair under
/// the approved minimum on a perfectly honest fill (the field case: 713177 vs
/// 713274, 0.0136%). We therefore relax the floor by one slippage band:
/// `floor = min_amount_out × (10_000 − slippageBps) / 10_000`. No-op when
/// `min_receive` is blank / unparseable or the quote carries no minimum.
pub fn okx_assert_min_receive(
    min_amount_out: Option<&BigInt>,
    slippage_bps: u16,
    min_receive: &str,
) -> Result<()> {
    let mr = min_receive.trim();
    if mr.is_empty() {
        return Ok(());
    }
    let got = match BigInt::parse_bytes(mr.as_bytes(), 10) {
        Some(g) => g,
        None => return Ok(()),
    };
    let min_out = match min_amount_out {
        Some(m) => m,
        None => return Ok(()),
    };
    // floor = MinAmountOut × (10_000 − slippageBps) / 10_000 — relax the
    // approved minimum by one slippage band to absorb quote→execute drift.
    let slip = normalize_slippage(slippage_bps) as i64;
    let floor = (min_out * BigInt::from(10_000 - slip)) / BigInt::from(10_000);
    if got < floor {
        return Err(Error::Env(format!(
            "okx: swap minReceiveAmount {got} is below the approved floor {floor} \
             (approved minimum {min_out}, less {slip} bps drift tolerance)"
        )));
    }
    Ok(())
}

/// Whether an OKX Solana broadcast/settlement error is the kind a fresh
/// blockhash + re-sign can cure (Go `isRetryableSolanaBroadcast`, commit
/// 6fcb1a8).
///
/// Both a retryable stale-blockhash case ("… Blockhash not found") and a
/// terminal program revert ("… Error processing Instruction 5: custom program
/// error: 0xb") arrive as the same `-32002 "Transaction simulation failed"`
/// envelope, so we check the DETERMINISTIC markers FIRST and bail, then allow
/// only genuine transient / blockhash markers.
pub fn is_retryable_solana_broadcast(err: &str) -> bool {
    if err.is_empty() {
        return false;
    }
    let s = err.to_lowercase();
    // Deterministic reverts — a fresh blockhash changes nothing.
    for m in [
        "custom program error",
        "error processing instruction",
        "insufficient",
        "slippage",
        "exceeds desired",
        "deserialize",
    ] {
        if s.contains(m) {
            return false;
        }
    }
    // Transient / stale-blockhash failures a fresh fetch + re-sign can cure.
    for m in ["blockhash", "block height exceeded", "expired", "timeout", "timed out", "deadline"] {
        if s.contains(m) {
            return true;
        }
    }
    false
}

/// Resolve whether to request OKX MEV-protected broadcast for an EVM swap (Go
/// `mevEnabled`, commit dd8197e). Defaults to on when the host sets no
/// preference; honors an explicit host choice otherwise. Solana ignores it.
pub fn mev_enabled(pref: Option<bool>) -> bool {
    pref.unwrap_or(true)
}

/// One tracked OKX order (Go `okxOrderStatusEntry`). `tx_status` is OKX's
/// numeric code as a string: "1" pending, "2" success, "3" failed.
/// `fail_reason` carries the upstream RPC error on failure; `tx_hash` is set
/// once the tx is on chain.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OkxOrderStatusEntry {
    #[serde(default, rename = "orderId")]
    pub order_id: String,
    #[serde(default, rename = "txStatus")]
    pub tx_status: String,
    #[serde(default, rename = "failReason")]
    pub fail_reason: String,
    #[serde(default, rename = "txHash")]
    pub tx_hash: String,
}

/// The `Crypto/Okx:orderStatus` data entry: a paginated envelope wrapping the
/// matched orders (Go `okxOrderStatusPage`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OkxOrderStatusPage {
    #[serde(default)]
    pub cursor: String,
    #[serde(default)]
    pub orders: Vec<OkxOrderStatusEntry>,
}

/// Normalize OKX's numeric `txStatus` into a stable label (Go
/// `okxTxStatusLabel`): "pending" | "success" | "failed". A missing entry
/// (order not yet visible to OKX) reads as "pending".
pub fn okx_tx_status_label(entry: Option<&OkxOrderStatusEntry>) -> &'static str {
    match entry {
        None => "pending",
        Some(e) => match e.tx_status.as_str() {
            "2" => "success",
            "3" => "failed",
            "1" => "pending",
            _ => {
                if !e.tx_hash.is_empty() {
                    "success"
                } else {
                    "pending"
                }
            }
        },
    }
}

/// Fetch a single OKX orderStatus entry (Go `okxFetchOrderStatus`). Returns
/// `Ok(None)` when the order isn't visible to OKX yet (just-accepted / unknown
/// id); surfaces transport / decode errors for callers that want them.
pub fn okx_fetch_order_status(
    key: &ApiKey,
    base: &str,
    chain_index: &str,
    address: &str,
    order_id: &str,
) -> Result<Option<OkxOrderStatusEntry>> {
    let params = json!({ "chainIndex": chain_index, "address": address, "orderId": order_id });
    let data = key.apply_get(base, "Crypto/Okx:orderStatus", &params)?;
    let entry_val = match &data {
        Value::Array(a) => match a.first() {
            Some(v) => v.clone(),
            None => return Ok(None),
        },
        Value::Null => return Ok(None),
        other => other.clone(),
    };
    let page: OkxOrderStatusPage = serde_json::from_value(entry_val)
        .map_err(|e| Error::Env(format!("okx: decode orderStatus: {e}")))?;
    Ok(page.orders.into_iter().next())
}

/// Normalized settlement state of a broadcast swap (Go `SwapOrderStatus`), the
/// `Swap:orderStatus` output. Status is "pending" | "success" | "failed".
#[derive(Debug, Clone, Serialize)]
pub struct SwapOrderStatus {
    #[serde(rename = "orderId")]
    pub order_id: String,
    pub chain: String,
    pub status: String,
    #[serde(rename = "txHash", skip_serializing_if = "String::is_empty")]
    pub tx_hash: String,
    #[serde(rename = "failReason", skip_serializing_if = "String::is_empty")]
    pub fail_reason: String,
}

/// Whether `owner` already holds at least one SPL token account for `mint` (Go
/// `solanaHasTokenAccount`): a `getTokenAccountsByOwner` probe with a mint
/// filter.
pub fn solana_has_token_account(rpc: &str, owner: &str, mint: &str) -> Result<bool> {
    let res = crate::rpc::call(
        rpc,
        "getTokenAccountsByOwner",
        json!([owner, { "mint": mint }, { "encoding": "base64" }]),
    )?;
    Ok(res
        .get("value")
        .and_then(Value::as_array)
        .map(|v| !v.is_empty())
        .unwrap_or(false))
}

/// Rent-exempt minimum lamports for an account of `data_bytes` (Go
/// `SolanaRentExemptMinimum`).
pub fn solana_rent_exempt_minimum(rpc: &str, data_bytes: u64) -> Result<u64> {
    let res = crate::rpc::call(rpc, "getMinimumBalanceForRentExemption", json!([data_bytes]))?;
    res.as_u64()
        .ok_or_else(|| Error::Env("parse getMinimumBalanceForRentExemption".into()))
}

/// Canonical SPL token-account rent fallback (lamports), used when the live
/// `getMinimumBalanceForRentExemption` probe fails.
pub const SOLANA_TOKEN_ACCOUNT_RENT: u64 = 2_039_280;

/// Extra lamports a native-SOL → SPL swap must hold back beyond the plain-send
/// reservation — the reservation for `Swap:maxSpendable` on Solana (Go
/// `solanaSwapSolReservation`, commit 03ad446). A native-SOL swap can create up
/// to TWO transient rent-exempt token accounts the wallet must front at peak
/// (both are closed before the tx ends, but Solana debits them mid-execution,
/// so the balance has to cover them or the swap reverts with "custom program
/// error: 0xb"):
///
///  1. the INPUT wSOL wrap account — unless the user already holds wSOL;
///  2. the OUTPUT token's ATA — unless it already exists or the output is wSOL.
///
/// Returns 0 when the input isn't native SOL. RPC probe errors degrade to
/// "assume the account is missing" (reserve it) so a slow upstream hands a
/// conservative max. The `SOLANA_TOKEN_ACCOUNT_RENT` fallback matches the
/// canonical SPL token-account rent.
///
/// NOTE: `Swap:maxSpendable` is EVM-only in this Rust port, so this helper is
/// not yet wired into an endpoint; it captures the Go decision + arithmetic
/// exactly and is exercised directly.
pub fn solana_swap_sol_reservation(
    rpc: &str,
    owner: &str,
    token_in_addr: &str,
    token_out_addr: &str,
) -> u64 {
    if !is_native_token_address(token_in_addr) {
        return 0;
    }
    let mut rent = solana_rent_exempt_minimum(rpc, 165).unwrap_or(0); // 165 = SPL token-account size
    if rent == 0 {
        rent = SOLANA_TOKEN_ACCOUNT_RENT;
    }

    let mut total = 0u64;
    // (1) Input wSOL wrap account, unless the user already holds wSOL.
    if !matches!(solana_has_token_account(rpc, owner, WRAPPED_SOL_MINT), Ok(true)) {
        total += rent;
    }
    // (2) Output token ATA, unless it already exists or the output is wSOL.
    let out_mint = solana_native_mint_or_addr(token_out_addr);
    if out_mint != WRAPPED_SOL_MINT {
        let has = solana_has_token_account(rpc, owner, &out_mint).unwrap_or(false);
        if !has {
            total += rent;
        }
    }
    total
}
