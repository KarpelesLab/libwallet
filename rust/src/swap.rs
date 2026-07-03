//! Token-swap quotes via OKX DEX (port of `wltswap` — the quote path). Quotes
//! come from the platform's `Crypto/Okx:quote` proxy, an authenticated REST
//! endpoint ([`crate::rest::ApiKey`]). Only the quote flow is ported here;
//! execution (`Crypto/Okx:swap` + on-chain broadcast) and ERC-20 approval need
//! the live proxy + credentials and land with the execute pass.

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::rest::ApiKey;
use crate::{Amount, Error, Result};

/// Default platform fee (bps), matching Go `DefaultFeeBps`.
pub const DEFAULT_FEE_BPS: u16 = 50;
/// Default slippage (bps), matching Go `DefaultSlippageBps`.
pub const DEFAULT_SLIPPAGE_BPS: u16 = 50;
/// Max accepted slippage (bps), matching Go `MaxSlippageBps`.
pub const MAX_SLIPPAGE_BPS: u16 = 5000;

const OKX_EVM_NATIVE: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const WRAPPED_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

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
        return if kind == "solana" { WRAPPED_SOL_MINT } else { OKX_EVM_NATIVE }.to_owned();
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
