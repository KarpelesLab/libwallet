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
