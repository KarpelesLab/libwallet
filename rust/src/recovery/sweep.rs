//! Moving a recovered address's funds: build and sign a transfer without
//! broadcasting it ([`prepare`]), so the host can show the user exactly what
//! will happen, then send it ([`broadcast`]).
//!
//! Every chain's native coin pays the fees of moving its tokens (ETH for
//! ERC-20, SOL for SPL, TRX for TRC-20). Sweep an address's tokens **before**
//! its native coin, or the tokens are stranded with nothing to pay for them.

use num_bigint::BigInt;
use serde_json::{json, Value};

use super::scan::{self, rpc_for};
use super::{Family, Slot, SlotKey};
use crate::bitfi::{self, PrivateKey};
use crate::handlers::ApiError;
use crate::Env;

/// How much to move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Amount {
    /// Everything the address holds of the asset, less the fee where the fee
    /// is paid in it.
    Max,
    /// Base units.
    Exact(BigInt),
}

impl Amount {
    /// `"max"` (any case) or a whole number of base units.
    pub fn parse(s: &str) -> Result<Amount, ApiError> {
        if s.eq_ignore_ascii_case("max") {
            return Ok(Amount::Max);
        }
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            if let Some(n) = BigInt::parse_bytes(s.as_bytes(), 10).filter(|n| *n > BigInt::from(0)) {
                return Ok(Amount::Exact(n));
            }
        }
        Err(ApiError::new(400, "Amount must be \"max\" or a whole, positive number of base units"))
    }

    fn as_u64(&self) -> Result<Option<u64>, ApiError> {
        match self {
            Amount::Max => Ok(None),
            Amount::Exact(n) => u64::try_from(n).map(Some).map_err(|_| ApiError::new(400, "amount too large")),
        }
    }
}

/// What a sweep should do.
pub struct Request<'a> {
    pub to: &'a str,
    /// `NATIVE`, or a token contract (ERC-20, TRC-20) / mint (SPL).
    pub asset: &'a str,
    pub amount: Amount,
    /// Bitcoin family: satoshi per virtual byte (the node's estimate otherwise).
    pub fee_rate: Option<u64>,
    /// Overrides the chain's node (tests, self-hosted).
    pub rpc: Option<&'a str>,
}

fn native(asset: &str) -> bool {
    asset.is_empty() || asset.eq_ignore_ascii_case("native")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build and sign, without broadcasting, a transfer of a slot's funds.
/// Returns `{Chain, From, To, Asset, Symbol, Decimals, Amount, Fee, Raw, …}`.
pub async fn prepare(env: &Env, slot: &Slot, key: SlotKey, req: &Request<'_>) -> Result<Value, ApiError> {
    let url = rpc_for(slot.chain, req.rpc).map_err(|e| ApiError::new(501, e))?;
    let to = req.to.trim();
    if to.is_empty() {
        return Err(ApiError::new(400, "To required"));
    }
    if to == slot.address {
        return Err(ApiError::new(400, "That's the address being recovered: choose an address of your own wallet."));
    }
    let mut out = match (slot.chain.family, key) {
        (Family::Bitcoin { network, .. }, SlotKey::Secp(key)) => {
            if !native(req.asset) {
                return Err(ApiError::new(400, format!("{} has no tokens to send", slot.chain.name)));
            }
            let raw = crate::rpc::call_async(&url, "modchain_assets", json!([slot.address])).await.map_err(ApiError::internal)?;
            let utxos = crate::bitcoin::parse_native_utxos(&raw).map_err(ApiError::internal)?;
            let rate = match req.fee_rate {
                Some(r) => r,
                None => fee_rate(&url).await?,
            };
            let amount = match req.amount.as_u64()? {
                None => bitfi::Amount::Max,
                Some(n) => bitfi::Amount::Exact(n),
            };
            let spend = bitfi::spend_utxos(slot.chain.name, network, slot.chain.symbol, &key, slot.scheme, &utxos, to, amount, rate)
                .map_err(|e| ApiError::new(400, e))?;
            json!({
                "Asset": "NATIVE", "Symbol": slot.chain.symbol, "Decimals": slot.chain.decimals,
                "Amount": spend.amount.to_string(), "Fee": spend.fee.to_string(), "Change": spend.change.to_string(),
                "FeeRate": rate, "Raw": hex(&spend.raw),
            })
        }
        (Family::Ethereum, SlotKey::Secp(key)) => {
            let token = (!native(req.asset)).then_some(req.asset);
            let amount = match &req.amount {
                Amount::Max => None,
                Amount::Exact(n) => Some(n.clone()),
            };
            Box::pin(prepare_ethereum(&key, &slot.address, &url, to, amount, token)).await?
        }
        // Boxed: each chain's builder is a large future, kept off the caller's stack.
        (Family::Solana, SlotKey::Ed25519(seed)) => Box::pin(prepare_solana(env, slot, &seed, &url, to, req)).await?,
        (Family::Tron, SlotKey::Secp(key)) => Box::pin(prepare_tron(slot, &key, &url, to, req)).await?,
        (Family::Monero, _) => return Err(ApiError::new(501, "Monero sends aren't available: export the keys into a Monero wallet instead.")),
        _ => return Err(ApiError::internal("key/chain mismatch")),
    };
    out["Chain"] = json!(slot.chain.name);
    out["From"] = json!(slot.address);
    out["Address"] = json!(slot.id());
    if out.get("To").is_none() {
        out["To"] = json!(to);
    }
    Ok(out)
}

/// The network's fee rate in satoshi per virtual byte. Bitcoin Cash nodes only
/// have the older `estimatefee`, which takes no target.
pub async fn fee_rate(url: &str) -> Result<u64, ApiError> {
    let per_kb = match crate::rpc::call_async(url, "estimatesmartfee", json!([6])).await {
        Ok(reply) => reply.get("feerate").cloned().unwrap_or(Value::Null),
        Err(_) => crate::rpc::call_async(url, "estimatefee", json!([])).await.map_err(ApiError::internal)?,
    };
    let per_kb = crate::bitcoin::parse_btc_amount(&per_kb).ok().filter(|r| *r > 0);
    let per_kb = per_kb.ok_or_else(|| ApiError::new(502, "the node has no fee estimate; pass FeeRate"))?;
    Ok(bitfi::fee_rate_from_per_kb(per_kb))
}

fn eth(wei: &BigInt) -> String {
    bitfi::format_units(&wei.to_string(), 18)
}

/// ABI-encoded `transfer(to, amount)`.
fn erc20_transfer(to: &str, amount: &BigInt) -> String {
    format!("0xa9059cbb{:0>64}{:0>64}", to.trim_start_matches("0x").to_lowercase(), amount.to_str_radix(16))
}

/// Build and sign an Ethereum transfer of ETH (`token` None) or an ERC-20 from
/// `from` (`key`'s address). `amount` None moves everything: for ETH, the
/// balance less the worst-case fee.
pub async fn prepare_ethereum(key: &PrivateKey, from: &str, url: &str, to: &str, amount: Option<BigInt>, token: Option<&str>) -> Result<Value, ApiError> {
    let to = to.trim();
    outscript::decode_evm_address(to).map_err(|_| ApiError::new(400, "That isn't an Ethereum address. Sending to another network's address would lose the funds."))?;
    if let Some(token) = token {
        outscript::decode_evm_address(token).map_err(|_| ApiError::new(400, format!("{token} is not a token contract")))?;
    }
    let assets = crate::rpc::call_async(url, "modchain_assets", json!([from])).await.map_err(ApiError::internal)?;
    let assets = scan::ethereum_assets(&assets).map_err(|e| ApiError::new(502, e))?;
    let find = |asset: &str| assets.iter().find(|a| a["Asset"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(asset)));
    let held = |asset: &str| -> BigInt {
        find(asset).and_then(|a| a["Balance"].as_str()).and_then(|b| BigInt::parse_bytes(b.as_bytes(), 10)).unwrap_or_default()
    };
    let native_held = held("NATIVE");
    let requested = |available: &BigInt| amount.clone().unwrap_or_else(|| available.clone());

    // A token moves through its contract: the transaction pays it no ETH.
    let (call_to, data, sent, symbol, decimals) = match token {
        Some(token) => {
            let sent = requested(&held(token));
            let decimals = find(token).and_then(|a| a["Decimals"].as_u64()).unwrap_or(18) as usize;
            if sent == BigInt::from(0) || sent > held(token) {
                return Err(ApiError::new(400, format!("This address holds {} of that token.", bitfi::format_units(&held(token).to_string(), decimals))));
            }
            let symbol = find(token).and_then(|a| a["Symbol"].as_str()).unwrap_or_default().to_owned();
            (token.to_owned(), erc20_transfer(to, &sent), sent, symbol, decimals)
        }
        None => (to.to_owned(), String::new(), BigInt::from(0), "ETH".to_owned(), 18),
    };

    // Gas for a token transfer is estimated with its call data, plus a margin.
    let mut tx = json!({ "to": call_to, "value": "0", "chainId": 1 });
    if !data.is_empty() {
        tx["data"] = json!(data);
        let call = json!([{ "from": from, "to": call_to, "data": data }]);
        let estimate = crate::rpc::call_async(url, "eth_estimateGas", call).await.map_err(ApiError::internal)?;
        let gas = u64::from_str_radix(estimate.as_str().unwrap_or("0").trim_start_matches("0x"), 16).unwrap_or(0);
        if gas == 0 {
            return Err(ApiError::new(502, "the node gave no gas estimate"));
        }
        tx["gas"] = json!(gas + gas / 5);
    } else {
        tx["gas"] = json!(21000);
    }
    let mut filled = crate::handlers::account::evm_fill(from, url, &json!({ "Transaction": tx })).await?;
    let fields = &filled["Transaction"];
    let price = fields.get("maxFeePerGas").or_else(|| fields.get("gasPrice")).and_then(Value::as_str).unwrap_or("0");
    let price = BigInt::parse_bytes(price.as_bytes(), 10).unwrap_or_default();
    let fee = price * fields["gas"].as_u64().unwrap_or(0);

    // The native amount needs the worst-case fee known, so it's filled in last.
    let sent = if token.is_some() {
        if native_held < fee {
            return Err(ApiError::new(400, format!("Moving a token needs up to {} ETH for the network fee, and this address holds {} ETH.", eth(&fee), eth(&native_held))));
        }
        sent
    } else {
        let sent = amount.clone().unwrap_or_else(|| &native_held - &fee);
        if sent <= BigInt::from(0) || &sent + &fee > native_held {
            return Err(ApiError::new(400, format!("This address holds {} ETH, and the network fee can be up to {} ETH.", eth(&native_held), eth(&fee))));
        }
        filled["Transaction"]["value"] = json!(sent.to_string());
        sent
    };
    let request = crate::handlers::account::evm_request_from_tx(&filled["Transaction"])?;
    let raw = bitfi::sign_ethereum(key, &request).map_err(ApiError::internal)?;
    Ok(json!({
        "To": to, "Asset": token.unwrap_or("NATIVE"), "Token": token, "Symbol": symbol, "Decimals": decimals,
        "Amount": sent.to_string(), "Fee": fee.to_string(), "Raw": format!("0x{}", hex(&raw)),
    }))
}

/// The SPL balance (base units) `owner` holds of `mint`, over all its token
/// accounts.
async fn spl_balance(url: &str, owner: &str, mint: &str) -> Result<BigInt, ApiError> {
    let reply = crate::rpc::call_async(url, "getTokenAccountsByOwner", json!([owner, { "mint": mint }, { "encoding": "jsonParsed" }]))
        .await
        .map_err(ApiError::internal)?;
    let mut total = BigInt::from(0);
    for account in reply.get("value").and_then(Value::as_array).into_iter().flatten() {
        if let Some(a) = account.pointer("/account/data/parsed/info/tokenAmount/amount").and_then(Value::as_str).and_then(|s| BigInt::parse_bytes(s.as_bytes(), 10)) {
            total += a;
        }
    }
    Ok(total)
}

/// Rent for a new SPL token account (165 bytes), when the node won't say.
const ATA_RENT_LAMPORTS: u64 = 2_039_280;

async fn prepare_solana(env: &Env, slot: &Slot, seed: &[u8; 32], url: &str, to: &str, req: &Request<'_>) -> Result<Value, ApiError> {
    let signer = purecrypto::ec::ed25519::Ed25519PrivateKey::from_bytes(*seed);
    let public = signer.public_key().to_bytes();
    use base64::Engine as _;
    // A transient account for the shared builder: never saved anywhere.
    let account: crate::models::account::Account = serde_json::from_value(json!({
        "Type": "solana", "Curve": "ed25519", "Address": slot.address,
        "Pubkey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public),
    }))
    .map_err(ApiError::internal)?;
    let net = crate::models::network::fetch(env, "solana.mainnet")
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(500, "no Solana mainnet network"))?;
    let lamports = crate::rpc::call_async(url, "getBalance", json!([slot.address]))
        .await
        .map_err(ApiError::internal)?
        .get("value")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let tx = if native(req.asset) {
        let amount = match &req.amount {
            Amount::Max => json!("MAX"),
            Amount::Exact(n) => json!(n.to_string()),
        };
        json!({ "to": to, "amount": amount, "asset": "" })
    } else {
        let held = spl_balance(url, &slot.address, req.asset).await?;
        let amount = match &req.amount {
            Amount::Max => held.clone(),
            Amount::Exact(n) => n.clone(),
        };
        if amount == BigInt::from(0) || amount > held {
            return Err(ApiError::new(400, format!("This address holds {held} base units of that token.")));
        }
        json!({ "to": to, "amount": amount.to_string(), "asset": req.asset })
    };
    let built = Box::pin(crate::handlers::solana_build::build_unsigned(env, &account, &net, url, &tx)).await?;

    // The address pays the fee, and the rent of the recipient's token account
    // when it doesn't have one yet.
    let mut needed = built.fee_lamports;
    if let Some(ata) = built.recipient_ata {
        let ata = bs58::encode(ata).into_string();
        if crate::handlers::solana_build::account_exists(url, &ata).await != Some(true) {
            needed += ATA_RENT_LAMPORTS;
        }
    }
    if built.token.is_some() && lamports < needed {
        return Err(ApiError::new(
            400,
            format!("Moving this token needs {} SOL for fees, and this address holds {} SOL. Send it a little SOL first.", bitfi::format_units(&needed.to_string(), 9), bitfi::format_units(&lamports.to_string(), 9)),
        ));
    }
    let signature = signer.sign(&built.message).to_bytes();
    let raw = crate::solana::assemble_tx(&built.message, &signature);
    let (asset, symbol, decimals) = match &built.token {
        Some(t) => (t.mint_b58.clone(), scan_symbol(&t.mint_b58), t.decimals as u32),
        None => ("NATIVE".into(), "SOL".into(), 9),
    };
    Ok(json!({
        "To": built.to, "Asset": asset, "Symbol": symbol, "Decimals": decimals,
        "Amount": built.amount.to_string(), "Fee": needed.to_string(),
        "Raw": bs58::encode(&raw).into_string(), "Txid": bs58::encode(signature).into_string(),
    }))
}

fn scan_symbol(mint: &str) -> String {
    crate::curated::for_chain("solana.mainnet")
        .iter()
        .find(|t| t.get("address").and_then(Value::as_str) == Some(mint))
        .and_then(|t| t.get("symbol").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
}

async fn prepare_tron(slot: &Slot, key: &PrivateKey, base: &str, to: &str, req: &Request<'_>) -> Result<Value, ApiError> {
    crate::tron::parse_address(to).map_err(|_| ApiError::new(400, "That isn't a Tron address. Sending to another network's address would lose the funds."))?;
    let signer = outscript::crypto::secp256k1::SecpPrivateKey::from_bytes(&key.0).map_err(|e| ApiError::internal(format!("bad key: {e:?}")))?;
    let post = |method: &'static str, body: Value| async move { crate::tron::post_async(base, method, &body).await.map_err(ApiError::internal) };
    let account = post("getaccount", crate::tron::account_body(&slot.address)).await?;
    let balance = crate::tron::parse_balance(&account);
    let resource = post("getaccountresource", crate::tron::account_body(&slot.address)).await.unwrap_or(Value::Null);

    let (transfer, out) = if native(req.asset) {
        // The bandwidth fee when no free bandwidth is left, and the account
        // creation fee when `to` has never been seen.
        let mut fee = 0;
        if crate::tron::free_bandwidth(&resource) < 300 {
            fee += crate::tron::TRANSFER_BANDWIDTH_SUN;
        }
        let exists = post("getaccount", crate::tron::account_body(to)).await.map(|v| crate::tron::account_exists(&v)).unwrap_or(true);
        if !exists {
            fee += crate::tron::NEW_ACCOUNT_SUN;
        }
        let amount = match req.amount.as_u64()? {
            None => balance.saturating_sub(fee),
            Some(n) => n,
        };
        let trx = |sun: u64| bitfi::format_units(&sun.to_string(), 6);
        if amount == 0 || amount.saturating_add(fee) > balance {
            return Err(ApiError::new(400, format!("This address holds {} TRX, and the network fee can be up to {} TRX.", trx(balance), trx(fee))));
        }
        let out = json!({ "Asset": "NATIVE", "Symbol": "TRX", "Decimals": 6, "Amount": amount.to_string(), "Fee": fee.to_string() });
        (crate::tron::Transfer::Trx { to: to.to_owned(), amount }, out)
    } else {
        let contract = crate::tron::normalize_address(req.asset).map_err(|_| ApiError::new(400, format!("{} is not a token contract", req.asset)))?;
        let param = crate::tron::balance_of_param(&slot.address).map_err(ApiError::internal)?;
        let reply = post("triggerconstantcontract", crate::tron::constant_call_body(&slot.address, &contract, "balanceOf(address)", &param)).await?;
        let held = crate::tron::parse_uint(&crate::tron::parse_constant_result(&reply).map_err(|e| ApiError::new(502, e.to_string()))?);
        let amount = match &req.amount {
            Amount::Max => held.clone(),
            Amount::Exact(n) => n.clone(),
        };
        if amount == BigInt::from(0) || amount > held {
            return Err(ApiError::new(400, format!("This address holds {held} base units of that token.")));
        }
        let energy = resource.get("EnergyLimit").and_then(Value::as_u64).unwrap_or(0).saturating_sub(resource.get("EnergyUsed").and_then(Value::as_u64).unwrap_or(0));
        if balance == 0 && energy == 0 {
            return Err(ApiError::new(400, "Moving a token on Tron burns TRX for energy, and this address holds none. Send it some TRX first (about 30 TRX covers a USDT transfer)."));
        }
        let (symbol, decimals) = scan::TRC20.iter().find(|(c, _, _)| *c == contract).map(|(_, s, d)| (*s, *d)).unwrap_or(("", 0));
        let fee_limit = crate::tron::DEFAULT_TRC20_FEE_LIMIT;
        let out = json!({
            "Asset": contract, "Symbol": symbol, "Decimals": decimals, "Amount": amount.to_string(),
            "Fee": fee_limit.to_string(), "FeeLimit": fee_limit.to_string(),
        });
        let amount = u128::try_from(&amount).map_err(|_| ApiError::new(400, "amount too large"))?;
        (crate::tron::Transfer::Trc20 { contract, to: to.to_owned(), amount, fee_limit }, out)
    };
    let block = crate::tron::fresh_ref_block(&post("getnowblock", json!({})).await?).map_err(ApiError::internal)?;
    let (txid, signed) = crate::tron::sign_transfer_with_key(&slot.address, &signer, &transfer, &block).map_err(ApiError::internal)?;
    let mut out = out;
    out["Raw"] = json!(hex(&signed));
    out["Txid"] = json!(hex(&txid));
    Ok(out)
}

/// Send a transaction from [`prepare`]. Returns its id.
pub async fn broadcast(chain: &super::Chain, raw: &str, rpc: Option<&str>) -> Result<String, ApiError> {
    let url = rpc_for(chain, rpc).map_err(|e| ApiError::new(501, e))?;
    let reply = match chain.family {
        Family::Bitcoin { .. } => crate::rpc::call_async(&url, "sendrawtransaction", json!([raw])).await,
        Family::Ethereum => crate::rpc::call_async(&url, "eth_sendRawTransaction", json!([raw])).await,
        Family::Solana => crate::rpc::call_async(&url, "sendTransaction", json!([raw, { "encoding": "base58" }])).await,
        Family::Tron => {
            let bytes = (0..raw.len())
                .step_by(2)
                .map(|i| raw.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(|| ApiError::new(400, "Raw must be hex"))?;
            let reply = crate::tron::post_async(&url, "broadcasthex", &crate::tron::broadcast_body(&bytes)).await.map_err(ApiError::internal)?;
            let txid = crate::tron::parse_broadcast(&reply, &[0u8; 32]).map_err(|e| ApiError::new(502, e.to_string()))?;
            return Ok(txid);
        }
        Family::Monero => return Err(ApiError::new(501, "Monero sends aren't available")),
    }
    .map_err(|e| ApiError::new(502, e.to_string()))?;
    reply.as_str().map(str::to_owned).ok_or_else(|| ApiError::new(502, "the node returned no transaction id"))
}
