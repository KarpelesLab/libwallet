//! Endpoint routing. Each Go `pobj.RegisterStatic("Path:action", fn)` and
//! object CRUD registration becomes an arm here. As packages are ported their
//! handlers are added and this match grows toward the ~107 Go endpoints.

mod account;
mod asset;
mod coininfo;
mod contact;
mod contract;
mod crash;
mod info;
mod lifecycle;
mod names;
mod network;
mod request;
mod simulate;
mod nft;
mod quote;
mod storekey;
mod swap;
mod token;
mod transaction;
mod wallet;
mod wallet_key;
mod wc;
mod web3;

use serde_json::Value;

use crate::handle::Handle;
use crate::Env;

/// Create all model tables on a fresh env (mirrors the Go per-package InitEnv).
pub fn init_models(env: &Env) -> crate::Result<()> {
    crate::models::contact::init(env)?;
    crate::models::crash::init(env)?;
    crate::models::wallet::init(env)?;
    crate::models::account::init(env)?;
    crate::models::asset::init(env)?;
    crate::models::network::init(env)?;
    crate::models::token::init(env)?;
    crate::models::nft::init(env)?;
    crate::models::transaction::init(env)?;
    crate::models::wc_session::init(env)?;
    crate::models::request::init(env)?;
    crate::models::connected_site::init(env)?;
    Ok(())
}

/// Error returned by an endpoint handler. `code` mirrors the numeric HTTP-ish
/// codes the Go side used (400/404/500/503...).
#[derive(Debug)]
pub struct ApiError {
    pub message: String,
    pub code: i64,
}

impl ApiError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        ApiError { message: message.into(), code }
    }

    pub fn not_found(path: &str) -> Self {
        ApiError::new(404, format!("unknown endpoint: {path}"))
    }
}

pub type ApiResult = Result<Value, ApiError>;

/// Route a request to its handler. `_verb`/`_params`/`_handle` are threaded
/// through for handlers that need them; Phase 0 only wires the Info endpoints.
pub fn route(handle: &Handle, path: &str, verb: &str, params: &Value) -> ApiResult {
    // Object-scoped `Wallet/Key/<id>[:action]` paths (the Dart client addresses
    // wallet keys by id in the path, not via a params field).
    if path == "Wallet/Key" {
        return wallet_key::list(&handle.env);
    }
    if let Some(rest) = path.strip_prefix("Wallet/Key/") {
        let (id, action) = rest.split_once(':').unwrap_or((rest, ""));
        return wallet_key::route(&handle.env, verb, id, action, params);
    }
    // Object-scoped `Web3/Connection[/<id>]` (manage connected dApps).
    if path == "Web3/Connection" {
        return web3::connection_route(&handle.env, verb, None, params);
    }
    if let Some(id) = path.strip_prefix("Web3/Connection/") {
        return web3::connection_route(&handle.env, verb, Some(id), params);
    }

    match path {
        "Info:ping" => info::ping(),
        "Info:version" => info::version(),
        "Info:paths" => info::paths(&handle.env),
        "Info:onboarding" => info::onboarding(&handle.env),
        "Info:first_run" => info::first_run(&handle.env),
        "Info:setWalletInfo" => info::set_wallet_info(&handle.env, params),
        "Info:getWalletInfo" => info::get_wallet_info(&handle.env),
        "Contact" => contact::route(&handle.env, verb, params),
        "Crash" => crash::route(&handle.env, verb, params),
        "Wallet" => wallet::route(&handle.env, verb, params),
        "Wallet:importPrivateKey" => wallet::import_private_key(&handle.env, params),
        "Wallet:importMnemonic" => wallet::import_mnemonic(&handle.env, params),
        "Wallet:multiCreate" => wallet::multi_create(&handle.env, params),
        "Wallet:backup" => wallet::backup(&handle.env, params),
        "Wallet:restore" => wallet::restore(&handle.env, params),
        "Account" => account::route(&handle.env, verb, params),
        "Account:signMessage" => account::sign_message(&handle.env, params),
        "Account:signTransaction" => account::sign_transaction(&handle.env, params),
        "Account:signAndSendTransaction" => account::sign_and_send_transaction(&handle.env, params),
        // Canonical Go names are plural; keep the singular as a compat alias.
        "Names:resolve" | "Name:resolve" => names::resolve(&handle.env, params),
        "Contracts:lookup" | "Contract:lookup" => contract::lookup(&handle.env, params),
        "Quote:get" => quote::get(&handle.env, params),
        "StoreKey:create" => storekey::create(&handle.env, params),
        "StoreKey:derivePassword" => storekey::derive_password(&handle.env, params),
        "WalletConnect:start" => wc::start(&handle.env, params),
        "WalletConnect:stop" => wc::stop(&handle.env),
        "WalletConnect:pair" => wc::pair(&handle.env, params),
        "WalletConnect:approveSession" => wc::approve_session(&handle.env, params),
        "WalletConnect:respond" => wc::respond(&handle.env, params),
        "WalletConnect:rejectSession" => wc::reject_session(&handle.env, params),
        "WalletConnect:respondError" => wc::respond_error(&handle.env, params),
        "WalletConnect:emitEvent" => wc::emit_event(&handle.env, params),
        "WalletConnect:disconnect" => wc::disconnect(&handle.env, params),
        "Wc:listSessions" | "WalletConnect:sessions" => {
            let list = crate::models::wc_session::list_by_state(&handle.env, "active")
                .map_err(ApiError::internal)?;
            Ok(serde_json::to_value(list).unwrap())
        }
        "Coin:info" => coininfo::info(&handle.env, params),
        "Swap:quote" => swap::quote(&handle.env, params),
        "Swap:execute" => swap::execute(&handle.env, params),
        "Swap:quotes" => swap::quotes(&handle.env, params),
        "Swap:maxSpendable" => swap::max_spendable(&handle.env, params),
        "Swap:buildApprovalData" => swap::build_approval_data(&handle.env, params),
        "Swap:buildApproval" => swap::build_approval(&handle.env, params),
        "Swap:availability" => swap::availability(&handle.env, params),
        "Swap:countryAvailability" => swap::country_availability(&handle.env, params),
        "Account:balance" => account::balance(&handle.env, params),
        "Account:tokenBalance" => account::token_balance(&handle.env, params),
        "Account:maxSendable" | "Transaction:maxSendable" => account::max_sendable(&handle.env, params),
        "Account:nativeAsset" => account::native_asset(&handle.env, params),
        "Account:xpub" => account::xpub(&handle.env, params),
        "Account:createView" => account::create_view(&handle.env, params),
        "Account:nextAddress" => account::next_address(&handle.env, params),
        "Account:listUTXOs" | "Account:utxos" => account::utxos(&handle.env, params),
        "Account:allAddresses" => account::all_addresses(&handle.env, params),
        "Account:addressFormats" => account::address_formats(&handle.env, params),
        "Account:setCurrent" => account::set_current(&handle.env, params),
        "Network:testRPC" => network::test_rpc(&handle.env, params),
        "Network:resolveRPC" => network::resolve_rpc(&handle.env, params),
        "Network:setCurrent" => network::set_current(&handle.env, params),
        "Asset" => asset::route(&handle.env, verb, params),
        "Asset:invalidateCache" => {
            // Drop the cached quote table so the next Asset conversion refetches.
            handle.env.cache_delete(&[crate::quote::CACHE_KEY]).map_err(ApiError::internal)?;
            Ok(serde_json::json!({ "invalidated": true }))
        }
        "Network" => network::route(&handle.env, verb, params),
        "Token" => token::route(&handle.env, verb, params),
        "Token:listCurated" => token::list_curated(&handle.env, params),
        "Token:discoverToken" => token::discover_token(&handle.env, params),
        "Nft" => nft::route(&handle.env, verb, params),
        "Transaction" => transaction::route(&handle.env, verb, params),
        "Transaction:validate" => transaction::validate(&handle.env, params),
        "Transaction:signAndSend" => transaction::sign_and_send(&handle.env, params),
        "Transaction:simulate" => simulate::simulate(&handle.env, params),
        "Web3:injectionScript" => web3::injection_script(&handle.env, params),
        "Web3:request" => web3::request(&handle.env, params),
        "Lifecycle:update" => lifecycle::update(&handle.env, params),
        "Request" => request::route(&handle.env, verb, params),
        "Request:test" => request::test(&handle.env),
        "Request:approve" => request::approve(&handle.env, params),
        "Request:reject" => request::reject(&handle.env, params),
        _ => Err(ApiError::not_found(path)),
    }
}

impl ApiError {
    /// Wrap a wltbase error as a 500.
    pub fn internal(e: impl std::fmt::Display) -> Self {
        ApiError::new(500, e.to_string())
    }
}
