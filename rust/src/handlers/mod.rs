//! Endpoint routing. Each Go `pobj.RegisterStatic("Path:action", fn)` and
//! object CRUD registration becomes an arm here. As packages are ported their
//! handlers are added and this match grows toward the ~107 Go endpoints.

mod account;
#[cfg(not(target_arch = "wasm32"))]
mod asset;
#[cfg(not(target_arch = "wasm32"))]
mod coininfo;
mod contact;
#[cfg(not(target_arch = "wasm32"))]
mod contract;
mod crash;
mod info;
mod lifecycle;
#[cfg(not(target_arch = "wasm32"))]
mod names;
mod network;
#[cfg(not(target_arch = "wasm32"))]
mod request;
#[cfg(not(target_arch = "wasm32"))]
mod simulate;
#[cfg(not(target_arch = "wasm32"))]
mod spot;
mod nft;
#[cfg(not(target_arch = "wasm32"))]
mod quote;
#[cfg(not(target_arch = "wasm32"))]
mod remotekey;
mod storekey;
#[cfg(not(target_arch = "wasm32"))]
mod swap;
mod token;
#[cfg(not(target_arch = "wasm32"))]
mod transaction;
mod wallet;
mod wallet_key;
#[cfg(not(target_arch = "wasm32"))]
mod wc;
#[cfg(not(target_arch = "wasm32"))]
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
    #[cfg(not(target_arch = "wasm32"))]
    crate::models::asset::init(env)?;
    crate::models::network::init(env)?;
    crate::models::token::init(env)?;
    crate::models::nft::init(env)?;
    #[cfg(not(target_arch = "wasm32"))]
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

/// Object names whose registered path is itself two segments (`A/B`); their id,
/// when present, is the *third* segment (`A/B/<id>`). Every other object is a
/// single segment with the id in the second (`A/<id>`).
const COMPOUND_OBJECTS: [&str; 2] = ["Wallet/Key", "Web3/Connection"];

/// Split a request path into `(object, id, action)`.
///
/// The Go apirouter/pobj layer addressed objects positionally: `Account/<id>`,
/// `Account/<id>:setCurrent`, `Wallet/Key/<id>:recrypt`, `Web3/Connection/<id>`.
/// The Rust handlers instead read the object id from `params["Id"]`, so we parse
/// the id out of the path here (see [`route`], which injects it into params).
/// `action` is `""` for the bare object form.
fn parse_path(path: &str) -> (&str, Option<&str>, &str) {
    let (left, action) = path.split_once(':').unwrap_or((path, ""));
    for obj in COMPOUND_OBJECTS {
        if left == obj {
            return (obj, None, action);
        }
        if let Some(rest) = left.strip_prefix(obj).and_then(|r| r.strip_prefix('/')) {
            return (obj, Some(rest), action);
        }
    }
    match left.split_once('/') {
        Some((obj, id)) => (obj, Some(id), action),
        None => (left, None, action),
    }
}

/// Return `params` with `Id` set to the path-derived object id. An explicit
/// `params["Id"]` (should never coexist with a path id) is left untouched.
fn with_path_id(params: &Value, id: &str) -> Value {
    match params {
        Value::Object(m) => {
            let mut m = m.clone();
            m.entry("Id".to_string()).or_insert_with(|| Value::String(id.to_string()));
            Value::Object(m)
        }
        Value::Null => serde_json::json!({ "Id": id }),
        other => other.clone(),
    }
}

/// Route a request to its handler. Object-scoped paths (`Object/<id>[:action]`,
/// the wire form the Dart client and the Go pobj router use) are parsed into
/// `(object, id, action)`; the id is injected into `params` so the flat match
/// below — keyed on the canonical `Object[:action]` — reaches the same handlers
/// whether the caller addressed the object by path or by an `Id` param.
pub fn route(handle: &Handle, path: &str, verb: &str, params: &Value) -> ApiResult {
    let env = &handle.env;
    let (object, id, action) = parse_path(path);

    // Expose the path id to handlers that read `params["Id"]`.
    let injected;
    let params: &Value = match id {
        Some(id) => {
            injected = with_path_id(params, id);
            &injected
        }
        None => params,
    };

    // Compound-name objects and the wallet actions that take the id positionally
    // are dispatched before the flat match (which is keyed on a rebuilt
    // `Object[:action]` string and cannot express the `A/B` object names).
    match object {
        "Wallet/Key" => {
            return match (id, action) {
                (None, "") => wallet_key::list(env),
                (id, action) => wallet_key::route(env, verb, id.unwrap_or(""), action, params),
            };
        }
        #[cfg(not(target_arch = "wasm32"))]
        "Web3/Connection" => return web3::connection_route(env, verb, id, params),
        "Wallet" if id.is_some() => {
            let wid = id.unwrap();
            match action {
                #[cfg(not(target_arch = "wasm32"))]
                "probeActivity" => return wallet::probe_activity(env, wid, params),
                "promoteMnemonic" => return wallet::promote_mnemonic(env, wid, params),
                #[cfg(not(target_arch = "wasm32"))]
                "exportToDevice" => return spot::export_to_device(env, wid, params),
                #[cfg(not(target_arch = "wasm32"))]
                "reshare" => return spot::wallet_reshare(env, wid, params),
                #[cfg(not(target_arch = "wasm32"))]
                "promote" => return spot::wallet_promote(env, wid, params),
                _ => {}
            }
        }
        _ => {}
    }

    // Canonical `Object` / `Object:action` key for the flat match.
    let canon: std::borrow::Cow<str> = if action.is_empty() {
        std::borrow::Cow::Borrowed(object)
    } else {
        std::borrow::Cow::Owned(format!("{object}:{action}"))
    };

    match canon.as_ref() {
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
        #[cfg(not(target_arch = "wasm32"))]
        "Account:signAndSendTransaction" => account::sign_and_send_transaction(&handle.env, params),
        // Canonical Go names are plural; keep the singular as a compat alias.
        #[cfg(not(target_arch = "wasm32"))]
        "Names:resolve" | "Name:resolve" => names::resolve(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Contracts:lookup" | "Contract:lookup" => contract::lookup(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Quote:get" => quote::get(&handle.env, params),
        "StoreKey:create" => storekey::create(&handle.env, params),
        "StoreKey:derivePassword" => storekey::derive_password(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:start" => wc::start(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:stop" => wc::stop(&handle.env),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:pair" => wc::pair(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:approveSession" => wc::approve_session(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:respond" => wc::respond(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:rejectSession" => wc::reject_session(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:respondError" => wc::respond_error(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:emitEvent" => wc::emit_event(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "WalletConnect:disconnect" => wc::disconnect(&handle.env, params),
        "Wc:listSessions" | "WalletConnect:sessions" => {
            let list = crate::models::wc_session::list_by_state(&handle.env, "active")
                .map_err(ApiError::internal)?;
            Ok(serde_json::to_value(list).unwrap())
        }
        #[cfg(not(target_arch = "wasm32"))]
        "Coin:info" => coininfo::info(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:quote" => swap::quote(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:execute" => swap::execute(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:quotes" => swap::quotes(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:maxSpendable" => swap::max_spendable(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:buildApprovalData" => swap::build_approval_data(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:buildApproval" => swap::build_approval(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:availability" => swap::availability(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:countryAvailability" => swap::country_availability(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Swap:orderStatus" => swap::order_status(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Account:balance" => account::balance(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Account:tokenBalance" => account::token_balance(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Account:maxSendable" | "Transaction:maxSendable" => account::max_sendable(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Account:nativeAsset" => account::native_asset(&handle.env, params),
        "Account:xpub" => account::xpub(&handle.env, params),
        "Account:createView" => account::create_view(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Account:nextAddress" => account::next_address(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Account:listUTXOs" | "Account:utxos" => account::utxos(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Account:allAddresses" => account::all_addresses(&handle.env, params),
        "Account:addressFormats" => account::address_formats(&handle.env, params),
        "Account:setCurrent" => account::set_current(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Network:testRPC" => network::test_rpc(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Network:resolveRPC" => network::resolve_rpc(&handle.env, params),
        "Network:setCurrent" => network::set_current(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Asset" => asset::route(&handle.env, verb, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Asset:invalidateCache" => {
            // Drop the cached quote table so the next Asset conversion refetches.
            handle.env.cache_delete(&[crate::quote::CACHE_KEY]).map_err(ApiError::internal)?;
            Ok(serde_json::json!({ "invalidated": true }))
        }
        "Network" => network::route(&handle.env, verb, params),
        "Token" => token::route(&handle.env, verb, params),
        "Token:listCurated" => token::list_curated(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Token:discoverToken" => token::discover_token(&handle.env, params),
        "Nft" => nft::route(&handle.env, verb, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Transaction" => transaction::route(&handle.env, verb, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Transaction:validate" => transaction::validate(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Transaction:signAndSend" => transaction::sign_and_send(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Transaction:backfill" => transaction::backfill(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Transaction:simulate" => simulate::simulate(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Web3:injectionScript" => web3::injection_script(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Web3:request" => web3::request(&handle.env, params),
        "Lifecycle:update" => lifecycle::update(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Spot:status" => spot::status(&handle.env),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:exportToDevice" => spot::export_to_device(&handle.env, "", params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:exportToDeviceConfirm" => spot::export_confirm(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:exportToDeviceCancel" => spot::export_cancel(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:importFromDevice" => spot::import_from_device(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:reshare" => spot::wallet_reshare(&handle.env, "", params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:promote" => spot::wallet_promote(&handle.env, "", params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:initiateKeygen" => spot::initiate_keygen(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:joinSign" => spot::join_sign(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:buildNewAgentBody" => spot::build_new_agent_body(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "ClawdWallet:pair" => spot::clawd_pair(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Wallet:repairRemoteKey" => spot::repair_remote_key(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "RemoteKey:new" => remotekey::new(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "RemoteKey:reshare" => remotekey::reshare(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "RemoteKey:validate" => remotekey::validate(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Request" => request::route(&handle.env, verb, params),
        #[cfg(not(target_arch = "wasm32"))]
        "Request:test" => request::test(&handle.env),
        #[cfg(not(target_arch = "wasm32"))]
        "Request:approve" => request::approve(&handle.env, params),
        #[cfg(not(target_arch = "wasm32"))]
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
