//! Web3 provider endpoints (port of `wltbase/injection.go`). Currently the
//! `Web3:injectionScript` builder; the full EIP-1193 `Web3:request` router
//! (wltbase/web3.go) lands with the connected-site permission model.

use serde_json::{json, Value};

use crate::Env;

use super::{ApiError, ApiResult};

/// The webview provider shim, with the config placeholder the Go side rewrites.
const PROVIDER_JS: &str = include_str!("../web3/provider.js");
const CONFIG_PLACEHOLDER: &str = "__LIBWALLET_CONFIG__";

/// `Web3:injectionScript` {Name, Rdns, Uuid, Icon?, Bridge, Host?} — build the
/// JS blob the host runs inside a webview to expose libwallet as an EIP-6963 /
/// window.solana / window.mpurse provider. Substitutes `__LIBWALLET_CONFIG__`
/// with the per-install config, pre-seeding `initialChainId` from the current
/// EVM network so the provider can answer `eth_chainId` on first paint.
pub fn injection_script(env: &Env, params: &Value) -> ApiResult {
    let req = |k: &str| -> Result<String, ApiError> {
        params
            .get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::new(400, format!("{k} is required")))
    };
    let name = req("Name")?;
    let rdns = req("Rdns")?;
    let uuid = req("Uuid")?;
    let bridge = req("Bridge")?;
    let icon = params.get("Icon").and_then(Value::as_str).unwrap_or("");

    let mut cfg = json!({
        "name": name,
        "rdns": rdns,
        "uuid": uuid,
        "icon": icon,
        "bridge": bridge,
    });

    // Initial state — lets the provider answer eth_chainId synchronously on
    // first paint. Best-effort: on any failure we omit it (Go does the same).
    if let Ok(Some(n)) = crate::models::network::fetch(env, "@") {
        if n.kind == "evm" {
            if let Ok(chain) = n.chain_id.parse::<u128>() {
                cfg["initialChainId"] = json!(format!("0x{chain:x}"));
                cfg["initialNetworkVersion"] = json!(n.chain_id);
            }
        }
    }

    // `Host`/`initialAccounts` pre-seeding depends on the connected-site
    // permission store (Web3:request), ported alongside that endpoint.

    let cfg_json = serde_json::to_string(&cfg).map_err(ApiError::internal)?;
    let script = PROVIDER_JS.replace(CONFIG_PLACEHOLDER, &cfg_json);
    Ok(json!({ "script": script }))
}
