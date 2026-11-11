//! `Airgap:*` endpoints — QR-payload interop with external signers. Strings
//! in, strings out; the host owns the camera and the screen.
//!
//! Scanning (any animated QR, frames in any order):
//!   `Airgap:decoderNew` → {Id}; `Airgap:decoderFeed` {Id, Part} → Progress
//!   (…, complete, payload); `Airgap:decoderStatus` {Id}; `Airgap:decoderDelete`.
//!   `Airgap:decode` {Parts:[…]} does it in one call when all frames are in hand.
//! Displaying: `Airgap:encode` {Type|FileType, Cbor|Bytes, Transport, …} → {parts}.
//! Keys: `Airgap:parseKeys` (preview) / `Airgap:importKeys` {Payload|Parts|
//!   DecoderId, Name?, EthAccounts?, Select?} → signer wallet + accounts.
//! Signing: `Airgap:signRequest` {Account, Transaction, Transport?, RPC|Network?,
//!   Offline?} → {requestId, parts, payload}; `Airgap:submitSignature`
//!   {Payload|Parts|DecoderId, RequestId?, Broadcast?, RPC|Network?} → signed tx
//! Display: `Airgap:qr` {Text|Parts} → QR modules, for hosts without a renderer.
//! Camera: `Airgap:scanFrame` {Width, Height, Luma, Id?} → the QR codes in a frame.
//!   (RequestId is mandatory for bitcoin answers — signed PSBT / raw tx — which
//!   carry none and are only accepted as the pending request's transaction).
//!   `Airgap:pending` {RequestId} shows an outstanding request.

use serde_json::{json, Value};

use crate::airgap::{self, decoder, import, registry, Transport};
use crate::Env;

use super::{ApiError, ApiResult};

fn bad(e: crate::Error) -> ApiError {
    ApiError::new(400, e.to_string())
}

fn str_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn usize_param(params: &Value, key: &str) -> Option<usize> {
    params.get(key).and_then(Value::as_u64).map(|n| n as usize)
}

fn progress_json(p: &decoder::Progress) -> Value {
    serde_json::to_value(p).unwrap_or(Value::Null)
}

// ── Decoder contexts ─────────────────────────────────────────────────────────

pub fn decoder_new(env: &Env, _params: &Value) -> ApiResult {
    let id = decoder::store_new(env).map_err(ApiError::internal)?;
    Ok(json!({ "Id": id }))
}

pub fn decoder_feed(env: &Env, params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id (decoder context) required"))?;
    let part = str_param(params, "Part").ok_or_else(|| ApiError::new(400, "Part (scanned frame) required"))?;
    let mut ctx = decoder::store_load(env, id).map_err(|e| ApiError::new(404, e.to_string()))?;
    let prog = ctx.feed(part).map_err(bad)?;
    decoder::store_save(env, id, &ctx).map_err(ApiError::internal)?;
    let mut j = progress_json(&prog);
    j["Id"] = Value::String(id.to_owned());
    Ok(j)
}

pub fn decoder_status(env: &Env, params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id (decoder context) required"))?;
    let ctx = decoder::store_load(env, id).map_err(|e| ApiError::new(404, e.to_string()))?;
    let mut j = progress_json(&ctx.progress().map_err(bad)?);
    j["Id"] = Value::String(id.to_owned());
    Ok(j)
}

pub fn decoder_delete(env: &Env, params: &Value) -> ApiResult {
    let id = str_param(params, "Id").ok_or_else(|| ApiError::new(400, "Id (decoder context) required"))?;
    decoder::store_delete(env, id).map_err(ApiError::internal)?;
    Ok(json!({ "Id": id, "deleted": true }))
}

/// One-shot: all frames at once.
pub fn decode(env: &Env, params: &Value) -> ApiResult {
    let frames = frames_from_params(params)?;
    let _ = env;
    let (prog, _) = decoder::decode_all(&frames).map_err(bad)?;
    Ok(progress_json(&prog))
}

fn frames_from_params(params: &Value) -> Result<Vec<String>, ApiError> {
    if let Some(arr) = params.get("Parts").and_then(Value::as_array) {
        let frames: Vec<String> = arr.iter().filter_map(Value::as_str).map(str::to_owned).collect();
        if frames.is_empty() {
            return Err(ApiError::new(400, "Parts is empty"));
        }
        return Ok(frames);
    }
    if let Some(p) = str_param(params, "Payload") {
        // A pasted multi-line payload (e.g. several xpubs) is one raw frame;
        // several UR/BBQr frames may also be newline-separated.
        let lines: Vec<String> = p.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect();
        if lines.len() > 1 && lines.iter().all(|l| decoder::classify(l) != decoder::Kind::Raw) {
            return Ok(lines);
        }
        return Ok(vec![p.to_owned()]);
    }
    Err(ApiError::new(400, "Payload, Parts or DecoderId required"))
}

/// The complete payload named by `DecoderId`, `Parts` or `Payload`.
fn payload_from_params(env: &Env, params: &Value) -> Result<decoder::Payload, ApiError> {
    if let Some(id) = str_param(params, "DecoderId") {
        let ctx = decoder::store_load(env, id).map_err(|e| ApiError::new(404, e.to_string()))?;
        return ctx.payload().map_err(bad)?.ok_or_else(|| ApiError::new(400, "decoder context is not complete yet"));
    }
    let frames = frames_from_params(params)?;
    let (prog, payload) = decoder::decode_all(&frames).map_err(bad)?;
    payload.ok_or_else(|| ApiError::new(400, format!("payload incomplete: {}/{} frames", prog.received, prog.expected)))
}

// ── Encoding ─────────────────────────────────────────────────────────────────

/// Generic framing for hosts that build their own payloads: a UR `Type` with
/// `Cbor` (hex) — or `Bytes` (base64) for the `bytes` type — or a BBQr
/// `FileType` letter with `Bytes`. `Transport` selects ur (default) or bbqr.
pub fn encode(_env: &Env, params: &Value) -> ApiResult {
    use base64::Engine;
    let transport = Transport::parse(str_param(params, "Transport").unwrap_or("")).map_err(bad)?;
    let bytes = match str_param(params, "Bytes") {
        Some(b) => Some(base64::engine::general_purpose::STANDARD.decode(b).map_err(|e| ApiError::new(400, format!("Bytes: {e}")))?),
        None => None,
    };
    match transport {
        Transport::Ur => {
            let ur_type = str_param(params, "Type").unwrap_or(registry::UR_BYTES);
            let cbor = match (str_param(params, "Cbor"), &bytes) {
                (Some(h), _) => airgap::unhex(h).map_err(bad)?,
                (None, Some(b)) => outscript::bcur::bytes_to_cbor(b),
                (None, None) => return Err(ApiError::new(400, "Cbor (hex) or Bytes (base64) required")),
            };
            let parts = airgap::ur_parts(ur_type, &cbor, usize_param(params, "MaxFragmentLen"), usize_param(params, "ExtraParts")).map_err(bad)?;
            Ok(json!({ "transport": "ur", "type": ur_type, "parts": parts, "count": parts.len() }))
        }
        Transport::Bbqr => {
            let b = bytes.ok_or_else(|| ApiError::new(400, "Bytes (base64) required for bbqr"))?;
            let ft = str_param(params, "FileType").and_then(|s| s.chars().next()).and_then(outscript::bbqr::FileType::from_char).unwrap_or(outscript::bbqr::FileType::BINARY);
            let compress = params.get("Compress").and_then(Value::as_bool).unwrap_or(true);
            let parts = airgap::bbqr_parts(&b, ft, usize_param(params, "MaxPartLen"), compress).map_err(bad)?;
            Ok(json!({ "transport": "bbqr", "fileType": ft.as_char().to_string(), "parts": parts, "count": parts.len() }))
        }
    }
}

// ── Keys ─────────────────────────────────────────────────────────────────────

pub fn parse_keys(env: &Env, params: &Value) -> ApiResult {
    let payload = payload_from_params(env, params)?;
    let export = import::parse(env, &payload).map_err(bad)?;
    Ok(serde_json::to_value(export).unwrap())
}

pub fn import_keys(env: &Env, params: &Value) -> ApiResult {
    let payload = payload_from_params(env, params)?;
    let export = import::parse(env, &payload).map_err(bad)?;
    let opts = import::ImportOptions {
        name: str_param(params, "Name").map(str::to_owned),
        eth_accounts: params.get("EthAccounts").and_then(Value::as_u64).map(|n| n as u32),
        select_paths: params.get("Select").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
        ..Default::default()
    };
    let imported = import::import(env, &export, &opts).map_err(bad)?;
    env.broadcast(&crate::response::event("wallet:created", json!({ "id": imported.wallet.id, "protocol": "airgap", "imported": true })));
    let mut j = serde_json::to_value(&imported).unwrap();
    j["export"] = json!({ "format": export.format, "device": export.device, "masterFingerprint": export.master_fingerprint });
    Ok(j)
}

// ── Signing ──────────────────────────────────────────────────────────────────
//
// What a request needs from the node — nonce and fees, UTXOs, a blockhash — is
// fetched here, async, and put into the Transaction; the builder then works
// from the Transaction alone. So the same code runs natively (driven by
// `rt::block_on`) and in the browser (awaited).

fn framing_from_params(params: &Value) -> Result<airgap::sign::Framing, ApiError> {
    Ok(airgap::sign::Framing {
        transport: Transport::parse(str_param(params, "Transport").unwrap_or("")).map_err(bad)?,
        max_fragment_len: usize_param(params, "MaxFragmentLen"),
        max_part_len: usize_param(params, "MaxPartLen"),
        extra_parts: usize_param(params, "ExtraParts"),
    })
}

/// The node to use: `RPC` > `Network` (id or `type.chainId`) > the current /
/// default network for the account's chain — unless `Offline: true`, in which
/// case none (the Transaction must then be complete).
fn rpc_from_params(env: &Env, params: &Value, account_kind: &str) -> Result<Option<String>, ApiError> {
    if params.get("Offline").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    if let Some(url) = str_param(params, "RPC") {
        return Ok(Some(url.to_owned()));
    }
    if let Some(net_id) = str_param(params, "Network") {
        let net = crate::models::network::fetch(env, net_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, format!("network {net_id} not found")))?;
        return Ok(Some(net.resolved_rpc().map_err(ApiError::internal)?));
    }
    let want = match account_kind {
        "ethereum" => "evm",
        other => other,
    };
    Ok(super::resolve_rpc_for_kind(env, params, want).ok())
}

/// At most this many previous transactions are fetched for one spend.
const MAX_PREV_TXS: usize = 50;

/// A bitcoin `Transaction` with what the PSBT builder would ask the node for:
/// the account's `UTXOs` (unless given) and — best effort — `PrevTxs`, the
/// previous transactions of the inputs the builder will pick, which let a
/// signer verify the amounts it shows. The builder only embeds a previous
/// transaction that hashes to its input's txid.
pub(crate) async fn prefill_bitcoin(account: &crate::models::account::Account, tx: &Value, url: &str) -> Result<Value, ApiError> {
    let mut tx = tx.clone();
    if !tx.is_object() {
        return Err(ApiError::new(400, "Transaction must be an object"));
    }
    if tx.get("UTXOs").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
        return Ok(tx);
    }
    let xpub = account.xpub().map_err(ApiError::internal)?;
    let assets = crate::rpc::call_async(url, "modchain_assets", json!([xpub])).await.map_err(ApiError::internal)?;
    let all = crate::bitcoin::parse_native_utxos(&assets).map_err(ApiError::internal)?;
    tx["UTXOs"] = Value::Array(all.iter().map(|u| json!({ "txo": u.txo, "amount_sats": u.amount_sats, "height": u.height, "path": u.path, "script": u.script })).collect());

    let want = tx.get("Amount").or_else(|| tx.get("amount")).and_then(Value::as_u64).unwrap_or(0);
    let fee_rate = tx.get("FeeRate").and_then(Value::as_u64).unwrap_or(10);
    if tx.get("PrevTxs").is_none() {
        if let Ok((selected, _)) = crate::bitcoin::select_utxos(&all, want, fee_rate) {
            let mut prev = serde_json::Map::new();
            for u in selected.iter().take(MAX_PREV_TXS) {
                let Some((txid, _)) = u.txo.split_once(':') else { continue };
                if prev.contains_key(txid) {
                    continue;
                }
                if let Ok(Value::String(raw)) = crate::rpc::call_async(url, "getrawtransaction", json!([txid])).await {
                    prev.insert(txid.to_owned(), Value::String(raw));
                }
            }
            if !prev.is_empty() {
                tx["PrevTxs"] = Value::Object(prev);
            }
        }
    }
    Ok(tx)
}

/// The account's `Transaction`, completed from the node `url` (when there is
/// one) so the request builder needs nothing more.
async fn prefill(env: &Env, account: &crate::models::account::Account, params: &Value, tx: &Value, url: Option<&str>) -> Result<Value, ApiError> {
    let Some(url) = url else { return Ok(tx.clone()) };
    match account.kind.as_str() {
        "bitcoin" => prefill_bitcoin(account, tx, url).await,
        "ethereum" => {
            let mut p = json!({ "Transaction": tx });
            // The EVM chain id is the signature's replay domain: it is pinned
            // from the Network model, never asked of the node. With an explicit
            // `RPC` there is no Network to vouch for the chain, so the caller
            // must supply chainId itself.
            if str_param(params, "RPC").is_none() {
                if let Some(net) = str_param(params, "Network") {
                    p["Network"] = json!(net);
                }
                p = super::account::evm_pin_chain_id(env, &p)?;
            }
            let filled = super::account::evm_fill(&account.address, url, &p).await?;
            Ok(filled["Transaction"].clone())
        }
        "solana" => {
            let mut tx = tx.clone();
            let prebuilt = tx.get("message").or_else(|| tx.get("Message")).is_some();
            if !prebuilt && tx.get("recentBlockhash").is_none() && tx.is_object() {
                let bh = crate::rpc::call_async(url, "getLatestBlockhash", json!([])).await.map_err(ApiError::internal)?;
                let bh = bh.get("value").and_then(|v| v.get("blockhash")).and_then(Value::as_str).ok_or_else(|| ApiError::new(502, "no blockhash in the node's answer"))?;
                tx["recentBlockhash"] = json!(bh);
            }
            Ok(tx)
        }
        _ => Ok(tx.clone()),
    }
}

pub async fn sign_request_impl(env: &Env, params: &Value) -> ApiResult {
    let account_id = str_param(params, "Account").or_else(|| str_param(params, "Id")).ok_or_else(|| ApiError::new(400, "Account required"))?;
    let tx = params.get("Transaction").ok_or_else(|| ApiError::new(400, "Transaction required"))?;
    let account = crate::models::account::fetch(env, account_id).map_err(ApiError::internal)?.ok_or_else(|| ApiError::new(404, "account not found"))?;
    let rpc = rpc_from_params(env, params, &account.kind)?;
    let framing = framing_from_params(params)?;
    let tx = prefill(env, &account, params, tx, rpc.as_deref()).await?;
    let built = airgap::sign::build_request(env, account_id, &tx, &framing, None).map_err(bad)?;
    let mut j = serde_json::to_value(&built).unwrap();
    j["count"] = json!(built.parts.len());
    Ok(j)
}

pub async fn submit_signature_impl(env: &Env, params: &Value) -> ApiResult {
    let payload = payload_from_params(env, params)?;
    let request_id = str_param(params, "RequestId");
    let accepted = airgap::sign::accept(env, &payload, request_id).map_err(bad)?;
    let mut j = serde_json::to_value(&accepted).unwrap();
    if let Some(id) = str_param(params, "DecoderId") {
        let _ = decoder::store_delete(env, id);
    }
    // A generic route (Account:signAndSendTransaction, …) waiting for this
    // answer takes it from here — broadcasting included, if its caller asked.
    if let Some(rid) = accepted.request_id.as_deref().filter(|r| super::signer::airgap_waiting(r)) {
        j["delivered"] = json!(super::signer::airgap_deliver(rid, Ok(j.clone())));
        return Ok(j);
    }
    if params.get("Broadcast").and_then(Value::as_bool) == Some(true) {
        j["broadcast"] = broadcast_accepted(env, params, &j).await?;
    }
    Ok(j)
}

/// Send an accepted transaction (`{chain, raw}`) through its chain's node.
pub(crate) async fn broadcast_accepted(env: &Env, params: &Value, accepted: &Value) -> ApiResult {
    let chain = accepted.get("chain").and_then(Value::as_str).unwrap_or_default();
    let raw = accepted.get("raw").and_then(Value::as_str).unwrap_or_default();
    let url = rpc_from_params(env, params, chain)?.ok_or_else(|| ApiError::new(400, "Broadcast needs an RPC/Network (not Offline)"))?;
    let (method, args) = match chain {
        "ethereum" => ("eth_sendRawTransaction", json!([raw])),
        "bitcoin" => ("sendrawtransaction", json!([raw.trim_start_matches("0x")])),
        "solana" => ("sendTransaction", json!([raw, { "encoding": "base58" }])),
        other => return Err(ApiError::new(400, format!("cannot broadcast {other}"))),
    };
    crate::rpc::call_async(&url, method, args).await.map_err(|e| ApiError::new(502, e.to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn sign_request(env: &Env, params: &Value) -> ApiResult {
    crate::rt::block_on(sign_request_impl(env, params))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn submit_signature(env: &Env, params: &Value) -> ApiResult {
    crate::rt::block_on(submit_signature_impl(env, params))
}

pub fn pending(env: &Env, params: &Value) -> ApiResult {
    let rid = str_param(params, "RequestId").ok_or_else(|| ApiError::new(400, "RequestId required"))?;
    match airgap::sign::pending_load(env, rid).map_err(ApiError::internal)? {
        Some(p) => Ok(serde_json::to_value(p).unwrap()),
        None => Err(ApiError::new(404, "no such pending request (expired?)")),
    }
}

// ── QR rendering ─────────────────────────────────────────────────────────────

/// At most this many frames are rendered per call.
const MAX_QR_FRAMES: usize = 512;

/// `Airgap:qr` {Text | Parts: […], Ecc?: "L"|"M"|"Q"|"H"} — the QR code
/// modules for each frame, for hosts without a QR renderer of their own:
/// `{codes: [{size, rows: ["0110…", …]}]}` (`1` = dark). UR and BBQr frames
/// are uppercase alphanumeric, which QR encodes compactly.
pub fn qr(_env: &Env, params: &Value) -> ApiResult {
    use anyd::codes::qr::EcLevel;
    let frames: Vec<&str> = match (str_param(params, "Text"), params.get("Parts").and_then(Value::as_array)) {
        (Some(t), _) => vec![t],
        (None, Some(a)) => a.iter().filter_map(Value::as_str).collect(),
        (None, None) => return Err(ApiError::new(400, "Text or Parts required")),
    };
    if frames.is_empty() || frames.len() > MAX_QR_FRAMES {
        return Err(ApiError::new(400, format!("1-{MAX_QR_FRAMES} frames required")));
    }
    let ecc = match str_param(params, "Ecc").unwrap_or("L") {
        "L" => EcLevel::L,
        "M" => EcLevel::M,
        "Q" => EcLevel::Q,
        "H" => EcLevel::H,
        other => return Err(ApiError::new(400, format!("unknown Ecc {other:?}"))),
    };
    let mut codes = Vec::with_capacity(frames.len());
    for f in frames {
        let rows = qr_rows(f, ecc).ok_or_else(|| ApiError::new(400, "frame too long for one QR code: use shorter parts (MaxFragmentLen / MaxPartLen)"))?;
        codes.push(json!({ "size": rows.len(), "rows": rows }));
    }
    Ok(json!({ "codes": codes }))
}

/// The modules of the QR code for `text`, one `'0'`/`'1'` string per row.
fn qr_rows(text: &str, ecc: anyd::codes::qr::EcLevel) -> Option<Vec<String>> {
    use anyd::traits::Encode;
    let encoder = anyd::codes::qr::QrEncoder::new();
    let symbol = encoder.build_text(text, ecc).ok()?;
    let anyd::output::Encoding::Matrix(m) = encoder.encode(&symbol).ok()? else { return None };
    Some((0..m.height()).map(|y| (0..m.width()).map(|x| if m.get(x, y) { '1' } else { '0' }).collect()).collect())
}

/// The largest camera frame `Airgap:scanFrame` looks at (pixels).
const MAX_SCAN_PIXELS: usize = 1920 * 1080;

/// `Airgap:scanFrame` {Width, Height, Luma (base64, one byte per pixel, rows
/// top to bottom), Id?} — read the QR codes in a camera frame, for hosts
/// without a detector of their own: `{texts: […]}`. With `Id` (a decoder
/// context) each code is also fed to it and its progress is returned, so a
/// scan loop is one call per frame.
pub fn scan_frame(env: &Env, params: &Value) -> ApiResult {
    use base64::Engine;
    let dim = |k: &str| params.get(k).and_then(Value::as_u64).map(|n| n as usize).filter(|n| *n > 0).ok_or_else(|| ApiError::new(400, format!("{k} required")));
    let (width, height) = (dim("Width")?, dim("Height")?);
    let pixels = width.checked_mul(height).filter(|n| *n <= MAX_SCAN_PIXELS).ok_or_else(|| ApiError::new(400, "frame too large: scale it down"))?;
    let luma = str_param(params, "Luma").ok_or_else(|| ApiError::new(400, "Luma (base64) required"))?;
    let luma = base64::engine::general_purpose::STANDARD.decode(luma).map_err(|e| ApiError::new(400, format!("Luma: {e}")))?;
    if luma.len() != pixels {
        return Err(ApiError::new(400, format!("Luma is {} bytes, expected Width × Height = {pixels}", luma.len())));
    }
    let frame = anyd::GrayFrame::new(&luma, width, height).map_err(|e| ApiError::new(400, format!("frame: {e:?}")))?;
    let texts: Vec<String> = anyd::pipeline::scan_2d(&frame).iter().filter_map(|s| s.text()).filter(|t| !t.is_empty()).collect();
    let mut out = json!({ "texts": texts });
    if let Some(id) = str_param(params, "Id") {
        let mut ctx = decoder::store_load(env, id).map_err(|e| ApiError::new(404, e.to_string()))?;
        // A frame that is not part of this payload is not an error of the scan.
        let mut fed = false;
        for t in &texts {
            fed |= ctx.feed(t).is_ok();
        }
        if fed {
            decoder::store_save(env, id, &ctx).map_err(ApiError::internal)?;
        }
        out["progress"] = progress_json(&ctx.progress().map_err(bad)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_modules_are_square_and_bounded() {
        let env = Env::init_memory().unwrap();
        let out = qr(&env, &json!({ "Parts": ["UR:BYTES/HDCXLKAHSSQZ", "B$2P0100ABCDEF"] })).unwrap();
        let codes = out["codes"].as_array().unwrap();
        assert_eq!(codes.len(), 2);
        for c in codes {
            let size = c["size"].as_u64().unwrap() as usize;
            let rows = c["rows"].as_array().unwrap();
            assert_eq!(rows.len(), size);
            assert!(rows.iter().all(|r| r.as_str().unwrap().len() == size && r.as_str().unwrap().bytes().all(|b| b == b'0' || b == b'1')));
            // Top-left finder pattern: a dark 7-module bar.
            assert!(rows[0].as_str().unwrap().starts_with("1111111"));
        }
        // Uppercase alphanumeric frames encode compactly: version 1 or 2.
        assert!(codes[0]["size"].as_u64().unwrap() <= 25);
        assert!(qr(&env, &json!({})).is_err());
        assert!(qr(&env, &json!({ "Text": "x", "Ecc": "Z" })).is_err());
        assert!(qr(&env, &json!({ "Text": "A".repeat(8000) })).is_err());
    }

    /// A rendered QR code, painted into a camera-like frame, is read back —
    /// and fed to a decoder context when one is named.
    #[test]
    fn scan_frame_reads_a_rendered_code() {
        use base64::Engine;
        let env = Env::init_memory().unwrap();
        // A real single-part UR, so the decoder context accepts it.
        let text = airgap::ur_single("bytes", &outscript::bcur::bytes_to_cbor(b"hello anyd")).unwrap().to_uppercase();
        let text = text.as_str();
        let rows = qr_rows(text, anyd::codes::qr::EcLevel::M).unwrap();
        // 6 px per module, a 4-module quiet zone, on a grey-ish background.
        let (scale, quiet) = (6usize, 4usize);
        let side = (rows.len() + 2 * quiet) * scale;
        let (width, height) = (side + 40, side + 24);
        let mut luma = vec![235u8; width * height];
        for (y, row) in rows.iter().enumerate() {
            for (x, m) in row.bytes().enumerate() {
                if m == b'1' {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            luma[(12 + (y + quiet) * scale + dy) * width + 20 + (x + quiet) * scale + dx] = 20;
                        }
                    }
                }
            }
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&luma);
        let out = scan_frame(&env, &json!({ "Width": width, "Height": height, "Luma": b64 })).unwrap();
        assert_eq!(out["texts"], json!([text]));

        let id = decoder_new(&env, &json!({})).unwrap()["Id"].as_str().unwrap().to_owned();
        let out = scan_frame(&env, &json!({ "Width": width, "Height": height, "Luma": b64, "Id": id })).unwrap();
        assert_eq!(out["progress"]["complete"], true, "{out}");

        // An empty frame finds nothing; a wrong size is refused.
        let blank = base64::engine::general_purpose::STANDARD.encode(vec![200u8; 64 * 48]);
        assert_eq!(scan_frame(&env, &json!({ "Width": 64, "Height": 48, "Luma": blank })).unwrap()["texts"], json!([]));
        assert!(scan_frame(&env, &json!({ "Width": 65, "Height": 48, "Luma": blank })).is_err());
        assert!(scan_frame(&env, &json!({ "Width": 100_000, "Height": 100_000, "Luma": "" })).is_err());
    }

    /// The bitcoin prefill leaves a Transaction that already carries its UTXOs
    /// alone (no node is contacted).
    #[test]
    fn prefill_keeps_supplied_utxos() {
        let account: crate::models::account::Account = serde_json::from_value(json!({ "Id": "acct-x", "Type": "bitcoin" })).unwrap();
        let tx = json!({ "To": "bc1q", "Amount": 1, "UTXOs": [{ "txo": "00:0", "amount_sats": 5 }] });
        let out = crate::rt::block_on(prefill_bitcoin(&account, &tx, "http://127.0.0.1:1")).unwrap();
        assert_eq!(out, tx);
        assert!(crate::rt::block_on(prefill_bitcoin(&account, &json!("nope"), "http://127.0.0.1:1")).is_err());
    }
}
