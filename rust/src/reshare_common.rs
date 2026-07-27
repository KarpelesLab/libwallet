//! Pure (transport-free) helpers shared by the native [`crate::reshare`]
//! ceremonies and the browser [`crate::reshare_wasm`] ones. These carry no
//! threads and no Spot client, so they compile on both targets — unlike
//! `reshare`, which is native-only (blocking threads + the sync Spot client).
//!
//! Ported from wltwallet/join.go (`joinPeer`, `sidFromRemoteKey`,
//! `buildPartyIDs`) plus the local-share opener shared with reshare.go.

use std::collections::HashMap;

use tsslib::tss::PartyId;

use crate::{Error, Result};

/// One committee member as described on the wire (Go `joinPeer`).
pub struct JoinPeer {
    pub spot_id: String,
    pub moniker: String,
    /// base64url(raw Ed25519 pubkey) — becomes the tss `PartyId.key`.
    pub key: String,
}

/// Extract the walletsign session id (`crwsv-*`) from a `<crws>:<crwsv>`
/// RemoteKey (Go `sidFromRemoteKey`). initiateKeygen/joinSign use the crwsv
/// suffix (unlike reshare, which uses the whole string).
pub fn sid_from_remote_key(rk: &str) -> &str {
    match rk.find(':') {
        Some(i) => &rk[i + 1..],
        None => rk,
    }
}

/// Build the sorted committee from the peer list + locate the local party (Go
/// `buildPartyIDs`). `PartyId.key` = base64url-decoded Ed25519 pubkey (all
/// parties must agree so SortedPartyIDs matches); id/moniker carry the moniker.
pub fn build_party_ids<'a>(
    peers: &'a [JoinPeer],
    me_spot: &str,
    me_moniker: &str,
) -> Result<(Vec<PartyId>, HashMap<String, &'a JoinPeer>, usize)> {
    use base64::Engine;
    if peers.len() < 2 {
        return Err(Error::Env(format!("initiateKeygen: need at least 2 peers, got {}", peers.len())));
    }
    let mut ids = Vec::with_capacity(peers.len());
    let mut by_moniker = HashMap::new();
    for p in peers {
        if p.moniker.is_empty() {
            return Err(Error::Env("initiateKeygen: peer with empty moniker".into()));
        }
        if by_moniker.insert(p.moniker.clone(), p).is_some() {
            return Err(Error::Env(format!("initiateKeygen: duplicate moniker {}", p.moniker)));
        }
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&p.key)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&p.key))
            .map_err(|_| Error::Env(format!("initiateKeygen: peer {} has an invalid base64 key", p.moniker)))?;
        if key.is_empty() {
            return Err(Error::Env(format!("initiateKeygen: peer {} has empty key bytes", p.moniker)));
        }
        ids.push(PartyId::new(p.moniker.clone(), p.moniker.clone(), key));
    }
    let sorted = PartyId::sort(ids, 0);
    let mut me_idx = None;
    if !me_moniker.is_empty() {
        me_idx = sorted.iter().position(|id| id.moniker == me_moniker);
    }
    if me_idx.is_none() && !me_spot.is_empty() {
        me_idx = sorted.iter().position(|id| by_moniker.get(&id.moniker).map(|p| p.spot_id.as_str()) == Some(me_spot));
    }
    let me_idx = me_idx.ok_or_else(|| Error::Env(format!("initiateKeygen: caller not in peer list (spot={me_spot} moniker={me_moniker})")))?;
    Ok((sorted, by_moniker, me_idx))
}

/// Open a locally-held (Plain/Password/StoreKey) FROST share to its JSON.
#[allow(clippy::ptr_arg)]
pub fn open_local_share(wk: &crate::models::wallet::WalletKey, material: &str) -> Result<String> {
    let xid: xuid::Xuid = wk.id.parse().map_err(|e| Error::Env(format!("bad walletkey id: {e}")))?;
    let uuid = xid.uuid().as_bytes().to_vec();
    let json = if wk.kind == "Plain" {
        crate::keystore::open(&wk.data, []).map_err(|e| Error::Env(e.to_string()))?
    } else {
        let k = crate::models::wallet::resolve_unlock_key(&wk.kind, material, &uuid)?;
        crate::keystore::open(&wk.data, [k]).map_err(|e| Error::Env(e.to_string()))?
    };
    String::from_utf8(json).map_err(|e| Error::Env(e.to_string()))
}
