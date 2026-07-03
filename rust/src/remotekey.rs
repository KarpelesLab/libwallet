//! Cross-device (RemoteKey) message routing — the transport-independent core of
//! the wltwallet spot broker (`broker.go`). A RemoteKey ceremony is the same
//! FROST/DKLs keygen/sign already ported ([`crate::tss`]); the only difference
//! from the all-local [`crate::tss::LocalHub`] path is that one party's tsslib
//! messages travel over the spot network to the WalletSign backend instead of
//! an in-process channel.
//!
//! This module ports the wire-routing decisions — the target and sender address
//! strings — which must match Go byte-for-byte for cross-device interop. The
//! spotlib client that actually carries the bytes is injected via
//! [`SpotTransport`]; the live network client lands with deployment (like the
//! WalletConnect WS transport, it's a thin impl over this tested layer).

use crate::Result;

/// The spot transport: send an already-serialized tsslib message to `target`
/// with the canonical `sender` address (Go `spot.SendToWithFrom`).
pub trait SpotTransport {
    fn send_to(&self, target: &str, body: &[u8], sender: &str) -> Result<()>;
}

/// A remote signing peer over the spot network (Go `spotPeer`): the peer's spot
/// id, the WalletSign session id, and our own spot id.
pub struct SpotPeer {
    pub peer: String,
    pub sid: String,
    /// Our spot id; empty falls back to the legacy leading-slash sender form.
    pub self_id: String,
}

impl SpotPeer {
    /// The spot target for a message: `<peer>/walletsign/<sid>/broadcast` for a
    /// broadcast (no `To`), `.../single` for a directed message.
    pub fn target(&self, has_to: bool) -> String {
        let base = format!("{}/walletsign/{}", self.peer, self.sid);
        if has_to {
            format!("{base}/single")
        } else {
            format!("{base}/broadcast")
        }
    }

    /// The canonical sender address `<self_id>/<sid>/<from_party_id>`, or the
    /// legacy `/<sid>/<from_party_id>` when `self_id` is unset (wdrone tolerates
    /// both; new code always sets self_id).
    pub fn sender(&self, from_party_id: &str) -> String {
        if self.self_id.is_empty() {
            format!("/{}/{}", self.sid, from_party_id)
        } else {
            format!("{}/{}/{}", self.self_id, self.sid, from_party_id)
        }
    }

    /// Route one serialized tsslib message to this peer (Go `spotPeer.Send`).
    pub fn send<T: SpotTransport>(
        &self,
        transport: &T,
        from_party_id: &str,
        has_to: bool,
        body: &[u8],
    ) -> Result<()> {
        transport.send_to(&self.target(has_to), body, &self.sender(from_party_id))
    }
}
