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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_and_sender_wire_format() {
        let p = SpotPeer { peer: "k.peer".into(), sid: "crwsv-1".into(), self_id: "k.self".into() };
        assert_eq!(p.target(false), "k.peer/walletsign/crwsv-1/broadcast");
        assert_eq!(p.target(true), "k.peer/walletsign/crwsv-1/single");
        assert_eq!(p.sender("party-a"), "k.self/crwsv-1/party-a");
        let legacy = SpotPeer { peer: "k.peer".into(), sid: "crwsv-1".into(), self_id: String::new() };
        assert_eq!(legacy.sender("party-a"), "/crwsv-1/party-a");
    }

    /// The RemoteKey ceremony transport, end-to-end over the LIVE relay: two
    /// spotlib clients run a real 2-party FROST keygen routed through the exact
    /// production `walletsign/<sid>/{broadcast,single}` paths + `<self>/<sid>/
    /// <party>` sender format (`SpotPeer`). This proves the byte-for-byte wire
    /// routing that `Wallet:initiateKeygen`/`joinSign` ride on (the endpoints
    /// additionally need the WalletSign backend to hold the wdrone party's share,
    /// which is not reachable here). Gated behind `SPOT_LIVE=1`.
    #[test]
    fn frost_keygen_over_live_spot_walletsign_routing() {
        if std::env::var("SPOT_LIVE").ok().as_deref() != Some("1") {
            return;
        }
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use tsslib::frosttss::Keygen;
        use tsslib::tss::{JsonMessage, MessageBroker, Parameters, PartyId};

        use crate::spotbroker::SpotBroker;

        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        let sid = "crwsv-test-sid";
        let a = Arc::new(spotlib::Client::builder().meta("project", "libwallet-test").build().unwrap());
        let b = Arc::new(spotlib::Client::builder().meta("project", "libwallet-test").build().unwrap());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if a.connection_count().1 > 0 && b.connection_count().1 > 0 {
                break;
            }
            assert!(Instant::now() < deadline, "clients did not come online");
            std::thread::sleep(Duration::from_millis(300));
        }
        let (a_id, b_id) = (a.target_id(), b.target_id());

        let (key_a, key_b) = (vec![1u8; 16], vec![2u8; 16]);
        let ids = PartyId::sort(
            vec![PartyId::new(hex(&key_a), "", key_a.clone()), PartyId::new(hex(&key_b), "", key_b.clone())],
            0,
        );
        let (party0, party1) = (ids[0].clone(), ids[1].clone());

        // Each broker's send closure re-parses the serialized JsonMessage to
        // recover (has_to, from_party_id) — exactly what the Go tssHub inspects —
        // then routes via SpotPeer over the peer's "walletsign" endpoint.
        //
        // The sender uses SpotPeer's relative form (`self_id` empty →
        // `/<sid>/<party>`): spotlib's relay auto-prepends this client's
        // authenticated id, yielding the Go-identical wire sender
        // `k.<self>/<sid>/<party>`. Passing the absolute form ourselves would
        // double-prefix and the message never routes.
        let make_send = |client: Arc<spotlib::Client>, peer: String| -> crate::spotbroker::SendFn {
            let sid = sid.to_string();
            Box::new(move |bytes: Vec<u8>| {
                let msg: JsonMessage = match serde_json::from_slice(&bytes) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                let has_to = msg.to.is_some();
                let from_id = msg.from.as_ref().map(|f| f.id.clone()).unwrap_or_default();
                let sp = SpotPeer { peer: peer.clone(), sid: sid.clone(), self_id: String::new() };
                let _ = client.send_to_with_from(&sp.target(has_to), &bytes, &sp.sender(&from_id), Duration::from_secs(20));
            })
        };
        let broker0 = SpotBroker::new(party0.index, make_send(a.clone(), b_id.clone()));
        let broker1 = SpotBroker::new(party1.index, make_send(b.clone(), a_id.clone()));

        // Inbound: the "walletsign" endpoint handler feeds bytes to the broker.
        let hb0 = broker0.clone();
        a.set_handler("walletsign", Some(move |m: &spotlib::Message| {
            let _ = hb0.deliver_inbound_bytes(&m.body);
            Ok(None)
        }));
        let hb1 = broker1.clone();
        b.set_handler("walletsign", Some(move |m: &spotlib::Message| {
            let _ = hb1.deliver_inbound_bytes(&m.body);
            Ok(None)
        }));

        let (bb0, bb1): (Arc<dyn MessageBroker + Send + Sync>, Arc<dyn MessageBroker + Send + Sync>) = (broker0, broker1);
        let (ids0, ids1) = (ids.clone(), ids.clone());
        let (p0, p1) = (party0.clone(), party1.clone());
        let _ = sid; // silence: captured by closures
        let h0 = std::thread::spawn(move || Keygen::new(Parameters::new(ids0, &p0, 1, bb0)).unwrap().wait());
        let h1 = std::thread::spawn(move || Keygen::new(Parameters::new(ids1, &p1, 1, bb1)).unwrap().wait());
        let key0 = h0.join().unwrap().expect("party0 keygen");
        let key1 = h1.join().unwrap().expect("party1 keygen");
        assert_eq!(hex(&crate::tss::frost_group_pubkey(&key0)), hex(&crate::tss::frost_group_pubkey(&key1)));
        a.close();
        b.close();
    }
}
