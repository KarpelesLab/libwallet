//! Cross-device (RemoteKey) spot message routing — the target/sender wire
//! format must match Go `spotPeer.Send` byte-for-byte for interop. The spotlib
//! client is mocked; only the address construction + dispatch is exercised.

use std::cell::RefCell;

use libwallet::remotekey::{SpotPeer, SpotTransport};

#[derive(Default)]
struct MockSpot {
    sent: RefCell<Vec<(String, Vec<u8>, String)>>, // (target, body, sender)
}
impl SpotTransport for MockSpot {
    fn send_to(&self, target: &str, body: &[u8], sender: &str) -> libwallet::Result<()> {
        self.sent.borrow_mut().push((target.to_owned(), body.to_vec(), sender.to_owned()));
        Ok(())
    }
}

#[test]
fn target_and_sender_match_go_format() {
    let peer = SpotPeer { peer: "peerSpotId".into(), sid: "sess123".into(), self_id: "meSpotId".into() };

    // Broadcast (no To) vs directed (To present).
    assert_eq!(peer.target(false), "peerSpotId/walletsign/sess123/broadcast");
    assert_eq!(peer.target(true), "peerSpotId/walletsign/sess123/single");

    // Canonical sender = <self_id>/<sid>/<from_party_id>.
    assert_eq!(peer.sender("partyA"), "meSpotId/sess123/partyA");

    // Legacy leading-slash form when self_id is unset.
    let legacy = SpotPeer { peer: "p".into(), sid: "s".into(), self_id: String::new() };
    assert_eq!(legacy.sender("partyA"), "/s/partyA");
}

#[test]
fn send_routes_body_to_transport() {
    let peer = SpotPeer { peer: "peer".into(), sid: "sid".into(), self_id: "me".into() };
    let spot = MockSpot::default();

    // A broadcast keygen message.
    peer.send(&spot, "party0", false, br#"{"type":"eddsa:keygen:round1"}"#).unwrap();
    // A directed signing message.
    peer.send(&spot, "party0", true, b"directed").unwrap();

    let sent = spot.sent.borrow();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].0, "peer/walletsign/sid/broadcast");
    assert_eq!(sent[0].1, br#"{"type":"eddsa:keygen:round1"}"#);
    assert_eq!(sent[0].2, "me/sid/party0");
    assert_eq!(sent[1].0, "peer/walletsign/sid/single");
    assert_eq!(sent[1].2, "me/sid/party0");
}
