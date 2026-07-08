//! A cross-device tsslib [`MessageBroker`] that carries ceremony messages over a
//! serialized transport (port of the remote-party side of wltwallet/broker.go).
//!
//! The all-local [`crate::tss::LocalHub`] delivers tsslib messages in-process; a
//! cross-device (RemoteKey / device-transfer) ceremony instead serializes each
//! outbound [`JsonMessage`] and ships it to the peer (over spotlib in
//! production), and deserializes inbound bytes back into the local tsslib
//! handlers. This module is that broker — transport-agnostic (the send side is a
//! closure) and inbound-buffering (messages that arrive before their handler
//! connects are held and flushed on [`MessageBroker::connect`], exactly as
//! LocalHub does), so a real FROST/DKLs ceremony runs to completion across two
//! async parties. The production wiring plugs a spotlib `send`/reader on top of
//! this tested core (like the WalletConnect WS transport over its relay client).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tsslib::tss::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver};

/// Serialize-and-send an outbound message to the peer. In production this is a
/// spotlib `SendToWithFrom`; in tests it's an in-memory channel to the peer.
pub type SendFn = Box<dyn Fn(Vec<u8>) + Send + Sync>;

/// A broker for one party of a cross-device ceremony. Outbound messages (from
/// this party) are serialized and handed to `send`; inbound bytes (delivered via
/// [`Self::deliver_inbound_bytes`]) are deserialized and dispatched to the
/// tsslib handler registered for their type (buffered until it connects).
pub struct SpotBroker {
    self_index: i32,
    send: SendFn,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    handlers: HashMap<String, Arc<dyn MessageReceiver + Send + Sync>>,
    pending: HashMap<String, Vec<JsonMessage>>,
}

impl SpotBroker {
    /// A broker for the party at `self_index` (its `PartyId.index`). `send`
    /// serializes+ships an outbound message to the peer.
    pub fn new(self_index: i32, send: SendFn) -> Arc<SpotBroker> {
        Arc::new(SpotBroker { self_index, send, inner: Mutex::new(Inner::default()) })
    }

    /// Deliver a serialized message received from the peer: deserialize and
    /// dispatch to the local handler (or buffer until it connects).
    pub fn deliver_inbound_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        let msg: JsonMessage = serde_json::from_slice(bytes).map_err(|e| format!("decode tss msg: {e}"))?;
        self.dispatch_inbound(msg);
        Ok(())
    }

    /// Dispatch an inbound message to its handler, or buffer it by type.
    fn dispatch_inbound(&self, msg: JsonMessage) {
        let handler = self.inner.lock().unwrap().handlers.get(&msg.typ).cloned();
        match handler {
            Some(h) => {
                let _ = h.receive(&msg);
            }
            None => {
                self.inner.lock().unwrap().pending.entry(msg.typ.clone()).or_default().push(msg);
            }
        }
    }
}

impl MessageReceiver for SpotBroker {
    fn receive(&self, msg: &JsonMessage) -> BrokerResult {
        let from_index = msg.from.as_ref().map(|p| p.index).unwrap_or(-1);
        if from_index == self.self_index {
            // Outbound (from this party) → serialize and ship to the peer.
            let bytes = serde_json::to_vec(msg).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            (self.send)(bytes);
            Ok(())
        } else {
            // Inbound (already deserialized, e.g. re-entrant) → dispatch.
            self.dispatch_inbound(msg.clone());
            Ok(())
        }
    }
}

impl MessageBroker for SpotBroker {
    fn connect(&self, typ: &str, dest: Arc<dyn MessageReceiver + Send + Sync>) {
        let queued = {
            let mut inner = self.inner.lock().unwrap();
            inner.handlers.insert(typ.to_string(), dest.clone());
            inner.pending.remove(typ).unwrap_or_default()
        };
        for msg in queued {
            let _ = dest.receive(&msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use tsslib::frosttss::Keygen;
    use tsslib::tss::{Parameters, PartyId};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Two real spotlib clients on the live relay run a 2-party FROST keygen,
    /// exchanging tsslib messages end-to-end over the Spot network (encrypted by
    /// spotlib). Gated behind `SPOT_LIVE=1` since it needs relay connectivity.
    #[test]
    fn two_party_frost_keygen_over_live_spot() {
        if std::env::var("SPOT_LIVE").ok().as_deref() != Some("1") {
            eprintln!("skipping live-spot test (set SPOT_LIVE=1 to run)");
            return;
        }
        use std::time::{Duration, Instant};
        let a = std::sync::Arc::new(spotlib::Client::builder().meta("project", "libwallet-test").build().unwrap());
        let b = std::sync::Arc::new(spotlib::Client::builder().meta("project", "libwallet-test").build().unwrap());
        // Wait for both clients online.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if a.connection_count().1 > 0 && b.connection_count().1 > 0 {
                break;
            }
            assert!(Instant::now() < deadline, "clients did not come online");
            std::thread::sleep(Duration::from_millis(300));
        }
        let (a_target, b_target) = (a.target_id(), b.target_id());

        let key_a = vec![1u8; 16];
        let key_b = vec![2u8; 16];
        let ids = PartyId::sort(
            vec![PartyId::new(hex(&key_a), "", key_a.clone()), PartyId::new(hex(&key_b), "", key_b.clone())],
            0,
        );
        let (party0, party1) = (ids[0].clone(), ids[1].clone());

        // Each broker sends over its client to the peer's "tss" endpoint.
        let (ca, cb) = (a.clone(), b.clone());
        let broker0 = SpotBroker::new(party0.index, Box::new(move |bytes| {
            let _ = ca.send_to_with_from(&format!("{b_target}/tss"), &bytes, "/tss", Duration::from_secs(20));
        }));
        let broker1 = SpotBroker::new(party1.index, Box::new(move |bytes| {
            let _ = cb.send_to_with_from(&format!("{a_target}/tss"), &bytes, "/tss", Duration::from_secs(20));
        }));

        // Register spot handlers that feed inbound bytes into each broker.
        let hb0 = broker0.clone();
        a.set_handler("tss", Some(move |msg: &spotlib::Message| { let _ = hb0.deliver_inbound_bytes(&msg.body); Ok(None) }));
        let hb1 = broker1.clone();
        b.set_handler("tss", Some(move |msg: &spotlib::Message| { let _ = hb1.deliver_inbound_bytes(&msg.body); Ok(None) }));

        let parties = ids.clone();
        let (p0, p1) = (party0.clone(), party1.clone());
        let (bb0, bb1): (Arc<dyn MessageBroker + Send + Sync>, Arc<dyn MessageBroker + Send + Sync>) = (broker0, broker1);
        let pa = parties.clone();
        let h0 = std::thread::spawn(move || Keygen::new(Parameters::new(pa.clone(), &p0, 1, bb0)).unwrap().wait());
        let h1 = std::thread::spawn(move || Keygen::new(Parameters::new(parties.clone(), &p1, 1, bb1)).unwrap().wait());
        let key0 = h0.join().unwrap().expect("party0 keygen");
        let key1 = h1.join().unwrap().expect("party1 keygen");
        assert_eq!(hex(&crate::tss::frost_group_pubkey(&key0)), hex(&crate::tss::frost_group_pubkey(&key1)));
    }

    #[test]
    fn two_party_frost_keygen_over_serialized_loopback() {
        // Two parties, each on its own thread, exchanging tsslib messages ONLY as
        // serialized bytes over in-memory channels — the cross-device transport
        // shape. If the keygen completes and both agree on the group key, the
        // SpotBroker correctly drives a real ceremony across the wire.
        let key_a = vec![1u8; 16];
        let key_b = vec![2u8; 16];
        let ids = PartyId::sort(
            vec![PartyId::new(hex(&key_a), "", key_a.clone()), PartyId::new(hex(&key_b), "", key_b.clone())],
            0,
        );
        let (party0, party1) = (ids[0].clone(), ids[1].clone());

        // Cross-wired channels: party0 → party1 and party1 → party0.
        let (tx01, rx01) = channel::<Vec<u8>>();
        let (tx10, rx10) = channel::<Vec<u8>>();
        let broker0 = SpotBroker::new(party0.index, Box::new(move |b| { let _ = tx01.send(b); }));
        let broker1 = SpotBroker::new(party1.index, Box::new(move |b| { let _ = tx10.send(b); }));

        // Reader threads: pump inbound bytes into the peer's broker.
        {
            let b0 = broker0.clone();
            std::thread::spawn(move || {
                while let Ok(bytes) = rx10.recv() {
                    let _ = b0.deliver_inbound_bytes(&bytes);
                }
            });
            let b1 = broker1.clone();
            std::thread::spawn(move || {
                while let Ok(bytes) = rx01.recv() {
                    let _ = b1.deliver_inbound_bytes(&bytes);
                }
            });
        }

        // Each party runs its keygen on its own thread (2-of-2, threshold 1).
        let parties = ids.clone();
        let (p0, p1) = (party0.clone(), party1.clone());
        let (b0, b1): (Arc<dyn MessageBroker + Send + Sync>, Arc<dyn MessageBroker + Send + Sync>) = (broker0, broker1);
        let parties_a = parties.clone();
        let h0 = std::thread::spawn(move || {
            let params = Parameters::new(parties_a.clone(), &p0, 1, b0);
            Keygen::new(params).unwrap().wait()
        });
        let h1 = std::thread::spawn(move || {
            let params = Parameters::new(parties.clone(), &p1, 1, b1);
            Keygen::new(params).unwrap().wait()
        });

        let key0 = h0.join().unwrap().expect("party0 keygen");
        let key1 = h1.join().unwrap().expect("party1 keygen");
        // Both parties derived the SAME group public key — the ceremony ran to
        // completion over the serialized cross-device transport.
        assert_eq!(
            hex(&crate::tss::frost_group_pubkey(&key0)),
            hex(&crate::tss::frost_group_pubkey(&key1)),
        );
    }
}
