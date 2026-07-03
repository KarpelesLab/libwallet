//! Multi-party TSS ceremony, proven end-to-end with an in-memory hub.
//!
//! The hub replicates tsslib's own (pub(crate)) test hub: each party has a
//! broker holding its peers; outbound messages (from == self) are routed to the
//! destination's inbound queue (or broadcast), inbound messages dispatch to the
//! registered handler or buffer until one connects. Production uses a
//! spotlib-backed broker instead; this harness proves the tsslib FROST DKG runs
//! and all parties converge on the same group public key.
//!
//! The ceremony is driven single-threaded: all brokers are created and wired
//! first, then all Keygens are constructed. Messages to not-yet-connected
//! parties buffer as pending and flush on connect, so the rounds cascade to
//! completion synchronously — no cross-thread locking, no deadlock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tsslib::frosttss::{Key, Keygen, SignatureData};
use tsslib::tss::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver, Parameters, PartyId};

struct Hub {
    party_index: usize,
    peers: OnceLock<Vec<Arc<Hub>>>,
    inner: Mutex<Inner>,
}

struct Inner {
    handlers: HashMap<String, Arc<dyn MessageReceiver + Send + Sync>>,
    pending: HashMap<String, Vec<JsonMessage>>,
}

impl Hub {
    fn new(index: usize) -> Arc<Hub> {
        Arc::new(Hub {
            party_index: index,
            peers: OnceLock::new(),
            inner: Mutex::new(Inner { handlers: HashMap::new(), pending: HashMap::new() }),
        })
    }

    fn peers(&self) -> &[Arc<Hub>] {
        self.peers.get().expect("peers wired")
    }

    fn deliver_inbound(&self, msg: &JsonMessage) -> BrokerResult {
        let handler = {
            let mut inner = self.inner.lock().unwrap();
            match inner.handlers.get(&msg.typ) {
                Some(h) => Some(h.clone()),
                None => {
                    inner.pending.entry(msg.typ.clone()).or_default().push(msg.clone());
                    None
                }
            }
        };
        match handler {
            Some(h) => h.receive(msg),
            None => Ok(()),
        }
    }
}

impl MessageReceiver for Hub {
    fn receive(&self, msg: &JsonMessage) -> BrokerResult {
        let from_index = msg.from.as_ref().map(|p| p.index).unwrap_or(-1);
        if from_index == self.party_index as i32 {
            // Outbound from this party.
            match &msg.to {
                Some(to) => self.peers()[to.index as usize].deliver_inbound(msg),
                None => {
                    for (j, peer) in self.peers().iter().enumerate() {
                        if j != self.party_index {
                            peer.deliver_inbound(msg)?;
                        }
                    }
                    Ok(())
                }
            }
        } else {
            self.deliver_inbound(msg)
        }
    }
}

impl MessageBroker for Hub {
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

/// Run an `n`-party, threshold-`t` FROST distributed key generation and return
/// each party's key share.
fn frost_keygen(n: usize, threshold: usize) -> Vec<Key> {
    let ids: Vec<PartyId> =
        (0..n).map(|i| PartyId::new(format!("p{i}"), "", vec![(i as u8) + 1])).collect();
    let sorted = PartyId::sort(ids, 0);

    let brokers: Vec<Arc<Hub>> = (0..n).map(Hub::new).collect();
    for b in &brokers {
        b.peers.set(brokers.clone()).ok();
    }

    let keygens: Vec<Keygen> = (0..n)
        .map(|i| {
            let broker: Arc<dyn MessageBroker + Send + Sync> = brokers[i].clone();
            let params = Parameters::new(sorted.clone(), &sorted[i], threshold, broker);
            Keygen::new(params).expect("keygen start")
        })
        .collect();

    keygens.iter().map(|k| k.wait().expect("keygen complete")).collect()
}

/// Run a FROST signing session over a committee (each entry pairs a committee
/// PartyId with that party's key share) and return each signer's result.
fn frost_sign(committee: &[(PartyId, Key)], threshold: usize, msg: &[u8]) -> Vec<SignatureData> {
    let ids: Vec<PartyId> = committee.iter().map(|(p, _)| p.clone()).collect();
    let sorted = PartyId::sort(ids, 0);

    let brokers: Vec<Arc<Hub>> = (0..sorted.len()).map(Hub::new).collect();
    for b in &brokers {
        b.peers.set(brokers.clone()).ok();
    }

    let signings: Vec<_> = (0..sorted.len())
        .map(|i| {
            // Match this committee slot to its key share by party key bytes.
            let key = committee
                .iter()
                .find(|(p, _)| p.cmp_key(&sorted[i]) == std::cmp::Ordering::Equal)
                .map(|(_, k)| k)
                .expect("committee key");
            let broker: Arc<dyn MessageBroker + Send + Sync> = brokers[i].clone();
            let params = Parameters::new(sorted.clone(), &sorted[i], threshold, broker);
            key.new_signing(msg.to_vec(), params).expect("signing start")
        })
        .collect();

    signings.iter().map(|s| s.wait().expect("signing complete")).collect()
}

#[test]
fn frost_keygen_then_sign_produces_one_agreed_signature() {
    let threshold = 1;
    let keys = frost_keygen(3, threshold);

    // Signing committee = threshold+1 parties. Recover their PartyIds in the
    // same order the keys were generated (sorted keygen order).
    let ids: Vec<PartyId> =
        (0..3).map(|i| PartyId::new(format!("p{i}"), "", vec![(i as u8) + 1])).collect();
    let sorted = PartyId::sort(ids, 0);
    let committee: Vec<(PartyId, Key)> =
        (0..=threshold).map(|i| (sorted[i].clone(), keys[i].clone())).collect();

    let msg = b"transaction hash to sign";
    let sigs = frost_sign(&committee, threshold, msg);

    assert_eq!(sigs.len(), threshold + 1);
    // All signers agree on the identical aggregate signature.
    let first = &sigs[0];
    for s in &sigs {
        assert_eq!(s, first, "committee members disagree on the signature");
    }
    // Standard Ed25519 shape: 64-byte R||S, over the given message.
    assert_eq!(first.signature.len(), 64);
    assert_eq!(first.r.len(), 32);
    assert_eq!(first.s.len(), 32);
    assert_eq!(first.signature, [first.r.clone(), first.s.clone()].concat());
    assert_eq!(first.m, msg);
}

#[test]
fn frost_dkg_converges_on_one_group_key() {
    let keys = frost_keygen(3, 1);
    assert_eq!(keys.len(), 3);

    // Every share validates and agrees on the group public key.
    let gpk = keys[0].group_public_key;
    for (i, k) in keys.iter().enumerate() {
        k.validate_basic().unwrap_or_else(|e| panic!("share {i} invalid: {e:?}"));
        assert_eq!(k.group_public_key, gpk, "share {i} has a different group key");
        assert_eq!(k.ks.len(), 3, "share {i} records all 3 participants");
    }

    // Shares are distinct secrets but share the group key.
    assert_ne!(keys[0].xi, keys[1].xi);

    // Go-compatible JSON round-trips.
    let json = keys[0].to_json().unwrap();
    let reloaded = Key::from_json(&json).unwrap();
    assert_eq!(reloaded.group_public_key, gpk);
}
