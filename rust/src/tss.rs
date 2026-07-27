//! Threshold-signature ceremonies (port of the Go wltwallet TSS paths).
//!
//! This module provides the **local** ceremony path — all key shares held on
//! one device — used for wallets whose shares are all StoreKey/Password/Plain
//! (no RemoteKey party). It runs the tsslib protocol over an in-process broker
//! ([`LocalHub`]). Cross-device signing (mobile + agent + wdrone over the Spot
//! network) will plug a spotlib-backed broker into the same tsslib APIs and
//! lands with the remote-key work.
//!
//! Currently wires FROST (ed25519 / Schnorr). DKLs23 (secp256k1) follows the
//! same shape via `tsslib::dklstss`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tsslib::frosttss::Keygen;
use tsslib::tss::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver, Parameters, PartyId};

pub use tsslib::frosttss::{Key, SignatureData};

#[derive(Debug)]
pub struct TssError(pub String);

impl std::fmt::Display for TssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tss error: {}", self.0)
    }
}

impl std::error::Error for TssError {}

/// In-process message broker connecting the local parties of a ceremony. Each
/// party gets one [`LocalHub`]; they share a peer list. Outbound messages
/// (from == self) route to the destination's inbound handler (or broadcast);
/// inbound messages dispatch to the connected handler or buffer until one
/// connects. Ceremonies are driven single-threaded (all brokers wired, then all
/// parties constructed) so the rounds cascade with no cross-thread locking.
pub struct LocalHub {
    party_index: usize,
    peers: OnceLock<Vec<Arc<LocalHub>>>,
    inner: Mutex<HubInner>,
}

struct HubInner {
    handlers: HashMap<String, Arc<dyn MessageReceiver + Send + Sync>>,
    pending: HashMap<String, Vec<JsonMessage>>,
}

impl LocalHub {
    fn new(index: usize) -> Arc<LocalHub> {
        Arc::new(LocalHub {
            party_index: index,
            peers: OnceLock::new(),
            inner: Mutex::new(HubInner { handlers: HashMap::new(), pending: HashMap::new() }),
        })
    }

    /// Build `n` wired hubs sharing a peer list.
    fn wired(n: usize) -> Vec<Arc<LocalHub>> {
        let hubs: Vec<Arc<LocalHub>> = (0..n).map(LocalHub::new).collect();
        for h in &hubs {
            let _ = h.peers.set(hubs.clone());
        }
        hubs
    }

    fn peers(&self) -> &[Arc<LocalHub>] {
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

impl MessageReceiver for LocalHub {
    fn receive(&self, msg: &JsonMessage) -> BrokerResult {
        let from_index = msg.from.as_ref().map(|p| p.index).unwrap_or(-1);
        if from_index == self.party_index as i32 {
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

impl MessageBroker for LocalHub {
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

/// Generate an `n`-share, threshold-`t` FROST key entirely on this device,
/// using deterministic index-based party keys. Handy for tests and simple
/// all-local wallets.
pub fn frost_keygen_local(n: usize, threshold: usize) -> Result<Vec<(PartyId, Key)>, TssError> {
    let keys: Vec<Vec<u8>> = (0..n).map(|i| vec![(i as u8) + 1]).collect();
    frost_keygen_with_parties(keys, threshold)
}

/// Generate a threshold FROST key with explicit party keys. Production
/// Wallet:create passes each WalletKey's UUID bytes here (Go derives the
/// tss party id from `WalletKey.Id.UUID`), so the resulting shares are keyed
/// consistently for later signing. Returns each share paired with its party id.
pub fn frost_keygen_with_parties(
    party_keys: Vec<Vec<u8>>,
    threshold: usize,
) -> Result<Vec<(PartyId, Key)>, TssError> {
    let n = party_keys.len();
    if n == 0 || threshold >= n {
        return Err(TssError(format!("invalid n={n}, threshold={threshold}")));
    }
    let ids: Vec<PartyId> =
        party_keys.iter().map(|k| PartyId::new(hex(k), "", k.clone())).collect();
    let parties = PartyId::sort(ids, 0);
    let hubs = LocalHub::wired(n);

    let keygens: Vec<Keygen> = (0..n)
        .map(|i| {
            let broker: Arc<dyn MessageBroker + Send + Sync> = hubs[i].clone();
            let params = Parameters::new(parties.clone(), &parties[i], threshold, broker);
            Keygen::new(params).map_err(|e| TssError(format!("keygen start: {e:?}")))
        })
        .collect::<Result<_, _>>()?;

    keygens
        .iter()
        .enumerate()
        .map(|(i, k)| {
            k.wait()
                .map(|key| (parties[i].clone(), key))
                .map_err(|e| TssError(format!("keygen: {e:?}")))
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Generate a threshold DKLs23 (secp256k1 / ECDSA) key locally. Unlike FROST,
/// tsslib's DKLs keygen is a synchronous local function (no broker), so the
/// whole DKG runs in one call. Party keys are the WalletKey UUIDs, as in
/// [`frost_keygen_with_parties`]. Returns each share paired with its party id.
pub fn dkls_keygen_local(
    party_keys: Vec<Vec<u8>>,
    threshold: usize,
) -> Result<Vec<(PartyId, tsslib::dklstss::Key)>, TssError> {
    let n = party_keys.len();
    if n == 0 || threshold >= n {
        return Err(TssError(format!("invalid n={n}, threshold={threshold}")));
    }
    let ids: Vec<PartyId> =
        party_keys.iter().map(|k| PartyId::new(hex(k), "", k.clone())).collect();
    let sorted = PartyId::sort(ids, 0);
    let mut rng = purecrypto::rng::OsRng;
    let keys = tsslib::dklstss::keygen(n, threshold, &sorted, &mut rng)
        .map_err(|e| TssError(format!("dkls keygen: {e:?}")))?;
    Ok(sorted.into_iter().zip(keys).collect())
}

/// Sign a 32-byte message `hash` with DKLs23 threshold ECDSA. `sorted_keys`
/// must be the full key set in keygen (sorted) order; the first `threshold + 1`
/// parties form the signing committee. Returns `(r, s, v)` — the ECDSA scalars
/// (32 bytes each, big-endian) plus the recovery parity. `dklstss::sign` is
/// synchronous (no broker), like keygen.
pub fn dkls_sign_local(
    sorted_keys: &[tsslib::dklstss::Key],
    threshold: usize,
    hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u8), TssError> {
    if sorted_keys.len() < threshold + 1 {
        return Err(TssError(format!(
            "need at least {} keys, got {}",
            threshold + 1,
            sorted_keys.len()
        )));
    }
    let signer_idx: Vec<usize> = (0..=threshold).collect();
    let mut rng = purecrypto::rng::OsRng;
    let sig = tsslib::dklstss::sign(sorted_keys, &signer_idx, hash, &mut rng)
        .map_err(|e| TssError(format!("dkls sign: {e:?}")))?;
    Ok((sig.r, sig.s, sig.v))
}

/// Like [`dkls_sign_local`] but adds a 32-byte HD-derivation `tweak`, producing
/// a signature that verifies under `group_key + tweak·G` — the derived account
/// key. Mirrors Go `dklstss.SignWithTweak`.
pub fn dkls_sign_local_tweaked(
    sorted_keys: &[tsslib::dklstss::Key],
    threshold: usize,
    tweak: &[u8; 32],
    hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u8), TssError> {
    if sorted_keys.len() < threshold + 1 {
        return Err(TssError(format!("need at least {} keys", threshold + 1)));
    }
    let signer_idx: Vec<usize> = (0..=threshold).collect();
    let tw = purecrypto::ec::secp256k1::Scalar::from_bytes_be_reduce(tweak);
    let mut rng = purecrypto::rng::OsRng;
    let sig = tsslib::dklstss::sign_with_tweak(sorted_keys, &signer_idx, &tw, hash, &mut rng)
        .map_err(|e| TssError(format!("dkls sign_with_tweak: {e:?}")))?;
    Ok((sig.r, sig.s, sig.v))
}

/// The wallet's group public key as the 33-byte SEC1-compressed secp256k1
/// encoding (Wallet.Pubkey for secp256k1 wallets).
/// Reshare a source DKLs key into a fresh `new_party_keys`-of-`new_threshold`
/// committee (synchronous, no broker — `dklstss::reshare`). The group public key
/// is preserved. Used by Wallet:promoteMnemonic (1-of-1 imported key → n-of-m).
/// Returns each new party paired with its share.
pub fn dkls_reshare(
    source: tsslib::dklstss::Key,
    new_party_keys: Vec<Vec<u8>>,
    new_threshold: usize,
) -> Result<Vec<(PartyId, tsslib::dklstss::Key)>, TssError> {
    let ids: Vec<PartyId> =
        new_party_keys.iter().map(|k| PartyId::new(hex(k), "", k.clone())).collect();
    let sorted = PartyId::sort(ids, 0);
    let mut rng = purecrypto::rng::OsRng;
    let new_keys = tsslib::dklstss::reshare(&[source], &[0], &sorted, new_threshold, &mut rng)
        .map_err(|e| TssError(format!("dkls reshare: {e:?}")))?;
    Ok(sorted.into_iter().zip(new_keys).collect())
}

pub fn dkls_group_pubkey(key: &tsslib::dklstss::Key) -> Result<[u8; 33], TssError> {
    key.ecdsa_pub
        .to_affine()
        .map(|a| a.to_sec1_compressed())
        .ok_or_else(|| TssError("group key is the identity point".into()))
}

/// The wallet's group public key as the 32-byte compressed Ed25519 encoding
/// (RFC 8032). This is `Wallet.Pubkey` (before base64url) and matches Go
/// `GroupPublicKey.ToEd25519PubKey().Serialize()`. Any share carries it.
pub fn frost_group_pubkey(key: &Key) -> [u8; 32] {
    key.group_public_key.compress()
}

/// Import a raw Ed25519 secret scalar (big-endian) as a 1-of-1 FROST key — the
/// `Wallet:importPrivateKey` migration path for ed25519. The party holds the
/// whole secret, so the caller should reshare afterward.
pub fn frost_import_key(priv_be: &[u8], party_key: &[u8]) -> Result<(PartyId, Key), TssError> {
    let scalar = tsslib::frost::scalar_from_be_mod_l(priv_be);
    let party = PartyId::new(hex(party_key), "", party_key.to_vec());
    let key = tsslib::frosttss::import_key(&scalar, &party)
        .map_err(|e| TssError(format!("frost import: {e:?}")))?;
    Ok((party, key))
}

// ── Legacy eddsatss (GG18-style Ed25519) — for opening + signing Go wallets
//    created before FROST. Unblocked by tsslib 0.2.4 (public subset_for_parties
//    + Key::public_key). Broker-based like FROST, driven over the LocalHub. ──

/// Generate a threshold legacy-EdDSA (eddsatss) key locally over the in-process
/// hub. Party keys are the WalletKey UUIDs, as in [`frost_keygen_with_parties`].
pub fn eddsa_keygen_local(
    party_keys: Vec<Vec<u8>>,
    threshold: usize,
) -> Result<Vec<(PartyId, tsslib::eddsatss::Key)>, TssError> {
    let n = party_keys.len();
    if n == 0 || threshold >= n {
        return Err(TssError(format!("invalid n={n}, threshold={threshold}")));
    }
    let ids: Vec<PartyId> = party_keys.iter().map(|k| PartyId::new(hex(k), "", k.clone())).collect();
    let parties = PartyId::sort(ids, 0);
    let hubs = LocalHub::wired(n);
    let keygens: Vec<tsslib::eddsatss::KeygenParty> = (0..n)
        .map(|i| {
            let broker: Arc<dyn MessageBroker + Send + Sync> = hubs[i].clone();
            let params = Parameters::new(parties.clone(), &parties[i], threshold, broker);
            tsslib::eddsatss::KeygenParty::new(params).map_err(|e| TssError(format!("eddsa keygen start: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    keygens
        .iter()
        .enumerate()
        .map(|(i, k)| k.wait().map(|key| (parties[i].clone(), key)).map_err(|e| TssError(format!("eddsa keygen: {e:?}"))))
        .collect()
}

/// The 32-byte compressed Ed25519 group public key of a legacy eddsatss share
/// (Go `EDDSAPub.ToEd25519PubKey().Serialize()`). Any share carries it.
pub fn eddsa_group_pubkey(key: &tsslib::eddsatss::Key) -> Result<[u8; 32], TssError> {
    key.public_key().map_err(|e| TssError(format!("eddsa pubkey: {e:?}")))
}

/// Threshold-sign `msg` with a committee of legacy eddsatss shares (each a full
/// keygen share; `SigningParty::new` narrows to the committee internally). The
/// committee must be ≥ threshold+1. Returns the 64-byte Ed25519 signature after
/// checking the signers agree.
pub fn eddsa_sign_local(
    committee: &[(PartyId, tsslib::eddsatss::Key)],
    threshold: usize,
    msg: &[u8],
) -> Result<Vec<u8>, TssError> {
    if committee.len() < threshold + 1 {
        return Err(TssError(format!("committee size {} < threshold+1 ({})", committee.len(), threshold + 1)));
    }
    let ids: Vec<PartyId> = committee.iter().map(|(p, _)| p.clone()).collect();
    let sorted = PartyId::sort(ids, 0);
    let hubs = LocalHub::wired(sorted.len());
    let signings: Vec<tsslib::eddsatss::SigningParty> = (0..sorted.len())
        .map(|i| {
            let key = committee
                .iter()
                .find(|(p, _)| p.cmp_key(&sorted[i]) == std::cmp::Ordering::Equal)
                .map(|(_, k)| k.clone())
                .ok_or_else(|| TssError("committee key missing".into()))?;
            let broker: Arc<dyn MessageBroker + Send + Sync> = hubs[i].clone();
            let params = Parameters::new(sorted.clone(), &sorted[i], threshold, broker);
            tsslib::eddsatss::SigningParty::new(params, key, msg).map_err(|e| TssError(format!("eddsa signing start: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    let sigs: Vec<tsslib::eddsatss::SignatureData> =
        signings.iter().map(|s| s.wait().map_err(|e| TssError(format!("eddsa signing: {e:?}")))).collect::<Result<_, _>>()?;
    let first = &sigs[0];
    for s in &sigs[1..] {
        if s.signature != first.signature {
            return Err(TssError("eddsa signers disagreed on the signature".into()));
        }
    }
    Ok(first.signature.clone())
}

// ── Legacy ecdsatss (GG18 secp256k1) — for opening + signing Go wallets created
//    before DKLs23. Unblocked by tsslib 0.2.5 (SigningParty::new_with_kdd — the
//    IL/tweak variant Go uses for HD-derived accounts). Broker-based. ──

/// Generate a threshold legacy-ECDSA (GG18) key over the in-process hub. Each
/// party needs its own Paillier `LocalPreParams`; `safe_prime_bits` trades
/// generation time for security (Go uses 1024; tests use small values — legacy
/// keygen is retired in Go, so this only builds test fixtures).
pub fn ecdsa_keygen_local(
    party_keys: Vec<Vec<u8>>,
    threshold: usize,
    safe_prime_bits: usize,
) -> Result<Vec<(PartyId, tsslib::ecdsatss::Key)>, TssError> {
    let n = party_keys.len();
    if n == 0 || threshold >= n {
        return Err(TssError(format!("invalid n={n}, threshold={threshold}")));
    }
    let ids: Vec<PartyId> = party_keys.iter().map(|k| PartyId::new(hex(k), "", k.clone())).collect();
    let parties = PartyId::sort(ids, 0);
    let hubs = LocalHub::wired(n);
    let mut rng = purecrypto::rng::OsRng;
    let keygens: Vec<tsslib::ecdsatss::KeygenParty> = (0..n)
        .map(|i| {
            let pre = tsslib::ecdsatss::LocalPreParams::generate(safe_prime_bits, &mut rng);
            let broker: Arc<dyn MessageBroker + Send + Sync> = hubs[i].clone();
            let params = Parameters::new(parties.clone(), &parties[i], threshold, broker);
            tsslib::ecdsatss::KeygenParty::new(params, pre).map_err(|e| TssError(format!("ecdsa keygen start: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    keygens
        .iter()
        .enumerate()
        .map(|(i, k)| k.wait().map(|key| (parties[i].clone(), key)).map_err(|e| TssError(format!("ecdsa keygen: {e:?}"))))
        .collect()
}

/// The 33-byte SEC1-compressed secp256k1 group public key of a legacy ecdsatss
/// share (Go `ECDSAPub`).
pub fn ecdsa_group_pubkey(key: &tsslib::ecdsatss::Key) -> Result<[u8; 33], TssError> {
    key.public_key().map_err(|e| TssError(format!("ecdsa pubkey: {e:?}")))
}

/// Threshold-sign a 32-byte `hash` with a committee of legacy ecdsatss shares,
/// applying the BIP32 key-derivation `tweak` (IL) via `new_with_kdd` so the
/// signature verifies under the child key `group + tweak·G` — matching Go's
/// `NewSigningWithKDD`. Returns `(r, s, v)` (32-byte big-endian scalars + parity).
pub fn ecdsa_sign_local_tweaked(
    committee: &[(PartyId, tsslib::ecdsatss::Key)],
    threshold: usize,
    tweak: &[u8; 32],
    hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u8), TssError> {
    if committee.len() < threshold + 1 {
        return Err(TssError(format!("committee size {} < threshold+1 ({})", committee.len(), threshold + 1)));
    }
    let ids: Vec<PartyId> = committee.iter().map(|(p, _)| p.clone()).collect();
    let sorted = PartyId::sort(ids, 0);
    let hubs = LocalHub::wired(sorted.len());
    let signings: Vec<tsslib::ecdsatss::SigningParty> = (0..sorted.len())
        .map(|i| {
            let key = committee
                .iter()
                .find(|(p, _)| p.cmp_key(&sorted[i]) == std::cmp::Ordering::Equal)
                .map(|(_, k)| k.clone())
                .ok_or_else(|| TssError("committee key missing".into()))?;
            let broker: Arc<dyn MessageBroker + Send + Sync> = hubs[i].clone();
            let params = Parameters::new(sorted.clone(), &sorted[i], threshold, broker);
            tsslib::ecdsatss::SigningParty::new_with_kdd(params, key, hash, Some(tweak.as_slice()))
                .map_err(|e| TssError(format!("ecdsa signing start: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    let sigs: Vec<tsslib::ecdsatss::SignatureData> =
        signings.iter().map(|s| s.wait().map_err(|e| TssError(format!("ecdsa signing: {e:?}")))).collect::<Result<_, _>>()?;
    let first = &sigs[0];
    for s in &sigs[1..] {
        if s.r != first.r || s.s != first.s {
            return Err(TssError("ecdsa signers disagreed on the signature".into()));
        }
    }
    Ok((first.r.clone(), first.s.clone(), first.recovery))
}

/// Import a raw secp256k1 secret scalar (32-byte big-endian) as a 1-of-1 DKLs
/// key — the `Wallet:importPrivateKey` migration path for secp256k1.
pub fn dkls_import_key(
    priv_be: &[u8; 32],
    party_key: &[u8],
) -> Result<(PartyId, tsslib::dklstss::Key), TssError> {
    let scalar = purecrypto::ec::secp256k1::Scalar::from_bytes_be(priv_be)
        .map_err(|e| TssError(format!("secp scalar: {e:?}")))?;
    let party = PartyId::new(hex(party_key), "", party_key.to_vec());
    let key = tsslib::dklstss::import_key(&scalar, &party)
        .map_err(|e| TssError(format!("dkls import: {e:?}")))?;
    Ok((party, key))
}

/// Verify a standard Ed25519 signature against a 32-byte public key. Used to
/// confirm a FROST aggregate signature is valid under the group key — the same
/// check any external Ed25519 verifier (or chain node) performs.
pub fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use purecrypto::ec::{Ed25519PublicKey, Ed25519Signature};
    let pk = Ed25519PublicKey::from_bytes(*pubkey);
    let s = Ed25519Signature::from_bytes(*sig);
    pk.verify(msg, &s).is_ok()
}

/// Sign `msg` with a committee of local shares (must be at least
/// `threshold + 1`). Returns the 64-byte Ed25519 signature. All committee
/// members produce the identical aggregate signature.
pub fn frost_sign_local(
    committee: &[(PartyId, Key)],
    threshold: usize,
    msg: &[u8],
) -> Result<Vec<u8>, TssError> {
    if committee.len() < threshold + 1 {
        return Err(TssError(format!(
            "committee size {} < threshold+1 ({})",
            committee.len(),
            threshold + 1
        )));
    }
    let ids: Vec<PartyId> = committee.iter().map(|(p, _)| p.clone()).collect();
    let sorted = PartyId::sort(ids, 0);
    let hubs = LocalHub::wired(sorted.len());

    let signings: Vec<_> = (0..sorted.len())
        .map(|i| {
            let key = committee
                .iter()
                .find(|(p, _)| p.cmp_key(&sorted[i]) == std::cmp::Ordering::Equal)
                .map(|(_, k)| k)
                .ok_or_else(|| TssError("committee key missing".into()))?;
            let broker: Arc<dyn MessageBroker + Send + Sync> = hubs[i].clone();
            let params = Parameters::new(sorted.clone(), &sorted[i], threshold, broker);
            key.new_signing(msg.to_vec(), params)
                .map_err(|e| TssError(format!("signing start: {e:?}")))
        })
        .collect::<Result<_, _>>()?;

    let sigs: Vec<SignatureData> = signings
        .iter()
        .map(|s| s.wait().map_err(|e| TssError(format!("signing: {e:?}"))))
        .collect::<Result<_, _>>()?;

    // All signers must agree on the aggregate signature.
    let first = &sigs[0];
    for s in &sigs[1..] {
        if s.signature != first.signature {
            return Err(TssError("signers disagreed on the signature".into()));
        }
    }
    Ok(first.signature.clone())
}

/// Like [`frost_sign_local`] but applies a BIP32 non-hardened key-derivation
/// `tweak` (big-endian, from [`crate::hdderive::ed25519_derive_pub_tweak`]) via
/// `Key::new_signing_with_tweak`, so the signature verifies under the derived
/// child pubkey (`group_pub + tweak·G`). All signers absorb the same additive
/// tweak; the Key's own chain code is not used here.
pub fn frost_sign_local_tweaked(
    committee: &[(PartyId, Key)],
    threshold: usize,
    msg: &[u8],
    tweak: &[u8; 32],
) -> Result<Vec<u8>, TssError> {
    if committee.len() < threshold + 1 {
        return Err(TssError(format!(
            "committee size {} < threshold+1 ({})",
            committee.len(),
            threshold + 1
        )));
    }
    // Reconstruct the additive ed25519 scalar from its big-endian encoding
    // (matches hdderive's accumulated `tweak`, which is < L).
    let tw = tsslib::frost::scalar_from_be_mod_l(tweak);
    let ids: Vec<PartyId> = committee.iter().map(|(p, _)| p.clone()).collect();
    let sorted = PartyId::sort(ids, 0);
    let hubs = LocalHub::wired(sorted.len());

    let signings: Vec<_> = (0..sorted.len())
        .map(|i| {
            let key = committee
                .iter()
                .find(|(p, _)| p.cmp_key(&sorted[i]) == std::cmp::Ordering::Equal)
                .map(|(_, k)| k)
                .ok_or_else(|| TssError("committee key missing".into()))?;
            let broker: Arc<dyn MessageBroker + Send + Sync> = hubs[i].clone();
            let params = Parameters::new(sorted.clone(), &sorted[i], threshold, broker);
            key.new_signing_with_tweak(msg.to_vec(), params, Some(tw.clone()))
                .map_err(|e| TssError(format!("signing start: {e:?}")))
        })
        .collect::<Result<_, _>>()?;

    let sigs: Vec<SignatureData> = signings
        .iter()
        .map(|s| s.wait().map_err(|e| TssError(format!("signing: {e:?}"))))
        .collect::<Result<_, _>>()?;

    let first = &sigs[0];
    for s in &sigs[1..] {
        if s.signature != first.signature {
            return Err(TssError("signers disagreed on the signature".into()));
        }
    }
    Ok(first.signature.clone())
}

#[cfg(test)]
mod legacy_tests {
    use super::*;

    /// Legacy eddsatss (GG18-style Ed25519) keygen → 2-of-3 threshold sign →
    /// external Ed25519 verify. Proves tsslib 0.2.4 unblocked the legacy path
    /// (public subset_for_parties + Key::public_key), so Rust can open + sign
    /// Go-created pre-FROST ed25519 wallets.
    #[test]
    fn eddsa_keygen_sign_verifies() {
        // Three party keys (16-byte UUIDs, as real WalletKeys use).
        let party_keys: Vec<Vec<u8>> = (1u8..=3).map(|i| vec![i; 16]).collect();
        let shares = eddsa_keygen_local(party_keys, 1).expect("keygen");
        assert_eq!(shares.len(), 3);

        // All shares agree on one group pubkey.
        let pk = eddsa_group_pubkey(&shares[0].1).expect("pubkey");
        for (_, k) in &shares[1..] {
            assert_eq!(eddsa_group_pubkey(k).unwrap(), pk, "shares must share the group key");
        }

        // Sign with a 2-of-3 subset and verify under the group key.
        let msg = b"legacy eddsa message";
        let committee: Vec<_> = shares[..2].to_vec();
        let sig = eddsa_sign_local(&committee, 1, msg).expect("sign");
        assert_eq!(sig.len(), 64);
        let sig64: [u8; 64] = sig.try_into().unwrap();
        assert!(ed25519_verify(&pk, msg, &sig64), "legacy eddsa sig must verify under the group key");

        // A different 2-subset produces a valid (possibly different) signature too.
        let committee2 = vec![shares[0].clone(), shares[2].clone()];
        let sig2 = eddsa_sign_local(&committee2, 1, msg).expect("sign2");
        assert!(ed25519_verify(&pk, msg, &sig2.try_into().unwrap()), "second subset must also verify");
    }

    /// The correctness crux of the ed25519 HD-derivation refactor: the tweak
    /// hdderive computes from the group pubkey ONLY (address-time, no shares)
    /// must equal the additive tweak FROST signing applies, so a threshold
    /// signature verifies under the DERIVED child pubkey.
    #[test]
    fn frost_hd_derivation_roundtrip() {
        let shares = frost_keygen_local(3, 1).expect("keygen");
        assert_eq!(shares.len(), 3);
        let group_pub = frost_group_pubkey(&shares[0].1);

        // Empty path: zero tweak, child_pub == group_pub.
        let (tw0, child0) = crate::hdderive::ed25519_derive_pub_tweak(&group_pub, &[]).unwrap();
        assert_eq!(tw0, [0u8; 32], "empty path must give a zero tweak");
        assert_eq!(child0, group_pub, "empty path must return the group pubkey");

        // Hardened index is rejected.
        assert!(crate::hdderive::ed25519_derive_pub_tweak(&group_pub, &[0x8000_0000]).is_err());

        // Non-hardened path (Solana-style m/44/501/0/0/7): derive the child
        // address + tweak, then sign with the same tweak and verify under the
        // derived child pubkey.
        let path = [44u32, 501, 0, 0, 7];
        let (tweak, child_pub) =
            crate::hdderive::ed25519_derive_pub_tweak(&group_pub, &path).unwrap();
        assert_ne!(child_pub, group_pub, "a real path must move the pubkey");

        let msg = b"frost hd derivation roundtrip";
        let committee: Vec<_> = shares[..2].to_vec();
        let sig = frost_sign_local_tweaked(&committee, 1, msg, &tweak).expect("tweaked sign");
        assert_eq!(sig.len(), 64);
        let sig64: [u8; 64] = sig.try_into().unwrap();
        assert!(
            ed25519_verify(&child_pub, msg, &sig64),
            "signature MUST verify under the DERIVED child pubkey"
        );
        // Sanity: it must NOT verify under the parent group key.
        assert!(
            !ed25519_verify(&group_pub, msg, &sig64),
            "derived-key signature must not verify under the parent key"
        );

        // A different signing subset produces an equally valid signature.
        let committee2 = vec![shares[0].clone(), shares[2].clone()];
        let sig_b = frost_sign_local_tweaked(&committee2, 1, msg, &tweak).expect("tweaked sign 2");
        let sig_b64: [u8; 64] = sig_b.try_into().unwrap();
        assert!(
            ed25519_verify(&child_pub, msg, &sig_b64),
            "second subset must also verify under the child pubkey"
        );
    }
}
