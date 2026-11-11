//! The host against a simulated device: a `Transport` that plays the device's
//! side of the pairing handshake and of the encrypted session, answers the
//! host-wallet commands from a test mnemonic, and signs for real.
//!
//! The wire formats are pinned by the firmware's own vectors where it
//! publishes them: the pairing known-answer test (`ncry::tests`,
//! `tools/ncry.py --selftest`, `docs/PHONE-APP.md` §4.5) and the host-wallet
//! layouts (`tools/hostwallet.py --selftest`).

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use outscript::crypto::secp256k1::SecpPrivateKey;
use outscript::psbt::Psbt;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use serde_json::{json, Value};

use super::proto::{frames, kind, Identity, Reassembler};
use super::session::{code_text, commitment, schedule, Cipher, Initiator};
use super::*;
use crate::airgap::import::{import, ImportOptions};
use crate::{bip39, hdderive};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const H: u32 = HARDENED;

fn h(s: &str) -> Vec<u8> {
    unhex(s).unwrap()
}

// ── The firmware's vectors ───────────────────────────────────────────────────

const KAT_HOST_PRIV: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const KAT_DEV_PRIV: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

#[test]
fn handshake_matches_the_firmware_vector() {
    let scalar = |s: &str| X25519PrivateKey::from_bytes(h(s).try_into().unwrap());
    let host = Initiator::from_key(scalar(KAT_HOST_PRIV));
    assert_eq!(hex(&host.public), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert_eq!(hex(&host.commit), "41b5c26ca1226fb39c62a654157393a96c0179a91af67a6f62f7bd9ad72f144a");
    let device = scalar(KAT_DEV_PRIV);
    let device_pub = device.public_key();
    assert_eq!(hex(&device_pub), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    // The key schedule, from the device's side of the exchange.
    let shared = device.diffie_hellman(&host.public).unwrap();
    let (h2d, d2h, code) = schedule(&shared, &host.commit, &device_pub, &host.public);
    assert_eq!(hex(&h2d), "b631096c19e44d3db26d6badc589fa733cc7834370b5a10294cc0dc172b572bb");
    assert_eq!(hex(&d2h), "8d6609a5de2fc1db62a52b7097c9a96540e77fad90341b703bdb2aa2a97259a6");
    assert_eq!(code_text(code), "398 660");

    // The host's side derives the same, and its first sealed records are the
    // firmware's bytes.
    let (mut cipher, host_code) = host.finish(&device_pub).unwrap();
    assert_eq!(host_code, 398_660);
    let record = cipher.seal(b"catcard");
    assert_eq!(hex(&record), "80a853252814c6dd77e16e59d98cf64481bf28f853b316");
    let (mut confirm, _) = Initiator::from_key(scalar(KAT_HOST_PRIV)).finish(&device_pub).unwrap();
    assert_eq!(hex(&confirm.seal(&[0x44, 0x00])), "a7c96031987b403d35728dfcb775d969c2a8");

    // The device opens it and answers; a replayed, altered or short record
    // does not authenticate.
    let mut dev = Cipher::new(d2h, h2d);
    assert_eq!(dev.open(&record).unwrap(), b"catcard");
    assert!(dev.open(&record).is_err(), "a replayed record was accepted");
    let reply = dev.seal(b"pong");
    let mut bent = reply.clone();
    bent[0] ^= 1;
    assert!(cipher.open(&bent).is_err());
    assert!(cipher.open(&reply[..10]).is_err());
    assert_eq!(cipher.open(&reply).unwrap(), b"pong");

    assert_eq!(code_text(7), "000 007");
    // A small-order device key gives an all-zero secret: refused.
    assert_eq!(Initiator::new().finish(&[0u8; 32]).err().unwrap().code, 502);
}

#[test]
fn wire_layouts_match_the_reference_tools() {
    // tools/hostwallet.py --selftest: the sign blob.
    let blob = proto::sign_blob(1, &[vec![84 | H, H, H, 0, 3]], b"psbt").unwrap();
    assert_eq!(blob, [1, 1, 1, 5, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0x70, 0x73, 0x62, 0x74]);
    assert_eq!(proto::parse_path("m/84'/0h/0H/0/3").unwrap(), [84 | H, H, H, 0, 3]);
    assert_eq!(proto::path_text(&[44 | H, 501 | H, 7 | H, H]), "m/44'/501'/7'/0'");
    assert!(proto::parse_path("m").is_err());
    assert!(proto::parse_path("m/1/2/3/4/5/6/7/8/9").is_err());
    assert!(proto::parse_path("m/2147483648").is_err());
    assert!(proto::sign_blob(1, &[], b"x").is_err());
    assert!(proto::sign_blob(1, &[vec![1]], b"").is_err());

    // …and the address reply.
    let mut reply = vec![1, 1, 0xde, 0xad, 0xbe, 0xef, 7, 0, 0, 0, 2, 1, 1, 3];
    reply.extend([3, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80]);
    reply.extend([5, 84, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]);
    reply.push(4);
    reply.extend(b"xpub");
    reply.push(4);
    reply.extend(b"bc1q");
    reply.extend([2, 2, 3, 2, 3, 7]);
    reply.extend([3, 44, 0, 0, 0x80, 0xf5, 1, 0, 0x80, 7, 0, 0, 0x80]);
    reply.extend([4, 44, 0, 0, 0x80, 0xf5, 1, 0, 0x80, 7, 0, 0, 0x80, 0, 0, 0, 0x80]);
    reply.push(3);
    reply.extend(b"So1");
    reply.extend([1, 9]);
    let a = Addresses::decode(&reply).unwrap();
    assert_eq!((a.fingerprint, a.account, a.entries.len()), ([0xde, 0xad, 0xbe, 0xef], 7, 2));
    assert_eq!((a.entries[0].xpub.as_str(), a.entries[0].address.as_str(), &a.entries[0].pubkey[..]), ("xpub", "bc1q", &[2u8, 3][..]));
    assert_eq!(a.entries[0].account_path, [84 | H, H, H]);
    assert_eq!((a.entries[1].xpub.as_str(), a.entries[1].address.as_str()), ("", "So1"));
    assert_eq!(a.entries[1].address_path, [44 | H, 501 | H, 7 | H, H]);
    for cut in 0..reply.len() {
        assert!(Addresses::decode(&reply[..cut]).is_err(), "a reply truncated at {cut} was accepted");
    }
    let mut trailing = reply.clone();
    trailing.push(0);
    assert!(Addresses::decode(&trailing).is_err());

    // …and the three sign results.
    assert_eq!(proto::read_bitcoin(&[2, 2, 2, 0, 0, 0, 0xAA, 0xBB, 1, 0, 0, 0, 0xCC]).unwrap(), (2, &[0xAA, 0xBB][..], &[0xCC][..]));
    assert!(proto::read_bitcoin(&[2, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(), "PSBT version 1");
    assert_eq!(proto::read_evm(&[3, 2, 0, 0, 0, 2, 0xf8]).unwrap(), [2, 0xf8]);
    assert!(proto::read_evm(&[3, 2, 0, 0, 0, 2, 0xf8, 0]).is_err());
    let mut sol = vec![4, 1, 1];
    sol.extend([0x55; 64]);
    sol.extend([1, 0, 0, 0, 0xEE]);
    assert_eq!(proto::read_solana(&sol).unwrap(), (vec![(1u8, [0x55u8; 64])], &[0xEE][..]));

    // docs/PHONE-APP.md §2: Identify from an unlocked Q1 running 7.0.0.
    let id = Identity::decode(&h("020001c00271310537 2e302e30".replace(' ', "").as_str())).unwrap();
    assert_eq!((id.protocol, id.board.as_str(), id.version.as_str()), (2, "q1", "7.0.0"));
    assert!(id.unlocked() && !id.bench());
    assert_eq!(id.caps, proto::caps::PAIRING | proto::caps::HOST_WALLET);
    // …and the message that carries the request, as the reader's APDU data.
    assert_eq!(proto::message(op::IDENTIFY, &[]), [2, 0, 0, 0, 0, 0]);
    assert_eq!(proto::parse_message(&h("00000d000000020001c002713105372e302e30")).unwrap().1.len(), 13);
    assert!(proto::parse_message(&[0, 0, 5, 0, 0, 0, 1]).is_err());
}

#[test]
fn messages_are_framed_into_reports_and_back() {
    // One frame: kind, sequence, opcode, total, payload; the rest zero.
    let one = frames(op::PAIR_COMMIT, &[7u8; 32]);
    assert_eq!(one.len(), 1);
    assert_eq!(&one[0][..8], [1, 0, 0x42, 0, 32, 0, 0, 0]);
    assert_eq!(&one[0][8..40], [7u8; 32]);
    assert!(one[0][40..].iter().all(|b| *b == 0));

    // A long sealed record: 56 bytes in the START frame, 62 in each CONT.
    let payload: Vec<u8> = (0..1040u32).map(|i| i as u8).collect();
    let many = frames(op::NCRY_MSG, &payload);
    assert_eq!(many.len(), 1 + (1040usize - 56).div_ceil(62));
    assert_eq!(&many[0][..8], [1, 0, 0x41, 0, 0x10, 0x04, 0, 0]);
    assert_eq!((many[1][0], many[1][1], many[2][1]), (2, 1, 2));
    assert_eq!(&many[1][2..], &payload[56..118]);

    // The same reports read back as a reply (the opcode's place is the
    // status), whether or not the platform leaves a zero report id in front.
    for with_id in [false, true] {
        let mut r = Reassembler::new();
        // An idle report before the reply is not part of it.
        assert_eq!(r.push(&[0u8; 64]).unwrap(), None);
        let mut done = None;
        for f in &many {
            let mut report = if with_id { vec![0u8] } else { Vec::new() };
            report.extend_from_slice(f);
            assert!(done.is_none());
            done = r.push(&report).unwrap();
        }
        assert_eq!(done, Some((op::NCRY_MSG, payload.clone())));
    }
    // A dropped frame is noticed, not spliced over.
    let mut r = Reassembler::new();
    r.push(&many[0]).unwrap();
    assert!(r.push(&many[2]).is_err());
    assert!(Reassembler::new().push(&many[1]).is_err(), "a continuation with nothing open");
}

// ── The simulated device ─────────────────────────────────────────────────────

#[derive(Default)]
struct Dev {
    handshake: Option<(X25519PrivateKey, [u8; 32])>,
    cipher: Option<Cipher>,
    code: u32,
    host_confirmed: bool,
    user_accepted: bool,
    confirm_polls: u32,
    /// The accounts shared in this session: (chain, `m/purpose'/coin'/account'`).
    exposed: Vec<(u8, Vec<u32>)>,
    upload: Option<(u8, usize, Vec<u8>)>,
    outcome: Option<Result<Vec<u8>, (u16, Vec<u8>)>>,
    wait_polls: u32,
}

/// A device holding `mnemonic`'s keys.
struct FakeCatCard {
    id: String,
    seed: Vec<u8>,
    /// The keys it signs with: another seed makes a device whose addresses
    /// are the account's and whose signatures are not.
    sign_seed: Vec<u8>,
    /// The account the person picks when asked to share.
    account: u32,
    locked: bool,
    /// The person says no to the pairing code / to any question.
    reject_pairing: bool,
    decline: bool,
    /// Report an Ethereum address that is not its key's.
    lie: bool,
    /// Finalise a PSBT itself and return the network transaction too.
    finalize: bool,
    /// Put a signature that does not verify under the right key's name.
    forge: bool,
    /// Polls answered "not yet" before the person accepts the code / answers.
    accept_after: u32,
    answer_after: u32,
    dev: RefCell<Dev>,
    clear_ops: RefCell<Vec<u16>>,
    sealed_ops: RefCell<Vec<u16>>,
}

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

impl FakeCatCard {
    fn new(mnemonic: &str) -> Self {
        let seed = bip39::mnemonic_to_seed(mnemonic, "").to_vec();
        FakeCatCard {
            id: format!("fake:{}", NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            sign_seed: seed.clone(),
            seed,
            account: 0,
            locked: false,
            reject_pairing: false,
            decline: false,
            lie: false,
            finalize: false,
            forge: false,
            accept_after: 0,
            answer_after: 0,
            dev: RefCell::new(Dev::default()),
            clear_ops: RefCell::new(Vec::new()),
            sealed_ops: RefCell::new(Vec::new()),
        }
    }

    /// Unplugged and plugged back in: the session is gone.
    fn replug(&self) {
        *self.dev.borrow_mut() = Dev::default();
    }

    fn count(&self, list: &RefCell<Vec<u16>>, opcode: u16) -> usize {
        list.borrow().iter().filter(|o| **o == opcode).count()
    }

    fn secp(seed: &[u8], path: &[u32]) -> SecpPrivateKey {
        SecpPrivateKey::from_bytes(&hdderive::derive_privkey_from_seed(seed, "secp256k1", &proto::path_text(path)).unwrap()).unwrap()
    }

    fn ed(seed: &[u8], path: &[u32]) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(hdderive::derive_privkey_from_seed(seed, "ed25519", &proto::path_text(path)).unwrap())
    }

    fn fingerprint(&self) -> [u8; 4] {
        outscript::hash::hash160(&hdderive::master_pubkey(&self.seed, "secp256k1").unwrap())[..4].try_into().unwrap()
    }

    fn identify(&self) -> Vec<u8> {
        let mut b = vec![2, 0, if self.locked { 0 } else { 1 }, 0xC0, 2];
        b.extend(b"q1");
        b.push(5);
        b.extend(b"7.0.0");
        b
    }

    /// The address reply for the account the person picked, and what it exposes.
    fn addresses(&self) -> (Vec<u8>, Vec<(u8, Vec<u32>)>) {
        let n = self.account | H;
        let mut out = vec![1, 1];
        out.extend(self.fingerprint());
        out.extend(self.account.to_le_bytes());
        out.push(0);
        let mut exposed = Vec::new();
        let mut count = 0u8;
        let mut entry = |shape: u8, chain: u8, fmt: u8, root: &[u32], at: &[u32], xpub: &str, address: &str, pubkey: &[u8]| {
            out.extend([shape, chain, fmt]);
            for p in [root, at] {
                out.push(p.len() as u8);
                p.iter().for_each(|c| out.extend(c.to_le_bytes()));
            }
            if shape == shape::UTXO {
                out.push(xpub.len() as u8);
                out.extend(xpub.as_bytes());
            }
            out.push(address.len() as u8);
            out.extend(address.as_bytes());
            out.push(pubkey.len() as u8);
            out.extend(pubkey);
            exposed.push((chain, root.to_vec()));
            count += 1;
        };
        // Bitcoin: every script type; and a chain it shares but does not sign.
        for (purpose, coin, chain, fmt, script) in [(44, 0, 1, 1, "p2pkh"), (49, 0, 1, 2, "p2sh:p2wpkh"), (84, 0, 1, 3, "p2wpkh"), (86, 0, 1, 4, "p2tr"), (84, 2, 4, 3, "p2wpkh")] {
            let root = [purpose | H, coin | H, n];
            let (key, cc) = hdderive::derive_secp_privkey_and_chaincode(&self.seed, &proto::path_text(&root)).unwrap();
            let pk = SecpPrivateKey::from_bytes(&key).unwrap().public_key().serialize_compressed();
            let child = hdderive::derive_pub(&pk, &cc, &[0, 0]).unwrap();
            let address = crate::bitcoin::address_for(&child, script, if chain == 1 { "bitcoin" } else { "litecoin" }).unwrap();
            entry(shape::UTXO, chain, fmt, &root, &[root[0], root[1], n, 0, 0], &crate::bitcoin::build_xpub(&pk, &cc), &address, &child);
        }
        let eth = [44 | H, 60 | H, n, 0, 0];
        let pk = hdderive::derive_pubkey_for_path(&self.seed, "secp256k1", &proto::path_text(&eth)).unwrap();
        let address = if self.lie { "0x000000000000000000000000000000000000dEaD".to_owned() } else { hdderive::evm_address(&pk).unwrap() };
        entry(shape::ACCOUNT, 2, format::EVM, &eth[..3], &eth, "", &address, &pk);
        let tron = [44 | H, 195 | H, n, 0, 0];
        let pk = hdderive::derive_pubkey_for_path(&self.seed, "secp256k1", &proto::path_text(&tron)).unwrap();
        entry(shape::ACCOUNT, 9, 6, &tron[..3], &tron, "", &hdderive::tron_address(&pk).unwrap(), &pk);
        let sol = [44 | H, 501 | H, n, H];
        let pk = Self::ed(&self.seed, &sol).public_key().to_bytes();
        entry(shape::ACCOUNT, 3, format::SOLANA, &sol[..3], &sol, "", &bs58::encode(&pk).into_string(), &pk);
        out[10] = count;
        (out, exposed)
    }

    /// Sign what was uploaded, as the chain's signer on the device would.
    fn sign(&self, chain: u8, keys: &[Vec<u32>], tx: &[u8]) -> Result<Vec<u8>, (u16, Vec<u8>)> {
        let refuse = |why: &str| (status::REFUSED, why.as_bytes().to_vec());
        let lv = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend((b.len() as u32).to_le_bytes());
            out.extend(b);
        };
        match chain {
            chain::BITCOIN => {
                let mut psbt = tx.to_vec();
                if self.forge {
                    // A signature by another key, filed under the right one.
                    let other = Self::secp(&bip39::mnemonic_to_seed(OTHER, ""), &keys[0]);
                    let p = Psbt::parse(tx).map_err(|_| refuse("not a PSBT"))?;
                    for n in 0..p.unsigned_tx().input_count() {
                        let pubkey = p.input(n).unwrap().map().records_of(outscript::psbt::input::BIP32_DERIVATION).next().unwrap().key_data().to_vec();
                        let mut key = vec![0x02];
                        key.extend(pubkey);
                        let mut sig = other.sign_der(&[0x11; 32]).as_bytes().to_vec();
                        sig.push(1);
                        psbt = Psbt::parse(&psbt).unwrap().set_input_record_to_vec(n, &key, &sig).unwrap();
                    }
                } else {
                    for path in keys {
                        let key = Self::secp(&self.sign_seed, path);
                        psbt = Psbt::parse(&psbt).map_err(|_| refuse("not a PSBT"))?.sign_to_vec(&key).map_err(|_| refuse("cannot sign"))?.0;
                    }
                }
                let mut network = Vec::new();
                if self.finalize {
                    psbt = Psbt::parse(&psbt).unwrap().finalize_to_vec().unwrap().0;
                    network = Psbt::parse(&psbt).unwrap().extract_tx_to_vec().unwrap();
                }
                let mut out = vec![kind::BITCOIN, 0];
                lv(&mut out, &psbt);
                lv(&mut out, &network);
                Ok(out)
            }
            chain::ETHEREUM => {
                use outscript::rlp::{self, RlpItem};
                let key = Self::secp(&self.sign_seed, &keys[0]);
                let (r, s, recid) = key.sign_recoverable(&purecrypto::hash::keccak256(tx));
                let scalar = |b: &[u8; 32]| RlpItem::bigint(&num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, b)).unwrap();
                // Typed: append y, r, s. Legacy EIP-155: `chainId, 0, 0`
                // become `v, r, s`.
                let typed = tx[0] < 0x80;
                let (item, _) = rlp::decode_one(if typed { &tx[1..] } else { tx }).map_err(|_| refuse("not a transaction"))?;
                let mut fields = item.as_list().ok_or_else(|| refuse("not a transaction"))?.to_vec();
                if typed {
                    fields.push(RlpItem::uint(recid as u64));
                } else {
                    let chain_id = rlp::decode_uint64_checked(fields[6].as_bytes().unwrap()).unwrap();
                    fields.truncate(6);
                    fields.push(RlpItem::uint(chain_id * 2 + 35 + recid as u64));
                }
                fields.extend([scalar(&r), scalar(&s)]);
                let mut signed = if typed { vec![tx[0]] } else { Vec::new() };
                signed.extend(rlp::encode_list(&fields));
                let mut out = vec![kind::EVM];
                lv(&mut out, &signed);
                Ok(out)
            }
            _ => {
                let claimed = Self::ed(&self.seed, &keys[0]).public_key().to_bytes();
                let slot = crate::solana::find_signer_slot(tx, &claimed).ok_or_else(|| refuse("not a signer of this transaction"))?;
                let sig = Self::ed(&self.sign_seed, &keys[0]).sign(tx).to_bytes();
                let mut out = vec![kind::SOLANA, 1, slot as u8];
                out.extend(sig);
                lv(&mut out, &crate::solana::assemble_tx(tx, &sig));
                Ok(out)
            }
        }
    }

    /// A host-wallet command, inside a paired session.
    fn inner(&self, dev: &mut Dev, opcode: u16, p: &[u8]) -> (u16, Vec<u8>) {
        let u32at = |b: &[u8]| u32::from_le_bytes(b[..4].try_into().unwrap());
        match opcode {
            op::IDENTIFY => (status::OK, self.identify()),
            op::HOST_ADDRESSES => {
                if !p.is_empty() {
                    return (status::BAD_REQUEST, vec![]);
                }
                if dev.outcome.is_some() || dev.upload.is_some() {
                    return (status::NOT_NOW, vec![2]);
                }
                if self.decline {
                    dev.outcome = Some(Err((status::DECLINED, vec![])));
                } else {
                    let (reply, exposed) = self.addresses();
                    dev.exposed = exposed;
                    dev.outcome = Some(Ok(reply));
                }
                dev.wait_polls = self.answer_after;
                (status::OK, vec![])
            }
            op::HOST_SIGN_BEGIN => {
                if p.len() != 5 {
                    return (status::BAD_REQUEST, vec![]);
                }
                if !(1..=3).contains(&p[0]) {
                    return (status::REFUSED, format!("{} cannot be signed here", chain::name(p[0])).into_bytes());
                }
                if !dev.exposed.iter().any(|(c, _)| *c == p[0]) {
                    return (status::REFUSED, b"nothing shared on this chain".to_vec());
                }
                dev.upload = Some((p[0], u32at(&p[1..]) as usize, Vec::new()));
                (status::OK, 1018u32.to_le_bytes().to_vec())
            }
            op::HOST_SIGN_DATA => {
                let Some((_, total, got)) = dev.upload.as_mut() else { return (status::BAD_REQUEST, vec![]) };
                if p.len() < 5 || p.len() - 4 > 1018 || u32at(p) as usize != got.len() || got.len() + p.len() - 4 > *total {
                    return (status::BAD_REQUEST, vec![]);
                }
                got.extend_from_slice(&p[4..]);
                (status::OK, (got.len() as u32).to_le_bytes().to_vec())
            }
            op::HOST_SIGN_COMMIT => {
                let Some((chain, total, blob)) = dev.upload.take() else { return (status::REFUSED, b"nothing uploaded".to_vec()) };
                // [version][chain][n][n × path][u32 len][tx], nothing after.
                let parsed = (|| {
                    let mut c = proto::Cursor::new(&blob);
                    if blob.len() != total || c.u8()? != 1 || c.u8()? != chain {
                        return Err("malformed".to_owned());
                    }
                    let n = c.u8()?;
                    let keys = (0..n).map(|_| c.path()).collect::<Result<Vec<_>, _>>()?;
                    let len = c.u32()? as usize;
                    let tx = c.take(len)?.to_vec();
                    c.done()?;
                    Ok((keys, tx))
                })();
                let Ok((keys, tx)) = parsed else { return (status::REFUSED, b"malformed sign request".to_vec()) };
                let below = |key: &Vec<u32>| dev.exposed.iter().any(|(c, root)| *c == chain && key.len() > root.len() && key.starts_with(root));
                if keys.is_empty() || !keys.iter().all(below) || (chain == chain::ETHEREUM && keys.len() != 1) {
                    return (status::REFUSED, b"key not shared in this session".to_vec());
                }
                dev.outcome = Some(if self.decline { Err((status::DECLINED, vec![])) } else { self.sign(chain, &keys, &tx) });
                dev.wait_polls = self.answer_after;
                (status::OK, vec![])
            }
            op::HOST_RESULT => {
                if p.len() != 4 {
                    return (status::BAD_REQUEST, vec![]);
                }
                if dev.wait_polls > 0 {
                    dev.wait_polls -= 1;
                    return (status::NOT_NOW, vec![3]);
                }
                let at = u32at(p) as usize;
                match dev.outcome.take() {
                    None => (status::NOT_NOW, vec![0]),
                    Some(Err(refusal)) => refusal,
                    Some(Ok(result)) if at > result.len() => {
                        dev.outcome = Some(Ok(result));
                        (status::BAD_REQUEST, vec![])
                    }
                    Some(Ok(result)) => {
                        let end = (at + proto::PAGE_MAX).min(result.len());
                        let mut body = (result.len() as u32).to_le_bytes().to_vec();
                        body.extend_from_slice(&result[at..end]);
                        if end < result.len() {
                            dev.outcome = Some(Ok(result));
                        }
                        (status::OK, body)
                    }
                }
            }
            op::HOST_ABORT => {
                dev.upload = None;
                (status::OK, vec![])
            }
            _ => (status::UNKNOWN_OPCODE, vec![]),
        }
    }

    fn handle(&self, opcode: u16, payload: &[u8]) -> (u16, Vec<u8>) {
        self.clear_ops.borrow_mut().push(opcode);
        let mut dev = self.dev.borrow_mut();
        match opcode {
            op::IDENTIFY => (status::OK, self.identify()),
            op::PAIR_COMMIT => {
                if self.locked {
                    return (status::NOT_NOW, vec![]);
                }
                let Ok(commit) = <[u8; 32]>::try_from(payload) else { return (status::BAD_REQUEST, vec![]) };
                *dev = Dev::default();
                let key = X25519PrivateKey::from_bytes(purecrypto::hash::sha256(self.id.as_bytes()));
                let public = key.public_key();
                dev.handshake = Some((key, commit));
                (status::OK, public.to_vec())
            }
            op::PAIR_REVEAL => {
                let Some((key, commit)) = dev.handshake.take() else { return (status::BAD_REQUEST, vec![]) };
                let Ok(host_pub) = <[u8; 32]>::try_from(payload) else { return (status::BAD_REQUEST, vec![]) };
                if commitment(&host_pub) != commit {
                    return (status::BAD_REQUEST, vec![]);
                }
                let shared = key.diffie_hellman(&host_pub).unwrap();
                let (h2d, d2h, code) = schedule(&shared, &commit, &key.public_key(), &host_pub);
                dev.cipher = Some(Cipher::new(d2h, h2d));
                dev.code = code;
                (status::OK, vec![])
            }
            op::PAIR_ABORT => {
                *dev = Dev::default();
                (status::OK, vec![])
            }
            op::NCRY_MSG => {
                let Some(mut cipher) = dev.cipher.take() else { return (status::NOT_NOW, vec![]) };
                // Anything that fails to authenticate ends the session.
                let plain = match cipher.open(payload) {
                    Ok(p) if p.len() >= 2 => p,
                    _ => {
                        *dev = Dev::default();
                        return (status::BAD_REQUEST, vec![]);
                    }
                };
                let inner_op = u16::from_le_bytes([plain[0], plain[1]]);
                self.sealed_ops.borrow_mut().push(inner_op);
                let (st, body) = if inner_op == op::PAIR_CONFIRM {
                    dev.host_confirmed = true;
                    if self.reject_pairing {
                        *dev = Dev::default();
                        return (status::DECLINED, vec![]);
                    }
                    dev.confirm_polls += 1;
                    dev.user_accepted |= dev.confirm_polls > self.accept_after;
                    (if dev.user_accepted { status::OK } else { status::NOT_NOW }, vec![])
                } else if !(dev.host_confirmed && dev.user_accepted) {
                    *dev = Dev::default();
                    return (status::BAD_REQUEST, vec![]);
                } else {
                    self.inner(&mut dev, inner_op, &plain[2..])
                };
                let mut reply = st.to_le_bytes().to_vec();
                reply.extend(body);
                let sealed = cipher.seal(&reply);
                dev.cipher = Some(cipher);
                (status::OK, sealed)
            }
            _ => (status::UNKNOWN_OPCODE, vec![]),
        }
    }
}

impl Transport for FakeCatCard {
    async fn request(&self, opcode: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), ApiError> {
        Ok(self.handle(opcode, payload))
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

// ── Harness ──────────────────────────────────────────────────────────────────

fn run<F: std::future::Future>(f: F) -> F::Output {
    crate::rt::block_on(f)
}

/// An environment whose host answers every `catcard:pair` event (`accept`),
/// and keeps the events it saw.
fn env_answering(accept: bool) -> (Env, Arc<Mutex<Vec<Value>>>) {
    let env = Env::init_memory().unwrap();
    crate::models::wallet::init(&env).unwrap();
    crate::models::account::init(&env).unwrap();
    crate::models::network::init(&env).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = events.clone();
    env.set_event_sink(Some(Box::new(move |ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        if ev["event"] == "catcard:pair" {
            assert!(session::pair_resolve(ev["data"]["id"].as_str().unwrap(), accept));
        }
        seen.lock().unwrap().push(ev);
    })));
    (env, events)
}

fn env() -> Env {
    env_answering(true).0
}

fn all_scripts() -> KeyQuery {
    KeyQuery::from_params(&json!({ "Scripts": ["p2wpkh", "p2sh:p2wpkh", "p2pkh", "p2tr"] })).unwrap()
}

/// Read the device's keys and import them as a CatCard wallet.
fn import_from(env: &Env, device: &FakeCatCard) -> crate::airgap::import::Imported {
    let export = run(keys(env, device, &all_scripts())).unwrap();
    import(env, &export, &ImportOptions { protocol: Some("catcard".into()), ..Default::default() }).unwrap()
}

fn account_of(env: &Env, imported: &crate::airgap::import::Imported, kind: &str, script: &str) -> (Account, AccountKeyInfo) {
    imported.accounts.iter().map(|a| load_account(env, &a.id).unwrap()).find(|(a, i)| a.kind == kind && i.script == script).unwrap()
}

/// A device that reports `MNEMONIC`'s addresses and signs with other keys.
fn impostor() -> FakeCatCard {
    let mut d = FakeCatCard::new(MNEMONIC);
    d.sign_seed = bip39::mnemonic_to_seed(OTHER, "").to_vec();
    d
}

// ── Pairing and the session ──────────────────────────────────────────────────

#[test]
fn pairing_compares_a_code_and_the_session_is_reused() {
    let (env, events) = env_answering(true);
    let mut device = FakeCatCard::new(MNEMONIC);
    device.accept_after = 2; // the person at the device takes a moment
    device.answer_after = 2;

    // Identify needs no pairing and asks nobody anything.
    let id = run(info(&device)).unwrap();
    assert_eq!((id["board"].as_str(), id["firmware"].as_str(), id["unlocked"].as_bool(), id["paired"].as_bool()), (Some("q1"), Some("7.0.0"), Some(true), Some(false)));
    assert!(device.sealed_ops.borrow().is_empty() && events.lock().unwrap().is_empty());

    // The first request that needs the channel pairs it: the code the host
    // is shown is the one on the device's screen.
    let export = run(keys(&env, &device, &all_scripts())).unwrap();
    assert_eq!(export.format, "catcard");
    assert_eq!(export.version.as_deref(), Some("q1 7.0.0"));
    {
        let ev = events.lock().unwrap();
        let pair: Vec<&Value> = ev.iter().filter(|e| e["event"] == "catcard:pair").collect();
        assert_eq!(pair.len(), 1);
        assert_eq!(pair[0]["data"]["code"], code_text(device.dev.borrow().code).as_str());
        assert_eq!(pair[0]["data"]["board"], "q1");
        // The person at the device was waited for, and the host was told.
        assert!(ev.iter().any(|e| e["event"] == "catcard:waiting" && e["data"]["for"] == "addresses" && e["data"]["stage"] == "deciding"));
        // No event carries anything but the code: never a key.
        assert!(ev.iter().all(|e| e["data"].as_object().unwrap().keys().all(|k| ["id", "code", "board", "version", "bench", "for", "stage"].contains(&k.as_str()))));
    }
    assert_eq!(device.count(&device.sealed_ops, op::PAIR_CONFIRM), 3);
    assert_eq!(run(info(&device)).unwrap()["paired"], true);

    // The next request reuses the session: no second handshake, no new code.
    run(keys(&env, &device, &all_scripts())).unwrap();
    assert_eq!(device.count(&device.clear_ops, op::PAIR_COMMIT), 1);
    assert_eq!(device.count(&device.sealed_ops, op::HOST_ADDRESSES), 2);

    // Unplugged and back: the session is gone on the device, and the next
    // request pairs again — with a new code to compare.
    device.replug();
    run(keys(&env, &device, &all_scripts())).unwrap();
    assert_eq!(device.count(&device.clear_ops, op::PAIR_COMMIT), 2);
    assert_eq!(events.lock().unwrap().iter().filter(|e| e["event"] == "catcard:pair").count(), 2);

    // Disconnecting forgets it on both sides.
    assert!(run(session::disconnect(&device)).unwrap());
    assert!(device.dev.borrow().cipher.is_none());
    assert_eq!(run(info(&device)).unwrap()["paired"], false);
}

#[test]
fn pairing_fails_closed() {
    // The host's user says the codes differ: the device is told, no session.
    let (env, _) = env_answering(false);
    let device = FakeCatCard::new(MNEMONIC);
    let err = run(keys(&env, &device, &all_scripts())).unwrap_err();
    assert_eq!(err.code, 4001, "{}", err.message);
    assert_eq!(device.count(&device.clear_ops, op::PAIR_ABORT), 1);
    assert!(device.sealed_ops.borrow().is_empty(), "something was sent before the code was confirmed");
    assert!(!session::held(&device));

    // The device's owner says no; a locked device; an older protocol.
    let env = self::env();
    let mut device = FakeCatCard::new(MNEMONIC);
    device.reject_pairing = true;
    assert_eq!(run(keys(&env, &device, &all_scripts())).unwrap_err().code, 4001);
    assert!(!session::held(&device));
    let mut device = FakeCatCard::new(MNEMONIC);
    device.locked = true;
    let err = run(keys(&env, &device, &all_scripts())).unwrap_err();
    assert_eq!(err.code, 423, "{}", err.message);
    assert_eq!(device.count(&device.clear_ops, op::PAIR_COMMIT), 0);

    // Nobody answers the code at all: nothing is assumed, and an answer that
    // comes after the wait is not accepted either.
    let waiting = super::transport::Waiters::<bool>::new();
    assert_eq!(run(waiting.wait("pair-nobody", 5, || {})), None);
    assert!(!waiting.resolve("pair-nobody", true));
}

// ── Keys ─────────────────────────────────────────────────────────────────────

#[test]
fn keys_match_the_mnemonic_and_import_as_a_catcard_wallet() {
    let env = env();
    let want = crate::walletcore::derive_addresses(MNEMONIC, "").unwrap();
    let device = FakeCatCard::new(MNEMONIC);

    // By default only the native-segwit Bitcoin account is reported.
    let export = run(keys(&env, &device, &KeyQuery::from_params(&json!({})).unwrap())).unwrap();
    assert_eq!(export.master_fingerprint.as_deref(), Some("73c5da0a"));
    let btc: Vec<_> = export.keys.iter().filter(|k| k.chain == "bitcoin").collect();
    assert_eq!(btc.len(), 1);
    assert_eq!((btc[0].path.as_str(), btc[0].script.as_str(), btc[0].address.as_str()), ("m/84'/0'/0'", "p2wpkh", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
    assert_eq!(btc[0].address, want.bitcoin);
    // Chains the device shares but does not sign for are named, not imported.
    let skipped: Vec<_> = export.keys.iter().filter(|k| k.chain == "unsupported").map(|k| k.name.clone().unwrap()).collect();
    assert_eq!(skipped, ["Litecoin", "Tron"]);

    let imported = import_from(&env, &device);
    assert_eq!(imported.wallet.protocol, "catcard");
    assert_eq!(imported.wallet.name, "CatCard");
    assert_eq!(imported.skipped.len(), 2);
    let kinds: Vec<_> = imported.accounts.iter().map(|a| (a.kind.as_str(), a.path.as_str())).collect();
    assert_eq!(kinds, [("bitcoin", "m/44'/0'/0'"), ("bitcoin", "m/49'/0'/0'"), ("bitcoin", "m/84'/0'/0'"), ("bitcoin", "m/86'/0'/0'"), ("ethereum", "m/44'/60'/0'/0/0"), ("solana", "m/44'/501'/0'/0'")]);
    let (eth, _) = account_of(&env, &imported, "ethereum", "");
    assert_eq!(eth.address, want.evm);
    let (sol, _) = account_of(&env, &imported, "solana", "");
    assert_eq!(sol.address, want.solana);
    let (taproot, info) = account_of(&env, &imported, "bitcoin", "p2tr");
    assert!(taproot.address.starts_with("bc1p"), "{}", taproot.address);
    assert_eq!(info.master_fingerprint.as_deref(), Some("73c5da0a"));

    // The account is the person's choice on the device, not the host's: a
    // host that expected another one is told.
    let mut second = FakeCatCard::new(MNEMONIC);
    second.account = 1;
    let export = run(keys(&env, &second, &KeyQuery::from_params(&json!({ "Account": 1 })).unwrap())).unwrap();
    assert_eq!(export.keys[0].path, "m/84'/0'/1'");
    assert_eq!(run(keys(&env, &second, &KeyQuery::from_params(&json!({ "Account": 0 })).unwrap())).unwrap_err().code, 409);
    assert!(KeyQuery::from_params(&json!({ "Count": 2 })).is_err());
    assert!(KeyQuery::from_params(&json!({ "Paths": ["m/44'/60'/0'/0/1"] })).is_err());
    assert!(KeyQuery::from_params(&json!({ "Scripts": ["p2wsh"] })).is_err());
    assert!(KeyQuery::from_params(&json!({ "Account": 0x8000_0000u32 })).is_err());

    // A device whose address is not its key's is not believed; a refusal on
    // the device is reported as one.
    let mut liar = FakeCatCard::new(MNEMONIC);
    liar.lie = true;
    let err = run(keys(&env, &liar, &all_scripts())).unwrap_err();
    assert_eq!(err.code, 502, "{}", err.message);
    let mut refusing = FakeCatCard::new(MNEMONIC);
    refusing.decline = true;
    assert_eq!(run(keys(&env, &refusing, &all_scripts())).unwrap_err().code, 4001);
}

#[test]
fn only_catcard_accounts_are_signed_for_and_never_in_software() {
    let env = env();
    let imported = import_from(&env, &FakeCatCard::new(MNEMONIC));
    let (eth, _) = account_of(&env, &imported, "ethereum", "");
    assert_eq!(load_account(&env, "acct-nope").unwrap_err().code, 404);
    // The software signing paths refuse a CatCard account, naming the route.
    let err = crate::evm::personal_sign(&env, &eth.id, &[], b"hi").unwrap_err().to_string();
    assert!(err.contains("CatCard:signTransaction"), "{err}");

    // What the protocol has no command for is said, not improvised.
    for route in ["showAddress", "signMessage"] {
        let err = run(crate::handlers::catcard::route(&env, route, &json!({ "Account": eth.id, "Message": "aGk=" }))).unwrap_err();
        assert_eq!(err.code, 501, "{}", err.message);
    }
    assert_eq!(run(crate::handlers::catcard::route(&env, "nope", &json!({}))).unwrap_err().code, 404);
}

// ── Signing ──────────────────────────────────────────────────────────────────

fn evm_tx() -> Value {
    json!({
        "to": "0x000000000000000000000000000000000000dEaD", "value": "1000000000000000",
        "nonce": 7, "gas": 21000, "chainId": 1,
        "maxFeePerGas": "30000000000", "maxPriorityFeePerGas": "1000000000",
    })
}

#[test]
fn evm_transaction_is_signed_and_bound_to_the_account() {
    let env = env();
    let device = FakeCatCard::new(MNEMONIC);
    let imported = import_from(&env, &device);
    let (account, info) = account_of(&env, &imported, "ethereum", "");

    for tx in [evm_tx(), json!({ "to": "0x000000000000000000000000000000000000dEaD", "value": "5", "nonce": 0, "gas": 21000, "chainId": 137, "gasPrice": "1000000000" })] {
        let out = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": tx, "Offline": true }))).unwrap();
        let raw = unhex(out["raw"].as_str().unwrap()).unwrap();
        assert!(crate::evm::recover_sender(&raw).unwrap().eq_ignore_ascii_case(&account.address), "{out}");
        let signed = outscript::evmtx::EvmTx::from_bytes(&raw).unwrap();
        assert_eq!(signed.chain_id, tx["chainId"].as_u64().unwrap());
        assert_eq!(signed.nonce, tx["nonce"].as_u64().unwrap());
    }
    // Same session as the import: the account was already shared, so the
    // device was asked for addresses once and to sign twice.
    assert_eq!(device.count(&device.sealed_ops, op::HOST_ADDRESSES), 1);
    assert_eq!(device.count(&device.sealed_ops, op::HOST_SIGN_COMMIT), 2);
    assert_eq!(device.count(&device.clear_ops, op::PAIR_COMMIT), 1);

    // A new session knows no shared account: the device is asked to share
    // again before it is asked to sign.
    device.replug();
    run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap();
    assert_eq!(device.count(&device.sealed_ops, op::HOST_ADDRESSES), 2);

    // A device that shows this account's address but signs with another key:
    // its signature is refused.
    let wrong = impostor();
    let err = run(sign_transaction(&env, &wrong, &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);
    assert_eq!(wrong.count(&wrong.sealed_ops, op::HOST_SIGN_COMMIT), 1);
    // A device holding other keys altogether is turned down before it is
    // asked to sign anything.
    let other = FakeCatCard::new(OTHER);
    let err = run(sign_transaction(&env, &other, &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);
    assert_eq!(other.count(&other.sealed_ops, op::HOST_SIGN_BEGIN), 0);
    // …and so is one on which the person shared another account.
    let mut elsewhere = FakeCatCard::new(MNEMONIC);
    elsewhere.account = 3;
    let err = run(sign_transaction(&env, &elsewhere, &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);
    assert!(err.message.contains("account 0"), "{}", err.message);

    // A refusal on the device, and an incomplete offline transaction (which
    // never reaches the device at all).
    let mut refusing = FakeCatCard::new(MNEMONIC);
    run(keys(&env, &refusing, &all_scripts())).unwrap();
    refusing.decline = true;
    let err = run(sign_transaction(&env, &refusing, &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 4001, "{}", err.message);
    let mut incomplete = evm_tx();
    incomplete.as_object_mut().unwrap().remove("chainId");
    let untouched = FakeCatCard::new(MNEMONIC);
    let err = run(sign_transaction(&env, &untouched, &account, &info, &json!({ "Transaction": incomplete, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
    assert!(untouched.clear_ops.borrow().is_empty(), "the device was involved in an incomplete transaction");
    // Broadcasting needs a node.
    let err = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": evm_tx(), "Offline": true, "Broadcast": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
}

#[test]
fn solana_message_is_signed_and_bound_to_the_account() {
    let env = env();
    let device = FakeCatCard::new(MNEMONIC);
    let imported = import_from(&env, &device);
    let (account, info) = account_of(&env, &imported, "solana", "");
    let from = crate::solana::pubkey_from_b64url(&account.pubkey).unwrap();
    let message = crate::solana::build_transfer_message(&from, &[9u8; 32], 1_000, &[3u8; 32]);
    let params = json!({ "Transaction": { "message": bs58::encode(&message).into_string() }, "Offline": true });

    let out = run(sign_transaction(&env, &device, &account, &info, &params)).unwrap();
    let raw = bs58::decode(out["raw"].as_str().unwrap()).into_vec().unwrap();
    assert_eq!(crate::solana::tx_message(&raw).unwrap(), &message[..]);
    let sig: [u8; 64] = bs58::decode(out["id"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();
    assert!(crate::tss::ed25519_verify(&from, &message, &sig));

    // Another key's signature is refused, and so is a message that does not
    // name this account as a signer (before the device is involved).
    assert_eq!(run(sign_transaction(&env, &impostor(), &account, &info, &params)).unwrap_err().code, 409);
    let foreign = crate::solana::build_transfer_message(&[5u8; 32], &[9u8; 32], 1_000, &[3u8; 32]);
    let untouched = FakeCatCard::new(MNEMONIC);
    let err = run(sign_transaction(&env, &untouched, &account, &info, &json!({ "Transaction": { "message": bs58::encode(&foreign).into_string() }, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
    assert!(untouched.clear_ops.borrow().is_empty());
}

fn btc_tx(account: &Account, inputs: usize) -> Value {
    let utxos: Vec<Value> = (0..inputs).map(|i| json!({ "txo": format!("{}:{i}", "11".repeat(32)), "amount_sats": 60_000, "path": format!("m/0/{i}") })).collect();
    json!({ "To": account.address, "Amount": 50_000 * inputs as u64, "FeeRate": 2, "UTXOs": utxos })
}

#[test]
fn bitcoin_spend_is_signed_verified_and_accepted() {
    let env = env();
    let device = FakeCatCard::new(MNEMONIC);
    let imported = import_from(&env, &device);

    // Every script type the device shares, with two inputs on different keys.
    for script in ["p2wpkh", "p2sh:p2wpkh", "p2tr"] {
        let (account, info) = account_of(&env, &imported, "bitcoin", script);
        let out = run(sign_transaction(&env, &device, &account, &info, &json!({ "Transaction": btc_tx(&account, 2), "Offline": true }))).unwrap();
        let raw = unhex(out["raw"].as_str().unwrap()).unwrap();
        let tx = outscript::btctx::BtcTx::from_bytes(&raw).unwrap();
        assert_eq!(tx.inputs.len(), 2, "{script}");
        assert!(tx.inputs.iter().all(|i| !i.witnesses.is_empty()), "{script}: an input has no witness");
        assert_eq!(out["summary"]["amount_sats"], 100_000);
        assert_eq!(out["account"], account.id.as_str());
    }
    let (account, info) = account_of(&env, &imported, "bitcoin", "p2wpkh");
    let params = json!({ "Transaction": btc_tx(&account, 1), "Offline": true });

    // A device that finalises the PSBT itself is checked the same way.
    let mut finalizing = FakeCatCard::new(MNEMONIC);
    finalizing.finalize = true;
    let out = run(sign_transaction(&env, &finalizing, &account, &info, &params)).unwrap();
    assert!(out["raw"].as_str().unwrap().len() > 100);
    // The upload spans several sealed records, and the result several pages.
    let big = run(sign_transaction(&env, &finalizing, &account, &info, &json!({ "Transaction": btc_tx(&account, 12), "Offline": true }))).unwrap();
    assert_eq!(outscript::btctx::BtcTx::from_bytes(&unhex(big["raw"].as_str().unwrap()).unwrap()).unwrap().inputs.len(), 11);
    assert!(finalizing.count(&finalizing.sealed_ops, op::HOST_SIGN_DATA) > 2);
    assert!(finalizing.count(&finalizing.sealed_ops, op::HOST_RESULT) > 4);

    // A device that shows this account's keys but cannot sign for them leaves
    // the inputs unsigned; one that files another key's signature under the
    // right key is caught by the signature check. Neither is accepted.
    let err = run(sign_transaction(&env, &impostor(), &account, &info, &params)).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);
    let mut forger = FakeCatCard::new(MNEMONIC);
    forger.forge = true;
    let err = run(sign_transaction(&env, &forger, &account, &info, &params)).unwrap_err();
    assert_eq!(err.code, 409, "{}", err.message);
    assert!(err.message.contains("not signed by this account's key"), "{}", err.message);
    // …and a device with other keys is not asked to sign at all.
    let other = FakeCatCard::new(OTHER);
    assert_eq!(run(sign_transaction(&env, &other, &account, &info, &params)).unwrap_err().code, 409);
    assert_eq!(other.count(&other.sealed_ops, op::HOST_SIGN_BEGIN), 0);

    // Other chains are not signed; no UTXOs and no node is an error; neither
    // involves the device.
    let untouched = FakeCatCard::new(MNEMONIC);
    let mut ltc = btc_tx(&account, 1);
    ltc["ChainId"] = json!("litecoin");
    assert_eq!(run(sign_transaction(&env, &untouched, &account, &info, &json!({ "Transaction": ltc, "Offline": true }))).unwrap_err().code, 400);
    let err = run(sign_transaction(&env, &untouched, &account, &info, &json!({ "Transaction": { "To": account.address, "Amount": 1 }, "Offline": true }))).unwrap_err();
    assert_eq!(err.code, 400, "{}", err.message);
    assert!(untouched.clear_ops.borrow().is_empty());
}

// ── The host bridge ──────────────────────────────────────────────────────────

#[test]
fn bridge_relays_packets_through_the_host() {
    let env = Arc::new(env_answering(true).0);
    // The "host": answers each catcard:packet event from a simulated device
    // and each pairing code as its user would, on other threads, through the
    // routes a real host calls.
    let device = Arc::new(Mutex::new(FakeCatCard::new(MNEMONIC)));
    let packets = Arc::new(Mutex::new(Vec::<String>::new()));
    let (sim, seen, host_env) = (device.clone(), packets.clone(), Arc::downgrade(&env));
    env.set_event_sink(Some(Box::new(move |ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        let Some(env) = host_env.upgrade() else { return };
        let id = ev["data"]["id"].as_str().unwrap_or_default().to_owned();
        match ev["event"].as_str() {
            Some("catcard:packet") => {
                let packet = ev["data"]["packet"].as_str().unwrap().to_owned();
                seen.lock().unwrap().push(packet.clone());
                let sim = sim.clone();
                std::thread::spawn(move || {
                    let bytes = unhex(&packet).unwrap();
                    let (opcode, payload) = proto::parse_message(&bytes).unwrap();
                    let (st, body) = sim.lock().unwrap().handle(opcode, payload);
                    run(crate::handlers::catcard::route(&env, "packetResponse", &json!({ "Id": id, "Data": hex(&proto::message(st, &body)) }))).unwrap();
                });
            }
            Some("catcard:pair") => {
                std::thread::spawn(move || {
                    run(crate::handlers::catcard::route(&env, "pairResponse", &json!({ "Id": id, "Accept": true }))).unwrap();
                });
            }
            _ => {}
        }
    })));

    let bridge = json!({ "Transport": "bridge" });
    let out = run(crate::handlers::catcard::route(&env, "info", &bridge)).unwrap();
    assert_eq!(out["board"], "q1");
    assert_eq!(packets.lock().unwrap()[0], "020000000000", "Identify, as the reader's APDU carries it");
    let keys = run(crate::handlers::catcard::route(&env, "getKeys", &bridge)).unwrap();
    assert_eq!(keys["keys"][0]["address"], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(keys["master_fingerprint"], "73c5da0a");

    // CatCard:import persists them, and the account signs over the bridge.
    let imported = run(crate::handlers::catcard::route(&env, "import", &json!({ "Keys": keys["keys"], "Name": "My CatCard" }))).unwrap();
    assert_eq!(imported["wallet"]["Name"], "My CatCard");
    assert_eq!(imported["wallet"]["Protocol"], "catcard");
    let eth = imported["accounts"].as_array().unwrap().iter().find(|a| a["Type"] == "ethereum" || a["Kind"] == "ethereum").cloned();
    let eth_id = match eth {
        Some(a) => a["Id"].as_str().unwrap().to_owned(),
        None => crate::models::account::list(&env).unwrap().into_iter().find(|a| a.kind == "ethereum").unwrap().id,
    };
    let signed = run(crate::handlers::catcard::route(&env, "signTransaction", &json!({ "Transport": "bridge", "Account": eth_id, "Transaction": evm_tx(), "Offline": true }))).unwrap();
    let want = crate::walletcore::derive_addresses(MNEMONIC, "").unwrap().evm;
    assert!(crate::evm::recover_sender(&unhex(signed["raw"].as_str().unwrap()).unwrap()).unwrap().eq_ignore_ascii_case(&want));

    // One pairing served all three requests, and after the handshake nothing
    // crossed the bridge in the clear but Identify: every other packet is a
    // sealed record.
    {
        let device = device.lock().unwrap();
        assert_eq!(device.count(&device.clear_ops, op::PAIR_COMMIT), 1);
    }
    let all = packets.lock().unwrap().clone();
    assert!(all.iter().all(|p| ["0200", "4100", "4200", "4300"].contains(&&p[..4])), "{all:?}");
    assert!(all.iter().filter(|p| p.starts_with("4100")).count() > 6);

    // The answer routes reject what nothing is waiting for.
    assert_eq!(run(crate::handlers::catcard::route(&env, "packetResponse", &json!({ "Id": "pkt-nope", "Data": "000000000000" }))).unwrap_err().code, 404);
    assert_eq!(run(crate::handlers::catcard::route(&env, "pairResponse", &json!({ "Id": "pair-nope", "Accept": true }))).unwrap_err().code, 404);
    assert_eq!(run(crate::handlers::catcard::route(&env, "pairResponse", &json!({ "Id": "pair-nope" }))).unwrap_err().code, 400);
    assert!(super::transport::kinds().contains(&"bridge"));
    run(crate::handlers::catcard::route(&env, "disconnect", &bridge)).unwrap();
    env.set_event_sink(None);
}

// ── The smart-card reader ────────────────────────────────────────────────────

#[test]
fn apdus_match_the_reference_client() {
    use proto::apdu;
    // tools/ccidclient.py --selftest, byte for byte.
    assert_eq!(apdu::commands(op::IDENTIFY, &[], false), [h("80cc00000000060200000000000000")]);
    assert_eq!(apdu::commands(0x0001, b"hi", true), [h("80cc000008010002000000686900")]);
    // Chained, short: 255 data bytes per APDU, the header on the first.
    let payload: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
    let a = apdu::commands(op::NCRY_MSG, &payload, true);
    assert_eq!(a.iter().map(|x| x[0]).collect::<Vec<_>>(), [0x90, 0x90, 0x80]);
    assert_eq!((a[0][4], &a[0][5..11]), (255, &[0x41, 0, 0, 2, 0, 0][..]));
    let joined: Vec<u8> = a.iter().flat_map(|x| x[5..x.len() - 1].to_vec()).collect();
    assert_eq!(joined, proto::message(op::NCRY_MSG, &payload));
    // Chained, extended: 1030 bytes on the first, the rest on the second.
    let a = apdu::commands(op::NCRY_MSG, &[0u8; 1500], false);
    assert_eq!((a.len(), a[0][0], a[1][0]), (2, 0x90, 0x80));
    assert_eq!((&a[0][4..7], &a[1][4..7]), (&[0, 0x04, 0x06][..], &[0, 0x01, 0xdc][..]));
    assert!(a.iter().all(|x| x.ends_with(&[0, 0])));
    assert_eq!(apdu::get_response(false), h("00c00000000000"));
    assert_eq!(apdu::get_response(true), h("00c0000000"));

    // docs/PHONE-APP.md §2: the Identify exchange, response included.
    let r = h("00000d000000020001c002713105372e302e309000");
    let (data, sw) = apdu::response(&r).unwrap();
    assert_eq!(sw, apdu::SW_OK);
    let (st, body) = proto::parse_message(data).unwrap();
    assert_eq!((st, Identity::decode(body).unwrap().board.as_str()), (status::OK, "q1"));
    assert!(apdu::more(0x612C) && !apdu::more(0x9000));
    assert!(apdu::response(&[0x90]).is_err());
    assert!(apdu::refusal(0x6D00).contains("6D00"));
}

/// The card in the device's reader: the one APDU, command chaining, and
/// replies paged by `Le` and `GET RESPONSE`, as the firmware documents them.
struct FakeCard {
    dev: FakeCatCard,
    chain: Vec<u8>,
    pending: Vec<u8>,
    seen: Vec<Vec<u8>>,
}

impl FakeCard {
    fn new(dev: FakeCatCard) -> Self {
        FakeCard { dev, chain: Vec::new(), pending: Vec::new(), seen: Vec::new() }
    }

    fn page(&mut self, le: usize) -> Vec<u8> {
        let n = le.min(self.pending.len());
        let mut out: Vec<u8> = self.pending.drain(..n).collect();
        let sw: u16 = if self.pending.is_empty() { 0x9000 } else { 0x6100 | self.pending.len().min(255) as u16 };
        out.extend(sw.to_be_bytes());
        out
    }

    fn transmit(&mut self, apdu: &[u8]) -> Vec<u8> {
        self.seen.push(apdu.to_vec());
        let sw = |w: u16| w.to_be_bytes().to_vec();
        if apdu.len() < 4 {
            return sw(0x6700);
        }
        let (cla, ins, rest) = (apdu[0], apdu[1], &apdu[4..]);
        // ISO 7816-4's cases: (data, Le — zero when there is none).
        let (data, le): (&[u8], usize) = match rest.len() {
            0 => (&[], 0),
            1 => (&[], if rest[0] == 0 { 256 } else { rest[0] as usize }),
            _ if rest[0] != 0 => {
                let lc = rest[0] as usize;
                match rest.len() - 1 {
                    n if n == lc => (&rest[1..], 0),
                    n if n == lc + 1 => (&rest[1..1 + lc], if rest[1 + lc] == 0 { 256 } else { rest[1 + lc] as usize }),
                    _ => return sw(0x6700),
                }
            }
            n => {
                let ext = |a: u8, b: u8| if (a, b) == (0, 0) { 65536 } else { u16::from_be_bytes([a, b]) as usize };
                if n == 3 {
                    (&[], ext(rest[1], rest[2]))
                } else {
                    let lc = u16::from_be_bytes([rest[1], rest[2]]) as usize;
                    match n - 3 {
                        m if m == lc => (&rest[3..], 0),
                        m if m == lc + 2 => (&rest[3..3 + lc], ext(rest[3 + lc], rest[4 + lc])),
                        _ => return sw(0x6700),
                    }
                }
            }
        };
        if !matches!(cla, 0x80 | 0x90 | 0x00) {
            return sw(0x6E00);
        }
        if apdu[2] != 0 || apdu[3] != 0 {
            return sw(0x6A86);
        }
        match (cla, ins) {
            (0x80 | 0x90, 0xCC) => {
                self.chain.extend_from_slice(data);
                if cla & 0x10 != 0 {
                    return sw(0x9000);
                }
                // A new message drops a reply still being paged.
                let message = std::mem::take(&mut self.chain);
                self.pending = match proto::parse_message(&message) {
                    Ok((opcode, payload)) => {
                        let (st, body) = self.dev.handle(opcode, payload);
                        proto::message(st, &body)
                    }
                    Err(_) => proto::message(status::BAD_REQUEST, &[3]),
                };
                self.page(le)
            }
            (0x00 | 0x80, 0xC0) if !data.is_empty() || le == 0 => sw(0x6700),
            (0x00 | 0x80, 0xC0) if self.pending.is_empty() => sw(0x6985),
            (0x00 | 0x80, 0xC0) => self.page(le),
            _ => sw(0x6D00),
        }
    }
}

/// An environment whose host relays each `catcard:apdu` event to `card` and
/// answers each pairing code, through the routes a real host calls.
fn env_with_card(card: &Arc<Mutex<FakeCard>>) -> Arc<Env> {
    let env = Arc::new(env_answering(true).0);
    let (card, host_env) = (card.clone(), Arc::downgrade(&env));
    env.set_event_sink(Some(Box::new(move |ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        let Some(env) = host_env.upgrade() else { return };
        let id = ev["data"]["id"].as_str().unwrap_or_default().to_owned();
        match ev["event"].as_str() {
            Some("catcard:apdu") => {
                let apdu = unhex(ev["data"]["apdu"].as_str().unwrap()).unwrap();
                let card = card.clone();
                std::thread::spawn(move || {
                    let reply = card.lock().unwrap().transmit(&apdu);
                    run(crate::handlers::catcard::route(&env, "apduResponse", &json!({ "Id": id, "Data": hex(&reply) }))).unwrap();
                });
            }
            Some("catcard:pair") => {
                std::thread::spawn(move || {
                    run(crate::handlers::catcard::route(&env, "pairResponse", &json!({ "Id": id, "Accept": true }))).unwrap();
                });
            }
            _ => {}
        }
    })));
    env
}

#[test]
fn every_operation_runs_through_the_smart_card_reader() {
    let want = crate::walletcore::derive_addresses(MNEMONIC, "").unwrap();
    // Extended APDUs (what a phone sends), then short ones only.
    for short in [false, true] {
        let mut dev = FakeCatCard::new(MNEMONIC);
        dev.finalize = true;
        let card = Arc::new(Mutex::new(FakeCard::new(dev)));
        let env = env_with_card(&card);
        let link = json!({ "Transport": "ccid", "ShortApdu": short });
        let with = |extra: Value| {
            let mut p = link.clone();
            p.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            p
        };

        let info = run(crate::handlers::catcard::route(&env, "info", &link)).unwrap();
        assert_eq!((info["board"].as_str(), info["unlocked"].as_bool()), (Some("q1"), Some(true)));
        assert_eq!(hex(&card.lock().unwrap().seen[0]), if short { "80cc00000602000000000000" } else { "80cc00000000060200000000000000" });

        // Pairing, sharing and the import.
        let keys = run(crate::handlers::catcard::route(&env, "getKeys", &link)).unwrap();
        assert_eq!(keys["keys"][0]["address"], want.bitcoin.as_str());
        run(crate::handlers::catcard::route(&env, "import", &json!({ "Keys": keys["keys"] }))).unwrap();
        let account = |kind: &str| crate::models::account::list(&env).unwrap().into_iter().find(|a| a.kind == kind).unwrap();

        // Signing on all three chains. The Bitcoin spend's upload fills whole
        // sealed records: 1046 bytes of message, more than one APDU carries.
        let btc = account("bitcoin");
        let out = run(crate::handlers::catcard::route(&env, "signTransaction", &with(json!({ "Account": btc.id, "Transaction": btc_tx(&btc, 11), "Offline": true })))).unwrap();
        assert!(outscript::btctx::BtcTx::from_bytes(&unhex(out["raw"].as_str().unwrap()).unwrap()).unwrap().inputs.len() >= 10);
        let eth = account("ethereum");
        let out = run(crate::handlers::catcard::route(&env, "signTransaction", &with(json!({ "Account": eth.id, "Transaction": evm_tx(), "Offline": true })))).unwrap();
        assert!(crate::evm::recover_sender(&unhex(out["raw"].as_str().unwrap()).unwrap()).unwrap().eq_ignore_ascii_case(&want.evm));
        let sol = account("solana");
        let from = crate::solana::pubkey_from_b64url(&sol.pubkey).unwrap();
        let message = crate::solana::build_transfer_message(&from, &[9u8; 32], 1_000, &[3u8; 32]);
        let out = run(crate::handlers::catcard::route(&env, "signTransaction", &with(json!({ "Account": sol.id, "Transaction": { "message": bs58::encode(&message).into_string() }, "Offline": true })))).unwrap();
        let sig: [u8; 64] = bs58::decode(out["id"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();
        assert!(crate::tss::ed25519_verify(&from, &message, &sig));

        {
            let card = card.lock().unwrap();
            // One pairing served everything.
            assert_eq!(card.dev.count(&card.dev.clear_ops, op::PAIR_COMMIT), 1, "short={short} clear={:x?} sealed={:x?}", card.dev.clear_ops.borrow(), card.dev.sealed_ops.borrow());
            let chained = card.seen.iter().filter(|a| a[0] == 0x90).count();
            let paged = card.seen.iter().filter(|a| a[..2] == [0x00, 0xC0]).count();
            assert!(chained > 0, "no message was long enough to chain");
            if short {
                // A sealed result page is over 256 bytes: paged by GET RESPONSE.
                assert!(paged > 4, "{paged}");
                assert!(card.seen.iter().all(|a| a.len() <= 5 + 255 + 1));
            } else {
                // With Le = 65536 every reply fits its first response.
                assert_eq!(paged, 0);
                assert!(card.seen.iter().all(|a| a.len() <= 7 + 1030 + 2 && a.ends_with(&[0, 0])));
            }
            assert!(card.pending.is_empty() && card.chain.is_empty());
        }
        run(crate::handlers::catcard::route(&env, "disconnect", &link)).unwrap();
        env.set_event_sink(None);
    }
}

#[test]
fn a_card_that_is_not_a_catcard_is_reported() {
    // Something else in the slot: it refuses the instruction.
    let env = Arc::new(env());
    let host_env = Arc::downgrade(&env);
    env.set_event_sink(Some(Box::new(move |ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        let (Some(env), Some("catcard:apdu")) = (host_env.upgrade(), ev["event"].as_str()) else { return };
        let id = ev["data"]["id"].as_str().unwrap().to_owned();
        std::thread::spawn(move || {
            run(crate::handlers::catcard::route(&env, "apduResponse", &json!({ "Id": id, "Data": "6d00" }))).unwrap();
        });
    })));
    let err = run(crate::handlers::catcard::route(&env, "info", &json!({ "Transport": "ccid" }))).unwrap_err();
    assert_eq!(err.code, 502, "{}", err.message);
    assert!(err.message.contains("6D00"), "{}", err.message);
    env.set_event_sink(None);

    // The host reporting a failure, a malformed answer, and an unknown id.
    let host_env = Arc::downgrade(&env);
    env.set_event_sink(Some(Box::new(move |ev: &str| {
        let ev: Value = serde_json::from_str(ev).unwrap();
        let (Some(env), Some("catcard:apdu")) = (host_env.upgrade(), ev["event"].as_str()) else { return };
        let id = ev["data"]["id"].as_str().unwrap().to_owned();
        std::thread::spawn(move || {
            run(crate::handlers::catcard::route(&env, "apduResponse", &json!({ "Id": id, "Error": "no card in the slot" }))).unwrap();
        });
    })));
    let err = run(crate::handlers::catcard::route(&env, "info", &json!({ "Transport": "ccid" }))).unwrap_err();
    assert!(err.message.contains("no card in the slot"), "{}", err.message);
    env.set_event_sink(None);
    assert_eq!(run(crate::handlers::catcard::route(&env, "apduResponse", &json!({ "Id": "apdu-nope", "Data": "9000" }))).unwrap_err().code, 404);
    assert_eq!(run(crate::handlers::catcard::route(&env, "apduResponse", &json!({ "Id": "apdu-nope", "Data": "zz" }))).unwrap_err().code, 400);
    assert!(super::transport::kinds().contains(&"ccid"));
}
