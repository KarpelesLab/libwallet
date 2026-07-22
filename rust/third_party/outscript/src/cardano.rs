//! Cardano (Shelley-era) addresses: enterprise, base and reward addresses for
//! mainnet and testnet, plus the blake2b-224 key credentials they encode.
//!
//! A Shelley address is a 1-byte header followed by one or two 28-byte
//! credentials. The header's high 4 bits select the address type and its low 4
//! bits carry the network id (0 = testnet, 1 = mainnet). Key credentials are the
//! blake2b-224 hash of the raw 32-byte Ed25519 public key. The whole payload is
//! Bech32-encoded (BIP-173, not Bech32m).
//!
//! See CIP-19 (<https://cips.cardano.org/cip/CIP-19>) for the binary format.
//!
//! Port of `cardano.go`.

use crate::hash::blake2b224;
use crate::out::Out;

// Address type nibbles (high 4 bits of the header byte).
const TYPE_BASE: u8 = 0x0; // payment key hash + stake key hash
const TYPE_ENTERPRISE: u8 = 0x6; // payment key hash only
const TYPE_REWARD: u8 = 0xe; // stake key hash only (reward/account address)

// Network ids (low 4 bits of the header byte).
const NET_TESTNET: u8 = 0x0;
const NET_MAINNET: u8 = 0x1;

/// Returns the 28-byte blake2b-224 credential for an Ed25519 public key, as used
/// in Cardano payment and stake credentials.
pub fn cardano_key_hash(pubkey: &[u8]) -> [u8; 28] {
    blake2b224(pubkey)
}

/// Maps a network flag to its network id nibble.
fn cardano_network(network: &str) -> Result<u8, String> {
    match network {
        "" | "cardano" | "cardano-mainnet" | "mainnet" => Ok(NET_MAINNET),
        "cardano-testnet" | "testnet" => Ok(NET_TESTNET),
        other => Err(format!("unsupported cardano network {other:?}")),
    }
}

/// Returns the Bech32 human-readable prefix for an address type nibble and
/// network id.
fn cardano_hrp(typ: u8, net: u8) -> String {
    let mut hrp = if typ == TYPE_REWARD { "stake" } else { "addr" }.to_string();
    if net == NET_TESTNET {
        hrp.push_str("_test");
    }
    hrp
}

/// Bech32-encodes a full address payload (header byte followed by credentials).
/// The header byte determines the human-readable prefix.
fn cardano_encode_address(payload: &[u8]) -> Result<String, String> {
    if payload.is_empty() {
        return Err("empty cardano address payload".into());
    }
    let hrp = cardano_hrp(payload[0] >> 4, payload[0] & 0x0f);
    let data = convert_bits(payload, 8, 5, true).ok_or("invalid bit conversion")?;
    Ok(bech32_encode(&hrp, &data))
}

/// Builds a type-6 enterprise address (payment credential only) from a 28-byte
/// payment key hash.
pub fn cardano_enterprise_address(
    payment_key_hash: &[u8],
    network: &str,
) -> Result<String, String> {
    if payment_key_hash.len() != 28 {
        return Err(format!(
            "cardano payment key hash must be 28 bytes, got {}",
            payment_key_hash.len()
        ));
    }
    let net = cardano_network(network)?;
    let header = (TYPE_ENTERPRISE << 4) | net;
    let mut payload = Vec::with_capacity(29);
    payload.push(header);
    payload.extend_from_slice(payment_key_hash);
    cardano_encode_address(&payload)
}

/// Builds a type-0 base address (payment credential + stake credential) from two
/// 28-byte key hashes.
pub fn cardano_base_address(
    payment_key_hash: &[u8],
    stake_key_hash: &[u8],
    network: &str,
) -> Result<String, String> {
    if payment_key_hash.len() != 28 {
        return Err(format!(
            "cardano payment key hash must be 28 bytes, got {}",
            payment_key_hash.len()
        ));
    }
    if stake_key_hash.len() != 28 {
        return Err(format!(
            "cardano stake key hash must be 28 bytes, got {}",
            stake_key_hash.len()
        ));
    }
    let net = cardano_network(network)?;
    let header = (TYPE_BASE << 4) | net;
    let mut payload = Vec::with_capacity(57);
    payload.push(header);
    payload.extend_from_slice(payment_key_hash);
    payload.extend_from_slice(stake_key_hash);
    cardano_encode_address(&payload)
}

/// Builds a type-14 reward (stake/account) address from a 28-byte stake key
/// hash.
pub fn cardano_reward_address(stake_key_hash: &[u8], network: &str) -> Result<String, String> {
    if stake_key_hash.len() != 28 {
        return Err(format!(
            "cardano stake key hash must be 28 bytes, got {}",
            stake_key_hash.len()
        ));
    }
    let net = cardano_network(network)?;
    let header = (TYPE_REWARD << 4) | net;
    let mut payload = Vec::with_capacity(29);
    payload.push(header);
    payload.extend_from_slice(stake_key_hash);
    cardano_encode_address(&payload)
}

/// Parses a Bech32-encoded Cardano Shelley address (`addr…`, `addr_test…`,
/// `stake…`, `stake_test…`) and returns the corresponding [`Out`]. The raw
/// payload (header byte followed by credentials) is preserved so the address can
/// be re-encoded via [`Out::address`].
pub fn parse_cardano_address(address: &str) -> Result<Out, String> {
    let (hrp, data) =
        bech32_decode(address).map_err(|e| format!("failed to decode cardano address: {e}"))?;
    match hrp.as_str() {
        "addr" | "addr_test" | "stake" | "stake_test" => {}
        other => return Err(format!("unsupported cardano address prefix {other:?}")),
    }
    let payload =
        convert_bits(&data, 5, 8, false).ok_or("failed to decode cardano address payload")?;
    if payload.is_empty() {
        return Err("empty cardano address payload".into());
    }

    let header = payload[0];
    let typ = header >> 4;
    let net = header & 0x0f;
    if net != NET_MAINNET && net != NET_TESTNET {
        return Err(format!("unsupported cardano network id {net}"));
    }

    let want_len = match typ {
        TYPE_BASE => 1 + 28 + 28,
        TYPE_ENTERPRISE | TYPE_REWARD => 1 + 28,
        _ => return Err(format!("unsupported cardano address type {typ}")),
    };
    if payload.len() != want_len {
        return Err(format!(
            "invalid cardano address length {} for type {typ}",
            payload.len()
        ));
    }

    // Cross-check that the human-readable prefix agrees with the header byte, so a
    // checksum-valid address can't claim a different network/kind than its HRP.
    // "stake"/"stake_test" must wrap a reward address; "addr"/"addr_test" must
    // wrap a payment (base/enterprise) address. The "_test" suffix must match the
    // testnet network id and its absence the mainnet id.
    let hrp_is_stake = hrp == "stake" || hrp == "stake_test";
    if hrp_is_stake != (typ == TYPE_REWARD) {
        return Err(format!(
            "cardano address prefix {hrp:?} does not match header type {typ}"
        ));
    }
    let want_net = if hrp.ends_with("_test") {
        NET_TESTNET
    } else {
        NET_MAINNET
    };
    if net != want_net {
        return Err(format!(
            "cardano address prefix {hrp:?} does not match header network id {net}"
        ));
    }

    let flag = if net == NET_TESTNET {
        "cardano-testnet"
    } else {
        "cardano"
    };
    Ok(Out::make("cardano", payload, &[flag]))
}

/// Renders a Cardano address for a parsed or generated [`Out`] whose raw payload
/// is "header byte + credentials". The network flag overrides the header's
/// network nibble so the same `Out` can produce mainnet or testnet forms.
pub fn cardano_address_from_out(raw: &[u8], network: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("empty cardano out".into());
    }
    let net = cardano_network(network)?;
    let mut payload = raw.to_vec();
    payload[0] = (payload[0] & 0xf0) | net;
    cardano_encode_address(&payload)
}

// ----- Bech32 (BIP-173) -----
//
// A self-contained Bech32 codec. Unlike the shared `bech32` module, this has no
// 90-character limit, which Cardano base addresses (per CIP-19) routinely
// exceed.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    for &c in bytes {
        out.push(c >> 5);
    }
    out.push(0);
    for &c in bytes {
        out.push(c & 0x1f);
    }
    out
}

fn bech32_create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = bech32_polymod(&values) ^ 1;
    (0..6)
        .map(|i| ((polymod >> (5 * (5 - i))) & 0x1f) as u8)
        .collect()
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let checksum = bech32_create_checksum(hrp, data);
    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &b in data.iter().chain(checksum.iter()) {
        s.push(CHARSET[b as usize] as char);
    }
    s
}

fn bech32_decode(s: &str) -> Result<(String, Vec<u8>), String> {
    let lower = s.to_ascii_lowercase();
    let upper = s.to_ascii_uppercase();
    if s != lower && s != upper {
        return Err("bech32 string must not be mixed-case".into());
    }
    let s = lower;
    let pos = s.rfind('1').ok_or("invalid bech32 separator position")?;
    if pos < 1 || pos + 7 > s.len() {
        return Err("invalid bech32 separator position".into());
    }
    let hrp = s[..pos].to_string();
    let mut data = Vec::with_capacity(s.len() - pos - 1);
    for c in s[pos + 1..].bytes() {
        match CHARSET.iter().position(|&x| x == c) {
            Some(idx) => data.push(idx as u8),
            None => return Err(format!("invalid bech32 character {:?}", c as char)),
        }
    }
    let mut values = bech32_hrp_expand(&hrp);
    values.extend_from_slice(&data);
    if bech32_polymod(&values) != 1 {
        return Err("invalid bech32 checksum".into());
    }
    let len = data.len() - 6;
    data.truncate(len);
    Ok((hrp, data))
}

/// Regroups data between bit widths (8↔5) for Bech32, following the reference
/// convertbits routine from BIP-173.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &value in data {
        let v = value as u32;
        if (v >> from) != 0 {
            return None;
        }
        acc = ((acc << from) | v) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}
