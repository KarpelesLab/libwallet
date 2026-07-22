//! Address parsing and encoding across Bitcoin-family, EVM, Massa and Solana
//! networks (port of `address.go`, `eip55.go`).

use crate::base58;
use crate::bech32;
use crate::hash::{dsha256, keccak256_once};
use crate::out::Out;
use crate::pushbytes::{parse_push_bytes, push_bytes};

/// Computes the EIP-55 checksummed hex address (`0x...`) for a 20-byte address.
pub fn eip55(addr: &[u8]) -> String {
    let hexstr = hex::encode(addr);
    let a = hexstr.as_bytes();
    let hash = keccak256_once(a);
    let mut out = String::with_capacity(2 + a.len());
    out.push('0');
    out.push('x');
    for (i, &c) in a.iter().enumerate() {
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0xf
        };
        if c > b'9' && nibble > 7 {
            out.push((c - 32) as char);
        } else {
            out.push(c as char);
        }
    }
    out
}

/// Builds a base58check address from a version byte and payload.
pub fn encode_base58_addr(version: u8, buf: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + buf.len() + 4);
    data.push(version);
    data.extend_from_slice(buf);
    let h = dsha256(&data);
    data.extend_from_slice(&h[..4]);
    base58::encode(&data)
}

/// Parses an EVM (`0x...`) address.
pub fn parse_evm_address(address: &str) -> Result<Out, String> {
    if address.len() != 42 || !address.starts_with("0x") {
        return Err("EVM addresses must be 42 characters long and start with 0x".into());
    }
    let data =
        hex::decode(&address[2..]).map_err(|e| format!("failed to parse ethereum address: {e}"))?;
    if address.bytes().any(|b| b.is_ascii_uppercase()) && address != eip55(&data) {
        return Err("bad checksum on ethereum address".into());
    }
    Ok(Out::make("eth", data, &["evm"]))
}

fn p2pkh_script(hash: &[u8]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9];
    s.extend_from_slice(&push_bytes(hash));
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn p2sh_script(hash: &[u8]) -> Vec<u8> {
    let mut s = vec![0xa9];
    s.extend_from_slice(&push_bytes(hash));
    s.push(0x87);
    s
}

/// Parses a Bitcoin-family address for the given network. The special network
/// `"auto"` attempts to detect the network from the address.
pub fn parse_bitcoin_based_address(network: &str, address: &str) -> Result<Out, String> {
    // case 1: explicit bitcoincash: prefix
    if address.starts_with("bitcoincash:") {
        if network != "bitcoin-cash" && network != "auto" {
            return Err(format!(
                "bitcoincash address provided while expecting a {network} address"
            ));
        }
        let (typ, buf) = bech32::cashaddr_decode("bitcoincash:", address)
            .map_err(|e| format!("failed to parse bitcoin cash address: {e}"))?;
        return cashaddr_out(typ, &buf);
    }

    // attempt segwit bech32 decode
    if let Some(pos) = address.rfind('1')
        && pos > 0
    {
        let hrp = &address[..pos];
        if let Ok((typ, buf)) = bech32::segwit_addr_decode(hrp, address) {
            let net = match hrp {
                "ltc" => "litecoin",
                "nc" => "namecoin",
                "bc" => "bitcoin",
                "tb" => "bitcoin-testnet",
                "mona" => "monacoin",
                "ep" => "electraproto",
                _ => return Err(format!("unsupported hrp value {hrp}")),
            };
            if net != network && network != "auto" {
                return Err(format!(
                    "got a {net} address where we expected a {network} address"
                ));
            }
            if typ == 1 && (net == "bitcoin" || net == "bitcoin-testnet") && buf.len() == 32 {
                let mut script = vec![0x51];
                script.extend_from_slice(&push_bytes(&buf));
                return Ok(Out::make("p2tr", script, &[net]));
            }
            if typ != 0 {
                return Err(format!("unsupported segwit type {typ}"));
            }
            let mut script = vec![0x00];
            script.extend_from_slice(&push_bytes(&buf));
            return match buf.len() {
                20 => Ok(Out::make("p2wpkh", script, &[net])),
                32 => Ok(Out::make("p2wsh", script, &[net])),
                n => Err(format!("invalid segwit address length {n}")),
            };
        }
    }

    // base58check
    if let Ok(mut buf) = base58::decode(address)
        && buf.len() >= 5
    {
        let chk_start = buf.len() - 4;
        let chk = buf[chk_start..].to_vec();
        buf.truncate(chk_start);
        let h = dsha256(&buf);
        if h[..4] == chk[..] {
            // a standard P2PKH/P2SH payload is exactly 1 version byte + a 20-byte
            // hash; reject anything else rather than emit a non-standard script.
            if buf.len() != 21 {
                return Err(format!(
                    "invalid base58 address payload length {}",
                    buf.len()
                ));
            }
            return parse_base58_versioned(network, &buf);
        }
    }

    // bitcoincash: addr missing its prefix
    if (network == "auto" || network == "bitcoin-cash")
        && let Ok((typ, buf)) =
            bech32::cashaddr_decode("bitcoincash:", &format!("bitcoincash:{address}"))
    {
        return cashaddr_out(typ, &buf);
    }

    Err(format!("unsupported address {address}"))
}

fn cashaddr_out(typ: u8, buf: &[u8]) -> Result<Out, String> {
    match typ {
        0 => Ok(Out::make("p2pkh", p2pkh_script(buf), &["bitcoin-cash"])),
        1 => Ok(Out::make("p2sh", p2sh_script(buf), &["bitcoin-cash"])),
        n => Err(format!("unsupported bitcoincash address type {n}")),
    }
}

fn parse_base58_versioned(network: &str, buf: &[u8]) -> Result<Out, String> {
    let version = buf[0];
    let payload = &buf[1..];
    let pkh = |net: &str| Out::make("p2pkh", p2pkh_script(payload), &[net]);
    let psh = |net: &str| Out::make("p2sh", p2sh_script(payload), &[net]);
    // For auto, also attach multiple flags.
    let pkh_multi = |nets: &[&str]| Out::make("p2pkh", p2pkh_script(payload), nets);
    let psh_multi = |nets: &[&str]| Out::make("p2sh", p2sh_script(payload), nets);

    match network {
        "auto" => match version {
            0x00 => Ok(pkh_multi(&["bitcoin", "bitcoin-cash"])),
            0x05 => Ok(psh_multi(&["bitcoin", "bitcoin-cash"])),
            0x0d => Ok(psh("namecoin")),
            0x10 => Ok(psh("dash")),
            0x16 => Ok(psh("dogecoin")),
            0x1e => Ok(pkh("dogecoin")),
            0x30 => Ok(pkh("litecoin")),
            0x32 => Ok(psh("litecoin")),
            0x34 => Ok(pkh("namecoin")),
            0x37 => Ok(psh("monacoin")),
            0x4c => Ok(pkh("dash")),
            0x6f => Ok(pkh("bitcoin-testnet")),
            0x89 => Ok(psh("electraproto")),
            0xc4 => Ok(psh("bitcoin-testnet")),
            v => Err(format!("unsupported base58 address version={v:x}")),
        },
        "bitcoin" | "bitcoin-cash" => match version {
            0x00 => Ok(pkh(network)),
            0x05 => Ok(psh(network)),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "bitcoin-testnet" => match version {
            0x6f => Ok(pkh(network)),
            0xc4 => Ok(psh(network)),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "litecoin" => match version {
            0x30 => Ok(pkh("litecoin")),
            0x32 => Ok(psh("litecoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "namecoin" => match version {
            0x34 => Ok(pkh("namecoin")),
            0x0d => Ok(psh("namecoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "dogecoin" => match version {
            0x16 => Ok(psh("dogecoin")),
            0x1e => Ok(pkh("dogecoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "monacoin" => match version {
            0x32 => Ok(pkh("monacoin")),
            0x37 => Ok(psh("monacoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "electraproto" => match version {
            0x37 => Ok(pkh("electraproto")),
            0x89 => Ok(psh("electraproto")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "dash" => match version {
            0x4c => Ok(pkh("dash")),
            0x10 => Ok(psh("dash")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        _ => Err(format!("unsupported {network} network for address parsing")),
    }
}

impl Out {
    /// Returns the human-readable address for this output. Flags provide network
    /// hints when multiple addresses are possible.
    pub fn address(&self, flags: &[&str]) -> Result<String, String> {
        // combined flags = provided ++ self.flags
        let mut combined: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
        combined.extend(self.flags.iter().cloned());
        let net = combined.first().map(|s| s.as_str()).unwrap_or("");

        match self.base_name() {
            "solana" => Ok(base58::encode(&self.raw)),
            "cardano" => crate::cardano::cardano_address_from_out(&self.raw, net),
            "eth" | "evm" => Ok(eip55(&self.raw)),
            "massa_pubkey" => {
                let h = dsha256(&self.raw);
                let mut b = self.raw.clone();
                b.extend_from_slice(&h[..4]);
                Ok(format!("P{}", base58::encode(&b)))
            }
            "massa" => {
                let typ = self.raw[0];
                let mut b = self.raw[1..].to_vec();
                let h = dsha256(&b);
                b.extend_from_slice(&h[..4]);
                match typ {
                    0 => Ok(format!("AU{}", base58::encode(&b))),
                    1 => Ok(format!("AS{}", base58::encode(&b))),
                    n => Err(format!("unsupported value for massa address type: {n}")),
                }
            }
            "p2pkh" | "p2pukh" => {
                let inner = &self.raw[2..self.raw.len() - 2];
                let (buf, _) = parse_push_bytes(inner).ok_or("invalid script for address type")?;
                match net {
                    "bitcoin-cash" | "bitcoincash" => {
                        bech32::cashaddr_encode("bitcoincash:", 0, buf).map_err(|e| e.to_string())
                    }
                    "litecoin" => Ok(encode_base58_addr(0x30, buf)),
                    "namecoin" => Ok(encode_base58_addr(0x34, buf)),
                    "dogecoin" => Ok(encode_base58_addr(0x1e, buf)),
                    "monacoin" => Ok(encode_base58_addr(0x32, buf)),
                    "electraproto" => Ok(encode_base58_addr(0x37, buf)),
                    "dash" => Ok(encode_base58_addr(0x4c, buf)),
                    "bitcoin-testnet" => Ok(encode_base58_addr(0x6f, buf)),
                    "bitcoin" => Ok(encode_base58_addr(0x00, buf)),
                    other => Err(format!("unsupported network {other:?} for p2pkh address")),
                }
            }
            "p2sh" => {
                let inner = &self.raw[1..self.raw.len() - 1];
                let (buf, _) = parse_push_bytes(inner).ok_or("invalid script for address type")?;
                match net {
                    "bitcoin-cash" | "bitcoincash" => {
                        bech32::cashaddr_encode("bitcoincash:", 1, buf).map_err(|e| e.to_string())
                    }
                    "litecoin" => Ok(encode_base58_addr(0x32, buf)),
                    "namecoin" => Ok(encode_base58_addr(0x0d, buf)),
                    "dogecoin" => Ok(encode_base58_addr(0x16, buf)),
                    "monacoin" => Ok(encode_base58_addr(0x37, buf)),
                    "electraproto" => Ok(encode_base58_addr(0x89, buf)),
                    "dash" => Ok(encode_base58_addr(0x10, buf)),
                    "bitcoin-testnet" => Ok(encode_base58_addr(0xc4, buf)),
                    "bitcoin" => Ok(encode_base58_addr(0x05, buf)),
                    other => Err(format!("unsupported network {other:?} for p2sh address")),
                }
            }
            "p2wpkh" | "p2wsh" => {
                let (buf, _) =
                    parse_push_bytes(&self.raw[1..]).ok_or("invalid script for address type")?;
                let hrp = match net {
                    "litecoin" => "ltc",
                    "namecoin" => "nc",
                    "bitcoin" => "bc",
                    "bitcoin-testnet" => "tb",
                    "monacoin" => "mona",
                    "electraproto" => "ep",
                    _ => {
                        return Err(format!(
                            "could not transform outscript of format {}",
                            self.name
                        ));
                    }
                };
                bech32::segwit_addr_encode(hrp, 0, buf).map_err(|e| e.to_string())
            }
            "p2tr" => {
                let (buf, _) =
                    parse_push_bytes(&self.raw[1..]).ok_or("invalid script for address type")?;
                let hrp = match net {
                    "bitcoin" => "bc",
                    "bitcoin-testnet" => "tb",
                    _ => {
                        return Err(format!(
                            "could not transform outscript of format {}",
                            self.name
                        ));
                    }
                };
                bech32::segwit_addr_encode(hrp, 1, buf).map_err(|e| e.to_string())
            }
            _ => Err(format!(
                "could not transform outscript of format {}",
                self.name
            )),
        }
    }
}
