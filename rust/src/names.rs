//! Name resolution (port of wltnames). ENS (Ethereum) resolves a name to an
//! address via two eth_call hops: registry.resolver(namehash) then
//! resolver.addr(namehash). Uses the blocking RPC client.

use purecrypto::hash::keccak256;
use serde_json::json;

use crate::{Error, Result};

/// The canonical ENS registry on Ethereum mainnet.
const ENS_REGISTRY: &str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
/// `resolver(bytes32)` selector.
const SEL_RESOLVER: [u8; 4] = [0x01, 0x78, 0xb8, 0xbf];
/// `addr(bytes32)` selector.
const SEL_ADDR: [u8; 4] = [0x3b, 0x3b, 0x57, 0xde];

/// Unicode format characters (general category Cf) and variation selectors:
/// invisible, so a name carrying one renders like another name while hashing
/// to a different node. Listed by hand — no category tables in this crate.
fn is_invisible_format_char(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD                  // soft hyphen
        | 0x034F                // combining grapheme joiner
        | 0x0600..=0x0605
        | 0x061C                // arabic letter mark
        | 0x06DD
        | 0x070F
        | 0x0890..=0x0891
        | 0x08E2
        | 0x115F..=0x1160       // hangul fillers
        | 0x17B4..=0x17B5
        | 0x180B..=0x180F       // mongolian selectors / vowel separator
        | 0x200B..=0x200F       // zero width space/joiners, LRM/RLM
        | 0x202A..=0x202E       // bidi embeddings/overrides
        | 0x2060..=0x206F       // word joiner, invisible operators, bidi isolates
        | 0x3164                // hangul filler
        | 0xFE00..=0xFE0F       // variation selectors
        | 0xFEFF                // BOM / zero width no-break space
        | 0xFFA0                // halfwidth hangul filler
        | 0xFFF9..=0xFFFB       // interlinear annotation
        | 0x110BD
        | 0x110CD
        | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A
        | 0xE0000..=0xE0FFF     // tags, variation selectors supplement
    )
}

/// Normalize an ENS name before hashing — a conservative interim for ENSIP-15,
/// whose full mapping/validity tables this crate does not carry.
///
/// The name is trimmed, NFC-normalized and lowercased. It is then REFUSED
/// (rather than hashed as typed) when a label is empty or holds whitespace, a
/// control character, an invisible format character or variation selector
/// (zero-width joiners, bidi controls, BOM…), a character that is still
/// uppercase after case folding, or a compatibility form (fullwidth letters,
/// ligatures, alternative full stops — anything NFKC would rewrite). Those are
/// exactly the inputs where hashing the raw string yields a different node
/// than the name the user reads, i.e. somebody else's registration.
///
/// What comes back is the string that gets hashed. Plain ASCII and ordinary
/// Unicode names pass unchanged apart from case; some names valid under
/// ENSIP-15 (emoji sequences that need a ZWJ or U+FE0F) are refused.
pub fn normalize_ens_name(name: &str) -> Result<String> {
    use unicode_normalization::UnicodeNormalization;
    let bad = |why: &str| Error::Env(format!("unsupported ENS name {name:?}: {why}"));

    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(bad("empty name"));
    }
    let folded: String = trimmed.nfc().collect::<String>().to_lowercase().nfc().collect();
    // Folding must be a fixed point, or the hash would depend on how many
    // times the name went through it.
    if folded.to_lowercase().nfc().collect::<String>() != folded {
        return Err(bad("unstable under case folding"));
    }
    if !folded.nfkc().eq(folded.chars()) {
        return Err(bad("contains a compatibility character (fullwidth, ligature or similar)"));
    }
    for label in folded.split('.') {
        if label.is_empty() {
            return Err(bad("empty label"));
        }
        for c in label.chars() {
            if c.is_whitespace() {
                return Err(bad("contains whitespace"));
            }
            if c.is_control() {
                return Err(bad("contains a control character"));
            }
            if is_invisible_format_char(c) {
                return Err(bad("contains an invisible format character"));
            }
            if c.is_uppercase() {
                return Err(bad("contains a character with no lowercase form"));
            }
            // Full stops other than '.' (ideographic and its variants).
            if matches!(c, '\u{3002}' | '\u{FF0E}' | '\u{FF61}' | '\u{2024}') {
                return Err(bad("contains an alternative full stop"));
            }
        }
    }
    Ok(folded)
}

/// EIP-137 namehash of a domain, hashing `name` exactly as given: callers
/// normalize first ([`normalize_ens_name`]; [`resolve_ens`] does).
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if !name.is_empty() {
        for label in name.split('.').rev() {
            let label_hash = keccak256(label.as_bytes());
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&node);
            buf[32..].copy_from_slice(&label_hash);
            node = keccak256(&buf);
        }
    }
    node
}

/// Resolve an ENS name to a lowercase 0x-address, or an error if unregistered.
/// The name is normalized first ([`normalize_ens_name`]) and refused when that
/// fails, so the node looked up is always the one for the name as displayed.
pub fn resolve_ens(rpc_url: &str, name: &str) -> Result<String> {
    let name = &normalize_ens_name(name)?;
    let node = namehash(name);

    // registry.resolver(node) -> resolver address (last 20 bytes of the return).
    let resolver_ret = eth_call(rpc_url, ENS_REGISTRY, &SEL_RESOLVER, &node)?;
    let resolver = addr_from_word(&resolver_ret)?;
    if resolver.iter().all(|&b| b == 0) {
        return Err(Error::Env(format!("no resolver for {name}")));
    }
    let resolver_hex = format!("0x{}", hex(&resolver));

    // resolver.addr(node) -> the resolved address.
    let addr_ret = eth_call(rpc_url, &resolver_hex, &SEL_ADDR, &node)?;
    let addr = addr_from_word(&addr_ret)?;
    if addr.iter().all(|&b| b == 0) {
        return Err(Error::Env(format!("{name} has no address record")));
    }
    Ok(format!("0x{}", hex(&addr)))
}

fn eth_call(url: &str, to: &str, selector: &[u8; 4], node: &[u8; 32]) -> Result<Vec<u8>> {
    let mut data = selector.to_vec();
    data.extend_from_slice(node);
    let res = crate::rpc::call(url, "eth_call", json!([{ "to": to, "data": format!("0x{}", hex(&data)) }, "latest"]))?;
    let s = res.as_str().ok_or_else(|| Error::Env("eth_call result not a string".into()))?;
    hex_decode(s.strip_prefix("0x").unwrap_or(s))
}

/// The 20-byte address in the low bytes of a 32-byte ABI word.
fn addr_from_word(word: &[u8]) -> Result<[u8; 20]> {
    if word.len() < 32 {
        return Err(Error::Env("ABI word shorter than 32 bytes".into()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&word[12..32]);
    Ok(a)
}

// --- SNS (Solana Name Service) --------------------------------------------

const SNS_PROGRAM: &str = "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX";
const SNS_PARENT: &str = "58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx";
const SNS_PREFIX: &str = "SPL Name Service";

fn sha256(data: &[u8]) -> [u8; 32] {
    purecrypto::hash::sha256(data)
}

/// True if `bytes` decompresses to a valid Ed25519 point (i.e. is on-curve, so
/// not a valid PDA).
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    purecrypto::ec::edwards25519::hazmat::EdwardsPoint::decompress(bytes).is_some()
}

fn b58_32(s: &str) -> Result<[u8; 32]> {
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Env(format!("bad base58 32-byte value: {s}")))
}

/// Solana findProgramAddress over seeds `[name_hash, class(0), parent]`: try
/// bumps 255..0, returning the first off-curve candidate (matching Go
/// createProgramAddress).
fn create_program_address(name_hash: &[u8; 32], parent: &[u8; 32], program: &[u8; 32]) -> Result<[u8; 32]> {
    let class = [0u8; 32];
    let mut seed = Vec::with_capacity(96);
    seed.extend_from_slice(name_hash);
    seed.extend_from_slice(&class);
    seed.extend_from_slice(parent);
    for bump in (0u16..=255).rev() {
        let mut h = seed.clone();
        h.push(bump as u8);
        h.extend_from_slice(program);
        h.extend_from_slice(b"ProgramDerivedAddress");
        let pda = sha256(&h);
        if !is_on_curve(&pda) {
            return Ok(pda);
        }
    }
    Err(Error::Env("unable to derive PDA".into()))
}

/// Resolve a Solana `.sol` name to its owner address (base58), via the SNS
/// domain PDA + getAccountInfo. Port of Go ResolveSNS.
pub fn resolve_sns(rpc_url: &str, name: &str) -> Result<String> {
    let name = name.trim().to_lowercase();
    let label = name.strip_suffix(".sol").ok_or_else(|| Error::Env("SNS names must end with .sol".into()))?;
    if label.is_empty() || label.contains('.') {
        return Err(Error::Env("SNS supports single-label .sol names only".into()));
    }

    let name_hash = sha256(format!("{SNS_PREFIX}{label}").as_bytes());
    let parent = b58_32(SNS_PARENT)?;
    let program = b58_32(SNS_PROGRAM)?;
    let domain = create_program_address(&name_hash, &parent, &program)?;
    let domain_b58 = bs58::encode(&domain).into_string();

    let res = crate::rpc::call(
        rpc_url,
        "getAccountInfo",
        json!([domain_b58, { "encoding": "base64" }]),
    )?;
    // The account at the domain address must belong to the name program: any
    // other program can write whatever "owner" it likes into its own data.
    if let Some(program_owner) = res.get("value").and_then(|v| v.get("owner")).filter(|o| !o.is_null()) {
        if program_owner.as_str() != Some(SNS_PROGRAM) {
            return Err(Error::Env("SNS domain account is not owned by the name service program".into()));
        }
    }
    let data_b64 = res
        .get("value")
        .and_then(|v| v.get("data"))
        .and_then(|d| d.get(0))
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::Env("SNS domain not found".into()))?;
    let data = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| Error::Env(format!("bad account data: {e}")))?
    };
    if data.len() < 96 {
        return Err(Error::Env(format!("SNS record too short ({} bytes)", data.len())));
    }
    // NameRecordHeader: parent(32) | owner(32) | class(32) | data.
    if data[0..32] != parent {
        return Err(Error::Env("SNS record parent mismatch".into()));
    }
    let owner: [u8; 32] = data[32..64].try_into().map_err(|_| Error::Env("SNS record too short".into()))?;
    if owner.iter().all(|&b| b == 0) {
        return Err(Error::Env("SNS name resolves to zero owner".into()));
    }
    // An off-curve owner is a program-derived account (a tokenized domain is
    // held by the NFT program's PDA, not by its holder): nobody has a key for
    // it, so funds sent there would not reach whoever the name stands for.
    if !is_on_curve(&owner) {
        return Err(Error::Env(
            "SNS name is owned by a program account (e.g. a tokenized domain), not a wallet; cannot resolve it to an address".into(),
        ));
    }
    Ok(bs58::encode(owner).into_string())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod sns_tests {
    use super::*;
    use base64::Engine;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn program_address_is_deterministic_and_off_curve() {
        let nh = sha256(b"SPL Name Servicebonfida");
        let parent = b58_32(SNS_PARENT).unwrap();
        let program = b58_32(SNS_PROGRAM).unwrap();
        let a = create_program_address(&nh, &parent, &program).unwrap();
        let b = create_program_address(&nh, &parent, &program).unwrap();
        assert_eq!(a, b);
        assert!(!is_on_curve(&a), "PDA must be off-curve");
    }

    fn mock(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}/")
    }

    /// A mock node answering getAccountInfo with a name record held by `owner`,
    /// the account itself owned by `program` (omitted from the reply if None).
    fn mock_record(owner: &[u8; 32], program: Option<&str>) -> String {
        let parent = b58_32(SNS_PARENT).unwrap();
        // NameRecordHeader: parent | owner | class(0).
        let mut record = Vec::new();
        record.extend_from_slice(&parent);
        record.extend_from_slice(owner);
        record.extend_from_slice(&[0u8; 32]);
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&record);
        let program = program.map(|p| format!(r#","owner":"{p}""#)).unwrap_or_default();
        mock(format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"value":{{"data":["{data_b64}","base64"]{program}}}}}}}"#
        ))
    }

    /// The first `sha256(counter)` that is / is not a valid Ed25519 point.
    fn key_with_curve(on_curve: bool) -> [u8; 32] {
        (0u8..=255).map(|i| sha256(&[i])).find(|k| is_on_curve(k) == on_curve).unwrap()
    }

    #[test]
    fn resolve_sns_returns_owner() {
        let owner = key_with_curve(true);
        let got = resolve_sns(&mock_record(&owner, Some(SNS_PROGRAM)), "example.sol").unwrap();
        assert_eq!(got, bs58::encode(&owner).into_string());
        // A reply without the owning program still resolves (nothing to check).
        let got = resolve_sns(&mock_record(&owner, None), "example.sol").unwrap();
        assert_eq!(got, bs58::encode(&owner).into_string());
    }

    #[test]
    fn resolve_sns_rejects_program_owned_names() {
        // Tokenized domain: the registry owner is a PDA nobody can sign for.
        let pda = key_with_curve(false);
        let err = resolve_sns(&mock_record(&pda, Some(SNS_PROGRAM)), "example.sol").unwrap_err();
        assert!(err.to_string().contains("program account"), "{err}");
        assert!(resolve_sns(&mock_record(&pda, None), "example.sol").is_err());
    }

    #[test]
    fn resolve_sns_rejects_account_of_another_program() {
        let owner = key_with_curve(true);
        let system = "11111111111111111111111111111111";
        let err = resolve_sns(&mock_record(&owner, Some(system)), "example.sol").unwrap_err();
        assert!(err.to_string().contains("name service program"), "{err}");
        let token = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        assert!(resolve_sns(&mock_record(&owner, Some(token)), "example.sol").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_ascii_without_panicking() {
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(hex_decode("AbCd").unwrap(), vec![0xab, 0xcd]);
        assert!(hex_decode("aé1").is_err()); // 4 bytes, char boundary inside a pair
        assert!(hex_decode("éé").is_err());
        assert!(hex_decode("+1").is_err());
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn resolve_sns_rejects_non_sol() {
        assert!(resolve_sns("http://unused", "foo.eth").is_err());
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    // `s` is a node reply: check it is hex digits before slicing by byte offset
    // (a multi-byte character would panic on a char boundary).
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(Error::Env("odd-length hex".into()));
    }
    if !b.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Env("invalid hex".into()));
    }
    Ok(b.chunks_exact(2)
        .map(|pair| {
            let nibble = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
            nibble(pair[0]) << 4 | nibble(pair[1])
        })
        .collect())
}
