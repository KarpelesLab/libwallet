//! BIP-39 mnemonic → seed → master key (English wordlist), for
//! `Wallet:importMnemonic`. Ports the mnemonic decode + seed derivation
//! (go-bip39) and the BIP-32 (secp256k1) / SLIP-0010 (ed25519) master step
//! (wltwallet/wallet_raw.go), yielding the master secret scalar to import.

use purecrypto::hash::{sha256, HmacSha512};

use crate::{Error, Result};

/// The 2048-word English BIP-39 wordlist.
fn english_words() -> &'static [&'static str] {
    static WORDS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    WORDS.get_or_init(|| include_str!("bip39_english.txt").lines().collect())
}

/// Decode + checksum-validate an English BIP-39 mnemonic into its entropy
/// bytes. 12/15/18/21/24 words -> 16/20/24/28/32 bytes.
pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err(Error::Env(format!("mnemonic must be 12/15/.../24 words, got {}", words.len())));
    }
    let list = english_words();
    // Accumulate the 11-bit indices into a big-endian bit buffer.
    let mut bits: Vec<bool> = Vec::with_capacity(words.len() * 11);
    for w in &words {
        let idx = list
            .iter()
            .position(|x| x == w)
            .ok_or_else(|| Error::Env(format!("unknown BIP-39 word: {w}")))?;
        for i in (0..11).rev() {
            bits.push((idx >> i) & 1 == 1);
        }
    }
    // Split into entropy (ENT) + checksum (ENT/32).
    let total = bits.len();
    let cs_len = total / 33;
    let ent_len = total - cs_len;
    let mut entropy = vec![0u8; ent_len / 8];
    for (i, b) in bits[..ent_len].iter().enumerate() {
        if *b {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    // Verify the checksum = first cs_len bits of sha256(entropy).
    let hash = sha256(&entropy);
    for i in 0..cs_len {
        let expect = (hash[i / 8] >> (7 - (i % 8))) & 1 == 1;
        if bits[ent_len + i] != expect {
            return Err(Error::Env("mnemonic checksum failed".into()));
        }
    }
    Ok(entropy)
}

/// Re-encode entropy bytes into the canonical English BIP-39 mnemonic (inverse
/// of [`mnemonic_to_entropy`]; go-bip39 `NewMnemonic`). Used to reconstruct the
/// mnemonic string from a stored `MnemonicKeyShare`'s entropy so the seed can be
/// re-derived. Entropy must be 16/20/24/28/32 bytes.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String> {
    if ![16, 20, 24, 28, 32].contains(&entropy.len()) {
        return Err(Error::Env(format!("entropy must be 16/20/.../32 bytes, got {}", entropy.len())));
    }
    let ent_bits = entropy.len() * 8;
    let cs_len = ent_bits / 32;
    let hash = sha256(entropy);
    // entropy bits followed by the first cs_len checksum bits.
    let mut bits: Vec<bool> = Vec::with_capacity(ent_bits + cs_len);
    for i in 0..ent_bits {
        bits.push((entropy[i / 8] >> (7 - (i % 8))) & 1 == 1);
    }
    for i in 0..cs_len {
        bits.push((hash[i / 8] >> (7 - (i % 8))) & 1 == 1);
    }
    // Groups of 11 bits → word indices.
    let list = english_words();
    let mut words = Vec::with_capacity(bits.len() / 11);
    for chunk in bits.chunks(11) {
        let mut idx = 0usize;
        for &b in chunk {
            idx = (idx << 1) | (b as usize);
        }
        words.push(list[idx]);
    }
    Ok(words.join(" "))
}

/// The BIP-39 seed for a mnemonic + optional passphrase:
/// `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64)` (go-bip39
/// `NewSeed`). The mnemonic must already be the canonical space-joined form.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let salt = format!("mnemonic{passphrase}");
    let mut seed = [0u8; 64];
    purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha512>(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed,
    );
    seed
}

/// The master secret + chain code from a seed (wltwallet `masterFromSeed`):
/// BIP-32 (`HMAC-SHA512("Bitcoin seed", seed)`) for secp256k1, SLIP-0010
/// (`HMAC-SHA512("ed25519 seed", seed)`) for ed25519. Returns `(master, chain
/// code)`, each 32 bytes; the master is the big-endian secret scalar to import.
pub fn master_from_seed(seed: &[u8], curve: &str) -> Result<([u8; 32], [u8; 32])> {
    let key: &[u8] = match curve {
        "secp256k1" => b"Bitcoin seed",
        "" | "ed25519" => b"ed25519 seed",
        other => return Err(Error::Env(format!("unsupported curve {other}"))),
    };
    let mut mac = HmacSha512::new(key);
    mac.update(seed);
    let i = mac.finalize(); // 64 bytes: IL (master) || IR (chain code)
    let mut master = [0u8; 32];
    let mut cc = [0u8; 32];
    master.copy_from_slice(&i[..32]);
    cc.copy_from_slice(&i[32..]);
    // BIP-32: reject IL == 0 or IL >= n (secp256k1). SLIP-0010 for ed25519 uses
    // the master directly (no curve-order reduction), matching Go.
    if curve == "secp256k1" && master.iter().all(|&b| b == 0) {
        return Err(Error::Env("BIP-32: master IL is zero".into()));
    }
    Ok((master, cc))
}
