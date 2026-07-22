# outscript

[![CI](https://github.com/KarpelesLab/outscript-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/outscript-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/outscript.svg)](https://crates.io/crates/outscript)
[![docs.rs](https://img.shields.io/docsrs/outscript)](https://docs.rs/outscript)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust crate for generating output scripts, parsing/encoding addresses, and
building/signing transactions across multiple cryptocurrency networks.

This is a Rust port of the Go library
[`github.com/KarpelesLab/outscript`](https://github.com/KarpelesLab/outscript).
All cryptography is provided by the pure-Rust
[`purecrypto`](https://crates.io/crates/purecrypto) crate.

## Supported Networks

| Network | Address Formats | Transactions |
|---------|----------------|--------------|
| Bitcoin | p2pkh, p2pk, p2wpkh, p2sh:p2wpkh, p2wsh, p2tr | `BtcTx` |
| Bitcoin Cash | p2pkh, p2pk (CashAddr) | `BtcTx` |
| Litecoin | p2pkh, p2pk, p2wpkh, p2sh:p2wpkh | `BtcTx` |
| Dogecoin | p2pkh, p2pk | `BtcTx` |
| Namecoin | p2pkh, p2sh | `BtcTx` |
| Monacoin | p2pkh, p2sh, p2wpkh | `BtcTx` |
| Dash | p2pkh, p2sh | `BtcTx` |
| Electraproto | p2pkh, p2sh, p2wpkh | `BtcTx` |
| EVM (Ethereum, etc.) | EIP-55 checksummed | `EvmTx` |
| Massa | AU (user) / AS (smart contract) | - |
| Solana | Base58 (32 bytes) | `SolanaTx` |
| Cardano | Shelley bech32 (addr / addr_test / stake) | `CardanoTx` |

## Usage

### Address generation

```rust
use outscript::Script;
use outscript::crypto::secp256k1::SecpPrivateKey;
use outscript::crypto::ed25519;
use outscript::PubKey;

// Bitcoin / EVM (secp256k1)
let key = SecpPrivateKey::from_bytes(&seed).unwrap();
let s = Script::new(key.public_key());
let addr = s.address("p2wpkh", &["bitcoin"]).unwrap(); // bc1q...
let eth  = s.address("eth", &[]).unwrap();              // 0x...

// Solana / Massa (ed25519)
let pk = ed25519::public_from_seed(&seed);
let s = Script::new(PubKey::Ed25519(pk));
let sol = s.address("solana", &["solana"]).unwrap();    // base58

// Cardano (ed25519). "cardano" yields a Shelley enterprise address (payment
// credential only); pass "cardano-testnet" for the testnet form.
let addr = s.address("cardano", &[]).unwrap();                  // addr1...
let test = s.address("cardano", &["cardano-testnet"]).unwrap(); // addr_test1...

// Base (payment+stake) and reward addresses need two key hashes:
use outscript::{cardano_base_address, cardano_reward_address, cardano_key_hash};
let ph = cardano_key_hash(&payment_pub);
let sh = cardano_key_hash(&stake_pub);
let base   = cardano_base_address(&ph, &sh, "cardano").unwrap();  // addr1...
let reward = cardano_reward_address(&sh, "cardano").unwrap();     // stake1...
```

### Address parsing

```rust
use outscript::{parse_bitcoin_based_address, parse_evm_address, parse_solana_address, parse_massa_address};

let out = parse_bitcoin_based_address("auto", "1A1zP1...").unwrap(); // auto-detect
let out = parse_evm_address("0x2AeB8ADD...").unwrap();
let out = parse_solana_address("83astBRgu...").unwrap();
let out = parse_massa_address("AU16f3K8u...").unwrap();

// Cardano (addr / addr_test / stake / stake_test)
use outscript::parse_cardano_address;
let out = parse_cardano_address("addr1vx2fxv2umyhttkxyxp8...").unwrap();
let raw = out.bytes(); // raw address bytes (header + credentials), for a tx output
```

### Bitcoin transactions

```rust
use outscript::{BtcTx, BtcTxSign};

let mut tx = BtcTx::from_bytes(&raw).unwrap();
tx.sign(&[
    BtcTxSign::new(&key0, "p2pk"),
    BtcTxSign::new(&key1, "p2wpkh").amount(600_000_000),
]).unwrap();
let bytes = tx.bytes();

// P2TR (BIP-341 key-path, SIGHASH_DEFAULT) — PrevScript is required.
tx.sign(&[BtcTxSign::new(&key, "p2tr").amount(100_000).prev_script(prev_spk)]).unwrap();
```

Taproot supports both raw `SecpPrivateKey` signing (the library applies the
BIP-341 tweak) and external signers implementing the [`Signer::sign_taproot`]
method (TSS / MuSig2 / FROST / HSM). Use [`crypto::secp256k1::taproot_tweak`]
and [`BtcTx::taproot_sighash`] to compute the tweaked key and sighash offline.

### EVM transactions

```rust
use outscript::{EvmTx, EvmTxType, AbiValue};
use num_bigint::BigInt;

let mut tx = EvmTx {
    tx_type: EvmTxType::Eip1559,
    chain_id: 1,
    nonce: 0,
    gas_tip_cap: BigInt::from(1_000_000_000u64),
    gas_fee_cap: BigInt::from(20_000_000_000u64),
    gas: 21000,
    to: "0x...".into(),
    value: BigInt::from(10u64).pow(18),
    ..Default::default()
};
tx.call("transfer(address,uint256)", &[/* AbiValue... */]).unwrap();
tx.sign(&key).unwrap();
let data = tx.to_bytes().unwrap();
let sender = tx.sender_address().unwrap();
```

### Solana transactions

```rust
use outscript::solana::{new_solana_tx, transfer_instruction, SolanaKey};

let ix = transfer_instruction(from, to, 1_000_000); // lamports
let mut tx = new_solana_tx(from, blockhash, &[ix]).unwrap();
tx.sign(&[seed]).unwrap();
let data = tx.to_bytes().unwrap();
let txid = tx.hash().unwrap(); // first signature
```

### Cardano transactions

Builds Shelley/Conway-era transactions: a CBOR-encoded body (inputs, outputs,
fee, optional TTL), ADA and native-asset outputs, and Ed25519 vkey witnesses.
The transaction id and signing digest are `blake2b-256` of the transaction body.

```rust
use outscript::{CardanoTx, CardanoInput, CardanoOutput, parse_cardano_address};

let to = parse_cardano_address("addr1vx2fxv2umyhttkxyxp8...").unwrap();

let mut tx = CardanoTx {
    inputs: vec![CardanoInput { txid: prev_txid /* 32 bytes */, index: 0 }],
    outputs: vec![CardanoOutput {
        address: to.bytes().to_vec(),
        amount: 1_000_000, // lovelace
        assets: vec![],
    }],
    fee: 170_000,
    ttl: 41_000_000, // optional (slot); 0 omits it
    witnesses: vec![],
};

// Sign with one or more 32-byte standard Ed25519 seeds (a vkey witness per seed)
tx.sign(&[seed]).unwrap();

let data = tx.to_bytes().unwrap(); // CBOR transaction
let txid = tx.hash().unwrap();           // blake2b-256 of the body
```

Cardano HD wallets (CIP-1852) use BIP32-Ed25519 *extended* keys, which store an
already-expanded 64-byte secret and cannot be used as a standard Ed25519 seed.
Sign with those (or any external/HSM signer) through the `CardanoSigner` trait:

```rust
use outscript::CardanoExtendedKey;

// secret is the 64-byte extended secret (e.g. the first 64 bytes of an xprv)
let ext = CardanoExtendedKey::new(&secret).unwrap();
tx.sign_with(&[&ext]).unwrap(); // standard Ed25519 signature, verifiable as usual
```

#### HD key derivation (CIP-1852 / BIP32-Ed25519)

Derive keys from BIP-39 entropy using the Icarus master-key scheme and the
CIP-1852 path `m/1852'/1815'/account'/role/index`:

```rust
use outscript::{cardano_icarus_master_key, cardano_harden as h, cardano_key_hash,
    cardano_base_address};

let master = cardano_icarus_master_key(&entropy, &[]).unwrap(); // &[] = no passphrase

// payment key m/1852'/1815'/0'/0/0 and stake key m/1852'/1815'/0'/2/0
let spend = master.derive_path(&[h(1852), h(1815), h(0), 0, 0]).unwrap();
let stake = master.derive_path(&[h(1852), h(1815), h(0), 2, 0]).unwrap();

let ph = cardano_key_hash(&spend.public_key());
let sh = cardano_key_hash(&stake.public_key());
let addr = cardano_base_address(&ph, &sh, "cardano").unwrap(); // addr1...

// `spend` signs transactions directly via sign_with.
// Watch-only soft derivation (no private key) is available from an xpub:
let xpub = master.derive_path(&[h(1852), h(1815), h(0), 0]).unwrap()
    .extended_public_key().unwrap();
let child = xpub.derive_child(0).unwrap();
```

Native tokens are added via `CardanoOutput.assets` (`CardanoAsset { policy_id,
asset_name, amount }`). Plutus scripts, certificates, staking actions and
metadata are out of scope.

### Block rewards

```rust
let reward = outscript::block_reward("bitcoin", 840_000).unwrap();      // 3.125 BTC in sats
let total  = outscript::cumulative_reward("bitcoin", 840_000).unwrap(); // total minted
```

## Architecture

- **Format / Insertable** — a sequence of operations (literal bytes, lookups,
  hashes, push-data, taproot tweak) that derive an output script from a key.
- **Script** — holds a [`PubKey`] and evaluates named formats, caching results.
- **Out** — a generated output script with its format name, hex and network
  flags; converts to/from human-readable addresses.
- **Transactions** — `BtcTx`, `EvmTx`, `SolanaTx`, `CardanoTx` with binary
  serialization, signing and hashing.

## License

See [LICENSE](LICENSE).
