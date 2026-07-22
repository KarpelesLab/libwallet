//! Cardano (Shelley/Conway-era) transactions: build, sign and (de)serialize the
//! CBOR wire format expected by the Cardano ledger.
//!
//! ```text
//! transaction = [transaction_body, transaction_witness_set, bool, auxiliary_data/nil]
//! ```
//!
//! Only Ed25519 vkey witnesses and ADA/native-asset outputs are supported;
//! Plutus scripts, certificates, metadata and staking actions are out of scope.
//! Inputs are encoded as a plain array (the CDDL `set` form without the optional
//! #6.258 tag).
//!
//! The transaction is signed by hashing the CBOR-encoded transaction body with
//! blake2b-256 and producing Ed25519 signatures over that 32-byte hash.
//! [`CardanoTx::sign`] takes standard 32-byte Ed25519 seeds; [`CardanoTx::sign_with`]
//! accepts any [`CardanoSigner`], including the BIP32-Ed25519 extended keys used
//! by Cardano HD wallets (see [`crate::cardano_derive`]) and external/HSM signers.
//!
//! Port of `cardanotx.go`.

use crate::cbor::{Cbor, split_array_items};
use crate::crypto::ed25519;
use crate::hash::blake2b_256;

/// References an unspent transaction output being spent.
#[derive(Debug, Clone)]
pub struct CardanoInput {
    /// 32-byte id of the transaction that produced the output.
    pub txid: Vec<u8>,
    /// Index of the output within that transaction.
    pub index: u64,
}

/// A native-token amount within an output (multiasset value).
#[derive(Debug, Clone)]
pub struct CardanoAsset {
    /// 28-byte minting policy id (script hash).
    pub policy_id: Vec<u8>,
    /// 0..32 byte asset name.
    pub asset_name: Vec<u8>,
    /// Token amount.
    pub amount: u64,
}

/// A transaction output: a destination address, an ADA amount in lovelace, and
/// optional native tokens. `address` holds the raw address bytes (header byte
/// followed by credentials), as produced by [`crate::out::Out::bytes`] for a
/// parsed Cardano address.
#[derive(Debug, Clone)]
pub struct CardanoOutput {
    /// Raw address bytes (header + credentials).
    pub address: Vec<u8>,
    /// Amount in lovelace.
    pub amount: u64,
    /// Optional native tokens.
    pub assets: Vec<CardanoAsset>,
}

/// Produces an Ed25519 signature over a 32-byte message (the transaction body
/// hash) and exposes the public key it signs with. This lets a [`CardanoTx`] be
/// signed by standard Ed25519 keys, BIP32-Ed25519 extended keys (see
/// [`crate::cardano_derive::CardanoExtendedKey`]), or external signers such as
/// HSMs.
pub trait CardanoSigner {
    /// Returns the 32-byte Ed25519 public key.
    fn cardano_public_key(&self) -> Vec<u8>;
    /// Returns a 64-byte Ed25519 signature over `message`.
    fn sign_cardano(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// Adapts a standard 32-byte Ed25519 seed to [`CardanoSigner`].
struct StdEd25519Signer {
    seed: [u8; 32],
}

impl CardanoSigner for StdEd25519Signer {
    fn cardano_public_key(&self) -> Vec<u8> {
        ed25519::public_from_seed(&self.seed).to_vec()
    }
    fn sign_cardano(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        Ok(ed25519::sign(&self.seed, message).to_vec())
    }
}

/// An Ed25519 verification-key witness: the 32-byte public key and its 64-byte
/// signature over the transaction body hash.
#[derive(Debug, Clone)]
pub struct CardanoVkeyWitness {
    /// 32-byte Ed25519 public key.
    pub vkey: Vec<u8>,
    /// 64-byte signature over the body hash.
    pub signature: Vec<u8>,
}

/// A Cardano transaction.
#[derive(Debug, Clone, Default)]
pub struct CardanoTx {
    /// Inputs being spent.
    pub inputs: Vec<CardanoInput>,
    /// Outputs being created.
    pub outputs: Vec<CardanoOutput>,
    /// Fee in lovelace.
    pub fee: u64,
    /// Optional time-to-live (slot); 0 means omit.
    pub ttl: u64,
    /// Ed25519 vkey witnesses.
    pub witnesses: Vec<CardanoVkeyWitness>,
}

/// Groups assets by policy id then asset name, summing amounts of duplicates,
/// and builds the CBOR multiasset map `{policy_id => {asset_name => amount}}`.
/// Returns an error if aggregating duplicate `(policy, asset name)` entries
/// overflows `u64`, rather than silently wrapping.
fn multiasset_map(assets: &[CardanoAsset]) -> Result<Cbor, String> {
    // (policy_id, [(asset_name, amount)]) grouping, built in insertion order;
    // the CBOR encoder applies the canonical key ordering at encode time.
    type Policy = (Vec<u8>, Vec<(Vec<u8>, u64)>);
    let mut policies: Vec<Policy> = Vec::new();
    for a in assets {
        let policy = policies.iter_mut().find(|(p, _)| *p == a.policy_id);
        let names = match policy {
            Some((_, names)) => names,
            None => {
                policies.push((a.policy_id.clone(), Vec::new()));
                &mut policies.last_mut().unwrap().1
            }
        };
        match names.iter_mut().find(|(n, _)| *n == a.asset_name) {
            Some((_, amount)) => {
                *amount = amount.checked_add(a.amount).ok_or_else(|| {
                    format!(
                        "cardano asset amount overflow for policy {} asset {}",
                        hex::encode(&a.policy_id),
                        hex::encode(&a.asset_name)
                    )
                })?;
            }
            None => names.push((a.asset_name.clone(), a.amount)),
        }
    }
    let entries = policies
        .into_iter()
        .map(|(policy, names)| {
            let inner = names
                .into_iter()
                .map(|(name, amount)| (Cbor::Bytes(name), Cbor::Uint(amount)))
                .collect();
            (Cbor::Bytes(policy), Cbor::Map(inner))
        })
        .collect();
    Ok(Cbor::Map(entries))
}

/// Returns the CBOR value for an output's amount: a bare coin for ADA-only
/// outputs, or `[coin, multiasset]` when native tokens are present.
fn output_value(out: &CardanoOutput) -> Result<Cbor, String> {
    if out.assets.is_empty() {
        Ok(Cbor::Uint(out.amount))
    } else {
        Ok(Cbor::Array(vec![
            Cbor::Uint(out.amount),
            multiasset_map(&out.assets)?,
        ]))
    }
}

impl CardanoTx {
    /// Builds the transaction_body as an integer-keyed CBOR map.
    fn body_map(&self) -> Result<Cbor, String> {
        if self.inputs.is_empty() {
            return Err("cardano transaction has no inputs".into());
        }
        if self.outputs.is_empty() {
            return Err("cardano transaction has no outputs".into());
        }

        let mut inputs = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            if input.txid.len() != 32 {
                return Err(format!(
                    "cardano input txid must be 32 bytes, got {}",
                    input.txid.len()
                ));
            }
            inputs.push(Cbor::Array(vec![
                Cbor::Bytes(input.txid.clone()),
                Cbor::Uint(input.index),
            ]));
        }

        let mut outputs = Vec::with_capacity(self.outputs.len());
        for out in &self.outputs {
            if out.address.is_empty() {
                return Err("cardano output has empty address".into());
            }
            outputs.push(Cbor::Array(vec![
                Cbor::Bytes(out.address.clone()),
                output_value(out)?,
            ]));
        }

        let mut entries = vec![
            (Cbor::Uint(0), Cbor::Array(inputs)),
            (Cbor::Uint(1), Cbor::Array(outputs)),
            (Cbor::Uint(2), Cbor::Uint(self.fee)),
        ];
        if self.ttl != 0 {
            entries.push((Cbor::Uint(3), Cbor::Uint(self.ttl)));
        }
        Ok(Cbor::Map(entries))
    }

    /// Returns the canonical CBOR encoding of the transaction body.
    pub fn body_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.body_map()?.encode())
    }

    /// Returns the 32-byte blake2b-256 hash of the transaction body, which is
    /// the digest Ed25519 witnesses sign and also the transaction id.
    pub fn sign_bytes(&self) -> Result<[u8; 32], String> {
        Ok(blake2b_256(&self.body_bytes()?))
    }

    /// Returns the transaction id: the blake2b-256 hash of the transaction body.
    pub fn hash(&self) -> Result<[u8; 32], String> {
        self.sign_bytes()
    }

    /// Signs the transaction body with each provided 32-byte standard Ed25519
    /// seed, appending a vkey witness for each. Existing witnesses are preserved.
    /// For BIP32-Ed25519 extended keys or external signers, use
    /// [`CardanoTx::sign_with`].
    pub fn sign(&mut self, seeds: &[[u8; 32]]) -> Result<(), String> {
        let signers: Vec<StdEd25519Signer> = seeds
            .iter()
            .map(|&seed| StdEd25519Signer { seed })
            .collect();
        let refs: Vec<&dyn CardanoSigner> =
            signers.iter().map(|s| s as &dyn CardanoSigner).collect();
        self.sign_with(&refs)
    }

    /// Signs the transaction body with each provided [`CardanoSigner`], appending
    /// a vkey witness for each. Existing witnesses are preserved.
    pub fn sign_with(&mut self, signers: &[&dyn CardanoSigner]) -> Result<(), String> {
        let digest = self.sign_bytes()?;
        for signer in signers {
            let pub_key = signer.cardano_public_key();
            if pub_key.len() != 32 {
                return Err(format!(
                    "cardano signer public key must be 32 bytes, got {}",
                    pub_key.len()
                ));
            }
            let sig = signer.sign_cardano(&digest)?;
            if sig.len() != 64 {
                return Err(format!(
                    "cardano signature must be 64 bytes, got {}",
                    sig.len()
                ));
            }
            self.witnesses.push(CardanoVkeyWitness {
                vkey: pub_key,
                signature: sig,
            });
        }
        Ok(())
    }

    /// Appends a pre-computed vkey witness (32-byte public key, 64-byte
    /// signature over [`CardanoTx::sign_bytes`]). For external/hardware signers.
    pub fn add_witness(&mut self, vkey: &[u8], signature: &[u8]) -> Result<(), String> {
        if vkey.len() != 32 {
            return Err(format!("cardano vkey must be 32 bytes, got {}", vkey.len()));
        }
        if signature.len() != 64 {
            return Err(format!(
                "cardano signature must be 64 bytes, got {}",
                signature.len()
            ));
        }
        self.witnesses.push(CardanoVkeyWitness {
            vkey: vkey.to_vec(),
            signature: signature.to_vec(),
        });
        Ok(())
    }

    /// Verifies every vkey witness signature against the transaction body
    /// digest.
    pub fn verify(&self) -> Result<(), String> {
        let digest = self.sign_bytes()?;
        for (i, w) in self.witnesses.iter().enumerate() {
            if w.vkey.len() != 32 {
                return Err(format!(
                    "witness {i} vkey has invalid length {}",
                    w.vkey.len()
                ));
            }
            if w.signature.len() != 64 {
                return Err(format!(
                    "witness {i} signature has invalid length {}",
                    w.signature.len()
                ));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&w.vkey);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&w.signature);
            if !ed25519::verify(&pk, &digest, &sig) {
                return Err(format!("witness {i} signature verification failed"));
            }
        }
        Ok(())
    }

    /// Builds the transaction_witness_set CBOR map. Returns an empty map when
    /// there are no witnesses.
    fn witness_set(&self) -> Cbor {
        if self.witnesses.is_empty() {
            return Cbor::Map(Vec::new());
        }
        let vkeys = self
            .witnesses
            .iter()
            .map(|w| {
                Cbor::Array(vec![
                    Cbor::Bytes(w.vkey.clone()),
                    Cbor::Bytes(w.signature.clone()),
                ])
            })
            .collect();
        Cbor::Map(vec![(Cbor::Uint(0), Cbor::Array(vkeys))])
    }

    /// Encodes the full transaction (body, witness set, validity flag, and null
    /// auxiliary data) as canonical CBOR. The embedded body bytes are
    /// byte-identical to those hashed for signing.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let body_bytes = self.body_bytes()?;
        let transaction = Cbor::Array(vec![
            Cbor::Raw(body_bytes),
            self.witness_set(),
            Cbor::Bool(true), // script validity flag; always true (no Plutus phase-2 support)
            Cbor::Null,       // auxiliary data
        ]);
        Ok(transaction.encode())
    }

    /// Decodes a CBOR-encoded Cardano transaction. Supports the subset produced
    /// by [`CardanoTx::to_bytes`]: ADA/native-asset outputs in the legacy
    /// (alonzo) array form and Ed25519 vkey witnesses.
    pub fn from_bytes(data: &[u8]) -> Result<CardanoTx, String> {
        let raw = split_array_items(data)
            .map_err(|e| format!("failed to decode cardano transaction: {e}"))?;
        if raw.len() < 2 {
            return Err(format!(
                "cardano transaction must have at least 2 elements, got {}",
                raw.len()
            ));
        }

        let body = Cbor::decode(&raw[0])
            .map_err(|e| format!("failed to decode transaction body: {e}"))?
            .0;
        let body = body.as_map().ok_or("transaction body is not a CBOR map")?;
        let get = |key: u64| {
            body.iter()
                .find(|(k, _)| k.as_uint() == Some(key))
                .map(|(_, v)| v)
        };

        let mut tx = CardanoTx::default();

        if let Some(inputs) = get(0) {
            let inputs = inputs.as_array().ok_or("inputs is not an array")?;
            for input in inputs {
                let fields = input.as_array().ok_or("invalid transaction input")?;
                if fields.len() != 2 {
                    return Err("invalid transaction input".into());
                }
                let txid = fields[0].as_bytes().ok_or("invalid input txid")?.to_vec();
                let index = fields[1].as_uint().ok_or("invalid input index")?;
                tx.inputs.push(CardanoInput { txid, index });
            }
        }

        if let Some(outputs) = get(1) {
            let outputs = outputs.as_array().ok_or("outputs is not an array")?;
            for raw_out in outputs {
                tx.outputs.push(decode_output(raw_out)?);
            }
        }

        if let Some(fee) = get(2) {
            tx.fee = fee.as_uint().ok_or("invalid fee")?;
        }
        if let Some(ttl) = get(3) {
            tx.ttl = ttl.as_uint().ok_or("invalid ttl")?;
        }

        let ws = Cbor::decode(&raw[1])
            .map_err(|e| format!("failed to decode witness set: {e}"))?
            .0;
        if let Some(entries) = ws.as_map()
            && let Some((_, vkeys)) = entries.iter().find(|(k, _)| k.as_uint() == Some(0))
        {
            let vkeys = vkeys.as_array().ok_or("vkey witnesses is not an array")?;
            for vk in vkeys {
                let fields = vk.as_array().ok_or("invalid vkey witness")?;
                if fields.len() != 2 {
                    return Err("invalid vkey witness".into());
                }
                let vkey = fields[0].as_bytes().ok_or("invalid vkey")?.to_vec();
                let signature = fields[1].as_bytes().ok_or("invalid signature")?.to_vec();
                tx.witnesses.push(CardanoVkeyWitness { vkey, signature });
            }
        }

        Ok(tx)
    }
}

/// Decodes a single transaction output in the legacy (alonzo) array form
/// `[address, value, ? datum_hash]`.
fn decode_output(raw: &Cbor) -> Result<CardanoOutput, String> {
    let fields = raw
        .as_array()
        .ok_or("only legacy (array) cardano outputs are supported")?;
    if fields.len() < 2 {
        return Err("invalid transaction output".into());
    }
    let address = fields[0]
        .as_bytes()
        .ok_or("invalid output address")?
        .to_vec();

    // value is either a bare coin (uint) or [coin, multiasset]
    if let Some(amount) = fields[1].as_uint() {
        return Ok(CardanoOutput {
            address,
            amount,
            assets: Vec::new(),
        });
    }
    let value = fields[1]
        .as_array()
        .ok_or("failed to decode output value")?;
    if value.len() != 2 {
        return Err("failed to decode output value".into());
    }
    let amount = value[0].as_uint().ok_or("failed to decode output coin")?;
    let multiasset = value[1].as_map().ok_or("failed to decode multiasset")?;
    let assets = flatten_assets(multiasset)?;
    Ok(CardanoOutput {
        address,
        amount,
        assets,
    })
}

/// Converts a decoded `{policy => {name => amount}}` map into a deterministically
/// ordered slice of [`CardanoAsset`].
fn flatten_assets(multiasset: &[(Cbor, Cbor)]) -> Result<Vec<CardanoAsset>, String> {
    let mut assets = Vec::new();
    for (policy, names) in multiasset {
        let policy_id = policy.as_bytes().ok_or("invalid policy id")?.to_vec();
        let names = names.as_map().ok_or("invalid asset map")?;
        for (name, amount) in names {
            assets.push(CardanoAsset {
                policy_id: policy_id.clone(),
                asset_name: name.as_bytes().ok_or("invalid asset name")?.to_vec(),
                amount: amount.as_uint().ok_or("invalid asset amount")?,
            });
        }
    }
    assets.sort_by(|a, b| {
        a.policy_id
            .cmp(&b.policy_id)
            .then_with(|| a.asset_name.cmp(&b.asset_name))
    });
    Ok(assets)
}
