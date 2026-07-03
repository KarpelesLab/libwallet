//! Signature/key descriptions — port of the Go `wltsign` package.
//!
//! A [`KeyDescription`] says how one wallet key share is protected. On
//! Wallet:create the caller supplies one per share; each resolves to a
//! recipient the share is encrypted to (or Plain / a remote party).

use serde::{Deserialize, Serialize};

use crate::keystore::{self, KeystoreError};
use bottlers::PublicKey;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyDescription {
    /// StoreKey | RemoteKey | Plain | Password
    #[serde(rename = "Type", default)]
    pub kind: String,
    /// StoreKey: base64url PKIX pubkey. Password: the password. Plain: ignored.
    #[serde(rename = "Key", default)]
    pub key: String,
    #[serde(rename = "Id", default)]
    pub id: String,
}

/// How a share is protected once resolved.
pub enum Recipient {
    /// Encrypt the share to this public key (StoreKey / Password).
    Encrypt(PublicKey),
    /// Store the share unencrypted (Plain).
    Plain,
    /// Held by a remote party (RemoteKey) — resolved server-side, not locally.
    Remote,
}

impl KeyDescription {
    /// Resolve this description to a recipient. `salt` is the WalletKey id
    /// (used only by the Password scheme, matching Go passwordToEd25519).
    pub fn resolve(&self, salt: &[u8]) -> Result<Recipient, KeystoreError> {
        match self.kind.as_str() {
            "StoreKey" => Ok(Recipient::Encrypt(keystore::public_key_from_pkix_b64(&self.key)?)),
            "Password" => {
                let k = keystore::password_to_ed25519(&self.key, salt)?;
                Ok(Recipient::Encrypt(k.public()))
            }
            "Plain" => Ok(Recipient::Plain),
            "RemoteKey" => Ok(Recipient::Remote),
            other => Err(KeystoreError::Decode(format!("unknown key description type {other}"))),
        }
    }
}
