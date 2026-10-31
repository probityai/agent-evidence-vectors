//! An ed25519 backend, behind the `ed25519` feature.
//!
//! It exists so the crate is usable without writing a backend first. Any other
//! key, whether an ECDSA key, a key in a KMS or a Sigstore signer, implements
//! [`crate::Signer`] and [`crate::Verifier`] instead and needs nothing here.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH};

use crate::error::{Error, Result};
use crate::traits::{Signer as DsseSigner, Verifier as DsseVerifier};

/// An ed25519 verifying key, with an optional identifier.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    key: VerifyingKey,
    key_id: Option<String>,
}

impl Ed25519Verifier {
    /// Builds a verifier from the 32 raw bytes of an ed25519 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey(format!("expected 32 bytes, got {}", bytes.len())))?;
        let key = VerifyingKey::from_bytes(&arr).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { key, key_id: None })
    }

    /// Attaches an identifier used to order verification attempts and to name
    /// the key in a verification result.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }
}

impl DsseVerifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(arr) = <[u8; SIGNATURE_LENGTH]>::try_from(signature) else {
            return false;
        };
        // verify_strict rejects small-order public keys and non-canonical
        // signature scalars, so two distinct signatures cannot both verify for
        // one message under one key.
        self.key
            .verify_strict(message, &Signature::from_bytes(&arr))
            .is_ok()
    }

    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }

    fn key_identity(&self) -> Option<Vec<u8>> {
        let mut identity = b"ed25519:".to_vec();
        identity.extend_from_slice(self.key.as_bytes());
        Some(identity)
    }
}

/// An ed25519 signing key, with an optional identifier.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    key: SigningKey,
    key_id: Option<String>,
}

impl Ed25519Signer {
    /// Builds a signer from the 32 raw bytes of an ed25519 secret key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey(format!("expected 32 bytes, got {}", bytes.len())))?;
        Ok(Self {
            key: SigningKey::from_bytes(&arr),
            key_id: None,
        })
    }

    /// Attaches an identifier written into the envelope's `keyid` member.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Returns the matching verifier, carrying the same identifier.
    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            key: self.key.verifying_key(),
            key_id: self.key_id.clone(),
        }
    }
}

impl DsseSigner for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(message).to_bytes().to_vec())
    }

    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }
}
