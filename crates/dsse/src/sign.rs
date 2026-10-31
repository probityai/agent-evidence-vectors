//! Envelope construction.

use crate::envelope::{encode_b64, Envelope, Signature};
use crate::error::Result;
use crate::pae::pae;
use crate::traits::Signer;

/// Builds an envelope by signing `PAE(payload_type, payload)` with one signer.
pub fn sign(payload_type: &str, payload: &[u8], signer: &dyn Signer) -> Result<Envelope> {
    sign_with(payload_type, payload, &[signer])
}

/// Builds an envelope carrying one signature per signer, all over the same
/// pre-authentication encoding.
///
/// The encoding is computed once and handed to every signer unchanged, so the
/// signatures in the resulting envelope are interchangeable and a verifier can
/// count them toward a threshold.
pub fn sign_with(payload_type: &str, payload: &[u8], signers: &[&dyn Signer]) -> Result<Envelope> {
    // Refused at minting, not only at verification. An envelope with an empty
    // type is one whose signature binds no type at all, which is the confusion
    // the pre-authentication encoding exists to prevent, and this crate should
    // not be able to produce one.
    if payload_type.is_empty() {
        return Err(crate::Error::EmptyPayloadType);
    }
    // Refused at minting for the same reason: verification refuses an envelope
    // with no signatures, so an empty signer list can only produce an envelope
    // nobody can accept.
    if signers.is_empty() {
        return Err(crate::Error::NoSignatures);
    }
    let pre_image = pae(payload_type, payload);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let sig = signer.sign(&pre_image)?;
        signatures.push(Signature {
            keyid: signer.key_id().filter(|k| !k.is_empty()),
            sig: encode_b64(&sig),
        });
    }
    Ok(Envelope {
        payload: encode_b64(payload),
        payload_type: payload_type.to_string(),
        signatures,
    })
}
