//! Threshold verification, and the only type that carries verified bytes.

use crate::envelope::{decode_b64, Envelope};
use crate::error::{Error, Result};
use crate::pae::pae;
use crate::traits::Verifier;

/// A payload that a threshold of trusted keys has signed.
///
/// This is the only way this crate hands back payload bytes for an application
/// to act on. The bytes in [`VerifiedPayload::payload`] are the exact bytes the
/// signature covered: they are decoded once, that decode builds the
/// pre-authentication encoding, and those same bytes are moved into this struct.
/// The envelope is never read again afterwards, which is what the protocol's
/// re-parsing warning requires: an implementation that goes back to the envelope
/// for the payload after verifying can be made to hand the application bytes
/// nobody signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayload {
    /// The authenticated payload type.
    pub payload_type: String,
    /// The exact bytes the signature covered.
    pub payload: Vec<u8>,
    /// The `key_id` of every distinct trusted key that verified, in the order
    /// the keys were supplied. A key reporting no identifier is named `#<n>` by
    /// its position.
    pub accepted_keys: Vec<String>,
}

/// Verifies an envelope against `keys`, requiring `threshold` distinct keys.
///
/// A `(t, n)` envelope is valid when signatures in it verify under at least `t`
/// of the `n` supplied keys. The count is over **distinct keys**, never over
/// signature entries: an envelope carrying one valid signature copied five times
/// has one key behind it, and counting entries would let a single key satisfy any
/// threshold. Each supplied key therefore contributes at most one, however many
/// entries it verifies.
///
/// Distinctness is checked here, not left to the caller. A threshold above 1
/// requires both a key identifier and a stable, algorithm-qualified key
/// identity from every verifier. Labels alone cannot distinguish two aliases
/// of one public key. A 1-of-n needs no key identity.
///
/// A payload that does not decode is a refusal: the protocol says to reject when
/// decoding fails, and there is exactly one payload. A signature entry that does
/// not decode is skipped, because `signatures` is covered by no signature.
/// Anyone who can touch the envelope can append an entry, and making one unusable
/// entry fatal hands them a denial of verification over an envelope that is
/// validly signed. If no entry at all decodes, that is
/// [`Error::NonCanonicalBase64`]. A signature that decodes but does not verify is
/// skipped, as the protocol also says.
pub fn verify(
    envelope: &Envelope,
    keys: &[&dyn Verifier],
    threshold: usize,
) -> Result<VerifiedPayload> {
    if threshold == 0 {
        return Err(Error::ZeroThreshold);
    }
    if envelope.payload_type.is_empty() {
        return Err(Error::EmptyPayloadType);
    }
    if envelope.signatures.is_empty() {
        return Err(Error::NoSignatures);
    }
    if envelope.signatures.len() > MAX_SIGNATURES {
        return Err(Error::TooManySignatures {
            got: envelope.signatures.len(),
            cap: MAX_SIGNATURES,
        });
    }
    check_countable(keys, threshold)?;

    let payload = decode_b64(&envelope.payload, "payload")?;
    let pre_image = pae(&envelope.payload_type, &payload);

    let mut entries = Vec::with_capacity(envelope.signatures.len());
    for entry in &envelope.signatures {
        // An entry that does not decode is skipped, not fatal. See the note on
        // this function: `signatures` is outside every signature, so a fatal
        // entry is a denial of verification anyone can mint.
        if let Ok(sig) = decode_b64(&entry.sig, "signatures[].sig") {
            entries.push((entry.keyid.as_deref().unwrap_or_default(), sig));
        }
    }
    if entries.is_empty() {
        return Err(Error::NonCanonicalBase64 {
            field: "signatures[].sig",
        });
    }

    let mut accepted = Vec::new();
    for (idx, key) in keys.iter().enumerate() {
        let key_id = key.key_id();
        if key_accepts(*key, &pre_image, &entries, key_id.as_deref()) {
            accepted.push(key_id.unwrap_or_else(|| format!("#{idx}")));
        }
    }

    if accepted.len() < threshold {
        return Err(Error::ThresholdNotMet {
            accepted: accepted.len(),
            threshold,
        });
    }

    Ok(VerifiedPayload {
        payload_type: envelope.payload_type.clone(),
        payload,
        accepted_keys: accepted,
    })
}

/// The most signature entries [`verify`] will attempt.
///
/// Verification is `keys x entries` signature checks, and nothing in the
/// envelope bounds `entries`. A cap is what turns "the caller passed us an
/// envelope" into bounded work; a depth cap bounds a stack and a size cap bounds
/// a heap, and this bounds arithmetic. 1024 is orders of magnitude above any real
/// multi-signature envelope, so it refuses nothing genuine.
pub const MAX_SIGNATURES: usize = 1024;

/// Refuses labels that collide, keys with no stable identity, and aliases of
/// one key that carry different labels.
fn check_countable(keys: &[&dyn Verifier], threshold: usize) -> Result<()> {
    if threshold < 2 {
        return Ok(());
    }
    let mut ids: Vec<String> = Vec::with_capacity(keys.len());
    let mut identities: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
    for (index, key) in keys.iter().enumerate() {
        match key.key_id().filter(|id| !id.is_empty()) {
            None => return Err(Error::UnidentifiedKey { index }),
            Some(id) => {
                if ids.contains(&id) {
                    return Err(Error::DuplicateKeyId { key_id: id });
                }
                ids.push(id);
            }
        }
        let identity = key
            .key_identity()
            .filter(|identity| !identity.is_empty())
            .ok_or(Error::UnidentifiedKeyIdentity { index })?;
        if let Some(first) = identities.iter().position(|seen| seen == &identity) {
            return Err(Error::DuplicateKeyIdentity {
                first,
                second: index,
            });
        }
        identities.push(identity);
    }
    Ok(())
}

/// Reports whether `key` verifies any of the envelope's signatures.
///
/// `keyid` is outside the pre-authentication encoding and so is attacker
/// controlled on any envelope an attacker can touch. The protocol allows it to
/// narrow the selection of keys to try and forbids using it for security
/// decisions, so it is used here only to try the matching entry first. Every
/// entry is still tried afterwards: a wrong or absent hint costs a few
/// signature checks and never withholds a verification that would otherwise
/// succeed.
fn key_accepts(
    key: &dyn Verifier,
    pre_image: &[u8],
    entries: &[(&str, Vec<u8>)],
    key_id: Option<&str>,
) -> bool {
    if let Some(id) = key_id.filter(|id| !id.is_empty()) {
        if entries
            .iter()
            .any(|(hint, sig)| *hint == id && key.verify(pre_image, sig))
        {
            return true;
        }
    }
    entries.iter().any(|(_, sig)| key.verify(pre_image, sig))
}
