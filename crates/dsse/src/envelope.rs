//! The DSSE JSON envelope, and the base64 policy its members decode under.

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// One DSSE signature entry.
///
/// `keyid` is an unauthenticated hint. It is not covered by the signature, so
/// this crate uses it only to order verification attempts and never to exclude
/// a key: an envelope carrying a wrong or absent `keyid` alongside a valid
/// signature still verifies. Treating `keyid` as a filter turns an
/// attacker-controlled string into a denial of verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Unauthenticated hint identifying which public key was used. Absent and
    /// empty are the same value per the envelope specification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Base64 of the signature over `PAE(payload_type, payload)`.
    pub sig: String,
}

/// A DSSE JSON envelope, exactly as it travels on the wire.
///
/// Member order is `payload`, `payloadType`, `signatures`, which is the order
/// the specification writes them and the order this type serialises them.
/// Unrecognised members are ignored on the way in, as the specification
/// requires of consumers, and are not preserved on the way out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Base64 of the signed bytes.
    pub payload: String,
    /// The opaque, case-sensitive string identifying how to interpret the
    /// decoded payload. It is covered by the signature.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// One or more signatures over the same pre-authentication encoding.
    pub signatures: Vec<Signature>,
}

impl Envelope {
    /// Parses an envelope from JSON bytes.
    ///
    /// This decodes the container only. It performs no cryptography and the
    /// payload it carries is unverified; call [`crate::verify`] to obtain bytes
    /// any trust may rest on.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| Error::MalformedEnvelope(e.to_string()))
    }

    /// Serialises the envelope to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::MalformedEnvelope(e.to_string()))
    }
}

/// Decodes one base64 envelope member, canonically.
///
/// Both RFC 4648 alphabets are accepted, because the protocol requires a
/// verifier to accept either. Within each alphabet the encoding must be
/// canonical: padded to a whole quad, and with the final symbol's discarded bits
/// zero. `base64`'s `STANDARD` and `URL_SAFE` engines enforce both.
///
/// Leniency here would be envelope malleability rather than convenience. `eA==`
/// and `eB==` differ in bits a lenient decoder throws away, so both decode to
/// the byte `x`: accepting either means one signature covers two distinct
/// envelopes, and anything that content-addresses the envelope disagrees with
/// anything that verifies it. Neither string is output `Base64()` can produce,
/// so refusing them turns nothing valid away.
pub(crate) fn decode_b64(s: &str, field: &'static str) -> Result<Vec<u8>> {
    if let Ok(v) = STANDARD.decode(s) {
        return Ok(v);
    }
    if let Ok(v) = URL_SAFE.decode(s) {
        return Ok(v);
    }
    Err(Error::NonCanonicalBase64 { field })
}

/// Encodes bytes as canonical padded standard-alphabet base64.
pub(crate) fn encode_b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}
