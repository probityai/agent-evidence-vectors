//! Typed refusals.

use thiserror::Error;

/// Errors from envelope, threshold and key validation, or a signing backend.
#[derive(Debug, Error, PartialEq, Eq, Clone, serde::Serialize)]
#[serde(tag = "variant", content = "fields")]
#[non_exhaustive]
pub enum Error {
    /// The envelope was not well-formed JSON, or a required member was absent.
    #[error("envelope is not a well-formed DSSE JSON envelope: {0}")]
    MalformedEnvelope(String),

    /// `payload` or a `sig` was not canonical RFC 4648 base64 in either the
    /// standard or the URL-safe alphabet.
    #[error("{field} is not canonical base64 in either the standard or URL-safe alphabet")]
    NonCanonicalBase64 {
        /// The envelope member that failed to decode.
        field: &'static str,
    },

    /// `signatures` was present but empty, or signing was asked to use no
    /// signer. The envelope schema requires at least one signature, so an empty
    /// list can never be satisfied.
    #[error("envelope carries no signatures; the schema requires at least one")]
    NoSignatures,

    /// No signature entry verified under any trusted key.
    ///
    /// This is the refusal for a changed payload, a changed `payloadType`, a
    /// signature over different bytes, a wrong-length signature, a signer that
    /// is not among the trusted keys, and an empty trusted set. It is separate
    /// from [`Error::ThresholdNotMet`] because the two call for different
    /// reactions: a threshold shortfall means some trusted key did sign these
    /// bytes, while this means none did. The caller cannot tell from the
    /// signature alone which of the causes above applies, and the crate does
    /// not guess; it reports what it observed.
    #[error(
        "no signature verified (signature entries tried: {entries}, trusted keys: {keys}); {}",
        mismatch_note(.mismatched_keys)
    )]
    NoValidSignature {
        /// How many signature entries decoded and were tried.
        entries: usize,
        /// How many trusted keys were supplied.
        keys: usize,
        /// The `key_id` of every trusted key that an entry named by `keyid`
        /// but whose signature did not verify. `keyid` is outside the signed
        /// bytes, so this is evidence that the signed bytes differ from what
        /// the signer signed, not proof. Empty when no entry named a trusted
        /// key.
        mismatched_keys: Vec<String>,
    },

    /// Some, but fewer than `threshold`, distinct trusted keys produced a
    /// valid signature. At least one trusted key did sign these exact bytes.
    #[error("signature threshold not met: {accepted} distinct trusted key(s) accepted, {threshold} required")]
    ThresholdNotMet {
        /// How many distinct trusted keys verified.
        accepted: usize,
        /// How many were required.
        threshold: usize,
    },

    /// A threshold of zero was requested. Zero would verify an envelope with no
    /// valid signature at all.
    #[error("a threshold of zero accepts an unsigned envelope")]
    ZeroThreshold,

    /// Two supplied keys reported the same identifier, so a threshold cannot
    /// count them apart. The count is over distinct keys, and a set that cannot
    /// be counted is refused rather than counted wrongly.
    #[error(
        "two supplied keys report key_id {key_id:?}; a threshold cannot count them as distinct"
    )]
    DuplicateKeyId {
        /// The identifier two keys share.
        key_id: String,
    },

    /// Two verifier entries refer to the same verification key under different
    /// identifiers. Counting both would let one signature satisfy a threshold.
    #[error("keys #{first} and #{second} have the same key identity")]
    DuplicateKeyIdentity {
        /// First occurrence in the supplied key set.
        first: usize,
        /// Repeated occurrence in the supplied key set.
        second: usize,
    },

    /// A threshold above one was requested with a key that reports no
    /// identifier. Anonymous keys cannot be told apart, so the same key supplied
    /// twice would satisfy a 2-of-n on its own.
    #[error("key #{index} reports no key_id, so a threshold above 1 cannot count distinct keys")]
    UnidentifiedKey {
        /// Which supplied key, by position.
        index: usize,
    },

    /// A key set cannot prove distinct keys when one verifier reports only a
    /// caller-chosen label instead of a stable key identity.
    #[error("key #{index} reports no key identity for a threshold above 1")]
    UnidentifiedKeyIdentity {
        /// Which supplied key, by position.
        index: usize,
    },

    /// `payloadType` was present but empty. An empty type binds nothing, and the
    /// whole purpose of the pre-authentication encoding is to bind the type.
    #[error("payloadType is empty; a DSSE envelope must name the type its payload is")]
    EmptyPayloadType,

    /// The envelope carries more signature entries than [`crate::MAX_SIGNATURES`].
    #[error("envelope carries {got} signature entries, at most {cap} are verified")]
    TooManySignatures {
        /// How many entries it carried.
        got: usize,
        /// The cap.
        cap: usize,
    },

    /// The signer could not produce a signature.
    #[error("signing failed: {0}")]
    Signing(String),

    /// A key could not be constructed from the supplied bytes.
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

/// The result of any operation in this crate.
pub type Result<T> = core::result::Result<T, Error>;

fn mismatch_note(mismatched_keys: &[String]) -> String {
    if mismatched_keys.is_empty() {
        "no entry named a trusted key, so the signer is untrusted or the signature is malformed"
            .to_string()
    } else {
        format!(
            "entries naming {} did not verify, so the payload, the payload type or the signature differs from what was signed",
            mismatched_keys.join(", ")
        )
    }
}
