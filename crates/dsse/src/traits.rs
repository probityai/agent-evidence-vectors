//! The two backend traits. Bring your own signatures.

/// Produces a signature over arbitrary bytes.
///
/// The bytes handed to [`Signer::sign`] are already the pre-authentication
/// encoding; an implementation must sign them as given and must not re-encode,
/// hash-and-truncate, or otherwise reinterpret them.
pub trait Signer {
    /// Signs `message`, returning the raw signature bytes.
    fn sign(&self, message: &[u8]) -> crate::Result<Vec<u8>>;

    /// An optional hint written into the envelope's `keyid` member. It creates
    /// no trust and a verifier must not rely on it.
    fn key_id(&self) -> Option<String> {
        None
    }
}

/// Checks a signature over arbitrary bytes.
///
/// An implementation must be total: any input, including a signature of the
/// wrong length or a malformed encoding, yields `false` rather than a panic.
pub trait Verifier {
    /// Returns true when `signature` is a valid signature over `message` under
    /// this key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;

    /// An optional identifier used to order verification attempts, and to name
    /// which keys were accepted. Two distinct trusted keys must not report the
    /// same identifier, or a threshold cannot count them apart.
    fn key_id(&self) -> Option<String> {
        None
    }

    /// Identifies the verification key independently of its display name.
    ///
    /// Return an algorithm-qualified public key or fingerprint. A threshold
    /// above one requires this value so two names for one key count only once.
    /// A backend that cannot provide it may still verify at threshold one.
    fn key_identity(&self) -> Option<Vec<u8>> {
        None
    }
}
