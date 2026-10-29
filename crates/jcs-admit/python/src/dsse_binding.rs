//! `jcs_admit.dsse`: DSSE envelopes and the pre-authentication encoding, through
//! the `dsse` crate with its ed25519 backend.
//!
//! Envelopes cross the boundary as their JSON bytes. Verification returns a
//! `VerifiedPayload` holding the exact bytes the signatures covered, which is the
//! crate's own contract: the payload is decoded once and never re-read from the
//! envelope, so an application cannot be handed bytes nobody signed.

use dsse::{Signer as _, Verifier as _};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

use crate::errors::{refusal, DsseError};

/// The `dsse` release this extension links, as pinned in `Cargo.toml`.
pub(crate) const BOUND_VERSION: &str = "0.1.3";

/// The prefix `dsse` writes in front of an ed25519 key's identity.
const ED25519_IDENTITY_PREFIX: &[u8] = b"ed25519:";

/// The raw public key of a verifier, read from the identity the crate reports.
fn public_key_of(verifier: &dsse::Ed25519Verifier) -> PyResult<Vec<u8>> {
    verifier
        .key_identity()
        .and_then(|id| id.strip_prefix(ED25519_IDENTITY_PREFIX).map(<[u8]>::to_vec))
        .ok_or_else(|| PyValueError::new_err("the dsse crate reported no ed25519 key identity"))
}

/// An ed25519 signing key, with an optional `keyid` hint.
///
/// `secret_key` is the 32-byte seed. The `keyid` is written into each signature
/// entry; it is unauthenticated and creates no trust.
#[pyclass(frozen, module = "jcs_admit.dsse")]
pub(crate) struct Ed25519Signer {
    inner: dsse::Ed25519Signer,
    public_key: Vec<u8>,
}

#[pymethods]
impl Ed25519Signer {
    #[new]
    #[pyo3(signature = (secret_key, /, key_id = None))]
    fn new(py: Python<'_>, secret_key: &[u8], key_id: Option<String>) -> PyResult<Self> {
        let mut inner = dsse::Ed25519Signer::from_bytes(secret_key)
            .map_err(|e| refusal::<_, DsseError>(py, &e))?;
        if let Some(id) = key_id {
            inner = inner.with_key_id(id);
        }
        let public_key = public_key_of(&inner.verifier())?;
        Ok(Self { inner, public_key })
    }

    /// The `keyid` hint written into each signature, or `None`.
    #[getter]
    fn key_id(&self) -> Option<String> {
        self.inner.key_id()
    }

    /// The 32 raw bytes of the matching public key.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public_key)
    }

    /// The matching verifier, carrying the same `keyid`.
    fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            inner: self.inner.verifier(),
            public_key: self.public_key.clone(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Ed25519Signer(key_id={:?}, public_key={})",
            self.inner.key_id(),
            hex(&self.public_key)
        )
    }
}

/// An ed25519 verifying key, with an optional identifier.
///
/// `public_key` is the 32 raw bytes. A threshold above one requires every key
/// to carry a distinct `key_id`; the crate refuses a key set it cannot count.
#[pyclass(frozen, module = "jcs_admit.dsse")]
pub(crate) struct Ed25519Verifier {
    inner: dsse::Ed25519Verifier,
    public_key: Vec<u8>,
}

#[pymethods]
impl Ed25519Verifier {
    #[new]
    #[pyo3(signature = (public_key, /, key_id = None))]
    fn new(py: Python<'_>, public_key: &[u8], key_id: Option<String>) -> PyResult<Self> {
        let mut inner = dsse::Ed25519Verifier::from_bytes(public_key)
            .map_err(|e| refusal::<_, DsseError>(py, &e))?;
        if let Some(id) = key_id {
            inner = inner.with_key_id(id);
        }
        let public_key = public_key_of(&inner)?;
        Ok(Self { inner, public_key })
    }

    /// The identifier this key reports, or `None`.
    #[getter]
    fn key_id(&self) -> Option<String> {
        self.inner.key_id()
    }

    /// The 32 raw bytes of the public key.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public_key)
    }

    fn __repr__(&self) -> String {
        format!(
            "Ed25519Verifier(key_id={:?}, public_key={})",
            self.inner.key_id(),
            hex(&self.public_key)
        )
    }
}

/// A payload that a threshold of trusted keys signed.
///
/// `payload` is the exact bytes the signatures covered and `payload_type` the
/// authenticated type; check the type before acting on the payload.
/// `accepted_keys` names every distinct trusted key that verified, in the order
/// the keys were supplied (a key with no identifier is named `#<n>`).
#[pyclass(frozen, module = "jcs_admit.dsse")]
pub(crate) struct VerifiedPayload {
    #[pyo3(get)]
    payload_type: String,
    #[pyo3(get)]
    payload: Py<PyBytes>,
    #[pyo3(get)]
    accepted_keys: Py<PyTuple>,
}

#[pymethods]
impl VerifiedPayload {
    fn __repr__(&self, py: Python<'_>) -> String {
        format!(
            "VerifiedPayload(payload_type={:?}, payload=<{} bytes>, accepted_keys={})",
            self.payload_type,
            self.payload.bind(py).as_bytes().len(),
            self.accepted_keys
                .bind(py)
                .repr()
                .map_or_else(|_| String::from("?"), |r| r.to_string())
        )
    }
}

/// One signer, or a sequence of them.
#[derive(FromPyObject)]
pub(crate) enum Signers<'py> {
    One(Bound<'py, Ed25519Signer>),
    Many(Vec<Bound<'py, Ed25519Signer>>),
}

/// The DSSE pre-authentication encoding of `payload_type` and `payload`.
///
/// `DSSEv1 SP LEN(type) SP type SP LEN(body) SP body`, with lengths in bytes.
#[pyfunction]
#[pyo3(signature = (payload_type, payload, /))]
pub(crate) fn pae<'py>(py: Python<'py>, payload_type: &str, payload: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &dsse::pae(payload_type, payload))
}

/// Sign `PAE(payload_type, payload)` and return the envelope's JSON bytes.
///
/// `signers` is one `Ed25519Signer` or a non-empty sequence of them; each adds
/// one signature over the same pre-image.
#[pyfunction]
#[pyo3(signature = (payload_type, payload, signers, /))]
pub(crate) fn sign<'py>(
    py: Python<'py>,
    payload_type: &str,
    payload: &[u8],
    signers: Signers<'py>,
) -> PyResult<Bound<'py, PyBytes>> {
    let held = match signers {
        Signers::One(one) => vec![one],
        Signers::Many(many) => many,
    };
    if held.is_empty() {
        // The crate would mint an envelope with an empty `signatures` list,
        // which no verifier accepts (`NoSignatures`); refuse it at minting.
        return Err(PyValueError::new_err("sign needs at least one signer"));
    }
    let concrete: Vec<&dsse::Ed25519Signer> = held.iter().map(|s| &s.get().inner).collect();
    let result = py.detach(|| {
        let refs: Vec<&dyn dsse::Signer> =
            concrete.iter().map(|s| *s as &dyn dsse::Signer).collect();
        dsse::sign_with(payload_type, payload, &refs).and_then(|envelope| envelope.to_json())
    });
    match result {
        Ok(json) => Ok(PyBytes::new(py, &json)),
        Err(e) => Err(refusal::<_, DsseError>(py, &e)),
    }
}

/// Verify `envelope` (JSON bytes) under one trusted key.
#[pyfunction]
#[pyo3(signature = (envelope, key, /))]
pub(crate) fn verify(
    py: Python<'_>,
    envelope: &[u8],
    key: Bound<'_, Ed25519Verifier>,
) -> PyResult<VerifiedPayload> {
    verify_threshold(py, envelope, vec![key], 1)
}

/// Verify `envelope` (JSON bytes), requiring `threshold` distinct trusted keys.
///
/// Counts distinct keys, never signature entries. A threshold above one needs a
/// distinct `key_id` on every key, and the crate refuses a key set it cannot
/// count.
#[pyfunction]
#[pyo3(signature = (envelope, keys, threshold, /))]
pub(crate) fn verify_threshold(
    py: Python<'_>,
    envelope: &[u8],
    keys: Vec<Bound<'_, Ed25519Verifier>>,
    threshold: usize,
) -> PyResult<VerifiedPayload> {
    let concrete: Vec<&dsse::Ed25519Verifier> = keys.iter().map(|k| &k.get().inner).collect();
    let result = py.detach(|| {
        let refs: Vec<&dyn dsse::Verifier> =
            concrete.iter().map(|k| *k as &dyn dsse::Verifier).collect();
        dsse::Envelope::from_json(envelope).and_then(|env| dsse::verify(&env, &refs, threshold))
    });
    match result {
        Ok(verified) => Ok(VerifiedPayload {
            payload_type: verified.payload_type,
            payload: PyBytes::new(py, &verified.payload).unbind(),
            accepted_keys: PyTuple::new(py, verified.accepted_keys)?.unbind(),
        }),
        Err(e) => Err(refusal::<_, DsseError>(py, &e)),
    }
}

/// Lowercase hex, for a `repr`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
