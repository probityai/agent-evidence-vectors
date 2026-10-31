//! `jcs_admit`: admission and RFC 8785 canonicalization through `jcs-admit`.
//!
//! The functions take `bytes` and return `bytes`. A `str` is refused with a
//! `TypeError` rather than encoded, for the reason the crate takes `&[u8]`: the
//! faults it refuses include byte sequences no `str` can hold, and an implicit
//! encode would move the check back onto the caller.

use jcs_admit::Options;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::{refusal, JcsError};

/// The `jcs-admit` release this extension links, as pinned in `Cargo.toml`.
///
/// The test suite compares it with the version Cargo resolved, so the constant
/// cannot drift from the crate actually built in.
pub(crate) const BOUND_VERSION: &str = "0.1.2";

/// Runs one admission with the interpreter released, then maps the result.
fn run(py: Python<'_>, data: &[u8], opts: &Options) -> PyResult<Py<PyBytes>> {
    // The input is immutable and borrowed from a `bytes` object this frame keeps
    // alive, so the walk over up to 20 MiB does not need to hold the interpreter.
    match py.detach(|| jcs_admit::admit_with(data, opts)) {
        Ok(canonical) => Ok(PyBytes::new(py, &canonical).unbind()),
        Err(e) => Err(refusal::<_, JcsError>(py, &e)),
    }
}

/// Builds `Options` from the keyword arguments `admit_with` and
/// `is_canonical_with` share.
fn options(
    max_depth: usize,
    max_bytes: Option<usize>,
    safe_integers: bool,
    integers_only: bool,
    reject_noncharacters: bool,
) -> Options {
    Options::rfc8785()
        .max_depth(max_depth)
        .max_bytes(max_bytes)
        .safe_integers(safe_integers)
        .integers_only(integers_only)
        .reject_noncharacters(reject_noncharacters)
}

/// Admit one JSON document and return its RFC 8785 canonical form.
///
/// Raises `JcsError` for a document the crate refuses.
#[pyfunction]
#[pyo3(signature = (data, /))]
pub(crate) fn admit(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    run(py, data, &Options::rfc8785())
}

/// Admit one JSON document under the RFC 7493 I-JSON profile.
///
/// Refuses an integer at or above 2**53 and a Unicode noncharacter, as well as
/// everything `admit` refuses.
#[pyfunction]
#[pyo3(signature = (data, /))]
pub(crate) fn admit_ijson(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    run(py, data, &Options::ijson())
}

/// Admit one JSON document under explicit options.
///
/// The defaults are RFC 8785 as written. `max_depth` saturates at
/// `MAX_SUPPORTED_DEPTH`; `max_bytes=None` removes the size cap.
#[pyfunction]
#[pyo3(signature = (
    data,
    /,
    *,
    max_depth = jcs_admit::DEFAULT_MAX_DEPTH,
    max_bytes = Some(jcs_admit::DEFAULT_MAX_BYTES),
    safe_integers = false,
    integers_only = false,
    reject_noncharacters = false,
),
// The default for `max_depth` and `max_bytes` is a constant, which PyO3 renders
// as `...`; the literals here are what `inspect.signature` shows, and the test
// suite holds them equal to the constants.
text_signature = "(data, /, *, max_depth=128, max_bytes=20971520, safe_integers=False, \
integers_only=False, reject_noncharacters=False)")]
pub(crate) fn admit_with(
    py: Python<'_>,
    data: &[u8],
    max_depth: usize,
    max_bytes: Option<usize>,
    safe_integers: bool,
    integers_only: bool,
    reject_noncharacters: bool,
) -> PyResult<Py<PyBytes>> {
    let opts = options(
        max_depth,
        max_bytes,
        safe_integers,
        integers_only,
        reject_noncharacters,
    );
    run(py, data, &opts)
}

/// Whether `data` is admissible under RFC 8785 and already its own canonical form.
#[pyfunction]
#[pyo3(signature = (data, /))]
pub(crate) fn is_canonical(py: Python<'_>, data: &[u8]) -> bool {
    py.detach(|| jcs_admit::is_canonical(data))
}

/// Whether `data` is admissible under the given options and already canonical.
///
/// A verifier should ask with the options its verify path uses: a document can
/// be canonical under RFC 8785 and refused under the I-JSON profile.
#[pyfunction]
#[pyo3(signature = (
    data,
    /,
    *,
    max_depth = jcs_admit::DEFAULT_MAX_DEPTH,
    max_bytes = Some(jcs_admit::DEFAULT_MAX_BYTES),
    safe_integers = false,
    integers_only = false,
    reject_noncharacters = false,
),
// The default for `max_depth` and `max_bytes` is a constant, which PyO3 renders
// as `...`; the literals here are what `inspect.signature` shows, and the test
// suite holds them equal to the constants.
text_signature = "(data, /, *, max_depth=128, max_bytes=20971520, safe_integers=False, \
integers_only=False, reject_noncharacters=False)")]
pub(crate) fn is_canonical_with(
    py: Python<'_>,
    data: &[u8],
    max_depth: usize,
    max_bytes: Option<usize>,
    safe_integers: bool,
    integers_only: bool,
    reject_noncharacters: bool,
) -> bool {
    let opts = options(
        max_depth,
        max_bytes,
        safe_integers,
        integers_only,
        reject_noncharacters,
    );
    py.detach(|| jcs_admit::is_canonical_with(data, &opts))
}
