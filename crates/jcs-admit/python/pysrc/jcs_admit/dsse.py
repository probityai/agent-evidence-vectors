"""DSSE envelopes and the pre-authentication encoding, bound from the ``dsse`` crate.

A signature covers ``PAE(payload_type, payload)``, so the payload type is part of
the signed bytes. Envelopes cross the boundary as their JSON bytes.

:func:`verify_threshold` counts distinct trusted keys, never signature entries,
and returns a :class:`VerifiedPayload` holding the exact bytes the signatures
covered. Check ``payload_type`` before acting on ``payload``.

A refusal raises :class:`DsseError`, whose ``variant`` and ``fields`` are the
Rust variant name and fields, unchanged.

>>> from jcs_admit import dsse
>>> signer = dsse.Ed25519Signer(bytes(range(32)), key_id="harness")
>>> envelope = dsse.sign("application/vnd.in-toto+json", b'{"a":1}', signer)
>>> dsse.verify(envelope, signer.verifier()).payload
b'{"a":1}'
"""

# _native is the compiled extension; the checker reads its .pyi stub and has no source for it
from jcs_admit._native import (  # pyright: ignore[reportMissingModuleSource]
    DSSE_VERSION,
    MAX_SIGNATURES,
    DsseError,
    Ed25519Signer,
    Ed25519Verifier,
    VerifiedPayload,
    pae,
    sign,
    verify,
    verify_threshold,
)

__all__ = [
    "DSSE_VERSION",
    "MAX_SIGNATURES",
    "DsseError",
    "Ed25519Signer",
    "Ed25519Verifier",
    "VerifiedPayload",
    "pae",
    "sign",
    "verify",
    "verify_threshold",
]
