"""Admission and RFC 8785 canonicalization, bound from the ``jcs-admit`` crate.

Every function takes ``bytes``. A ``str`` raises ``TypeError``: the refusals
this module exists for include byte sequences that no ``str`` can hold.

A refusal raises :class:`JcsError`. ``error.variant`` is the Rust variant name
(``"DuplicateMember"``, ``"TooDeep"`` and so on) and ``error.fields`` its fields
with their Rust names, the same pair the crate serializes and the npm package
reports.

``jcs_admit.dsse`` signs and verifies DSSE envelopes through the ``dsse``
crate, linked into the same extension.

>>> import jcs_admit
>>> jcs_admit.admit(b'{ "b": 1, "a": [1.0, 1e30] }')
b'{"a":[1,1e+30],"b":1}'
"""

from importlib.metadata import version as _version

from jcs_admit import dsse
# _native is the compiled extension; the checker reads its .pyi stub and has no source for it
from jcs_admit._native import (  # pyright: ignore[reportMissingModuleSource]
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    JCS_ADMIT_VERSION,
    MAX_SUPPORTED_DEPTH,
    JcsError,
    admit,
    admit_ijson,
    admit_with,
    is_canonical,
    is_canonical_with,
)

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_DEPTH",
    "JCS_ADMIT_VERSION",
    "MAX_SUPPORTED_DEPTH",
    "JcsError",
    "admit",
    "admit_ijson",
    "admit_with",
    "is_canonical",
    "is_canonical_with",
    "dsse",
]

__version__ = _version("jcs-admit")
