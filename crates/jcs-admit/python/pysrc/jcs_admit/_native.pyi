# Type stub for the compiled extension. CI runs `python -m mypy.stubtest
# jcs_admit._native` against the built module, so a binding change that is not
# reflected here fails the build.

from collections.abc import Sequence
from typing import Any, Final, final

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_DEPTH",
    "DSSE_VERSION",
    "DsseError",
    "Ed25519Signer",
    "Ed25519Verifier",
    "JCS_ADMIT_VERSION",
    "JcsError",
    "MAX_SIGNATURES",
    "MAX_SUPPORTED_DEPTH",
    "VerifiedPayload",
    "admit",
    "admit_ijson",
    "admit_with",
    "is_canonical",
    "is_canonical_with",
    "pae",
    "sign",
    "verify",
    "verify_threshold",
]

DEFAULT_MAX_DEPTH: Final[int]
MAX_SUPPORTED_DEPTH: Final[int]
DEFAULT_MAX_BYTES: Final[int]
JCS_ADMIT_VERSION: Final[str]
MAX_SIGNATURES: Final[int]
DSSE_VERSION: Final[str]

class JcsError(ValueError):
    variant: str
    fields: Any

def admit(data: bytes, /) -> bytes: ...
def admit_ijson(data: bytes, /) -> bytes: ...
def admit_with(
    data: bytes,
    /,
    *,
    max_depth: int = 128,
    max_bytes: int | None = 20971520,
    safe_integers: bool = False,
    integers_only: bool = False,
    reject_noncharacters: bool = False,
) -> bytes: ...
def is_canonical(data: bytes, /) -> bool: ...
def is_canonical_with(
    data: bytes,
    /,
    *,
    max_depth: int = 128,
    max_bytes: int | None = 20971520,
    safe_integers: bool = False,
    integers_only: bool = False,
    reject_noncharacters: bool = False,
) -> bool: ...

class DsseError(ValueError):
    variant: str
    fields: Any

@final
class Ed25519Signer:
    def __new__(cls, secret_key: bytes, /, key_id: str | None = None) -> Ed25519Signer: ...
    @property
    def key_id(self) -> str | None: ...
    @property
    def public_key(self) -> bytes: ...
    def verifier(self) -> Ed25519Verifier: ...

@final
class Ed25519Verifier:
    def __new__(cls, public_key: bytes, /, key_id: str | None = None) -> Ed25519Verifier: ...
    @property
    def key_id(self) -> str | None: ...
    @property
    def public_key(self) -> bytes: ...

@final
class VerifiedPayload:
    @property
    def payload_type(self) -> str: ...
    @property
    def payload(self) -> bytes: ...
    @property
    def accepted_keys(self) -> tuple[str, ...]: ...

def pae(payload_type: str, payload: bytes, /) -> bytes: ...
def sign(
    payload_type: str, payload: bytes, signers: Ed25519Signer | Sequence[Ed25519Signer], /
) -> bytes: ...
def verify(envelope: bytes, key: Ed25519Verifier, /) -> VerifiedPayload: ...
def verify_threshold(
    envelope: bytes, keys: Sequence[Ed25519Verifier], threshold: int, /
) -> VerifiedPayload: ...
