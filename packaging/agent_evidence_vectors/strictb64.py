"""Base64 under the canonical-spelling rule, for every reader in this package.

``base64.b64decode`` ignores the bits of the last character no byte uses, so an
86-character Ed25519 signature has sixteen spellings that decode to the same
bytes, and ``validate=False`` also drops any byte outside the alphabet. A
signature, payload or key carried as text is read here only in the one spelling
an encoder writes: the text must equal the encoding of the bytes it decodes to.
Every refusal raises ``binascii.Error``, a ``ValueError``, as ``b64decode`` does.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any


def _text(value: Any) -> str:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("ascii")
    if not isinstance(value, str):
        raise TypeError("base64 text must be a string")
    return value


def std(value: Any) -> bytes:
    """Standard alphabet with padding, in its canonical spelling only."""
    text = _text(value)
    out = base64.b64decode(text, validate=True)
    if base64.b64encode(out).decode("ascii") != text:
        raise binascii.Error("non-canonical base64")
    return out


def url(value: Any) -> bytes:
    """URL-safe alphabet without padding (RFC 7515), in its canonical spelling only."""
    text = _text(value)
    if "=" in text:
        raise binascii.Error("padded base64url")
    out = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(out).decode("ascii").rstrip("=") != text:
        raise binascii.Error("non-canonical base64url")
    return out
