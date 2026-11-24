"""The one host our identifiers are written under, and the two they are read under.

A signed record cannot be edited without breaking its signature, so every record
already issued keeps the identifiers it was signed with, under
``https://probityai.github.io/``, forever. From the release that flips
``IDENTIFIER_HOST``, new records carry ``https://probityai.org/``. Both hosts are
ours: GitHub serves the old one for the probityai organisation and forwards every
path on it to the same path on the new one, which is verified for that
organisation. So the two spellings name one type, and a verifier that accepted
only one would reject either every record already issued or every record issued
from now on. Accepting both widens nothing an attacker controls: an identifier is
a label, not a credential, and trust comes from the signature and the key, which
this code does not change. The match is byte-exact on the scheme and the host; no
other spelling is recognised.

So:

* every identifier this package WRITES is built through :func:`identifier`, which
  uses ``IDENTIFIER_HOST``. It is still the old host, so no emitted byte changes
  until a release flips it;
* every identifier a reader takes from a RECORD is compared through
  :func:`canonical_identifier` (or :func:`same_identifier`), which maps both
  recognised hosts to ``IDENTIFIER_HOST`` and leaves every other string alone;
* what a reader reports back (an echoed type, a receipt field) stays the record's
  own bytes, and signed bytes are never touched.

``http://``, ``www.``, a port, a trailing dot, upper case, userinfo,
``probityai.org.example``, ``probityai.organisation`` and every other spelling
stay unrecognised and keep failing exactly as they fail today. The pairs every
implementation must reproduce are ``spec/identifiers/host-equivalence.json``.
"""

from __future__ import annotations

from typing import TypeVar, cast

__all__ = [
    "IDENTIFIER_HOST",
    "RECOGNISED_HOSTS",
    "canonical_identifier",
    "identifier",
    "same_identifier",
]

#: The host every identifier we write uses.
IDENTIFIER_HOST = "probityai.github.io"
#: The hosts whose identifiers we read as ours, oldest first.
RECOGNISED_HOSTS = ("probityai.github.io", "probityai.org")


def identifier(path: str) -> str:
    """``https://<IDENTIFIER_HOST>/<path>``: how every identifier constant is built."""
    return f"https://{IDENTIFIER_HOST}/{path}"


_T = TypeVar("_T")


def canonical_identifier(value: _T) -> _T:
    """The identifier ``value`` names, spelled under ``IDENTIFIER_HOST``.

    A string that starts with exactly ``https://<h>/`` for a host ``h`` in
    ``RECOGNISED_HOSTS`` comes back with that prefix replaced by
    ``https://<IDENTIFIER_HOST>/`` and the rest unchanged. Anything else, a
    non-string included, comes back as it was, so a comparison that failed
    before still fails.

    The result has the type of the argument: a string stays a string, and an
    untyped record member stays untyped. A signature that said ``object`` would
    refuse every caller that looks the answer up in a table keyed by string.
    """
    if isinstance(value, str):
        for host in RECOGNISED_HOSTS:
            prefix = f"https://{host}/"
            if value.startswith(prefix):
                return cast(_T, f"https://{IDENTIFIER_HOST}/{value[len(prefix) :]}")
    return value


def same_identifier(a: object, b: object) -> bool:
    """Whether ``a`` and ``b`` name one identifier under the recognised hosts."""
    return bool(canonical_identifier(a) == canonical_identifier(b))
