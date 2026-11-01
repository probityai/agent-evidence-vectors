"""This corpus's preimage, in a module that imports nothing but the standard library.

scripts/release-digests.py recomputes every corpus digest by loading the module
that owns the preimage. The generator signs receipts and imports cryptography,
so loading it to reach one hashing routine made `release-digests.py --check`
fail for a reader who cloned the tag and installed nothing. The routine lives
here, the generator imports it, and verification needs the standard library
alone.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def canonical_context(context: dict[str, Any]) -> bytes:
    """A member's context in RFC 8785 form: its members are ASCII strings and a
    list of them, so sorted keys and no whitespace are the RFC's bytes."""
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("ascii")


def member_preimage(entry: dict[str, Any], read: Callable[[str], bytes]) -> bytes:
    """What one member contributes, and what its identifier is the digest of.

    A member without a context is its receipt's bytes. A member with one is the
    receipt's bytes, then its context canonicalized, then the bytes of the
    commitment the context names, so two members that present one receipt in
    two chains, or against two commitments, are two members with two
    identifiers. The receipts a chain names are members of their own and are
    bound by their identifiers.
    """
    body = read(entry["file"])
    context = entry.get("context")
    if context is None:
        return body
    commitment = context.get("commitment")
    return body + canonical_context(context) + (read(commitment) if commitment else b"")


def member_id(entry: dict[str, Any], read: Callable[[str], bytes]) -> str:
    return "v" + hashlib.sha256(member_preimage(entry, read)).hexdigest()[:16]


def digest_of(entries: list[dict[str, Any]], read: Callable[[str], bytes]) -> str:
    """The preimage: every member's preimage, in identifier order, concatenated.

    The generator calls this over the bytes it is about to write and the
    release check calls it over the files on disk, so the two can never be two
    spellings of one rule.
    """
    ordered = sorted(entries, key=lambda entry: entry["id"])
    return hashlib.sha256(b"".join(member_preimage(e, read) for e in ordered)).hexdigest()


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """The digest this corpus publishes, recomputed from the files on disk."""

    def read(rel: str) -> bytes:
        with open(os.path.join(root, rel), "rb") as fh:
            return fh.read()

    return digest_of(manifest["vectors"], read)
