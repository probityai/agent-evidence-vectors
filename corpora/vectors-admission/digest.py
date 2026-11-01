"""This corpus's preimage, in a module that imports nothing but the standard library.

scripts/release-digests.py recomputes every corpus digest by loading the module
that owns the preimage, and a reader who cloned the tag and installed nothing has
to be able to run it. The generator imports the reference rail to derive the test
key; this module imports nothing.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def digest_of(entries: list[dict[str, Any]], read: Callable[[str], bytes]) -> str:
    """Every member's statement bytes then policy bytes, in identifier order.

    A member is a pair, so both halves are in the preimage: the same statement
    under two policies is two members with two answers, and a digest over the
    statements alone would not move when a policy did.
    """
    ordered = sorted(entries, key=lambda entry: entry["id"])
    return hashlib.sha256(
        b"".join(read(entry["file"]) + read(entry["policy"]) for entry in ordered)
    ).hexdigest()


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """The digest this corpus publishes, recomputed from the files on disk."""

    def read(rel: str) -> bytes:
        with open(os.path.join(root, rel), "rb") as fh:
            return fh.read()

    return digest_of(manifest["vectors"], read)
