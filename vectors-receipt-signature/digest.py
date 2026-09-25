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
import os
from collections.abc import Callable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def digest_of(entries: list[dict[str, Any]], read: Callable[[str], bytes]) -> str:
    """The preimage: every member's bytes, in identifier order, concatenated.

    The generator calls this over the bytes it is about to write and the
    release check calls it over the files on disk, so the two can never be two
    spellings of one rule.
    """
    ordered = sorted(entries, key=lambda entry: entry["id"])
    return hashlib.sha256(b"".join(read(entry["file"]) for entry in ordered)).hexdigest()


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """The digest this corpus publishes, recomputed from the receipts on disk."""

    def read(rel: str) -> bytes:
        with open(os.path.join(root, rel), "rb") as fh:
            return fh.read()

    return digest_of(manifest["vectors"], read)
