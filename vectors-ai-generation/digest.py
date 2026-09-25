"""This corpus's preimage, in a module that imports nothing but the standard library.

The generator signs its members with Ed25519 and so needs a third-party library;
verifying a published release must not. The preimage therefore lives here, where
a machine that installed nothing can reach it, and the generator imports it
rather than spelling it a second time.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def ordered_digest(entries: list[dict[str, Any]], read: Callable[[str], bytes]) -> str:
    """sha256 over every member's file bytes, concatenated in identifier order."""
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda entry: entry["id"]):
        digest.update(read(entry["file"]))
    return digest.hexdigest()


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """The digest of the member files on disk under root."""

    def read(rel: str) -> bytes:
        with open(os.path.join(root, rel), "rb") as handle:
            return handle.read()

    return ordered_digest(manifest["vectors"], read)
