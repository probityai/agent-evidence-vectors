"""This corpus's preimage, in a module that imports nothing but the standard library.

The generator signs its members with Ed25519 and so needs a third-party library;
verifying a published release must not. The preimage therefore lives here, where
a machine that installed nothing can reach it, and the generator imports it
rather than spelling it a second time.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """sha256 over every member's file bytes, concatenated in identifier order."""
    digest = hashlib.sha256()
    for entry in sorted(manifest["vectors"], key=lambda entry: entry["id"]):
        with open(os.path.join(root, entry["file"]), "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()
