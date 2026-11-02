"""This corpus's preimage, in a module that imports nothing but the standard library.

One definition of the corpus digest, reachable from a machine that installed
nothing, because verifying a published release must not require the signing
stack that produced it. A member's bytes are its envelope followed by its
disclosed arguments when it carries any: the arguments are an input a verifier
reads, so a change to them is a change to the corpus.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def _read(root: str, rel: str) -> bytes:
    with open(os.path.join(root, rel), "rb") as fh:
        return fh.read()


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """sha256 over every member's envelope and arguments, in identifier order."""
    parts: list[bytes] = []
    for entry in sorted(manifest["vectors"], key=lambda entry: entry["id"]):
        parts.append(_read(root, entry["file"]))
        if "arguments" in entry:
            parts.append(_read(root, entry["arguments"]))
    return hashlib.sha256(b"".join(parts)).hexdigest()
