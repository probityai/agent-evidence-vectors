"""This corpus's preimage, in a module that imports nothing but the standard library.

Why this file exists rather than a function inside gen_vectors.py: the sibling
corpora record the reason and it holds here unchanged. A second spelling of one
preimage drifts from the first, and a release signature over a drifted digest
certifies the drift instead of the corpus. So the preimage has exactly one
definition, and the definition is reachable from a machine that installed
nothing, because verifying a published release must not require the signing
stack that produced it.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """sha256 over every member's bytes, concatenated in identifier order."""
    return hashlib.sha256(
        b"".join(
            open(os.path.join(root, entry["file"]), "rb").read()
            for entry in sorted(manifest["vectors"], key=lambda entry: entry["id"])
        )
    ).hexdigest()
