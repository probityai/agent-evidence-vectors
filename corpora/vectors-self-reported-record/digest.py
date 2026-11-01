"""This corpus's preimage, in a module that imports nothing but the standard library.

`scripts/release-digests.py` recomputes every corpus digest by loading the module
that owns that corpus's preimage and calling it, rather than restating the
concatenation itself: a second spelling of one preimage drifts from the first,
and a release signature over a drifted digest certifies the drift instead of the
corpus.

For most corpora here the owning module is the generator. For this one it cannot
be, for the reason `vectors-scitt-cose/digest.py` records: this generator signs,
so it imports a signing library, and loading it to reach one hashing routine puts
that library on the one path that must have no dependency at all. Verifying a
published release has to work for somebody who installed nothing.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """sha256 over every member's bytes, concatenated in identifier order.

    Identifier order rather than manifest order: manifest order is editable and
    the digest must not be.
    """
    digest = hashlib.sha256()
    for entry in sorted(manifest["vectors"], key=lambda entry: entry["id"]):
        with open(os.path.join(root, entry["file"]), "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()
