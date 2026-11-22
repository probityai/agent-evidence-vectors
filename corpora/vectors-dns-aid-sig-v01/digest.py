"""This corpus's preimage, in a module that imports nothing but the standard library.

scripts/release-digests.py recomputes every corpus digest by loading the module
that owns the corpus's preimage, and that path has to run for a reader who
cloned the tag and installed nothing. gen_vectors.py signs the members with
ECDSA through the cryptography package, so loading it to reach one hashing
routine would put a third-party import on the verification path. The preimage
therefore lives here; gen_vectors.py and release-digests.py both load this
file, so there is still one definition. scripts/scitt-digest-isolation-test.py
holds the property by running the check with no site-packages visible.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def corpus_digest(manifest: dict[str, Any], root: str | Path = ROOT) -> str:
    """SHA-256 over the member files in identifier order, read from disk and checked."""
    base = Path(root)
    body = b""
    for entry in sorted(manifest["vectors"], key=lambda e: e["id"]):
        data = (base / entry["file"]).read_bytes()
        if _sha(data) != entry["sha256"]:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        body += data
    return _sha(body)
