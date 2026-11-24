"""This corpus's preimage, for scripts/release-digests.py, with the standard library alone.

The digest is the SHA-256 of every case's record.json and context.json, read
back from disk and concatenated in sorted path order. check_vectors.py and
gen_vectors.py compute the same value, so a changed file changes all three.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

FILES = ("record.json", "context.json")


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    base = Path(root)
    paths = [f"{entry['path']}/{name}" for entry in manifest["vectors"] for name in FILES]
    return hashlib.sha256(b"".join((base / p).read_bytes() for p in sorted(paths))).hexdigest()
