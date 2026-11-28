"""This corpus's preimage, in a module that imports nothing but the standard library.

scripts/release-digests.py recomputes every corpus digest by loading the module that owns that
corpus's preimage. gen_vectors.py imports the ``cryptography`` package at module scope, so loading
it would put a third-party package on the one path that must run for somebody who installed
nothing. The preimage lives here, gen_vectors.py loads it by path, and release-digests.py loads it
the same way: one definition, reached through the standard library alone.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entries_digest(entries: list[dict[str, Any]]) -> str:
    """The digest of the manifest entries, each carrying its files' digests."""
    return _sha((json.dumps(entries, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode())


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not from their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return entries_digest(entries)
