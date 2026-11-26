"""This corpus's preimage, in a module that imports nothing but the standard library.

scripts/release-digests.py recomputes every corpus digest by loading the module that owns
that corpus's preimage. For this corpus that cannot be gen_vectors.py: the generator signs
the mandates with the `cryptography` package, so loading it for one hashing routine would put
a third-party dependency on the path that has to work for somebody who installed nothing.
Generation may depend on what it needs; verification may not. The generator loads this file
by path and calls it, so the preimage is spelled once, here, and
scripts/scitt-digest-isolation-test.py holds the property by running the check where no
third-party package is visible.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_hex(data: bytes) -> str:
    """The hex SHA-256 of these bytes."""
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    """The bytes this corpus writes for a JSON value: sorted keys, two-space indent, ASCII."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def entries_digest(entries: list[dict[str, Any]]) -> str:
    """The corpus digest over manifest entries whose file digests are already recomputed."""
    return sha256_hex(json_bytes(entries))


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: sha256_hex((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return entries_digest(entries)
