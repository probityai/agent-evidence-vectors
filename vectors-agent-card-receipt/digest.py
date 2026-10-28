"""This corpus's preimage, in a module that imports nothing but the standard library.

scripts/release-digests.py recomputes every corpus digest by loading the module
that owns the preimage. gen_vectors.py imports `cryptography` to sign the cases,
so a reader who cloned the tag and installed nothing could not verify the release
through it. The preimage lives here, gen_vectors.py imports it, and the release
check reaches it through the standard library alone. See
vectors-scitt-cose/digest.py for the same split and scripts/scitt-digest-isolation-test.py
for the check that holds it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def enc(value: object) -> bytes:
    """The committed form of every JSON file in a case."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return sha(enc(entries))
