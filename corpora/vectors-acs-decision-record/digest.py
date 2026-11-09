"""The control-decision corpus digest, with no third-party import.

SHA-256 over one line per member, ``<path> <sha256 of the file>``, in manifest order.
It lives apart from the generator so a reader who installed nothing can recompute it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    lines = []
    for entry in manifest["vectors"]:
        data = (Path(root) / entry["path"]).read_bytes()
        lines.append(f"{entry['path']} {hashlib.sha256(data).hexdigest()}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()
