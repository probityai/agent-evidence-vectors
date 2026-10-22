"""Write and check INPUTS.json: the upstream source and every pinned file's SHA-256.

``python ccs_pins.py`` rewrites INPUTS.json from the files on disk. The tests compare
the committed INPUTS.json with ``render(build())``, so a vendored byte that moves, a
file that appears or a file that goes missing fails the suite.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PINS = HERE / "INPUTS.json"
FIXTURES = HERE / "fixtures" / "ccs-v1.4.0"
RESULTS = HERE / "results"
UPSTREAM_TREE = "vectors/v1.4.0-conformance"

SOURCE: dict[str, Any] = {
    "repository": "https://github.com/DSHCorrectover/ccs-conformance-vectors",
    "commit": "c848faeade7a2ad9d211cf065e0e1ef415b4a3e7",
    "tree": UPSTREAM_TREE,
    "tree_sha": "5da3c1520b5a78b342c4c60f0f1e93f2ddf6bd6e",
    "tree_sha_also_at": "effff90f231d11bb3be93d3d0d0792f36934cc78",
    "set_version": "1.4.0-conformance",
    "specification": "draft-correctover-ccs-10",
    "license": "CC0-1.0",
    "author": "Guigui Wang (Correctover)",
    "attribution": (
        "Every file under fixtures/ccs-v1.4.0/ is retained byte for byte from the "
        "commit's vectors/v1.4.0-conformance tree; LICENSE.upstream is the "
        "repository's LICENSE at the same commit. This package changes none of them."
    ),
}

TOOLS: dict[str, str] = {
    "agent-evidence-vectors": "0.18.1",
    "cryptography": "50.0.2",
    "jcs-admit": "0.1.0",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def upstream_path(rel: str) -> str:
    if rel == "LICENSE.upstream":
        return "LICENSE"
    return f"{UPSTREAM_TREE}/{rel}"


def entry(path: Path, role: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "path": path.relative_to(HERE).as_posix(),
        "sha256": digest(path),
        "bytes": path.stat().st_size,
        "role": role,
    }
    if role == "upstream":
        out["source_path"] = upstream_path(path.relative_to(FIXTURES).as_posix())
    return out


def build() -> dict[str, Any]:
    upstream = sorted(p for p in FIXTURES.rglob("*") if p.is_file())
    results = sorted(p for p in RESULTS.iterdir() if p.is_file())
    return {
        "source": SOURCE,
        "tools": TOOLS,
        "files": [entry(p, "upstream") for p in upstream] + [entry(p, "result") for p in results],
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False) + "\n"


if __name__ == "__main__":
    PINS.write_text(render(build()), encoding="ascii")
