#!/usr/bin/env python3
"""Copy the RFC 8785 vector files into the jcsvectors Go module.

A Go package can embed only files under its own directory, and ``corpora/`` is a
separate sentinel module that the module proxy never serves. So the Go module
carries byte copies of the two corpora it publishes, written here and checked by
``scripts/regenerability-gate.py``, which runs this script on a copy of the tree
and refuses any copied file that differs from what it writes.

The set copied is exactly what each source declares: the a2a corpus's
MANIFEST.json and every file its ``vectors`` list names, and the byte corpus's
cases.json. Nothing else in either directory is copied.

Usage (from the repository root):
    python3 scripts/gen-jcsvectors-data.py
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "jcsvectors"
A2A = "vectors-a2a-jcs-v01"
BYTES = "jcs-byte-vectors"


def sources() -> list[Path]:
    """Every source file to copy, relative to ``corpora/``."""
    manifest = json.loads((ROOT / "corpora" / A2A / "MANIFEST.json").read_text("utf-8"))
    files = [Path(A2A) / "MANIFEST.json"]
    files += [Path(A2A) / entry["path"] for entry in manifest["vectors"]]
    files.append(Path(BYTES) / "cases.json")
    return files


def main() -> int:
    for corpus in (A2A, BYTES):
        shutil.rmtree(DEST / corpus, ignore_errors=True)
    for rel in sources():
        target = DEST / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "corpora" / rel, target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
