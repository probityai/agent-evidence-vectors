"""The corpus file layout, written from the published format and nothing else.

Every minter in this directory imports this module and the standard library and nothing
from the corpus generators, the readers or the rail. The format restated here is the one
each corpus README publishes: a JSON file is ``json.dumps`` with two-space indentation,
sorted keys and ASCII escapes, then one newline; a case directory is listed in
``MANIFEST.json`` with the SHA-256 of every file it holds; ``corpusDigest`` is the SHA-256
of the listed entries written in that same JSON form; ``counts`` tallies the expected
decisions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def pretty(value: Any) -> bytes:
    """Return the published JSON file form of ``value``."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def write_case(out: Path, name: str, files: dict[str, bytes]) -> dict[str, str]:
    """Write one case directory under ``out/cases`` and return its file digests, by name."""
    directory = out / "cases" / name
    directory.mkdir(parents=True, exist_ok=True)
    for filename, data in files.items():
        (directory / filename).write_bytes(data)
    return {filename: sha256_hex(files[filename]) for filename in sorted(files)}


def tally(entries: list[dict[str, Any]]) -> dict[str, int]:
    """Count the expected decisions, keyed by decision word."""
    counts: dict[str, int] = {}
    for entry in entries:
        word = entry["expected"]["decision"]
        counts[word] = counts.get(word, 0) + 1
    return dict(sorted(counts.items()))


def write_manifest(out: Path, entries: list[dict[str, Any]], **top: Any) -> None:
    """Write ``MANIFEST.json`` with the entries, their digest, their counts and ``top``."""
    manifest = dict(top)
    manifest["vectors"] = entries
    manifest["corpusDigest"] = sha256_hex(pretty(entries))
    manifest["counts"] = tally(entries)
    (out / "MANIFEST.json").write_bytes(pretty(manifest))
