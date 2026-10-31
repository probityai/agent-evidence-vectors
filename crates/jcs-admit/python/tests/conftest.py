"""Shared fixtures: where the bound crates' own sources live.

The extension links exact releases of `jcs-admit` and `dsse` from crates.io.
These tests read each release's own vector files out of the Cargo registry,
located through `cargo metadata` against the committed lockfile, so the corpus
under test is byte for byte the one that shipped with the code under test.
"""

from __future__ import annotations

import functools
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent.parent / "Cargo.toml"


@dataclass(frozen=True)
class Crate:
    name: str
    version: str
    root: Path


@functools.cache
def bound_crate(name: str) -> Crate:
    """The registry source of the crate `name` this extension resolved to."""
    out = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
            str(MANIFEST),
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout
    packages = [p for p in json.loads(out)["packages"] if p["name"] == name]
    assert len(packages) == 1, f"expected one resolved {name}, found {len(packages)}"
    pkg = packages[0]
    root = Path(pkg["manifest_path"]).parent
    assert root.is_dir(), f"{name} source is not on disk at {root}"
    return Crate(name=name, version=pkg["version"], root=root)


def data_lines(path: Path) -> list[str]:
    """Non-comment, non-blank lines of a tab-separated vector file."""
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert lines, f"{path} yielded no rows; a corpus that reads nothing passes vacuously"
    return lines
