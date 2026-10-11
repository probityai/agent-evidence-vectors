#!/usr/bin/env python3
"""Exercise the gate on the real built source archive and independent mutations."""

from __future__ import annotations

import argparse
import io
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path


def run(root: Path, dist: Path, reason: str | None) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/package-boundary-gate.py"),
            "--root",
            str(root),
            "--dist",
            str(dist),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if reason is None:
        assert result.returncode == 0, result.stdout + result.stderr
    else:
        assert result.returncode == 1 and reason in result.stdout, result.stdout + result.stderr


def altered(
    source: Path,
    target: Path,
    transform: Callable[[str, bytes], bytes | None],
    target_name: str | None,
    injected_name: str | None = None,
) -> None:
    with tarfile.open(source, "r:gz") as original, tarfile.open(target, "w:gz") as changed:
        prefix = ""
        for member in original:
            prefix = member.name.split("/", 1)[0]
            if member.isdir():
                changed.addfile(member)
                continue
            stream = original.extractfile(member)
            assert stream is not None
            with stream:
                if member.name.split("/", 1)[1] != target_name:
                    changed.addfile(member, stream)
                    continue
                data = stream.read()
            replacement = transform(member.name.split("/", 1)[1], data)
            if replacement is not None:
                member.size = len(replacement)
                changed.addfile(member, io.BytesIO(replacement))
        if injected_name:
            member = tarfile.TarInfo(prefix + "/" + injected_name)
            member.size = 12
            changed.addfile(member, io.BytesIO(b"unexpected\n\n"))


def source_change(_name: str, data: bytes) -> bytes:
    return data + b"\n"


def missing_criterion(name: str, data: bytes) -> bytes | None:
    return None if name == "spec/predicates/observed-effect.md" else data


def dependency_change(name: str, data: bytes) -> bytes:
    if name != "PKG-INFO":
        return data
    assert b"\n\n" in data
    return data.replace(b"\n\n", b"\nRequires-Dist: undeclared-runtime-dependency\n\n", 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args()
    root, dist = args.root.resolve(), args.dist.resolve()
    sources = list(dist.glob("*.tar.gz"))
    assert len(sources) == 1, "controls need the actual built sdist"
    source = sources[0]
    run(root, dist, None)
    documentation = tomllib.loads((root / "pyproject.toml").read_text())["project"]["urls"][
        "Documentation"
    ].encode()

    def url_change(name: str, data: bytes) -> bytes:
        if name != "PKG-INFO":
            return data
        assert documentation in data
        return data.replace(documentation, b"https://invalid.example/wrong-documentation", 1)

    controls = [
        ("research-artifact", lambda _name, data: data, None, "docs/research/reintroduced.md"),
        ("source-missing", missing_criterion, "spec/predicates/observed-effect.md", None),
        ("source-bytes", source_change, "vectors/MANIFEST.json", None),
        ("source-bytes", source_change, ".gitignore", None),
        ("source-unlisted", lambda _name, data: data, None, "docs/operator-private.md"),
        ("metadata-urls", url_change, "PKG-INFO", None),
        ("metadata-dependencies", dependency_change, "PKG-INFO", None),
    ]
    with tempfile.TemporaryDirectory(prefix="aev-package-boundary-") as directory:
        for index, (reason, transform, target_name, injected_name) in enumerate(controls):
            case = Path(directory) / str(index)
            case.mkdir()
            altered(source, case / source.name, transform, target_name, injected_name)
            run(root, case, reason)
    print("OK: actual built sdist passed; seven independent artifact mutations were refused")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
