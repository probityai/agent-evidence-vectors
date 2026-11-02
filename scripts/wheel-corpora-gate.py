#!/usr/bin/env python3
"""Refuse a wheel or sdist that lacks, or alters, a corpus the signed digest list names.

``release/CORPUS-DIGESTS.txt`` is signed and names every corpus the release
claims. The wheel and the sdist are built from two separate lists in
``pyproject.toml``, and the wheel is built from the sdist, so a corpus missing
from the sdist list is missing from the published wheel even though the wheel
list names it. The 0.22.0 through 0.29.1 wheels shipped without the IETF
corpus for that reason, and the replay step could not see it because it only
replays what the wheel carries.

For every corpus row in the digest list this gate requires, in both artifacts,
every tracked non-Python file of that corpus directory, with the same SHA-256
as the file in the checkout. The digest list itself is held to the checkout
bytes by ``release-digests.py --check``, so the chain is: signed list, checkout
bytes, shipped bytes.

Usage: python3 scripts/wheel-corpora-gate.py <wheel> <sdist> [--root DIR]
Exit 0 when every corpus is whole in both artifacts; 1 and name each gap
otherwise; 2 when an input cannot be read (the check did not run).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

PREFIX = "agent_evidence_vectors/corpora/"
DIGESTS = "release/CORPUS-DIGESTS.txt"
TREE_PREFIX = "corpora/"


def _tracked_manifests():
    """The one place that knows where a corpus sits: release-digests.py."""
    path = Path(__file__).resolve().parent / "release-digests.py"
    spec = importlib.util.spec_from_file_location("release_digests", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("release_digests", module)
    spec.loader.exec_module(module)
    return module.tracked_manifests


class Unreadable(Exception):
    """An input could not be read, so the check could not run."""


def listed_corpora(root: Path) -> list[str]:
    try:
        lines = (root / DIGESTS).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise Unreadable(f"{DIGESTS}: {exc}") from exc
    rows = [line.split() for line in lines if line.strip() and not line.startswith("#")]
    if not rows:
        raise Unreadable(f"{DIGESTS} names no corpus")
    return sorted(row[1].split("/")[0] for row in rows)


def corpus_directory(root: Path, corpus: str) -> str:
    """The repository directory of a listed corpus, at the root or under corpora/."""
    try:
        manifests = _tracked_manifests()(root)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Unreadable(f"git ls-files */MANIFEST.json: {exc}") from exc
    for listed, repo_path in manifests:
        if listed.split("/")[0] == corpus:
            return repo_path.rsplit("/", 1)[0]
    return corpus


def wheel_key(rel: str) -> str:
    """The path inside agent_evidence_vectors/corpora/ for a tracked file."""
    return rel.removeprefix(TREE_PREFIX)


def tracked_files(root: Path, corpus: str) -> list[str]:
    directory = corpus_directory(root, corpus)
    try:
        out = subprocess.run(
            ["git", "ls-files", "--", directory],
            cwd=root, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Unreadable(f"git ls-files {corpus}: {exc}") from exc
    return [f for f in out.splitlines() if not f.endswith(".py")]


def wheel_digests(wheel: Path) -> dict[str, str]:
    try:
        with zipfile.ZipFile(wheel) as z:
            return {
                n[len(PREFIX):]: hashlib.sha256(z.read(n)).hexdigest()
                for n in z.namelist()
                if n.startswith(PREFIX) and not n.endswith("/")
            }
    except (OSError, zipfile.BadZipFile) as exc:
        raise Unreadable(f"{wheel}: {exc}") from exc


def sdist_digests(sdist: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    try:
        with tarfile.open(sdist) as t:
            for member in t.getmembers():
                if not member.isfile() or "/" not in member.name:
                    continue
                handle = t.extractfile(member)
                if handle is not None:
                    found[member.name.split("/", 1)[1]] = hashlib.sha256(handle.read()).hexdigest()
    except (OSError, tarfile.TarError) as exc:
        raise Unreadable(f"{sdist}: {exc}") from exc
    return found


def check(root: Path, wheel: Path, sdist: Path) -> list[str]:
    in_wheel, in_sdist = wheel_digests(wheel), sdist_digests(sdist)
    failures: list[str] = []
    for corpus in listed_corpora(root):
        files = tracked_files(root, corpus)
        if not files:
            failures.append(f"{corpus} is listed in {DIGESTS} but has no tracked file")
        for rel in files:
            want = hashlib.sha256((root / rel).read_bytes()).hexdigest()
            for label, shipped in (("wheel", in_wheel), ("sdist", in_sdist)):
                got = shipped.get(wheel_key(rel) if label == "wheel" else rel)
                if got is None:
                    failures.append(f"{corpus}: {rel} is not in the {label}")
                elif got != want:
                    failures.append(f"{corpus}: {rel} in the {label} differs from the checkout")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check a wheel and sdist against the corpus list")
    parser.add_argument("wheel", type=Path)
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    try:
        failures = check(args.root, args.wheel, args.sdist)
        count = len(listed_corpora(args.root))
    except Unreadable as exc:
        print(f"INCONCLUSIVE: {exc}")
        return 2
    for line in failures:
        print(f"FAIL: {line}")
    print(f"{count} corpora listed; {len(failures)} gap(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
