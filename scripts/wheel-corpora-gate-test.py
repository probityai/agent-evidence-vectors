#!/usr/bin/env python3
"""Tests for scripts/wheel-corpora-gate.py.

The gate is only worth having if it goes red when a corpus is dropped, so every
case but the first builds a small staged checkout with two corpora, ships it as
a wheel and an sdist, removes or alters one thing, and asserts the gate refuses
and NAMES the corpus. The first case is the control: a whole pair passes, so a
gate that refuses everything cannot satisfy the rest.

Usage: python3 scripts/wheel-corpora-gate-test.py
Exit 0 when every case holds; 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from _workflow_test_fixture import fixture_git

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("wheel_corpora_gate", HERE / "wheel-corpora-gate.py")
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CORPORA = ("vectors-alpha", "vectors-ietf-demo")
FILES = {
    "vectors-alpha/MANIFEST.json": b'{"a":1}',
    "vectors-alpha/cases/c1.json": b'{"case":1}',
    "vectors-alpha/gen_vectors.py": b"print('generator')",
    "vectors-ietf-demo/MANIFEST.json": b'{"i":1}',
    "vectors-ietf-demo/cases/c1.json": b'{"case":2}',
    "vectors-ietf-demo/upstream/u.json": b'{"u":1}',
}
DIGEST_LINES = "".join(
    f"{'0' * 64}  {c}/MANIFEST.json  suite  vectors=1  no-suiteRevision\n" for c in CORPORA
)


def stage(root: Path) -> None:
    fixture_git(root, "init", "-q")
    for rel, data in {**FILES, "release/CORPUS-DIGESTS.txt": DIGEST_LINES.encode()}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    fixture_git(root, "add", "-A")
    identity = ("-c", "user.name=t", "-c", "user.email=t@example.invalid")
    fixture_git(root, *identity, "commit", "-q", "-m", "s")


def artifacts(root: Path, shipped: dict[str, bytes]) -> tuple[Path, Path]:
    wheel, sdist = root.parent / "p.whl", root.parent / "p.tar.gz"
    with zipfile.ZipFile(wheel, "w") as z:
        for rel, data in shipped.items():
            if not rel.endswith(".py"):
                z.writestr(gate.PREFIX + rel, data)
    with tarfile.open(sdist, "w:gz") as t:
        for rel, data in shipped.items():
            info = tarfile.TarInfo("pkg-1.0/" + rel)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return wheel, sdist


def whole(shipped: dict[str, bytes]) -> None:
    pass


def drop_corpus(shipped: dict[str, bytes]) -> None:
    for rel in [r for r in shipped if r.startswith("vectors-ietf-demo/")]:
        del shipped[rel]


def drop_one_file(shipped: dict[str, bytes]) -> None:
    del shipped["vectors-ietf-demo/upstream/u.json"]


def alter_a_byte(shipped: dict[str, bytes]) -> None:
    shipped["vectors-alpha/cases/c1.json"] = b'{"case":9}'


CASES: list[tuple[str, Callable[[dict[str, bytes]], None], str | None]] = [
    ("a whole pair passes", whole, None),
    ("a corpus dropped from both artifacts is named", drop_corpus, "vectors-ietf-demo"),
    ("one case file dropped is named", drop_one_file, "upstream/u.json"),
    ("an altered byte is named", alter_a_byte, "differs from the checkout"),
]


def main() -> int:
    failed = 0
    for label, mutate, expect in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            stage(root)
            shipped = dict(FILES)
            mutate(shipped)
            wheel, sdist = artifacts(root, shipped)
            problems = gate.check(root, wheel, sdist)
            ok = (not problems) if expect is None else any(expect in p for p in problems)
            print(f"{'ok  ' if ok else 'FAIL'} {label}")
            failed += 0 if ok else 1
    with tempfile.TemporaryDirectory() as tmp:
        try:
            gate.check(Path(tmp), Path(tmp) / "none.whl", Path(tmp) / "none.tar.gz")
            ok = False
        except gate.Unreadable:
            ok = True
        print(f"{'ok  ' if ok else 'FAIL'} an unreadable input is inconclusive, not a pass")
        failed += 0 if ok else 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
