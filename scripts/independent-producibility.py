#!/usr/bin/env python3
"""Independent producibility: a second generator, sharing no code, re-mints a corpus byte for byte.

    python3 scripts/independent-producibility.py              # every minter
    python3 scripts/independent-producibility.py vectors-open-weight-art53

The regenerability gate proves that a corpus is what ITS generator writes. That is one
implementation agreeing with itself: a defect in the generator, or a rule it encodes that
the README does not state, is reproduced every time. A vector set is a unit of conformance
only when a second implementer, reading the published case table and file layout, writes
the same bytes. This gate runs that second implementer.

Each corpus with a second generator has one file, ``tools/independent-mint/<corpus>.py``.
Before it runs, it is copied into an empty directory together with the helper modules in
``tools/independent-mint/_*.py`` and nothing else, and it is started with ``python -E -s -S``:
no environment paths, no user or site packages, and no route to this repository, so it can
import only the standard library and its own helpers. Its imports are also read from its
source and refused when they name anything else, which states the reason before the run
would fail on it.

It must write exactly the files the corpus holds as minted output: ``MANIFEST.json`` and
every file of every case directory the manifest lists. A file it does not write, a file it
writes that the corpus lacks, and a byte that differs are each named.

The census line counts the corpora with a second generator against every corpus with a
manifest. It is a report and not a refusal: corpora arrive in parallel pull requests, and a
census that refused would fail each of them for a file no one of them owns. The burn-down is
the board row the README names.

Exit 0 when every minter reproduces its corpus; 1 when one does not; 2 when a minter is
named that does not exist.
"""

from __future__ import annotations

import argparse
import ast
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MINTERS = ROOT / "tools" / "independent-mint"
CORPORA = ROOT / "corpora"


def minters(directory: Path = MINTERS) -> dict[str, Path]:
    """Return every second generator, keyed by the corpus id its file is named for."""
    return {
        path.stem: path for path in sorted(directory.glob("*.py")) if not path.name.startswith("_")
    }


def helpers(directory: Path = MINTERS) -> list[Path]:
    """Return the helper modules a minter may import."""
    return sorted(directory.glob("_*.py"))


def foreign_imports(source: str, allowed_local: set[str]) -> list[str]:
    """Return each imported top-level module that is neither standard library nor a helper."""
    tree = ast.parse(source)
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names.append("." * node.level + (node.module or ""))
            elif node.module:
                names.append(node.module.split(".")[0])
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    return sorted({name for name in names if name not in stdlib and name not in allowed_local})


def minted_files(corpus: Path) -> dict[str, bytes]:
    """Return the corpus's minted output: MANIFEST.json and every file of every listed case."""
    manifest_path = corpus / "MANIFEST.json"
    files = {"MANIFEST.json": manifest_path.read_bytes()}
    manifest = json.loads(files["MANIFEST.json"])
    for entry in manifest["vectors"]:
        directory = corpus / entry["path"]
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                files[path.relative_to(corpus).as_posix()] = path.read_bytes()
    return files


def written_files(out: Path) -> dict[str, bytes]:
    """Return every file under ``out``, keyed by its relative path."""
    return {
        path.relative_to(out).as_posix(): path.read_bytes()
        for path in sorted(out.rglob("*"))
        if path.is_file()
    }


def check_minter(corpus_id: str, minter: Path, corpora: Path = CORPORA) -> list[str]:
    """Run one minter in isolation and return each difference from the committed corpus."""
    helper_paths = helpers(minter.parent)
    local = {path.stem for path in helper_paths}
    foreign = foreign_imports(minter.read_text(encoding="utf-8"), local)
    for helper in helper_paths:
        foreign += foreign_imports(helper.read_text(encoding="utf-8"), local)
    if foreign:
        return [
            f"{corpus_id}: imports {', '.join(sorted(set(foreign)))}; a minter may import the "
            "standard library and tools/independent-mint/_*.py only"
        ]
    corpus = corpora / corpus_id
    if not (corpus / "MANIFEST.json").is_file():
        return [f"{corpus_id}: no corpora/{corpus_id}/MANIFEST.json to compare with"]
    with tempfile.TemporaryDirectory(prefix="independent-mint-") as scratch:
        source = Path(scratch) / "src"
        out = Path(scratch) / "out"
        source.mkdir()
        out.mkdir()
        for path in [*helper_paths, minter]:
            shutil.copy2(path, source / path.name)
        run = subprocess.run(
            [sys.executable, "-E", "-s", "-S", str(source / minter.name), str(out)],
            cwd=source,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
        if run.returncode != 0:
            return [
                f"{corpus_id}: the minter exited {run.returncode}: {run.stderr.strip()[-2000:]}"
            ]
        written = written_files(out)
    committed = minted_files(corpus)
    problems = [
        f"{corpus_id}: not written by the minter: {name}"
        for name in sorted(committed.keys() - written.keys())
    ]
    problems += [
        f"{corpus_id}: written by the minter, absent from the corpus: {name}"
        for name in sorted(written.keys() - committed.keys())
    ]
    problems += [
        f"{corpus_id}: bytes differ: {name}"
        for name in sorted(committed.keys() & written.keys())
        if committed[name] != written[name]
    ]
    return problems


def census(corpora: Path = CORPORA, minted: Sequence[str] = ()) -> tuple[int, int, list[str]]:
    """Return (corpora with a second generator, corpora with a manifest, the ids without one)."""
    every = sorted(path.parent.name for path in corpora.glob("*/MANIFEST.json"))
    missing = [name for name in every if name not in set(minted)]
    return len(every) - len(missing), len(every), missing


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("corpora", nargs="*", help="corpus ids (default: every minter)")
    parser.add_argument(
        "--list-missing", action="store_true", help="name every corpus with no second generator"
    )
    args = parser.parse_args(argv)
    available = minters()
    names = args.corpora or sorted(available)
    unknown = [name for name in names if name not in available]
    if unknown:
        print(f"no tools/independent-mint/<id>.py for: {', '.join(unknown)}", file=sys.stderr)
        return 2
    problems: list[str] = []
    for name in names:
        found = check_minter(name, available[name])
        print(f"{name}: {'reproduced byte for byte' if not found else f'{len(found)} differences'}")
        problems += found
    covered, total, missing = census(minted=sorted(available))
    print(f"census: {covered} of {total} corpora have a second generator")
    if args.list_missing:
        for name in missing:
            print(f"  no second generator: {name}")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
