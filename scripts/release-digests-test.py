#!/usr/bin/env python3
"""Tests for scripts/release-digests.py.

Every case but one asserts a REFUSAL, and each refusal is asserted to NAME the
thing it is about. A generator that writes a digest list cannot be tested by
running it and reading the output: the output is exactly what it wrote, so the
only interesting question is what it does when the tree disagrees with itself.

Every case runs against a STAGED COPY of this repository, never against the
repository itself. The copy is a real git checkout because the corpora are
enumerated with `git ls-files`: a plain directory copy would present an empty
list, and the generator would then refuse for the right reason by accident,
which proves nothing about the case being tested.

Usage: uv run --extra dev python scripts/release-digests-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from _workflow_test_fixture import fixture_git

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "release-digests.py"

OUTPUT = "release/CORPUS-DIGESTS.txt"
AEE_MANIFEST = "vectors/MANIFEST.json"
AGENT_MANIFEST = "vectors-ai-agent-action/MANIFEST.json"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


def stage(destination: Path) -> None:
    """Copy the tracked tree into a fresh git checkout."""
    for rel in fixture_git(REPO_ROOT, "ls-files", "-z").split("\0"):
        if not rel:
            continue
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    fixture_git(destination, "init", "-q")
    fixture_git(destination, "add", "-A")


def edit_json(root: Path, rel: str, change: Callable[[dict[str, Any]], None]) -> None:
    path = root / rel
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def declared_digest_typo(root: Path) -> None:
    """The manifest declares a digest the files do not hash to."""
    edit_json(root, AEE_MANIFEST, lambda d: d.update(corpusDigest="0" * 64))


def vector_edited(root: Path) -> None:
    """A vector file changes without the manifest being regenerated."""
    statements = sorted((root / "vectors" / "statements").glob("*.json"))
    first = statements[0]
    document = json.loads(first.read_text(encoding="utf-8"))
    document["_mutation"] = "one byte of one vector, and the corpus digest moves"
    first.write_text(json.dumps(document) + "\n", encoding="utf-8")


def agent_action_edited(root: Path) -> None:
    """The second corpus is covered too, and by its own preimage."""
    statements = sorted((root / "vectors-ai-agent-action" / "statements").glob("*.json"))
    first = statements[0]
    first.write_text(first.read_text(encoding="utf-8").replace("{", "{ ", 1), encoding="utf-8")


def unregistered_corpus(root: Path) -> None:
    """A third corpus arrives with no routine that owns its preimage."""
    directory = root / "vectors-unregistered"
    directory.mkdir()
    (directory / "MANIFEST.json").write_text(
        json.dumps({"suite": "invented", "corpusDigest": "1" * 64, "vectors": []}) + "\n",
        encoding="utf-8",
    )
    fixture_git(root, "add", "-A")


def suite_name_removed(root: Path) -> None:
    """A corpus whose line would not say what it is."""
    edit_json(root, AGENT_MANIFEST, lambda d: d.pop("suite", None))


def unregistered_space(root: Path) -> None:
    unregistered_corpus(root)
    fixture_git(root, "mv", "vectors-unregistered", "vectors unregistered")


def unregistered_newline(root: Path) -> None:
    unregistered_corpus(root)
    fixture_git(root, "mv", "vectors-unregistered", "vectors\nunregistered")


REFUSALS: tuple[Case, ...] = (
    (
        "a declared digest the files do not produce",
        declared_digest_typo,
        (AEE_MANIFEST, "0000000000"),
    ),
    ("an edited vector", vector_edited, (AEE_MANIFEST, "Regenerate")),
    ("an edited agent-action vector", agent_action_edited, (AGENT_MANIFEST,)),
    ("an unregistered corpus", unregistered_corpus, ("RECOMPUTERS", "vectors-unregistered")),
    (
        "an unregistered corpus with a space",
        unregistered_space,
        ("RECOMPUTERS", "vectors unregistered"),
    ),
    (
        "an unregistered corpus with a newline",
        unregistered_newline,
        ("RECOMPUTERS", "vectors\nunregistered"),
    ),
    ("a corpus with no suite name", suite_name_removed, (AGENT_MANIFEST, "names no suite")),
)


def check_generate(name: str, mutate: Mutation, wanted: tuple[str, ...], tmp: Path) -> list[str]:
    """Run the generator over a mutated copy and require a refusal that names it."""
    failures: list[str] = []
    root = tmp / name.replace(" ", "-")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    stage(root)
    mutate(root)
    done = subprocess.run(
        [sys.executable, str(GENERATOR), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = done.stdout + done.stderr
    if done.returncode == 0:
        failures.append(f"{name}: the generator wrote a digest list anyway.\n{output}")
        return failures
    missing = [want for want in wanted if want not in output]
    if missing:
        failures.append(
            f"{name}: the right exit status, and the refusal does not name {missing!r}. "
            f"A refusal that names the wrong thing sends the next person to the wrong "
            f"file.\n{output}"
        )
    return failures


def check_stale_file(tmp: Path) -> list[str]:
    """`--check` refuses a digest list that is out of date, and says so."""
    root = tmp / "stale"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    stage(root)
    path = root / OUTPUT
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    lines[-1] = "f" * 64 + lines[-1][64:]
    path.write_text("".join(lines), encoding="utf-8")
    done = subprocess.run(
        [sys.executable, str(GENERATOR), "--check", "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = done.stdout + done.stderr
    if done.returncode == 0:
        return [f"stale: --check accepted a digest list nothing produces.\n{output}"]
    if "recomputed" not in output or "on disk" not in output:
        return [f"stale: the refusal does not show the difference it found.\n{output}"]
    return []


def check_absent_file(tmp: Path) -> list[str]:
    """`--check` refuses an absent file rather than treating it as agreeing."""
    root = tmp / "absent"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    stage(root)
    (root / OUTPUT).unlink()
    done = subprocess.run(
        [sys.executable, str(GENERATOR), "--check", "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = done.stdout + done.stderr
    if done.returncode == 0:
        return [f"absent: --check passed with no file to check.\n{output}"]
    if "does not exist" not in output:
        return [f"absent: the refusal does not say the file is missing.\n{output}"]
    return []


def check_round_trip(tmp: Path) -> list[str]:
    """The accepting case: an untouched tree writes the file it already has.

    A gate nobody can satisfy gets deleted, and a generator that is not stable
    across runs cannot be signed: the second run would invalidate the first
    run's signature for no reason anybody caused.
    """
    root = tmp / "clean"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    stage(root)
    before = (root / OUTPUT).read_text(encoding="utf-8")
    done = subprocess.run(
        [sys.executable, str(GENERATOR), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        return [f"clean: the generator refused an untouched tree.\n{done.stdout}{done.stderr}"]
    after = (root / OUTPUT).read_text(encoding="utf-8")
    if before != after:
        return [
            "clean: regenerating an untouched tree produced different bytes, so the "
            f"file is not stable and a signature over it would not survive a rerun.\n"
            f"before:\n{before}\nafter:\n{after}"
        ]
    checked = subprocess.run(
        [sys.executable, str(GENERATOR), "--check", "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    if checked.returncode != 0:
        return [f"clean: --check refused what the generator just wrote.\n{checked.stderr}"]
    return []


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for name, mutate, wanted in REFUSALS:
            failures.extend(check_generate(name, mutate, wanted, tmp))
        failures.extend(check_stale_file(tmp))
        failures.extend(check_absent_file(tmp))
        failures.extend(check_round_trip(tmp))
    total = len(REFUSALS) + 3
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS) + 2} assert a refusal the "
        "generator makes and name the corpus it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
