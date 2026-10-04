#!/usr/bin/env python3
"""Tests for scripts/indeterminate-scoring-gate.py.

The defect these cases hold closed was found by an outside reader of the agent
audit record corpus. Members N1 and N2 listed two readings a conforming verifier
may take, `valid` and `indeterminate`, and pinned `expected.verdict` to one of
them, while the manifest told implementers to score on `expected.verdict`. A
second implementation taking the other listed reading would have been scored
wrong by the corpus's own instructions, and every judge in this repository
passed the corpus because each one special-cased the indeterminate kind and never
read the field. The same shape sat in two older corpora.

Every case but one works on a STAGED COPY of the tracked manifests, breaks it in
exactly one way, and asks the gate. Three of them are worth naming.

`a verdict pinned on an open member is refused` is the original defect, put back
on N1 exactly as it shipped.

`a gate that reads no readings refuses` strips every declared reading. A gate
that finds nothing to check must say so rather than pass, because a gate
quantified over nothing is indistinguishable from a clean one.

`a new corpus is read` adds a corpus directory the gate has never seen. The gate
must find it without being told, so the next corpus to use the indeterminate
bucket is held to the same rule on the day it lands.

Usage: python3 scripts/indeterminate-scoring-gate-test.py
Exit 0 when every case holds; 1 with a summary of the failures.
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

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "indeterminate-scoring-gate.py"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, int, tuple[str, ...]]


def stage(destination: Path) -> None:
    """Copy every tracked top-level MANIFEST.json, and nothing else."""
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "*/MANIFEST.json"],
        capture_output=True,
        text=True,
        check=True,
    )
    copied = 0
    for rel in listed.stdout.split():
        if rel.count("/") != 1:
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / rel, target)
        copied += 1
    if copied < 10:
        raise SystemExit(
            f"test setup: staged {copied} manifest(s), so every case below would be "
            "asking the gate about a tree that is not this repository. Fix the case, "
            "never the gate."
        )


def run(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def edit(root: Path, corpus: str, change: Callable[[dict[str, Any]], None]) -> None:
    path = root / corpus / "MANIFEST.json"
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    change(loaded)
    path.write_text(json.dumps(loaded, indent=2) + "\n", encoding="utf-8")


def member(manifest: dict[str, Any], match: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    for entry in manifest["vectors"]:
        if match(entry):
            found: dict[str, Any] = entry
            return found
    raise SystemExit("test setup: no member matches, so this case asserts nothing")


def pin_n1(root: Path) -> None:
    edit(
        root,
        "vectors-agent-audit-record",
        lambda m: member(m, lambda e: e.get("draftId") == "N1")["expected"].update(
            verdict="indeterminate"
        ),
    )


def pin_observed_effect_reference_reading(root: Path) -> None:
    edit(
        root,
        "vectors-observed-effect",
        lambda m: member(m, lambda e: e["kind"] == "indeterminate")["expected"].update(
            verdict="valid"
        ),
    )


def pin_scitt_map_form(root: Path) -> None:
    edit(
        root,
        "vectors-scitt-cose",
        lambda m: member(m, lambda e: e["id"] == "v3283077e1d1b5d8c")["expected"].update(
            verdict="invalid"
        ),
    )


def contradict_condition_scoped(root: Path) -> None:
    edit(
        root,
        "vectors",
        lambda m: member(m, lambda e: e["kind"] == "indeterminate")["expected"].update(
            verdict="valid"
        ),
    )


def strip_every_reading(root: Path) -> None:
    for path in root.glob("*/MANIFEST.json"):
        loaded = json.loads(path.read_text(encoding="utf-8"))
        for entry in loaded.get("vectors", []):
            entry.pop("readings", None)
            if isinstance(entry.get("expected"), dict):
                entry["expected"].pop("readings", None)
        path.write_text(json.dumps(loaded, indent=2) + "\n", encoding="utf-8")


def new_corpus(root: Path) -> None:
    (root / "vectors-new-family").mkdir()
    (root / "vectors-new-family" / "MANIFEST.json").write_text(
        json.dumps(
            {
                "suite": "a-family-this-gate-has-never-seen",
                "vectors": [
                    {
                        "id": "v0000000000000001",
                        "kind": "indeterminate",
                        "expected": {"verdict": "valid"},
                        "readings": [{"verdict": "valid"}, {"verdict": "malformed"}],
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def untouched(_: Path) -> None:
    return None


CASES: list[Case] = [
    ("the tracked manifests pass", untouched, 0, ()),
    (
        "a verdict pinned on an open member is refused",
        pin_n1,
        1,
        ("vectors-agent-audit-record", "vbdf904629383722b", "['indeterminate', 'valid']"),
    ),
    (
        "pinning the reference reader's own reading is refused too",
        pin_observed_effect_reference_reading,
        1,
        ("vectors-observed-effect", "vba26029515229883"),
    ),
    (
        "map-form readings are read as verdicts",
        pin_scitt_map_form,
        1,
        ("vectors-scitt-cose", "v3283077e1d1b5d8c", "['invalid', 'valid']"),
    ),
    (
        "a condition-scoped member keeps a verdict, and it must be the one its readings imply",
        contradict_condition_scoped,
        1,
        ("vectors/MANIFEST.json", "implies 'invalid'"),
    ),
    (
        "a gate that reads no readings refuses",
        strip_every_reading,
        1,
        ("read no member that declares readings",),
    ),
    (
        "a new corpus is read",
        new_corpus,
        1,
        ("vectors-new-family", "v0000000000000001"),
    ),
]


def main() -> int:
    failures: list[str] = []
    for name, mutate, want_code, want_text in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage(root)
            mutate(root)
            code, out = run(root)
        missing = [text for text in want_text if text not in out]
        if code != want_code or missing:
            failures.append(f"{name}: exit {code} (wanted {want_code}), missing {missing}\n{out}")
        else:
            print(f"ok   {name}")
    for failure in failures:
        print(f"FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
