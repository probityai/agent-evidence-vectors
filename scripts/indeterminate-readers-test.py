#!/usr/bin/env python3
"""The packaged readers score an indeterminate member on its readings, and only there.

An indeterminate member is one the specification leaves open: its manifest entry
lists every verdict a conforming verifier may reach, under `readings`. The agent
audit record corpus shipped N1 and N2 with `expected.verdict` pinned to one of
those readings and a note telling implementers to score on `expected.verdict`,
so a second implementation taking the other listed reading would have been
scored wrong. The packaged judge passed it because it never read the pinned
field. These cases hold both packaged readers that carry indeterminate members
to the rule, on a staged copy of each tracked corpus:

- the tracked corpus is judged clean;
- pinning `expected.verdict` on an indeterminate member is a finding, whichever
  reading is pinned;
- deleting any one listed reading is a finding, so every listed reading is
  load-bearing: the reference reader's own reading, because the reader then
  lands outside the set, and the other, because one reading is a rule and a
  member carrying a rule is not indeterminate;
- `auditrecord.conforming_verdicts` returns every listed reading for an
  indeterminate member and the one expected verdict for any other, so a second
  implementation that answers either reading of N2 is scored as conforming, and
  N1, which draft-gilda-audit-agent-audit-record-00 settles, is scored on `valid`.

Usage: uv run --extra generators python scripts/indeterminate-readers-test.py
Exit 0 when every case holds; 1 with a summary of the failures.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402,F401  (the readers resolve the rail's Ed25519 through it)
from agent_evidence_vectors import auditrecord, observedeffect  # noqa: E402

READERS: list[tuple[str, ModuleType]] = [
    ("vectors-agent-audit-record", auditrecord),
    ("vectors-observed-effect", observedeffect),
]
PINNED = "pins expected.verdict beside readings"
STAGED: list[Path] = []


def staged(corpus: str, change: Callable[[dict[str, Any]], None] | None) -> Path:
    root = Path(tempfile.mkdtemp())
    STAGED.append(root)
    shutil.copytree(REPO_ROOT / corpus, root / corpus)
    if change is not None:
        path = root / corpus / "MANIFEST.json"
        loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        change(loaded)
        path.write_text(json.dumps(loaded, indent=2) + "\n", encoding="utf-8")
    return root / corpus


def findings(reader: ModuleType, directory: Path) -> list[str]:
    judged = reader.judge(str(directory))
    out = list(judged.findings)
    for _, _, member_findings in judged.members:
        out.extend(member_findings)
    return out


def indeterminate(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in manifest["vectors"] if e["kind"] == "indeterminate"]


def _set_on(
    ident: str, change: Callable[[dict[str, Any]], None]
) -> Callable[[dict[str, Any]], None]:
    def apply(manifest: dict[str, Any]) -> None:
        for e in manifest["vectors"]:
            if e["id"] == ident:
                change(e)

    return apply


def _pin(value: str) -> Callable[[dict[str, Any]], None]:
    return lambda e: e["expected"].update(verdict=value)


def _drop(position: int) -> Callable[[dict[str, Any]], None]:
    return lambda e: e["readings"].pop(position)


def reader_failures(corpus: str, reader: ModuleType) -> list[str]:
    """The tracked corpus is clean; a pinned verdict and a deleted reading are not."""
    manifest = json.loads((REPO_ROOT / corpus / "MANIFEST.json").read_text(encoding="utf-8"))
    members = indeterminate(manifest)
    if not members:
        return [f"{corpus}: no indeterminate member, so these cases test nothing"]
    out: list[str] = []
    clean = findings(reader, staged(corpus, None))
    if clean:
        out.append(f"{corpus}: the tracked corpus is not clean: {clean}")
    for entry in members:
        ident = entry["id"]
        for reading in entry["readings"]:
            got = findings(reader, staged(corpus, _set_on(ident, _pin(reading["verdict"]))))
            if not any(PINNED in f for f in got):
                out.append(
                    f"{corpus} {ident}: pinning expected.verdict={reading['verdict']!r} "
                    f"is not a finding: {got}"
                )
        for position, reading in enumerate(entry["readings"]):
            if not findings(reader, staged(corpus, _set_on(ident, _drop(position)))):
                out.append(
                    f"{corpus} {ident}: deleting reading {position} "
                    f"({reading['verdict']!r}) changes nothing"
                )
    return out


def scoring_failures() -> list[str]:
    """conforming_verdicts scores a second reader on N2 by its readings, and on
    N1, which -00 settles, by its one verdict."""
    manifest = json.loads(
        (REPO_ROOT / "vectors-agent-audit-record" / "MANIFEST.json").read_text(encoding="utf-8")
    )
    out: list[str] = []
    for entry in manifest["vectors"]:
        allowed = auditrecord.conforming_verdicts(entry)
        if entry["kind"] == "indeterminate":
            want = {r["verdict"] for r in entry["readings"]}
        else:
            want = {entry["expected"]["verdict"]}
        if allowed != want:
            out.append(f"{entry['draftId']}: conforming_verdicts {allowed}, wanted {want}")
    for draft_id, wanted in (("N1", {"valid"}), ("N2", {"valid", "indeterminate"})):
        entry = next(e for e in manifest["vectors"] if e["draftId"] == draft_id)
        allowed = auditrecord.conforming_verdicts(entry)
        if allowed != wanted:
            out.append(f"{draft_id}: a second reader is scored against {allowed}")
    return out


def main() -> int:
    failures: list[str] = []
    for corpus, reader in READERS:
        failures.extend(reader_failures(corpus, reader))
    failures.extend(scoring_failures())
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print("ok   indeterminate members are scored on their readings, and only there")
    return 0


if __name__ == "__main__":
    try:
        status = main()
    finally:
        for root in STAGED:
            shutil.rmtree(root, ignore_errors=True)
    sys.exit(status)
