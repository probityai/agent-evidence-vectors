#!/usr/bin/env python3
"""Tests for the suite-revision reader in vectors/gen_manifest.py.

The revision used to live in prose alone -- a heading in vectors/CHANGES.md and
some README sentences -- while MANIFEST.json carried a `suite` NAME and no
number. An independent implementer filing a crosswalk read `manifest["suite"]`
for the revision, because that was the only suite-shaped key in the file and
there was nothing better to read. The reader under test copies the number into
the manifest so a consumer never has to parse prose for it.

The cases that matter are the two refusals, because both failure modes would
otherwise print as a finding. A missing changelog and a changelog with no
heading each mean the generator COULD NOT ESTABLISH the revision; neither means
the corpus has none, and a reader that returned 0 or fell back to the suite name
would write that ambiguity into a published artifact.

The anchoring case is the third. The heading regex is anchored to the start of a
line: a sentence that mentions a revision mid-line is prose about some other
revision, and counting it would let a stray paragraph silently renumber the
corpus.

Every case builds its own changelog in a temporary directory, so the file needs
no repository state beyond the real changelog the first case reads.

Usage: python3 scripts/manifest-revision-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
GEN = REPO / "vectors" / "gen_manifest.py"
CHANGES = REPO / "vectors" / "CHANGES.md"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("gen_manifest_under_test", GEN)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {GEN}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(root: Path, text: str) -> str:
    path = root / "CHANGES.md"
    path.write_text(text, encoding="utf-8")
    return str(path)


def case_real_changelog_matches_the_manifest(root: Path) -> None:
    """The number in the manifest is the number in the changelog, not a copy."""
    import json

    gen = _load()
    from_changelog = gen.suite_revision(str(CHANGES))  # type: ignore[attr-defined]
    with open(REPO / "vectors" / "MANIFEST.json", encoding="utf-8") as fh:
        in_manifest = json.load(fh)["suiteRevision"]
    if from_changelog != in_manifest:
        raise AssertionError(
            f"changelog says {from_changelog}, manifest says {in_manifest}; "
            "regenerate with python3 vectors/gen_manifest.py"
        )


def case_missing_changelog_refuses(root: Path) -> None:
    """A changelog that cannot be read is a failed check, never a revision."""
    gen = _load()
    try:
        gen.suite_revision(str(root / "no-such-file.md"))  # type: ignore[attr-defined]
    except SystemExit as exc:
        if "cannot read" not in str(exc):
            raise AssertionError(f"refused for the wrong reason: {exc}") from exc
        return
    raise AssertionError("an unreadable changelog returned a revision")


def case_no_heading_refuses(root: Path) -> None:
    """A changelog with no heading of the right shape is a failed check."""
    gen = _load()
    path = _write(root, "# Conformance suite changelog\n\nnothing of the shape\n")
    try:
        gen.suite_revision(path)  # type: ignore[attr-defined]
    except SystemExit as exc:
        if "carries no" not in str(exc):
            raise AssertionError(f"refused for the wrong reason: {exc}") from exc
        return
    raise AssertionError("a changelog with no heading returned a revision")


def case_newest_heading_wins(root: Path) -> None:
    """File order does not decide the revision; the highest number does."""
    gen = _load()
    path = _write(root, "## suiteRevision 28\na\n## suiteRevision 9\nb\n## suiteRevision 27\nc\n")
    got = gen.suite_revision(path)  # type: ignore[attr-defined]
    if got != 28:
        raise AssertionError(f"expected 28 from three headings, got {got}")


def case_mid_line_mention_does_not_count(root: Path) -> None:
    """Prose mentioning a revision mid-line cannot renumber the corpus."""
    gen = _load()
    path = _write(root, "see the note at ## suiteRevision 99 elsewhere\n## suiteRevision 28\n")
    got = gen.suite_revision(path)  # type: ignore[attr-defined]
    if got != 28:
        raise AssertionError(f"a mid-line mention was counted: got {got}, wanted 28")


CASES: list[Callable[[Path], None]] = [
    case_real_changelog_matches_the_manifest,
    case_missing_changelog_refuses,
    case_no_heading_refuses,
    case_newest_heading_wins,
    case_mid_line_mention_does_not_count,
]


def main() -> int:
    failures: list[str] = []
    ran = 0
    for case in CASES:
        ran += 1
        with tempfile.TemporaryDirectory() as raw:
            try:
                case(Path(raw))
            except Exception as exc:  # noqa: BLE001 -- every case is reported, not the first
                failures.append(f"{case.__name__}: {exc}")
            else:
                print(f"ok {case.__name__}")
    for line in failures:
        print(f"FAIL {line}", file=sys.stderr)
    print(f"{ran - len(failures)}/{ran} cases held")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
