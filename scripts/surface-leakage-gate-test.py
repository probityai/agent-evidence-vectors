#!/usr/bin/env python3
"""Tests for scripts/surface-leakage-gate.py.

A leakage measurement is the easiest kind of check to ship broken, because the
number it prints looks like evidence whichever way the code is wired. A gate
measuring nothing reports a low figure and passes. A gate measuring the labels it
was handed reports a high one and passes too, once the baseline is written from
the same broken run. Neither can be told from a working gate by reading its
output, so every case here breaks a staged copy of the corpus in one way and
requires the refusal.

Two of the cases carry most of the weight.

`a giveaway member on every reject vector` is the defect the gate exists for,
built by hand: it puts one member into every reject statement and nowhere else,
which is exactly what an accidentally leaky generator does. If that case does not
refuse, the gate is not measuring the corpus.

`the verdict back in every vector's name` is the reverse of the fix that landed:
it renames every vector after its answer and files it under `accept/` or
`reject/` again, which is the shape both corpora had until they were
content-addressed. The gate must refuse the rise. That keeps the identifier
surface pinned at the level the fix reached, so the largest leak this repository
ever carried cannot come back the way it arrived.

It replaces a case that ran the fix FORWARDS -- content-addressing the filenames
and flattening the tree -- and required the gate to refuse the declarations left
stale behind it. That case was written while the leak was live, and the fix has
since landed for both corpora. Run against the corpus as it now stands its
mutation renamed each vector to the name it already had, the gate accepted the
untouched tree, and the refusal it asserted could not fire, because the
declaration it was about had already been removed. A refusal case whose mutation
is a no-op passes vacuously and is worth less than no case at all, so it is gone
and this one holds the same surface from the other side. The downward turn of the
ratchet is still covered, by `a surface inside its null still naming a blocker`.

A mutation that cannot be built against the tree as it stands raises
`CannotConstruct` and is reported as a FAILURE of its case, never skipped and
never allowed to surface as a raw `KeyError`. The distinction is the one the whole
repository runs on: a case that could not construct its input is a case that did
not run, and a case that did not run has not passed.

The two acceptance cases are the control. Without them every case here would be
satisfied by a gate that refuses everything, which is the same non-evidence in the
other direction.

Usage: python3 scripts/surface-leakage-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "surface-leakage-gate.py"
BASELINE_REL = "docs/SURFACE-LEAKAGE-BASELINE.json"
#: The corpora the fixture must carry, DERIVED from the gate rather than
#: restated. They were two separate lists and they drifted: the gate gained
#: vectors-scitt-cose and this list did not, so every case staged a tree with
#: that corpus missing and the gate died on the absent MANIFEST.json instead of
#: refusing the defect the case had built. Fourteen of fourteen cases failed
#: for one reason that had nothing to do with any of them.
def _staged() -> tuple[str, ...]:
    spec = importlib.util.spec_from_file_location("surface_leakage_gate", GATE)
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise SystemExit(f"test setup: {GATE} could not be loaded to read CORPORA")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return tuple(f"{corpus}/" for corpus in module.CORPORA) + (BASELINE_REL,)


STAGED = _staged()

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


class CannotConstruct(Exception):
    """A case could not build the mutation it exists to make.

    Raised instead of letting a `KeyError` out, and instead of skipping. Every
    case below is a claim about what the gate does to a particular defect, and
    the claim is only tested if the defect gets built. When a schema moves under
    a case -- which is what happened when the corpora were content-addressed and
    the `blockedBy` row a case deleted stopped existing -- the case stops
    constructing anything, and the two ways that can be reported are a crash
    nobody can act on and a silence that reads as a pass. Neither says which key
    went missing or what the file carries now, so this does.
    """


def require(holder: Any, key: str, what: str) -> Any:
    """One member of `holder`, or a refusal naming what is there instead."""
    if not isinstance(holder, dict):
        raise CannotConstruct(
            f"{what} is a {type(holder).__name__}, not an object, so {key!r} cannot "
            "be read from it. This case builds no mutation, so the refusal it "
            "asserts is unproven: repoint it at the shape the file now has."
        )
    if key not in holder:
        raise CannotConstruct(
            f"{what} carries no {key!r}; it carries {sorted(holder)!r}. This case "
            "builds no mutation, so the refusal it asserts is unproven. Repoint it "
            "at a subject that exists -- never delete the assertion, and never "
            "treat the missing key as the gate having nothing left to refuse."
        )
    return holder[key]


def stage(destination: Path) -> None:
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    copied = 0
    for rel in listed.stdout.split():
        if not any(rel == p or rel.startswith(p) for p in STAGED):
            continue
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied += 1
    if copied < 2:
        raise SystemExit(
            f"test setup: staged {copied} file(s), so every case below would be "
            "asking the gate about an empty tree. Fix the case, never the gate."
        )


def run(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def manifest(root: Path, corpus: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (root / corpus / "MANIFEST.json").read_text(encoding="utf-8")
    )
    return loaded


def write_manifest(root: Path, corpus: str, data: dict[str, Any]) -> None:
    (root / corpus / "MANIFEST.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )


def baseline(root: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (root / BASELINE_REL).read_text(encoding="utf-8")
    )
    return loaded


def write_baseline(root: Path, data: dict[str, Any]) -> None:
    (root / BASELINE_REL).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# --- corpus mutations ------------------------------------------------------


def vector_rows(data: dict[str, Any], corpus: str) -> list[dict[str, Any]]:
    """The manifest rows OF THE PASSED DICT, so a caller that rewrites the file
    writes back the object it mutated. Re-reading the manifest here instead would
    hand back rows belonging to a second copy, and a mutation that renamed files
    while updating that copy would move every vector out from under a manifest
    still naming the old paths."""
    listed = require(data, "vectors", f"{corpus}/MANIFEST.json")
    if not isinstance(listed, list) or not listed:
        raise CannotConstruct(
            f"{corpus}/MANIFEST.json lists no vectors, so every case below would be "
            "mutating an empty corpus."
        )
    return [row for row in listed if isinstance(row, dict)]


def rows_of(root: Path, corpus: str) -> list[dict[str, Any]]:
    """Manifest rows for a case that only reads them or edits files in place."""
    return vector_rows(manifest(root, corpus), corpus)


def giveaway_member(root: Path) -> None:
    """One member, present on every reject statement and no accept one.

    The shape an accidentally leaky generator produces: a field added while
    building the invalid side and never added to the valid side. A rail could
    then answer the whole corpus by looking for it.
    """
    corpus = "vectors"
    touched = 0
    for entry in rows_of(root, corpus):
        if require(entry, "kind", f"{corpus} manifest row") != "reject":
            continue
        path = root / corpus / str(require(entry, "file", f"{corpus} manifest row"))
        try:
            statement = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue  # the deliberately undecodable vectors stay undecodable
        if not isinstance(statement, dict):
            continue
        statement["_buildTag"] = "invalid-side"
        path.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
        touched += 1
    if touched < 2:
        raise CannotConstruct(
            f"{corpus} holds fewer than two decodable reject statements, so no "
            "member could be added to the invalid side and nothing was tagged."
        )


def giveaway_depth(root: Path) -> None:
    """Every reject statement nested one level deeper than every accept one.

    Aimed at the `shape` surface, which is under target today, so this case fails
    only if the gate is reading structure at all.
    """
    corpus = "vectors"
    touched = 0
    for entry in rows_of(root, corpus):
        if require(entry, "kind", f"{corpus} manifest row") != "reject":
            continue
        path = root / corpus / str(require(entry, "file", f"{corpus} manifest row"))
        try:
            statement = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if not isinstance(statement, dict):
            continue
        statement["_pad"] = {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}
        path.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
        touched += 1
    if touched < 2:
        raise CannotConstruct(
            f"{corpus} holds fewer than two decodable reject statements, so none "
            "could be nested deeper and nothing was padded."
        )


def relabel_identifiers(root: Path) -> None:
    """Put the verdict back in every vector's name and directory.

    The reverse of the change that closed the largest leak this repository has
    carried. Both corpora used to name each vector `ok-...` or `bad-...` and file
    it under `accept/` or `reject/`, and measured over the whole manifest-relative
    path a classifier read the verdict off the name alone with a separability of
    1.0000. They are content-addressed and flat now, and the identifier surface
    measures at its own null, which is to say it carries nothing.

    This case undoes that, so the gate has to refuse the rise on the identifier
    surface. Both halves of the old shape are restored, because either alone very
    nearly names the label and a case that restored only one would understate what
    is being held back.
    """
    moved = 0
    for corpus in ("vectors", "vectors-ai-agent-action"):
        data = manifest(root, corpus)
        for index, entry in enumerate(vector_rows(data, corpus)):
            kind = str(require(entry, "kind", f"{corpus} manifest row"))
            source = root / corpus / str(require(entry, "file", f"{corpus} manifest row"))
            if not source.is_file() or kind not in ("accept", "reject"):
                continue
            prefix = "ok" if kind == "accept" else "bad"
            new_rel = f"{kind}/{prefix}-{index:04d}-restored-old-name.json"
            target = root / corpus / new_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            source.rename(target)
            entry["file"] = new_rel
            moved += 1
        write_manifest(root, corpus, data)
    if moved < 2:
        raise CannotConstruct(
            "no vector was renamed, so the identifier surface is unchanged and "
            "this case measured nothing."
        )


def one_more_reject_vector(root: Path) -> None:
    """The ordinary way this corpus grows: a parent, plus one mutation.

    A gate that refused here would refuse every future vector, so this is the
    case that keeps the whole file from being satisfiable by refusing everything.

    The vector is written the way the corpus is actually built -- named after a
    digest of its own bytes, in the one directory that holds every kind. Written
    the old way, under `reject/` with the verdict in its name, this case FAILS,
    and correctly: one label-bearing filename is enough to lift the identifier
    surface of a corpus that now carries nothing off its own null, and the gate
    refusing that is the ratchet doing its job rather than a false alarm.
    """
    corpus = "vectors"
    data = manifest(root, corpus)
    parents = [
        e
        for e in vector_rows(data, corpus)
        if require(e, "kind", f"{corpus} manifest row") == "accept"
    ]
    if not parents:
        raise CannotConstruct(
            f"{corpus} holds no accept vector to build an ordinary reject vector "
            "from, so this case cannot add one the way the corpus grows."
        )
    parent = parents[0]
    statement = json.loads(
        (root / corpus / str(require(parent, "file", f"{corpus} manifest row")))
        .read_text(encoding="utf-8")
    )
    predicate = require(statement, "predicate", f"{corpus} accept statement")
    require(predicate, "result", f"{corpus} accept statement's predicate")
    predicate["result"] = "PASS"
    raw = (json.dumps(statement, indent=2, sort_keys=True) + "\n").encode("utf-8")
    identifier = "v" + hashlib.sha256(raw).hexdigest()[:16]
    rel = f"statements/{identifier}.json"
    (root / corpus / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / corpus / rel).write_bytes(raw)
    data["vectors"].append(
        {
            "id": identifier,
            "kind": "reject",
            "file": rel,
            "conditions": ["aee-c-1"],
            "expected": {"verdict": "invalid", "codes": ["result-not-lowercase"]},
        }
    )
    write_manifest(root, corpus, data)


# --- baseline mutations ----------------------------------------------------


def surfaces_of(data: dict[str, Any], corpus: str) -> dict[str, Any]:
    corpora = require(data, "corpora", BASELINE_REL)
    recorded = require(corpora, corpus, f"{BASELINE_REL} corpora")
    rows: dict[str, Any] = require(recorded, "surfaces", f"{BASELINE_REL} {corpus}")
    return rows


def row_of(data: dict[str, Any], corpus: str, surface: str) -> dict[str, Any]:
    row: dict[str, Any] = require(
        surfaces_of(data, corpus), surface, f"{BASELINE_REL} {corpus} surfaces"
    )
    return row


# A case once dropped the `blockedBy` declaration off a surface that was really
# outside its null, pinned to vectors-ai-agent-action/paths. That leak closed
# when the Appendix B family gained its reject twins and the ratchet removed the
# last declaration in the baseline, so no row is left to construct it from. The
# refusal it checked -- a surface outside its null with nothing named for it --
# is still checked by "a recorded null edited below the corpus's real noise
# floor", which builds that state rather than waiting for a real leak.


def lower_a_recorded_figure(root: Path) -> None:
    data = baseline(root)
    row_of(data, "vectors", "paths")["separability"] = 0.30
    write_baseline(root, data)


def raise_a_recorded_figure(root: Path) -> None:
    data = baseline(root)
    row_of(data, "vectors", "paths")["separability"] = 0.90
    write_baseline(root, data)


def declare_a_surface_inside_its_null(root: Path) -> None:
    """A blocker on a surface that shuffling the labels already explains."""
    data = baseline(root)
    row = row_of(data, "vectors", "shape")
    if float(row.get("separability", 1.0)) > float(row.get("null", 0.0)):
        raise CannotConstruct(
            f"{BASELINE_REL} vectors/shape records {row.get('separability')} "
            f"against a null of {row.get('null')}, so it is already outside its "
            "null and a blocker on it would not be stale. Repoint the case at a "
            "surface that is inside its own null."
        )
    row["blockedBy"] = "nothing at all"
    write_baseline(root, data)


def drop_a_surface_row(root: Path) -> None:
    data = baseline(root)
    rows = surfaces_of(data, "vectors")
    require(rows, "lexicon", f"{BASELINE_REL} vectors surfaces")
    del rows["lexicon"]
    write_baseline(root, data)


def sink_a_recorded_null(root: Path) -> None:
    """Pretend a surface's noise floor is lower than it is.

    The null is the threshold, so understating it turns ordinary sampling spread
    into a reported leak. This is the case that stops the null being a number
    somebody can quietly tune to make a corpus look dirty or clean.
    """
    data = baseline(root)
    row = row_of(data, "vectors", "paths")
    require(row, "null", f"{BASELINE_REL} vectors/paths")
    row["null"] = 0.30
    write_baseline(root, data)


def move_the_fingerprint(root: Path) -> None:
    """Claim the null was calibrated over a corpus of a different shape.

    The class counts set the null's level, so a null carried across a change in
    them is a threshold describing some other corpus. Without this the gate would
    keep applying a stale noise floor after the corpus grew.
    """
    data = baseline(root)
    corpora = require(data, "corpora", BASELINE_REL)
    recorded = require(corpora, "vectors", f"{BASELINE_REL} corpora")
    shape = require(recorded, "fingerprint", f"{BASELINE_REL} vectors")
    counted = int(require(shape, "accept", f"{BASELINE_REL} vectors fingerprint"))
    # More than the drift the null tolerates, computed from the recorded count
    # rather than pinned to a constant, so this stays a real overshoot as the
    # corpus grows instead of quietly becoming a figure the gate waves through.
    shape["accept"] = counted + max(2, int(counted * 0.2))
    write_baseline(root, data)


def remove_the_baseline(root: Path) -> None:
    path = root / BASELINE_REL
    if not path.is_file():
        raise CannotConstruct(
            f"{BASELINE_REL} is not in the staged tree, so removing it changes "
            "nothing and this case would assert a refusal of its own staging bug."
        )
    path.unlink()


def sync_after_a_giveaway(root: Path) -> tuple[int, str]:
    """--sync must not be the way out of a refusal it just made.

    Run with the gate's own sync argument rather than through `run`, because the
    property under test is that the escape hatch refuses too. A gate whose fix
    command silently records the leak has a bypass with no diff behind it.
    """
    giveaway_member(root)
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root), "--sync"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


SYNC_CASES: list[tuple[str, Callable[[Path], tuple[int, str]], tuple[str, ...]]] = [
    (
        "--sync refuses to write down a leak it just refused",
        sync_after_a_giveaway,
        ("will not raise a figure",),
    ),
]

REFUSALS: list[Case] = [
    (
        "a giveaway member on every reject vector",
        giveaway_member,
        ("lexicon", "more predictable"),
    ),
    (
        "every reject vector nested one level deeper",
        giveaway_depth,
        ("shape", "more predictable"),
    ),
    (
        "the verdict back in every vector's name",
        relabel_identifiers,
        ("identifier", "more predictable"),
    ),
    (
        "a recorded figure edited below what the corpus measures",
        lower_a_recorded_figure,
        ("more predictable",),
    ),
    (
        "a recorded figure holding slack the corpus does not need",
        raise_a_recorded_figure,
        ("--sync",),
    ),
    (
        "a surface inside its null still naming a blocker",
        declare_a_surface_inside_its_null,
        ("outlived its subject",),
    ),
    (
        "a recorded null edited below the corpus's real noise floor",
        sink_a_recorded_null,
        ("outside its own null",),
    ),
    (
        "a null calibrated over a corpus of another shape",
        move_the_fingerprint,
        ("describe a different corpus",),
    ),
    ("a surface the baseline records nothing for", drop_a_surface_row, ("records nothing",)),
    ("no baseline at all", remove_the_baseline, ("is absent",)),
]

ACCEPTANCES: list[Case] = [
    ("the corpus as it stands", lambda root: None, ()),
    ("one more reject vector, built the ordinary way", one_more_reject_vector, ()),
]


def unbuildable(name: str, reason: str) -> str:
    return (
        f"{name}: the mutation could not be constructed, so the gate was never "
        f"asked and this case proves nothing. {reason}"
    )


def check(group: str, cases: list[Case], want_refusal: bool, tmp: Path) -> list[str]:
    failures: list[str] = []
    for index, (name, mutate, phrases) in enumerate(cases):
        root = tmp / f"{group}{index}"
        root.mkdir()
        stage(root)
        try:
            mutate(root)
        except CannotConstruct as unmet:
            # A failure of this case, never a skip and never a crash that takes
            # the rest of the run's verdicts with it.
            failures.append(unbuildable(name, str(unmet)))
            continue
        code, output = run(root)
        if want_refusal and code == 0:
            failures.append(f"{name}: the gate accepted it:\n{output}")
            continue
        if not want_refusal and code != 0:
            failures.append(f"{name}: the gate refused it:\n{output}")
            continue
        missing = [phrase for phrase in phrases if phrase not in output]
        if missing:
            failures.append(
                f"{name}: the right exit status, and the output does not carry "
                f"{missing!r}. A refusal that names the wrong surface sends the next "
                f"person to the wrong corpus.\n{output}"
            )
    return failures


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        failures.extend(check("refuse", REFUSALS, True, tmp))
        failures.extend(check("accept", ACCEPTANCES, False, tmp))
        for index, (name, drive, phrases) in enumerate(SYNC_CASES):
            root = tmp / f"sync{index}"
            root.mkdir()
            stage(root)
            try:
                code, output = drive(root)
            except CannotConstruct as unmet:
                failures.append(unbuildable(name, str(unmet)))
                continue
            if code == 0:
                failures.append(f"{name}: --sync accepted it:\n{output}")
            else:
                missing = [phrase for phrase in phrases if phrase not in output]
                if missing:
                    failures.append(f"{name}: the refusal omits {missing!r}\n{output}")
    total = len(REFUSALS) + len(ACCEPTANCES) + len(SYNC_CASES)
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS) + len(SYNC_CASES)} assert a "
        "refusal the gate makes and name the surface it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
