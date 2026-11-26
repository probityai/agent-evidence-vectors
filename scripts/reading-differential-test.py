#!/usr/bin/env python3
"""Mutation proof for ``reading-differential.py``.

A harness whose whole purpose is to refuse silence has to be shown refusing it,
because the failure it exists to prevent is a run that returned nothing and was
read as confirmation. Every case below drives the REAL gate against a rigged
copy of ``spec/READINGS.toml`` and asserts it goes red with a NAMED phrase.

Two guards make the cases mean something, and both were earned elsewhere in this
repository:

  * a mutation that changes nothing is a hard failure, never a pass. Each case
    hashes the ledger text before and after and refuses when they match, so an
    edit that silently missed cannot report success. A line count cannot see a
    one-value-for-one-value swap, which is why the check is a digest.
  * the control asserts the UNMUTATED ledger passes, so a gate that fails on
    everything cannot masquerade as a gate that catches these.

Six of the cases were written by attacking the gate rather than by reading it,
and each of those names the result the unpatched gate returned: a ledger can
otherwise flag the edited side as the implemented one, express a rival in the
replay driver instead of the rail, address a real witness to a registry decision
about other text, or claim an authority-text digest nothing ever compared.

The cases that need a Go build share one per-vector coverage sweep through
``--reach-cache``, which is keyed on the rail source digest and the corpus
fingerprint. A cache that could go stale silently would be a second way to
manufacture an absence, so a miss re-measures rather than assuming.

Usage: python3 scripts/reading-differential-test.py
       python3 scripts/reading-differential-test.py --fast   # skip the Go cases
Exit 0 when every case behaves; 1 otherwise.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "reading-differential.py"
LEDGER = REPO_ROOT / "spec" / "READINGS.toml"


def _harness() -> Any:
    spec = importlib.util.spec_from_file_location("reading_differential", GATE)
    if spec is None or spec.loader is None:
        raise AssertionError(f"{GATE} cannot be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run(path: Path, extra: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--readings", str(path), *extra],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    return proc.returncode, proc.stdout + proc.stderr


def _apply(path: Path, mutate: Callable[[str], str]) -> None:
    before = path.read_text(encoding="utf-8")
    after = mutate(before)
    if _digest(before) == _digest(after):
        raise AssertionError(
            "mutation applied nothing -- the ledger is byte-identical, so the "
            "case would have proven nothing"
        )
    path.write_text(after, encoding="utf-8")


# --- helpers the cases build declarations out of ---------------------------


def _cited_sentence(module: Any) -> tuple[int, str]:
    """A normative sentence something in the corpus already cites."""
    sentences = module.enumerate_sentences(module.SPEC.read_text(encoding="utf-8"))
    spans = [s for group in module.citation_spans(REPO_ROOT).values() for s in group]
    for line_no, text in sentences:
        if module.KEYWORD.search(text) and module._cited(line_no, spans):
            return line_no, _digest(text)[:16]
    raise AssertionError("no normative sentence is cited, so the corpus is not the one this tests")


def _declaration(line_no: int, digest: str, klass: str, reason: str) -> str:
    return (
        f'\n[[uncited]]\nsentence = "L{line_no}"\ndigest = "{digest}"\n'
        f'class = "{klass}"\nreason = "{reason}"\n'
    )


def _edit(find: str, replace: str, file: str = "aee/jcs.go") -> str:
    return f'\n[[reading.variant.edit]]\nfile = "{file}"\nfind = {find}\nreplace = {replace}\n'


def _reading(
    rid: str,
    find: str,
    replace: str,
    extra: str = "",
    edits: bool = True,
    file: str = "aee/jcs.go",
    left_edit: str = "",
) -> str:
    edit = _edit(find, replace, file) if edits else ""
    return (
        f'\n[[reading]]\nid = "{rid}"\ntitle = "a rigged reading"\n'
        f'sentence = "L139-148"\nwitnessSketch = "a rigged sketch"\n{extra}'
        f'\n[[reading.variant]]\nid = "left"\nimplemented = true\nsummary = "the reference"\n'
        f"{left_edit}"
        f'\n[[reading.variant]]\nid = "right"\nsummary = "the rival"\n{edit}'
    )


# --- the cases -------------------------------------------------------------


def case_stale_declaration(module: Any) -> Callable[[str], str]:
    """A declaration whose sentence has BECOME cited.

    Without this clause the ledger becomes permanent: citations land, the rows
    keep excusing sentences nobody needs excused, and the count of uncited
    obligations stops falling while everything still reads correct.
    """
    line_no, digest = _cited_sentence(module)
    return lambda text: text + _declaration(
        line_no, digest, "producer-obligation-ungated", "rigged"
    )


def case_declaration_without_reason(_: Any) -> Callable[[str], str]:
    return lambda text: re.sub(
        r'(sentence = "L88"\n(?:.*\n)*?reason = )"[^"]*"', r'\1"   "', text, count=1
    )


def case_phantom_sentence(_: Any) -> Callable[[str], str]:
    return lambda text: text + _declaration(
        99999, "0" * 16, "producer-obligation-ungated", "rigged"
    )


def case_wrong_digest(_: Any) -> Callable[[str], str]:
    """A declaration keyed on a line number inherits whatever moves onto it."""
    return lambda text: text.replace('digest = "78a5496ffb841a05"', 'digest = "78a5496ffb841a06"')


def case_declaration_deleted(_: Any) -> Callable[[str], str]:
    """Delete whichever uncited declaration comes first, not a named one.

    This used to name `sentence = "L1464"`. Line numbers move whenever the
    authority is re-vendored, and when that one stopped existing the pattern
    matched nothing: the mutation returned the ledger unchanged and the case
    proved nothing about the harness. The suite's own no-op check is what
    caught it, and only after a second defect stopped hiding it -- the CI step
    passed this file's path as an argument to another test, so this test had
    not run at that venue at all.

    Selecting the first block keeps the mutation anchored to the SHAPE the
    ledger guarantees rather than to a coordinate that expires.
    """
    return lambda text: re.sub(
        r'\[\[uncited\]\]\n(?:.*\n)*?reason = "[^"]*"\n', "", text, count=1
    )


def case_class_outside_vocabulary(_: Any) -> Callable[[str], str]:
    return lambda text: text.replace(
        'sentence = "L88"\ndigest = "78a5496ffb841a05"\nclass = "consumer-policy-unvectorable"',
        'sentence = "L88"\ndigest = "78a5496ffb841a05"\nclass = "looks-fine-to-me"',
    )


def case_expect_a_finding(_: Any) -> Callable[[str], str]:
    """`expect = "MASKED"` turns the sharpest available result into a target."""
    return lambda text: text.replace('expect = "DISCRIMINATED"', 'expect = "MASKED"')


def case_no_witness_sketch(_: Any) -> Callable[[str], str]:
    return lambda text: text.replace("witnessSketch = ", "witnessSketchPending = ", 1)


def case_two_implemented_variants(_: Any) -> Callable[[str], str]:
    return lambda text: text.replace(
        'id = "narrow"\nsummary =', 'id = "narrow"\nimplemented = true\nsummary =', 1
    )


def case_rival_without_an_edit(_: Any) -> Callable[[str], str]:
    return lambda text: text + _reading("rigged-empty-rival", "", "", edits=False)


def case_noop_edit(_: Any) -> Callable[[str], str]:
    """The GEO no-op refusal, in corpus clothing: an edit that changes no bytes
    leaves the rival rail equal to the reference, and the differential then
    reports MASKED about a comparison it never made."""
    return lambda text: text + _reading(
        "rigged-noop",
        '"\\t\\tif depth >= maxParseDepth {"',
        '"\\t\\tif depth >= maxParseDepth {"',
    )


def case_edit_anchor_absent(_: Any) -> Callable[[str], str]:
    return lambda text: text + _reading(
        "rigged-absent-anchor",
        '"if depth >= someConstantNobodyDeclared {"',
        '"if depth > someConstantNobodyDeclared {"',
    )


def case_masked_is_a_finding(_: Any) -> Callable[[str], str]:
    """A rival that changes bytes and computes exactly what the reference does.

    Both oracles stay put, the site is reached by every vector, and the run has
    therefore proven nothing. This is the shape the reviewer nearly sent as
    confirmation, and the gate must name it a finding rather than a pass.
    """
    return lambda text: text + _reading(
        "rigged-inert", '"maxParseBytes = 20 << 20"', '"maxParseBytes = 20971520"'
    )


def case_falsified_equivalence(_: Any) -> Callable[[str], str]:
    """An equivalence declaration on a reading a vector actually separates."""
    return lambda text: text.replace(
        'expect = "DISCRIMINATED"',
        'equivalence = "the two readings agree on every admissible input"',
    )


DEPTH_FIND = '"\\t\\tif depth >= maxParseDepth {"'
DEPTH_REPLACE = '"\\t\\tif depth > maxParseDepth {"'
COMMENT_FIND = '"// RFC 8785 (JCS) canonicalization and RFC 7493 (I-JSON) profile checks,"'
COMMENT_REPLACE = '"// RFC 8785 (JCS) canonicalization plus RFC 7493 (I-JSON) profile checks,"'


def case_implemented_variant_edits(_: Any) -> Callable[[str], str]:
    """The implemented flag on the side that carries the rail edit.

    Driven against the live ledger this returned DISCRIMINATED at exit 0 and
    emitted a witness saying bad-742 is VALID under the implemented reading --
    the opposite of what the shipped rail answers, because neither rail in that
    comparison was the shipped one. The rival here changes a comment so the two
    trees still differ and the byte-identical refusal cannot be what catches it.
    """
    return lambda text: text + _reading(
        "rigged-implemented-edit",
        COMMENT_FIND,
        COMMENT_REPLACE,
        left_edit=_edit(DEPTH_FIND, DEPTH_REPLACE),
    )


def case_edit_in_the_replay_driver(_: Any) -> Callable[[str], str]:
    """A rival expressed in cmd/mutrun rather than in the rail.

    The driver decides which fields of a verify report become the observation,
    so blanking one moved 195 of 250 vectors and was scored REPORT-ONLY with a
    witness whose two sides printed the same string. Nothing about any reading
    of any sentence changed.
    """
    return lambda text: text + _reading(
        "rigged-driver-edit",
        '"\\to.PrimaryCode = string(withKey.PrimaryCode)"',
        '"\\to.PrimaryCode = \\"\\""',
        file="cmd/mutrun/main.go",
        left_edit=_edit(COMMENT_FIND, COMMENT_REPLACE),
    )


def case_stale_authority_pin(_: Any) -> Callable[[str], str]:
    """The ledger's [meta] pin, which nothing read until it was attacked."""
    return lambda text: re.sub(
        r'specDigest = "[0-9a-f]{64}"', f'specDigest = "{"0" * 64}"', text, count=1
    )


def case_witness_addressed_elsewhere(module: Any) -> Callable[[str], str]:
    """A differential measured at one sentence, addressed to a decision about another.

    The witness is shaped to be pasted into the interpretation registry against
    the named decision, where the sibling gate accepts it as proof that reading
    is forced. Unless the two are tied together, a real measurement retires an
    unwitnessedForced id no vector ever discriminated.
    """
    ledger = module.load_ledger(LEDGER)
    claimed = [
        span
        for reading in ledger.get("reading", [])
        for span in module._spans(str(reading.get("sentence", "")))
    ]
    anchors = module.registry_decision_anchors(REPO_ROOT)
    elsewhere = next(
        (
            i
            for i, spans in sorted(anchors.items())
            if spans and not module._overlap(claimed, spans)
        ),
        None,
    )
    if elsewhere is None:
        raise AssertionError("every registry decision anchors a declared reading's sentence")
    return lambda text: re.sub(r"registryDecision = \d+", f"registryDecision = {elsewhere}", text)


def case_sentence_without_a_span(_: Any) -> Callable[[str], str]:
    return lambda text: re.sub(r'sentence = "L\d+-\d+"', 'sentence = "the nesting bullet"', text)


def _staged_root(root: Path, edit: Callable[[str], str]) -> Path:
    """A tree carrying only what ``citation_spans`` reads, with one file rigged."""
    for rel in (
        "vectors/reject/INDEX.md",
        "vectors/accept/INDEX.md",
        "vectors/interpretation-decisions.json",
        "vectors/coverage-unforced.json",
    ):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        target.write_text(edit(text) if rel.endswith("reject/INDEX.md") else text,
                          encoding="utf-8")
    return root


def _unstaged(root: Path, staged: tuple[str, ...]) -> list[str]:
    """The top-level entries a build of ``cmd/mutrun`` reads that ``staged`` omits.

    Asked of the Go toolchain, not of the harness: the list it stages is written
    by hand, and a package the build gained (``internal/identifiers``, imported by
    ``corpusreaders``) was missing from it until a run on the branch died with
    ``no required module provides package``.
    """
    proc = subprocess.run(
        ["go", "list", "-deps", "-f", "{{if .Module}}{{if .Module.Main}}{{.Dir}}{{end}}{{end}}",
         "./cmd/mutrun"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"go list -deps ./cmd/mutrun failed:\n{proc.stderr}")
    base = root.resolve()
    needed = {"go.mod"}
    for line in proc.stdout.split():
        rel = Path(line).resolve().relative_to(base)
        if rel.parts:
            needed.add(rel.parts[0])
    return sorted(needed - set(staged))


def check_stage_covers_the_build(module: Any, failures: list[str]) -> None:
    """The staged tree must hold every directory a build of the rail reads.

    A rail is staged as a handful of named members, not the whole repository, so
    a package the build starts to import is silently outside the copy and the
    harness dies at its first build. Two assertions:

      * the live ``STAGED`` omits nothing the build reads.
      * the same check on ``STAGED`` without ``internal`` must name ``internal``.
        A check that cannot see an omission passes for the wrong reason, which is
        how the first version of this list went stale unnoticed.
    """
    missing = _unstaged(REPO_ROOT, module.STAGED)
    if missing:
        failures.append(
            f"stage covers the build: {missing} are read by a build of ./cmd/mutrun "
            "and are not in STAGED, so a staged rail cannot build"
        )
        return
    reduced = tuple(member for member in module.STAGED if member != "internal")
    if reduced == tuple(module.STAGED):
        failures.append("stage covers the build: STAGED has no internal member to drop")
        return
    seen = _unstaged(REPO_ROOT, reduced)
    if seen != ["internal"]:
        failures.append(
            f"stage covers the build: with internal removed the check reports {seen}, "
            "not ['internal']; it cannot see an omission"
        )
        return
    print("  control: STAGED covers every directory a build of ./cmd/mutrun reads")


def check_citation_read_path(module: Any, failures: list[str]) -> None:
    """The per-vector citation index must be read, and must refuse to read empty.

    This is not a ledger mutation and cannot be one: the defect it pins lived in
    the GATE, not in any declaration. The reader kept the index lines beginning
    ``| `bad-``, so when vector identifiers became content addresses it matched
    nothing, reported an empty citation source without a word, and layer 0
    called five obligations uncited that five reject vectors cite by line range.
    A citation source that silently empties manufactures exactly the absence
    this harness exists to refuse, so there are three assertions:

      * a POSITIVE CONTROL first. An emptiness check whose read path is broken
        passes for the wrong reason, so the live index must yield spans before
        either refusal below proves anything.
      * an index whose vector rows carry no `spec` column must DIE, not return
        an empty list that layer 0 reads as a corpus citing nothing.
      * an index whose identifiers have moved to a shape the shared definition
        does not know must DIE naming the row. That is the exact rename this
        reader survived by accident of matching nothing at all.
    """
    live = module.citation_spans(REPO_ROOT).get("reject-per-vector", [])
    if not live:
        failures.append(
            "citation read path: the live reject index yields no per-vector "
            "span, so the two refusals below would pass on a broken reader"
        )
        return
    print(f"  control: the reject index cites {len(live)} spec spans")

    rigged: list[tuple[str, Callable[[str], str], str]] = [
        (
            "a per-vector index whose rows cite no specification line",
            lambda text: re.sub(r"\| L\d+[^|\n]*\|\n", "| |\n", text),
            "broken read path",
        ),
        (
            "a per-vector index whose identifiers moved to an unknown shape",
            lambda text: re.sub(r"`v([0-9a-f]{16})`", r"`bad-\1`", text),
            "not an identifier shape this corpus publishes",
        ),
    ]
    for name, edit, phrase in rigged:
        with tempfile.TemporaryDirectory() as td:
            root = _staged_root(Path(td), edit)
            if (root / "vectors/reject/INDEX.md").read_text(encoding="utf-8") == (
                REPO_ROOT / "vectors/reject/INDEX.md"
            ).read_text(encoding="utf-8"):
                failures.append(f"{name}: the rigging changed no bytes")
                continue
            # `die` prints its reason and raises with only an exit code, so the
            # reason is read off stderr rather than off the exception.
            noise = io.StringIO()
            try:
                with contextlib.redirect_stderr(noise):
                    spans = module.citation_spans(root)
            except SystemExit as exc:
                said = f"{exc}\n{noise.getvalue()}"
                if phrase not in said:
                    failures.append(
                        f"{name}: refused, but never said {phrase!r}. A refusal "
                        f"with the wrong reason is not the catch. It said:\n{said}"
                    )
                else:
                    print(f"  caught: {name}")
                continue
            failures.append(
                f"{name}: the reader ACCEPTED it and returned "
                f"{len(spans.get('reject-per-vector', []))} per-vector spans"
            )


Case = tuple[str, Callable[[Any], Callable[[str], str]], list[str], int, str]

FAST: list[Case] = [
    ("declaration whose sentence has become cited",
     case_stale_declaration, ["--layer", "0"], 1, "stopped being true"),
    ("declaration that states no reason",
     case_declaration_without_reason, ["--layer", "0"], 1, "states no reason"),
    ("declaration naming no normative sentence",
     case_phantom_sentence, ["--layer", "0"], 1, "names no normative sentence"),
    ("declaration pinned to the wrong sentence text",
     case_wrong_digest, ["--layer", "0"], 1, "the declaration pins"),
    ("an uncited obligation with its declaration deleted",
     case_declaration_deleted, ["--layer", "0"], 1, "is cited by nothing"),
    ("declaration class outside the vocabulary",
     case_class_outside_vocabulary, ["--layer", "0"], 1, "outside the declared vocabulary"),
    ("a ledger that expects a finding",
     case_expect_a_finding, ["--layer", "0"], 1, "findings, never"),
    ("a reading with no witness sketch",
     case_no_witness_sketch, ["--layer", "0"], 1, "carries no witnessSketch"),
    ("two variants claiming to be the implemented reading",
     case_two_implemented_variants, ["--layer", "0"], 1, "claim to be the implemented one"),
    ("a rival variant that declares no edit",
     case_rival_without_an_edit, ["--layer", "0"], 1, "reference under another name"),
    ("a ledger pinned to a revision of the authority text that is gone",
     case_stale_authority_pin, ["--layer", "0"], 1, "the ledger pins the authority text at"),
    ("a witness addressed to a decision about other text",
     case_witness_addressed_elsewhere, ["--layer", "0"], 1, "anchors none of"),
    ("a reading whose sentence names no line span",
     case_sentence_without_a_span, ["--layer", "0"], 1, "names no Lnnn"),
]

SLOW: list[Case] = [
    ("a variant edit that changes no bytes",
     case_noop_edit, ["--layer", "2"], 2, "changes no bytes"),
    ("a variant edit whose anchor is not in the rail",
     case_edit_anchor_absent, ["--layer", "2"], 2, "not exactly once"),
    ("a rival that computes what the reference computes",
     case_masked_is_a_finding, ["--layer", "2", "--fail-on-finding"], 1,
     "FINDING -- not a confirmation"),
    ("an equivalence declaration a vector falsifies",
     case_falsified_equivalence, ["--layer", "2"], 1, "FALSIFIED"),
    ("the implemented variant carrying the rail edit",
     case_implemented_variant_edits, ["--layer", "2"], 2,
     "is not the rail the repository ships"),
    ("a rival expressed in the replay driver rather than the rail",
     case_edit_in_the_replay_driver, ["--layer", "2"], 2, "is not part of the rail"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fast", action="store_true", help="skip the cases that need a Go toolchain"
    )
    args = parser.parse_args()
    module = _harness()
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="aee-reading-test-") as shared:
        cache = str(Path(shared) / "reach.json")
        cases = FAST + ([] if args.fast else SLOW)
        control_args = ["--layer", "0"] if args.fast else ["--reach-cache", cache]

        with tempfile.TemporaryDirectory() as td:
            staged = Path(td) / "READINGS.toml"
            shutil.copy2(LEDGER, staged)
            rc, out = _run(staged, control_args)
            if rc != 0:
                print(f"CONTROL FAILED: the committed ledger exits {rc}\n{out}", file=sys.stderr)
                return 1
            print("  control: the committed ledger passes (rc=0)")

        check_citation_read_path(module, failures)
        if not args.fast:
            check_stage_covers_the_build(module, failures)

        for name, build, extra, expected_rc, phrase in cases:
            with tempfile.TemporaryDirectory() as td:
                staged = Path(td) / "READINGS.toml"
                shutil.copy2(LEDGER, staged)
                try:
                    _apply(staged, build(module))
                except AssertionError as exc:
                    failures.append(f"{name}: {exc}")
                    continue
                shared_cache = ["--reach-cache", cache] if "2" in extra else []
                rc, out = _run(staged, [*extra, *shared_cache])
                if rc == 0:
                    failures.append(f"{name}: the gate ACCEPTED the mutation (rc=0)")
                elif rc != expected_rc:
                    failures.append(
                        f"{name}: expected rc={expected_rc}, got {rc}. The two "
                        "codes mean different things -- 1 is a falsified "
                        "declaration, 2 is a run that could not be trusted"
                    )
                elif phrase not in out:
                    failures.append(
                        f"{name}: the gate failed but never said {phrase!r}; a red "
                        f"run with the wrong reason is not the catch. Output:\n{out}"
                    )
                else:
                    print(f"  caught: {name}")

    if failures:
        print("\nFAIL: the harness did not catch every mutation.", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"\nOK: control passes and all {len(cases) + 2} mutations go red with a "
        "named reason."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
