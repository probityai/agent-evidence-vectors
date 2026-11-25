#!/usr/bin/env python3
"""Reading differential: can this corpus tell two admissible readings apart?

The defect this exists for, and why nothing here could see it
-------------------------------------------------------------
An outside implementer has now found the same class of gap four times, at
revisions 2, 8, 13 and 25 of the same review: a rule whose text admits two
readings, implemented one way by him and the other way by us, scoring
IDENTICALLY over the whole corpus. Each time the discovery was an accident of
his instrumenting his own checker; nothing in this repository asks the question.
At revision 13 we wrote the general lesson down in his own words -- "the corpus
cannot currently tell us apart, and one vector settles it either way" -- and
built nothing on it, and the identical finding arrived again seven days later.

The instruments already here cannot reach it, and the reason is structural
rather than an omission:

  * ``forcing-gate.py`` mutates the RAIL. The rail implements ONE reading, so
    the code that would express a rival reading was never written and has no
    site to be mutated at. Its operators are weakenings -- drop a guard, widen a
    conjunction -- and a reading swap is not a weakening. Its oracle is
    verdict-only, and the live case produces zero verdict flips.
  * ``spec-anchor-gate.py`` pins the bytes an anchor addresses. A wrong anchor
    addresses its bytes perfectly well.
  * ``interpretation-registry-gate.py`` asks whether a forced decision names a
    live vector. A vector that runs proves the rule is EXERCISED. It has never
    been able to prove the reading is FORCED, which is why every one of its
    twenty forced decisions currently sits in an ``unwitnessedForced``
    declaration: the instrument that would produce a witness did not exist.

So the thing to mutate is neither the artifact nor the rail. It is the READING.
Build the rail under each admissible reading of one sentence, replay the whole
corpus under both, and ask whether ANY vector's observable moved.

Zero difference is a finding, never a confirmation
--------------------------------------------------
This is the single property whose absence let 248 of 248 read as settling a
question it could not see, and it is transplanted from the GEO mutation replay,
where a mutation that applied to nothing is the sharpest available finding and
never a pass. The reviewer arrived at the same rule independently and very
nearly did not report it: "I mutated the sealed existential to the broad reading
and got zero per-vector differences, which I nearly sent as confirmation. It
confirms nothing."

Hence five verdicts, and only the first two are evidence of anything:

  DISCRIMINATED  some vector's VERDICT differs. The corpus pins the reading.
  REPORT-ONLY    verdicts agree, the reported condition codes differ. Pinned in
                 diagnostics only. Recorded, never counted as a kill -- and the
                 verdict a verdict-only oracle throws away, which is exactly how
                 the live case reads as nothing happening.
  MASKED         vectors REACH the site and every one of them is decided
                 elsewhere, so both readings land in the same place for
                 different reasons. A FINDING. It emits the witness sketch
                 naming the vector shape that would discriminate.
  UNREACHED      no vector executes the site at all. A harder finding than
                 MASKED.
  EQUIVALENT     both oracles unchanged AND a declared equivalence argument
                 holds. It LEAVES the denominator rather than joining the
                 findings, and the declaration is falsifiable: a differential
                 that later moves fails this gate rather than being absorbed.

Reachability is not discrimination, which is why layer 1 exists. Seventy-three
of the corpus's vectors reach the sealed existential; every candidate carries a
dirty seal AND a clean one, so the broad reading is satisfied by the clean seal
and the sweep rejects the dirty one. An instrument that asked only "does a
vector reach this rule" would have reported full coverage.

The three layers
----------------
  L0  Sentence coverage. Enumerate every RFC 2119 sentence in the authority
      text and ask whether ANY vector, condition row, interpretation decision or
      declared-unforced cell cites it. An uncited obligation must carry a
      declaration in ``spec/READINGS.toml`` giving a class and a reason, and a
      declaration whose sentence has BECOME cited fails: a declaration that has
      stopped being true is worse than none. Each declaration is keyed on a
      digest of the sentence TEXT, never on its line number, so an obligation
      that moves under an unrelated edit cannot inherit somebody else's excuse.
  L1  Reachability, per site and per vector, from a coverage-instrumented replay
      of the unmutated rail. It separates the three states a "no vector notices"
      result can hide: nothing reaches the site, something reaches it and is
      decided earlier, something reaches it and is decided by it.
  L2  The differential itself, over ``spec/READINGS.toml``.

What is reused rather than rewritten
------------------------------------
The site parser, the corpus fingerprint, the observation key and the build
helper are imported from ``forcing-gate.py``. A second copy of any of them would
be a second answer to the same question and the two would drift; the coverage
block reader in particular already encodes the fact that a guard's condition
executes whether or not its branch is taken.

Guards, each of which has a failure it is for
---------------------------------------------
  * An edit whose ``find`` text does not appear EXACTLY once is refused. Zero
    matches and two matches are different bugs and both are silent.
  * An edit that leaves the file byte-identical is refused. A line count cannot
    see a one-value-for-one-value swap, so the text is hashed.
  * An edit outside the rail package is refused. ``cmd/mutrun`` is the
    instrument that REPORTS the observation, so an edit there changes what the
    harness sees rather than what the rail does. Driven against the committed
    ledger, one such edit moved 195 of 250 vectors and was scored REPORT-ONLY
    with a witness whose two sides printed the same string.
  * The implemented variant's rail must be byte-identical to the rail the
    repository ships. It was not enough to say so: with the implemented flag on
    the side carrying the edit, the live ledger returned DISCRIMINATED at exit
    0 and emitted a witness saying bad-742 is VALID under the implemented
    reading, which is the opposite of what the shipped rail answers. A
    differential between two rails neither of which exists publishes the reading
    nobody implements.
  * Two variants of one reading whose rail sources are byte-identical are
    refused. A differential between a tree and itself returns MASKED and looks
    like a measurement.
  * The staged reference tree must reproduce the repository's own replay, vector
    for vector, before any variant is built. Staging is a copy of a subset of
    the module, and a subset that answers differently would make every number
    below a fact about the copy.
  * The corpus is fingerprinted before the first replay and again after the
    last. A corpus written mid-run is read one way by one variant and another
    way by the other, and the difference is reported as discrimination.
  * A variant rail that panics on any vector stops the run. A crash is not an
    observable.

Usage:
    scripts/reading-differential.py                 # all three layers
    scripts/reading-differential.py --layer 0       # the sentence lint alone
    scripts/reading-differential.py --json out.json # machine-readable result
    scripts/reading-differential.py --fail-on-finding
Layers 1 and 2 need a Go toolchain. A missing toolchain is a FAILURE, never a
skip. Exit 0 when every declaration holds; 1 when one is falsified or an
expectation is unmet; 2 when the run itself could not be trusted.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "spec" / "predicates" / "adversarial-execution-evidence.md"
READINGS = REPO_ROOT / "spec" / "READINGS.toml"
VECTORS = REPO_ROOT / "vectors"

# ONE definition of how a vector row is found, imported rather than restated.
# The reader below used to carry its own copy keyed on the retired `bad-` and
# `ok-` name prefixes; when identifiers became content addresses it matched
# nothing and reported an empty citation index without complaint.
sys.path.insert(0, str(VECTORS))
from gen_manifest import corpus_files, table_rows  # noqa: E402

# Everything a build of cmd/mutrun reads. The whole repository is copied by the
# forcing campaign because it mutates in place under many workers; this harness
# builds a handful of trees and a 150 MB copy per variant would dominate the
# run. The reference control below is what makes the subset safe to use: if the
# subset ever stopped reproducing the repository's own replay, the run stops.
STAGED = ("go.mod", "aee", "corpusreaders", "internal", "observedeffect", "cmd")
# Present in some checkouts and not others; the core module carries no external
# dependency. Named rather than globbed so a member that stops being copied is a
# deliberate edit here instead of a silent build difference.
STAGED_OPTIONAL = ("go.sum",)
# The package a reading may be expressed in. Everything else in the staged tree
# is the instrument rather than the subject: cmd/mutrun decides which fields of
# a verify report become the observation, so an edit there moves every vector's
# observable at once and no reading of any sentence could have done that.
RAIL_PACKAGE = "aee"

VERDICTS = ("DISCRIMINATED", "REPORT-ONLY", "MASKED", "UNREACHED", "EQUIVALENT")
# The verdicts a ledger entry may claim in advance. The three findings are
# deliberately unspellable: an author who writes `expect = "MASKED"` has turned
# the sharpest available result into a target, which is the exact move the
# no-op refusal exists to prevent.
EXPECTABLE = ("DISCRIMINATED", "REPORT-ONLY")

# The declared-non-coverage vocabulary vectors/coverage-unforced.json already
# ships, plus the one class that file has no cell for. Reusing it means an L0
# declaration can be promoted into that file without a translation step.
EXEMPTION_CLASSES = (
    "consumer-policy-unvectorable",
    "producer-obligation-ungated",
    "forcible-but-unforced",
    # The design this was built from called the fourth class
    # `changelog-restatement`. The measurement found a restatement outside the
    # changelog too -- the row-level partition rule is restated in the
    # non-normative consumer-policy example -- so the class is named for the
    # property that excuses the sentence rather than for the section it sits in.
    "restatement-elsewhere-normative",
    # Not an excuse and not from the design: a sentence the corpus DOES force,
    # whose citing entry's anchor stops short of it. It is the sharpest thing
    # this layer finds, so it is declared with the one-token widening that
    # closes it and it deletes itself the moment that widening lands.
    "anchor-stops-short-of-the-obligation",
)


def die(message: str, code: int = 2) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(code)


def _sibling(name: str) -> Any:
    """Import a hyphenated sibling gate as a module."""
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        die(f"{path} cannot be imported, and this harness reuses its site parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# layer 0: is there a vector that exercises this sentence at all
# ---------------------------------------------------------------------------

KEYWORD = re.compile(r"\b(MUST NOT|MUST|REQUIRED|SHALL|SHOULD NOT|SHOULD)\b")
OBLIGATION = re.compile(r"\b(MUST|REQUIRED|SHALL)\b")
# The abbreviation guards the restatement lint already uses. A sentence splitter
# that breaks on "e.g." reports two half-sentences, and half a sentence carrying
# the keyword and half carrying the subject are both wrong.
SENTENCE_END = re.compile(r"(?<!e\.g)(?<!i\.e)(?<!vs)(?<!cf)(?<!No)[.;](?=\s|$)")
FENCE = re.compile(r"^\s*(```|~~~)")
ANCHOR = re.compile(r"\bL(\d+)(?:-(\d+))?\b")

Sentence = tuple[int, str]
Span = tuple[int, int]


def _flush(buffer: list[Sentence], out: list[Sentence]) -> None:
    """Split one paragraph into sentences, keeping each one's starting line."""
    if not buffer:
        return
    text = " ".join(t for _, t in buffer)
    offsets: list[tuple[int, int]] = []
    cursor = 0
    for line_no, line in buffer:
        offsets.append((cursor, line_no))
        cursor += len(line) + 1
    position = 0
    for match in [*SENTENCE_END.finditer(text), None]:
        end = match.end() if match else len(text)
        raw = text[position:end]
        segment = raw.strip()
        if segment:
            # THE LINE LOOKUP USES THE SENTENCE'S FIRST NON-SPACE CHARACTER, NOT
            # `position`. After a terminator, `position` points at the SPACE this
            # function inserted when it joined the paragraph's lines, and that
            # offset still falls inside the PREVIOUS line's range -- so a sentence
            # opening a new line was attributed to the line above it.
            #
            # It produced a phantom finding rather than a cosmetic one. The
            # subject-cardinality obligation opens L210; this reported it at L209,
            # the tail of an unrelated sentence about time axes. That became an
            # uncited-obligation row asserting "the obligation begins at L209",
            # and a repair instruction to widen two CORRECT anchors down to L209 --
            # which would have pulled a sentence about the producer's clock into an
            # anchor about subject cardinality, the exact defect the anchor gate
            # exists to refuse.
            start = position + (len(raw) - len(raw.lstrip()))
            line_no = offsets[0][1]
            for offset, candidate in offsets:
                if offset <= start:
                    line_no = candidate
            out.append((line_no, segment))
        position = end
        if match is None:
            break


def enumerate_sentences(text: str) -> list[Sentence]:
    """Every prose sentence outside a fenced block, with the line it starts on.

    Fenced blocks are skipped because an obligation inside one is an example
    rather than a rule. That skip costs nothing here and it was checked rather
    than assumed: the authority text carries 94 RFC 2119 occurrences outside
    fences and none inside.
    """
    out: list[Sentence] = []
    buffer: list[Sentence] = []
    in_fence = False
    for line_no, raw in enumerate(text.splitlines(), 1):
        if FENCE.match(raw):
            in_fence = not in_fence
            _flush(buffer, out)
            buffer = []
            continue
        if in_fence:
            continue
        if not raw.strip():
            _flush(buffer, out)
            buffer = []
            continue
        buffer.append((line_no, raw.strip()))
    _flush(buffer, out)
    return out


def _spans(text: str) -> list[Span]:
    return [
        (int(m.group(1)), int(m.group(2) or m.group(1)))
        for m in ANCHOR.finditer(text)
    ]


def _per_vector_spans(index: Path) -> list[Span]:
    """Spec spans cited by the vector rows of one index, read by TABLE not name.

    This reader used to keep the lines beginning ``| `bad-`` and ``| `ok-``,
    which is a citation index keyed on a VECTOR NAME. When names became content
    addresses both filters matched nothing, both sources reported zero spans
    without a word, and layer 0 reported five obligations as cited by nothing
    that five reject vectors cite by line range today. A citation source that
    silently empties is worse than one that is missing: missing is checked for
    above, empty is indistinguishable from a corpus that really has no citation.

    So the rows are found the way ``gen_manifest.table_rows`` finds them -- by
    the table whose first column is called `vector` -- and that function refuses
    a row it cannot read rather than skipping it. Names will move again; the
    header will not, and if it does the refusal names the file.
    """
    return [s for row in table_rows(str(index)) for cell in row for s in _spans(cell)]


def citation_spans(root: Path) -> dict[str, list[Span]]:
    """Every line span anything in the corpus points at the specification with.

    This is the most GENEROUS possible reading of "a vector exercises it": the
    span need only CONTAIN the sentence and the citation need not be about it.
    Coverage measured this way is an upper bound on the real thing, and the
    summary says so on a clean run rather than letting green imply more than it
    means.
    """
    out: dict[str, list[Span]] = {}
    reject_index = root / "vectors" / "reject" / "INDEX.md"
    accept_index = root / "vectors" / "accept" / "INDEX.md"
    if not reject_index.is_file():
        die(f"{reject_index} is missing; the condition registry is the primary citation index")
    reject_lines = reject_index.read_text(encoding="utf-8").splitlines()
    out["condition-registry"] = [
        s for line in reject_lines if re.match(r"^\|\s*aee-c-\d+\s*\|", line) for s in _spans(line)
    ]
    out["reject-per-vector"] = _per_vector_spans(reject_index)
    out["accept-per-vector"] = (
        _per_vector_spans(accept_index) if accept_index.is_file() else []
    )
    if not out["reject-per-vector"]:
        die(
            f"{reject_index}: the vector table cites no specification line at "
            "all. That table is the primary per-vector citation index and it "
            "carries a `spec` column on every row; a reader that returns "
            "nothing from it is a broken read path, and layer 0 would go on to "
            "report every sentence only that table cites as uncited"
        )
    registry = root / "vectors" / "interpretation-decisions.json"
    out["interpretation-registry"] = []
    if registry.is_file():
        data = json.loads(registry.read_text(encoding="utf-8"))
        out["interpretation-registry"] = [
            s
            for entry in [*data.get("decisions", []), *data.get("openCorners", [])]
            for anchor in entry.get("specAnchors", [])
            for s in _spans(str(anchor))
        ]
    unforced = root / "vectors" / "coverage-unforced.json"
    out["coverage-unforced"] = []
    if unforced.is_file():
        cells = json.loads(unforced.read_text(encoding="utf-8"))
        out["coverage-unforced"] = [
            s
            for cell in cells.get("cells", [])
            for anchor in cell.get("specAnchors", [])
            for s in _spans(str(anchor))
        ]
    return out


def _cited(line_no: int, spans: list[Span]) -> bool:
    return any(lo <= line_no <= hi for lo, hi in spans)


def _check_declaration(
    entry: dict[str, Any],
    normative: dict[int, str],
    uncited: dict[int, str],
    errors: list[str],
) -> int | None:
    """One `[[uncited]]` row: does it name a real sentence, and is it still true?"""
    raw = str(entry.get("sentence", ""))
    match = ANCHOR.fullmatch(raw)
    if match is None:
        errors.append(f"L0 declaration {raw!r}: sentence must be a single Lnnn anchor")
        return None
    line_no = int(match.group(1))
    text = normative.get(line_no)
    if text is None:
        errors.append(
            f"L0 declaration L{line_no}: names no normative sentence in the "
            "authority text, so it excuses nothing"
        )
        return line_no
    pin, actual = str(entry.get("digest", "")), _digest(text)[:16]
    if pin != actual:
        errors.append(
            f"L0 declaration L{line_no}: the sentence there digests {actual} but "
            f"the declaration pins {pin}. A declaration keyed on a line number "
            "inherits whatever sentence moves onto it"
        )
    klass = str(entry.get("class", ""))
    if klass not in EXEMPTION_CLASSES:
        errors.append(
            f"L0 declaration L{line_no}: class {klass!r} is outside the declared "
            f"vocabulary {EXEMPTION_CLASSES}"
        )
    if not str(entry.get("reason", "")).strip():
        errors.append(
            f"L0 declaration L{line_no}: states no reason; an undeclared reason "
            "is an exemption wearing a declaration's clothes"
        )
    if line_no not in uncited:
        errors.append(
            f"L0 declaration L{line_no}: that sentence is cited now, so the "
            "declaration has stopped being true -- delete it. A declaration that "
            "no longer flags anything is a stale claim about coverage"
        )
    return line_no


def check_authority_pin(root: Path, ledger: dict[str, Any], errors: list[str]) -> str:
    """The ledger's ``[meta]`` pin must name the text it was written against.

    This was written into the ledger and read by nothing, which is the defect
    the whole file exists to argue against: a declared control that never runs
    reports the same green as one that holds. Every L0 number, every sentence
    digest and both reading pairs are claims about ONE revision of the authority
    text, and a spec edit that lands without a matching pin leaves them claims
    about a document that is gone.
    """
    meta = ledger.get("meta", {})
    rel = str(meta.get("spec", "")).strip() or str(SPEC.relative_to(REPO_ROOT))
    path = root / rel
    if not path.is_file():
        errors.append(f"the ledger pins the authority text at {rel}, which is not a file")
        return ""
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    pin = str(meta.get("specDigest", "")).strip()
    if pin != actual:
        errors.append(
            f"the ledger pins the authority text at {pin or '<nothing>'} and "
            f"{rel} digests {actual}. Update the pin in the same edit that moves "
            "the specification, or every figure below is a measurement of a "
            "revision the ledger was not written against"
        )
    return actual


def layer0(root: Path, ledger: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    """Enumerate the normative sentences and hold the declarations honest."""
    spec_path = root / "spec" / "predicates" / "adversarial-execution-evidence.md"
    if not spec_path.is_file():
        die(f"{spec_path} is missing; there is no authority text to enumerate")
    sentences = enumerate_sentences(spec_path.read_text(encoding="utf-8"))
    normative = [(n, s) for n, s in sentences if KEYWORD.search(s)]
    obligations = [(n, s) for n, s in normative if OBLIGATION.search(s)]
    shoulds = [(n, s) for n, s in normative if not OBLIGATION.search(s)]

    sources = citation_spans(root)
    every_span = [s for spans in sources.values() for s in spans]
    uncited = {n: s for n, s in normative if not _cited(n, every_span)}

    declared: dict[int, dict[str, Any]] = {}
    for entry in ledger.get("uncited", []):
        line_no = _check_declaration(entry, dict(normative), uncited, errors)
        if line_no is None:
            continue
        if line_no in declared:
            errors.append(f"L0 declaration L{line_no}: declared twice")
        declared[line_no] = entry

    for line_no, text in sorted(uncited.items()):
        if line_no in declared:
            continue
        kind = "obligation" if OBLIGATION.search(text) else "SHOULD"
        errors.append(
            f"L0: the {kind} at L{line_no} is cited by nothing -- no condition "
            f"row, no vector anchor, no interpretation decision, no unforced "
            f"cell -- and carries no declaration in {READINGS.name}: {text[:110]}"
        )

    return {
        "specLines": len(spec_path.read_text(encoding="utf-8").splitlines()),
        "sentences": len(sentences),
        "normative": len(normative),
        "obligations": len(obligations),
        "shoulds": len(shoulds),
        "obligationsCited": sum(1 for n, _ in obligations if _cited(n, every_span)),
        "shouldsCited": sum(1 for n, _ in shoulds if _cited(n, every_span)),
        "uncited": sorted(uncited),
        "declared": sorted(declared),
        "sources": {k: len(v) for k, v in sources.items()},
    }


# ---------------------------------------------------------------------------
# the rail under one reading
# ---------------------------------------------------------------------------


class Rail:
    """One staged Go tree, built and replayed."""

    def __init__(self, fg: Any, root: Path, work: Path, name: str, keys: str) -> None:
        self.fg = fg
        self.root = root
        self.name = name
        self.tree = work / name
        self.keys = keys
        self.binary = str(work / f"mutrun-{name}")
        self.cover_binary = str(work / f"mutrun-{name}.cover")

    def stage(self) -> None:
        self.tree.mkdir(parents=True)
        for member in STAGED + STAGED_OPTIONAL:
            src = self.root / member
            if not src.exists():
                if member in STAGED_OPTIONAL:
                    continue
                die(
                    f"{src} is missing, so no rail can be built; this harness "
                    "stages exactly the module a mutrun build reads"
                )
            if src.is_dir():
                shutil.copytree(src, self.tree / member, symlinks=True)
            else:
                shutil.copy2(src, self.tree / member)

    def source_digest(self) -> str:
        """A digest over every Go source byte the staged tree is built from.

        The whole tree rather than the rail package alone. Two trees differing
        only in ``cmd/mutrun`` are not two rails that agree; they are one rail
        watched two ways, and hashing the narrower set made the byte-identical
        refusal below state something false about exactly that pair.
        """
        hashed = hashlib.sha256()
        for path in sorted(self.tree.rglob("*.go")):
            hashed.update(path.relative_to(self.tree).as_posix().encode("utf-8") + b"\0")
            hashed.update(hashlib.sha256(path.read_bytes()).digest())
        return hashed.hexdigest()

    def build(self, cover: bool = False) -> None:
        self.fg.go_build(
            "./cmd/mutrun", self.cover_binary if cover else self.binary, self.tree, cover=cover
        )

    def replay(self, vectors: Path) -> dict[str, dict[str, Any]]:
        proc = subprocess.run(
            [self.binary, str(vectors), self.keys], capture_output=True, timeout=900
        )
        if proc.returncode != 0:
            die(
                f"the {self.name} rail failed to replay the corpus, so nothing "
                f"below is a measurement:\n{proc.stderr.decode('utf-8', 'replace')}"
            )
        lines = self.fg.jsonl(proc.stdout.decode("utf-8"))
        panicked = [line["id"] for line in lines if line.get("panic")]
        if panicked:
            die(
                f"the {self.name} rail panicked on {len(panicked)} vector(s) "
                f"({', '.join(panicked[:5])}). A crash is not an observable and "
                "must never be scored as a reading difference"
            )
        return {line["id"]: line for line in lines}


def vector_files(vectors: Path) -> dict[str, Path]:
    """The corpus, read the one way the repository defines it.

    This globbed a directory per verdict, which is the layout retired at
    suiteRevision 28, and after the flat corpus landed it found nothing and
    stopped layers 1 and 2 outright. Reading it through ``corpus_files`` means
    the layout is defined once: a tree it cannot read is refused there, by name,
    instead of coming back empty here.
    """
    out = {Path(path).stem: Path(path) for _, path in corpus_files(str(vectors))}
    if not out:
        die(f"{vectors}/statements carries no vector; nothing below is a measurement")
    return out


# ---------------------------------------------------------------------------
# layer 1: which vectors execute which lines
# ---------------------------------------------------------------------------


def _covdata_blocks(profile: Path) -> dict[str, list[tuple[int, int, int]]]:
    blocks: dict[str, list[tuple[int, int, int]]] = {}
    if not profile.is_file():
        return blocks
    for line in profile.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("mode:"):
            continue
        location, _statements, count = line.rsplit(" ", 2)
        filepath, span = location.rsplit(":", 1)
        start, end = span.split(",")
        blocks.setdefault(filepath.split("/")[-1], []).append(
            (int(start.split(".")[0]), int(end.split(".")[0]), int(count))
        )
    return blocks


def _one_vector_coverage(
    rail: Rail, work: Path, vid: str, path: Path
) -> tuple[str, dict[str, list[tuple[int, int, int]]]]:
    """Coverage of the rail under exactly one vector.

    mutrun takes a corpus DIRECTORY, so the vector is presented as a one-file
    corpus of symlinks rather than by teaching the tool a second input mode.
    The one-file corpus is FLAT, because that is the only layout the corpus
    reader accepts: this built a directory per verdict and put the vector in the
    one its path named, which after the flat corpus landed meant every scratch
    corpus was three empty directories.
    """
    scratch = work / "pv" / vid
    corpus = scratch / "corpus" / "statements"
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / path.name).symlink_to(path)
    covdir = scratch / "cov"
    covdir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [rail.cover_binary, str(scratch / "corpus"), rail.keys],
        capture_output=True,
        env=dict(os.environ, GOCOVERDIR=str(covdir)),
        timeout=300,
        check=False,
    )
    profile = scratch / "profile.txt"
    subprocess.run(
        ["go", "tool", "covdata", "textfmt", f"-i={covdir}", f"-o={profile}"],
        capture_output=True,
        timeout=300,
        check=False,
    )
    return vid, _covdata_blocks(profile)


def load_reach_cache(
    path: str, rail_digest: str, corpus: str
) -> dict[str, dict[str, list[tuple[int, int, int]]]] | None:
    """A previous sweep, accepted only when the rail AND the corpus still match.

    The sweep is the expensive half of a run and a developer loop repeats it
    unchanged. Two digests key it because either one moving changes the answer,
    and a cache keyed on neither would answer a question about a tree that is
    gone. A miss recomputes and says so; it is never a reason to skip the sweep.
    """
    if not path or not Path(path).is_file():
        return None
    blob = json.loads(Path(path).read_text(encoding="utf-8"))
    if blob.get("railDigest") != rail_digest or blob.get("corpusFingerprint") != corpus:
        print("reach cache: stale (rail or corpus moved); re-measuring.")
        return None
    return {
        vid: {
            filename: [(int(a), int(b), int(c)) for a, b, c in blocks]
            for filename, blocks in files.items()
        }
        for vid, files in blob["coverage"].items()
    }


def write_reach_cache(
    path: str,
    rail_digest: str,
    corpus: str,
    coverage: dict[str, dict[str, list[tuple[int, int, int]]]],
) -> None:
    if not path:
        return
    Path(path).write_text(
        json.dumps(
            {"railDigest": rail_digest, "corpusFingerprint": corpus, "coverage": coverage},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def per_vector_coverage(
    rail: Rail, work: Path, vectors: dict[str, Path], workers: int
) -> dict[str, dict[str, list[tuple[int, int, int]]]]:
    out: dict[str, dict[str, list[tuple[int, int, int]]]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_one_vector_coverage, rail, work, vid, path)
            for vid, path in vectors.items()
        ]
        for future in concurrent.futures.as_completed(futures):
            vid, blocks = future.result()
            out[vid] = blocks
    empty = [vid for vid, blocks in out.items() if not blocks]
    if empty:
        die(
            f"the coverage-instrumented rail produced no profile for "
            f"{len(empty)} vector(s) ({', '.join(sorted(empty)[:5])}). An empty "
            "read path reports 'reaches nothing' identically to real "
            "unreachability, so no reachability number here would be a fact"
        )
    return out


def reached_by(
    coverage: dict[str, dict[str, list[tuple[int, int, int]]]], filename: str, lines: set[int]
) -> list[str]:
    """The vectors that executed at least one covered block over these lines."""
    out: list[str] = []
    for vid, blocks in coverage.items():
        for lo, hi, count in blocks.get(filename, []):
            if count > 0 and any(lo <= line <= hi for line in lines):
                out.append(vid)
                break
    return sorted(out)


def layer1(
    fg: Any,
    rail: Rail,
    work: Path,
    coverage: dict[str, dict[str, list[tuple[int, int, int]]]],
) -> dict[str, Any]:
    """Per-site reach counts over every site the rail's own parser enumerates."""
    mutgen = str(work / "mutgen")
    fg.go_build("./cmd/mutgen", mutgen, rail.tree)
    proc = subprocess.run(
        [mutgen, "-pkg", str(rail.tree / "aee"), "-list"], capture_output=True, timeout=300
    )
    if proc.returncode != 0:
        die(
            "mutgen could not enumerate the rail's mutation sites:\n"
            + proc.stderr.decode("utf-8", "replace")
        )
    sites = fg.jsonl(proc.stdout.decode("utf-8"))
    if not sites:
        die("mutgen found no sites in the rail; there is nothing to measure reachability over")

    counts: dict[str, int] = {}
    for site in sites:
        reachers = [
            vid
            for vid, blocks in coverage.items()
            if fg.branch_taken(blocks, site) == "taken"
        ]
        counts[site["key"]] = len(reachers)
    unreached = sorted(key for key, n in counts.items() if n == 0)
    return {
        "sites": len(sites),
        "vectors": len(coverage),
        "reachedByNone": len(unreached),
        "reachedByOne": sum(1 for n in counts.values() if n == 1),
        "unreachedSites": unreached,
        "counts": counts,
    }


# ---------------------------------------------------------------------------
# layer 2: the differential
# ---------------------------------------------------------------------------


def resolve_edit(tree: Path, edit: dict[str, Any], label: str) -> tuple[Path, str, str, set[int]]:
    """Locate one edit's anchor text and return the lines it sits on.

    A `find` that matches zero times and one that matches twice are different
    bugs and both are silent: the first leaves the variant equal to the
    reference and the second edits a site the author never read.
    """
    rel = str(edit.get("file", ""))
    if not rel:
        die(f"{label}: edit names no file")
    if Path(rel).parts[:1] != (RAIL_PACKAGE,):
        die(
            f"{label}: {rel} is not part of the rail. A reading is expressed in "
            f"{RAIL_PACKAGE}/ and nowhere else -- an edit to the replay driver "
            "changes what the harness SEES rather than what the rail DOES, so "
            "every vector's observable moves at once for a reason no reading of "
            "any sentence could have produced"
        )
    path = tree / rel
    if not path.is_file():
        die(f"{label}: {rel} is not a file in the staged rail")
    body = path.read_text(encoding="utf-8")
    find = str(edit.get("find", ""))
    replace = str(edit.get("replace", ""))
    if not find:
        die(f"{label}: edit carries no find text")
    if replace == find:
        die(
            f"{label}: the edit changes no bytes. A variant byte-identical to "
            "the reference is not a rival reading, and the differential would "
            "return MASKED and read exactly like a measurement"
        )
    hits = body.count(find)
    if hits != 1:
        die(
            f"{label}: the edit's find text appears {hits} times in {rel}, not "
            "exactly once. Zero means the edit silently applied nothing and the "
            "variant is the reference; more than one means it would edit a site "
            "nobody read"
        )
    offset = body.index(find)
    first = body.count("\n", 0, offset) + 1
    lines = set(range(first, first + find.count("\n") + 1))
    return path, find, replace, lines


def apply_variant(tree: Path, variant: dict[str, Any], label: str) -> None:
    for index, edit in enumerate(variant.get("edit", [])):
        path, find, replace, _ = resolve_edit(tree, edit, f"{label} edit {index}")
        before = path.read_text(encoding="utf-8")
        after = before.replace(find, replace, 1)
        if _digest(before) == _digest(after):
            die(
                f"{label} edit {index} changes no bytes in {path.name}. A "
                "variant that is byte-identical to the reference is not a rival "
                "reading, and the differential would return MASKED and read "
                "exactly like a measurement"
            )
        path.write_text(after, encoding="utf-8")


def reading_site_lines(tree: Path, reading: dict[str, Any]) -> dict[str, set[int]]:
    """Where in the REFERENCE source this reading's variants disagree."""
    lines: dict[str, set[int]] = {}
    for variant in reading.get("variant", []):
        label = f"reading {reading['id']} variant {variant.get('id')}"
        for index, edit in enumerate(variant.get("edit", [])):
            path, _, _, spanned = resolve_edit(tree, edit, f"{label} edit {index}")
            lines.setdefault(path.name, set()).update(spanned)
    return lines


def compare(
    fg: Any, reference: dict[str, dict[str, Any]], rival: dict[str, dict[str, Any]]
) -> tuple[list[str], list[str]]:
    """E1 (the verdict moved) and E2 (something else the harness sees moved)."""
    if set(reference) != set(rival):
        die(
            "the two rails replayed different vector sets, so the comparison is "
            "between two corpora rather than two readings"
        )
    verdict_moved: list[str] = []
    report_moved: list[str] = []
    for vid in sorted(reference):
        left, right = fg.as_observed(reference[vid]), fg.as_observed(rival[vid])
        if left["verdict"] != right["verdict"]:
            verdict_moved.append(vid)
        elif fg.observation_key(left) != fg.observation_key(right):
            report_moved.append(vid)
    return verdict_moved, report_moved


def witness_for(
    fg: Any,
    reference: dict[str, dict[str, Any]],
    rival: dict[str, dict[str, Any]],
    reading: dict[str, Any],
    implemented: dict[str, Any],
    challenger: dict[str, Any],
    verdict_moved: list[str],
    report_moved: list[str],
) -> dict[str, Any] | None:
    """The discrimination witness, shaped for the interpretation registry.

    Emitted ONLY for a verdict or code difference. A MASKED or UNREACHED reading
    gets no witness, which is the whole point: the file that publishes forced
    readings must not be able to launder silence into a citation.
    """
    if verdict_moved:
        vid, observable = verdict_moved[0], "verdict"
        left = str(fg.as_observed(reference[vid])["verdict"])
        right = str(fg.as_observed(rival[vid])["verdict"])
    elif report_moved:
        vid, observable = report_moved[0], "codes"
        left = "+".join(sorted(fg.as_observed(reference[vid])["codes"]))
        right = "+".join(sorted(fg.as_observed(rival[vid])["codes"]))
    else:
        return None
    return {
        "rivalReading": str(challenger.get("summary", challenger.get("id"))),
        "witnessVector": vid,
        "observable": observable,
        "underReading": left,
        "underRival": right,
        "readingId": reading["id"],
        "implementedVariant": implemented.get("id"),
        "rivalVariant": challenger.get("id"),
    }


def score_reading(
    fg: Any,
    reading: dict[str, Any],
    reach: list[str],
    verdict_moved: list[str],
    report_moved: list[str],
    errors: list[str],
) -> str:
    """The verdict algebra. Zero difference is never a pass."""
    equivalence = str(reading.get("equivalence", "")).strip()
    if verdict_moved:
        outcome = "DISCRIMINATED"
    elif report_moved:
        outcome = "REPORT-ONLY"
    elif not reach:
        outcome = "UNREACHED"
    elif equivalence:
        outcome = "EQUIVALENT"
    else:
        outcome = "MASKED"

    # One-directional, exactly as the GEO equivalence branch is. A declaration
    # can only ever move a silent result out of the findings; it can never
    # suppress a difference, and a difference DISPROVES it rather than being
    # absorbed by it.
    if equivalence and (verdict_moved or report_moved):
        errors.append(
            f"reading {reading['id']}: the declared equivalence argument is "
            f"FALSIFIED -- {len(verdict_moved)} verdict and {len(report_moved)} "
            "report difference(s) were measured. Somebody wrote the "
            "discriminating vector; delete the declaration"
        )
    expect = str(reading.get("expect", "")).strip()
    if expect and expect != outcome:
        errors.append(
            f"reading {reading['id']}: declared expect = {expect!r}, measured "
            f"{outcome}"
        )
    return outcome


def load_ledger(path: Path) -> dict[str, Any]:
    if not path.is_file():
        die(f"{path} is missing; there is no reading ledger to run")
    try:
        ledger = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        die(f"{path} does not parse: {exc}")
    return ledger


def registry_decision_anchors(root: Path) -> dict[Any, list[Span]]:
    """The ids a witness may be addressed to, and the spec lines each addresses."""
    path = root / "vectors" / "interpretation-decisions.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        entry.get("id"): [
            s for anchor in entry.get("specAnchors", []) for s in _spans(str(anchor))
        ]
        for entry in [*data.get("decisions", []), *data.get("openCorners", [])]
    }


def _overlap(left: list[Span], right: list[Span]) -> bool:
    return any(a <= d and c <= b for a, b in left for c, d in right)


def _check_registry_link(
    rid: str, reading: dict[str, Any], anchors: dict[Any, list[Span]], errors: list[str]
) -> None:
    """A witness may only be addressed to a decision that reads the same lines.

    The witness this harness emits is shaped to be pasted into
    ``vectors/interpretation-decisions.json`` against the named decision, where
    the sibling registry gate will then accept it as proof that that decision's
    reading is forced. Nothing tied the two together: a differential measured at
    one sentence could be addressed to a decision about another, and the
    laundered witness would retire an ``unwitnessedForced`` id no vector has
    ever discriminated.
    """
    claimed = _spans(str(reading.get("sentence", "")))
    if not claimed:
        errors.append(
            f"reading {rid}: sentence {reading.get('sentence')!r} names no Lnnn "
            "span, so nothing ties the differential to a place in the authority "
            "text"
        )
    decision = reading.get("registryDecision")
    if decision is None:
        return
    if decision not in anchors:
        errors.append(
            f"reading {rid}: registryDecision {decision!r} is not in "
            "vectors/interpretation-decisions.json. A witness addressed to a "
            "decision that does not exist retires nothing"
        )
        return
    if claimed and not _overlap(claimed, anchors[decision]):
        errors.append(
            f"reading {rid}: registryDecision {decision!r} anchors none of "
            f"{reading.get('sentence')!r}, so a witness measured here would be "
            "addressed to a decision about other text -- which is how a forced "
            "reading gets a citation no vector earned"
        )


def _check_reading(
    rid: str, reading: dict[str, Any], anchors: dict[Any, list[Span]], errors: list[str]
) -> None:
    if not str(reading.get("witnessSketch", "")).strip():
        errors.append(
            f"reading {rid}: carries no witnessSketch. An author who cannot "
            "say what vector shape would tell the two readings apart has not "
            "yet written a reading pair, and a MASKED result would name no "
            "way out of itself"
        )
    expect = str(reading.get("expect", "")).strip()
    if expect and expect not in EXPECTABLE:
        errors.append(
            f"reading {rid}: expect = {expect!r} is not one of {EXPECTABLE}. "
            "MASKED, UNREACHED and EQUIVALENT are findings, never "
            "expectations -- a ledger that can ask for one has turned the "
            "sharpest available result into a target"
        )
    _check_registry_link(rid, reading, anchors, errors)


def validate_ledger(ledger: dict[str, Any], errors: list[str]) -> None:
    anchors = registry_decision_anchors(REPO_ROOT)
    seen: set[str] = set()
    for reading in ledger.get("reading", []):
        rid = str(reading.get("id", ""))
        if not rid:
            errors.append("a reading entry carries no id")
            continue
        if rid in seen:
            errors.append(f"reading {rid}: declared twice")
        seen.add(rid)
        _check_reading(rid, reading, anchors, errors)
        _check_variants(rid, reading.get("variant", []), errors)


def _check_variants(rid: str, variants: list[dict[str, Any]], errors: list[str]) -> None:
    if len(variants) != 2:
        errors.append(
            f"reading {rid}: names {len(variants)} variant(s); a differential is "
            "between exactly two readings"
        )
        return
    implemented = [v for v in variants if v.get("implemented")]
    if len(implemented) != 1:
        errors.append(
            f"reading {rid}: {len(implemented)} variant(s) claim to be the "
            "implemented one; exactly one must, and it is the reading the "
            "registry publishes"
        )
    for variant in variants:
        if not str(variant.get("summary", "")).strip():
            errors.append(f"reading {rid} variant {variant.get('id')}: states no summary")
        if not variant.get("implemented") and not variant.get("edit"):
            errors.append(
                f"reading {rid} variant {variant.get('id')}: is not the "
                "implemented reading and declares no edit, so it is the "
                "reference under another name"
            )


def run_reading(
    fg: Any,
    reading: dict[str, Any],
    root: Path,
    work: Path,
    keys: str,
    coverage: dict[str, dict[str, list[tuple[int, int, int]]]],
    site_lines: dict[str, set[int]],
    reference_digest: str,
    errors: list[str],
) -> dict[str, Any]:
    rid = str(reading["id"])
    reach = sorted(
        {
            vid
            for filename, lines in site_lines.items()
            for vid in reached_by(coverage, filename, lines)
        }
    )

    variants = reading["variant"]
    implemented = next(v for v in variants if v.get("implemented"))
    challenger = next(v for v in variants if not v.get("implemented"))

    rails: dict[str, Rail] = {}
    replays: dict[str, dict[str, dict[str, Any]]] = {}
    for variant in (implemented, challenger):
        name = f"{rid}--{variant['id']}"
        rail = Rail(fg, root, work, name, keys)
        rail.stage()
        apply_variant(rail.tree, variant, f"reading {rid} variant {variant['id']}")
        rail.build()
        rails[str(variant["id"])] = rail
        replays[str(variant["id"])] = rail.replay(root / "vectors")

    left, right = rails[str(implemented["id"])], rails[str(challenger["id"])]
    if left.source_digest() != reference_digest:
        die(
            f"reading {rid}: variant {implemented['id']!r} is flagged implemented "
            "and its rail is not the rail the repository ships. The implemented "
            "variant IS the shipped reading, so an edit on it makes the "
            "differential a comparison between two rails neither of which "
            "exists, and the witness then publishes the reading nobody "
            "implements -- with the sides of a live pair swapped this way the "
            "gate returned DISCRIMINATED and named the shipped verdict as the "
            "rival's"
        )
    if left.source_digest() == right.source_digest():
        die(
            f"reading {rid}: the two variants build byte-identical rails, so the "
            "differential compares a tree with itself and would return MASKED"
        )

    verdict_moved, report_moved = compare(
        fg, replays[str(implemented["id"])], replays[str(challenger["id"])]
    )
    outcome = score_reading(fg, reading, reach, verdict_moved, report_moved, errors)
    witness = witness_for(
        fg,
        replays[str(implemented["id"])],
        replays[str(challenger["id"])],
        reading,
        implemented,
        challenger,
        verdict_moved,
        report_moved,
    )

    candidates = [str(v) for v in reading.get("witnessCandidates", [])]
    unknown = [v for v in candidates if v not in replays[str(implemented["id"])]]
    if unknown:
        errors.append(
            f"reading {rid}: witnessCandidates names {unknown}, which the corpus "
            "does not replay"
        )
    candidate_moved = [v for v in candidates if v in verdict_moved or v in report_moved]
    candidate_outcome = ""
    if candidates:
        candidate_outcome = "DISCRIMINATES" if candidate_moved else "MASKED"

    return {
        "id": rid,
        "title": reading.get("title", ""),
        "sentence": reading.get("sentence", ""),
        "verdict": outcome,
        "reach": len(reach),
        "reachedBy": reach,
        "verdictMoved": verdict_moved,
        "reportMoved": report_moved,
        "witness": witness,
        "witnessSketch": reading.get("witnessSketch", ""),
        "witnessCandidates": candidates,
        "candidateOutcome": candidate_outcome,
        "registryDecision": reading.get("registryDecision"),
        "implemented": implemented.get("id"),
        "rival": challenger.get("id"),
    }


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------


def reference_control(fg: Any, rail: Rail, root: Path, work: Path) -> None:
    """The staged subset must answer what the repository answers, vector for vector."""
    whole = str(work / "mutrun-repository")
    fg.go_build("./cmd/mutrun", whole, root)
    proc = subprocess.run(
        [whole, str(root / "vectors"), rail.keys], capture_output=True, timeout=900
    )
    if proc.returncode != 0:
        die(
            "the repository's own rail failed to replay the corpus:\n"
            + proc.stderr.decode("utf-8", "replace")
        )
    truth = {line["id"]: line for line in fg.jsonl(proc.stdout.decode("utf-8"))}
    staged = rail.replay(root / "vectors")
    moved, reported = compare(fg, truth, staged)
    if moved or reported:
        die(
            f"the staged reference rail disagrees with the repository's own on "
            f"{len(moved) + len(reported)} vector(s) "
            f"({', '.join((moved + reported)[:5])}). Staging copies a subset of "
            "the module, and a subset that answers differently would make every "
            "number below a fact about the copy rather than about the rail"
        )
    print(f"reference control: {len(truth)} vectors, 0 disagreements with the repository rail.")


def report(result: dict[str, Any], fail_on_finding: bool) -> None:
    zero = result["layer0"]
    print(
        f"L0 sentence coverage: {zero['normative']} normative sentences "
        f"({zero['obligations']} obligation-bearing, {zero['shoulds']} SHOULD). "
        f"Cited by something: {zero['obligationsCited']}/{zero['obligations']} "
        f"obligations, {zero['shouldsCited']}/{zero['shoulds']} SHOULDs. "
        f"{len(zero['uncited'])} uncited, {len(zero['declared'])} declared."
    )
    print(
        "    Coverage is not discrimination: a sentence counts as cited when any "
        "anchor span CONTAINS it, whether or not the citation is about it, so "
        "these figures are an upper bound on what the corpus exercises."
    )
    one = result.get("layer1")
    if one:
        print(
            f"L1 reachability: {one['sites']} rail sites over {one['vectors']} "
            f"vectors. {one['reachedByNone']} reached by no vector, "
            f"{one['reachedByOne']} by exactly one."
        )
    readings = result.get("readings", [])
    if not readings:
        return
    tally: dict[str, int] = {v: 0 for v in VERDICTS}
    for entry in readings:
        tally[entry["verdict"]] += 1
    print(
        f"L2 reading differential: {len(readings)} reading(s). "
        + ", ".join(f"{tally[v]} {v}" for v in VERDICTS if tally[v])
    )
    for entry in readings:
        line = (
            f"  {entry['verdict']:<14} {entry['id']} ({entry['sentence']}) "
            f"reach={entry['reach']} verdictMoved={len(entry['verdictMoved'])} "
            f"reportMoved={len(entry['reportMoved'])}"
        )
        print(line)
        if entry["candidateOutcome"]:
            print(
                f"    witnessCandidates {entry['witnessCandidates']} -> "
                f"{entry['candidateOutcome']}"
            )
        if entry["verdict"] in ("MASKED", "UNREACHED"):
            print(
                f"    FINDING -- not a confirmation. The corpus scores both "
                f"readings identically, so it has not answered this question. "
                f"Write: {entry['witnessSketch']}"
            )
        elif entry["witness"]:
            print(f"    witness: {json.dumps(entry['witness'], sort_keys=True)}")
    findings = [e for e in readings if e["verdict"] in ("MASKED", "UNREACHED")]
    confirmed = [e for e in readings if e["verdict"] in ("DISCRIMINATED", "REPORT-ONLY")]
    print(
        f"    {len(confirmed)} reading(s) are pinned by a vector; "
        f"{len(findings)} are FINDINGS the corpus cannot yet settle"
        + (" (--fail-on-finding is set)" if fail_on_finding and findings else "")
    )


def run_rail_layers(
    work: Path,
    wanted: set[str],
    ledger: dict[str, Any],
    args: argparse.Namespace,
    result: dict[str, Any],
    errors: list[str],
) -> None:
    """Everything that needs a built rail: the reference control, the sweep, L1, L2."""
    fg = _sibling("forcing-gate")
    keys = fg.rv.write_pinned_key_policy(fg.rv.derive_test_keys(), str(work))
    before = fg.corpus_fingerprint(VECTORS)

    reference = Rail(fg, REPO_ROOT, work, "reference", keys)
    reference.stage()
    reference.build()
    reference_control(fg, reference, REPO_ROOT, work)

    chosen = [
        r
        for r in ledger.get("reading", [])
        if not args.only or str(r.get("id")) in args.only.split(",")
    ]
    if args.only and not chosen:
        die(f"--only {args.only!r} selected no reading")
    # Every edit is resolved against the reference BEFORE the sweep, so a ledger
    # whose anchor has drifted fails in seconds rather than after a per-vector
    # coverage run it was never going to use.
    site_lines = {str(r["id"]): reading_site_lines(reference.tree, r) for r in chosen}

    reference.build(cover=True)
    rail_digest = reference.source_digest()
    coverage = load_reach_cache(args.reach_cache, rail_digest, before)
    if coverage is None:
        coverage = per_vector_coverage(reference, work, vector_files(VECTORS), args.workers)
        write_reach_cache(args.reach_cache, rail_digest, before, coverage)

    if "1" in wanted:
        result["layer1"] = layer1(fg, reference, work, coverage)
    if "2" in wanted:
        result["readings"] = [
            run_reading(
                fg,
                reading,
                REPO_ROOT,
                work,
                keys,
                coverage,
                site_lines[str(reading["id"])],
                rail_digest,
                errors,
            )
            for reading in chosen
        ]
    fg.refuse_moved_corpus(before, fg.corpus_fingerprint(VECTORS))
    result["corpusFingerprint"] = before


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--layer", default="all", help="0, 1, 2, a comma-separated subset, or all"
    )
    parser.add_argument("--only", default="", help="restrict layer 2 to these reading ids")
    parser.add_argument("--json", default="", help="write the full result to this path")
    parser.add_argument(
        "--fail-on-finding",
        action="store_true",
        help="exit 1 when any reading comes back MASKED or UNREACHED",
    )
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 2))
    # Both of these exist for this gate's own test, which drives rigged ledgers
    # against the real rail; production runs never move either.
    parser.add_argument(
        "--readings", default="", help="path to the reading ledger (the committed one by default)"
    )
    parser.add_argument(
        "--reach-cache",
        default="",
        help="reuse a per-vector coverage sweep keyed by the rail and corpus digests",
    )
    args = parser.parse_args()

    wanted = {"0", "1", "2"} if args.layer == "all" else set(args.layer.split(","))
    if not wanted <= {"0", "1", "2"}:
        die("--layer takes 0, 1, 2, a comma-separated subset, or all")

    ledger = load_ledger(Path(args.readings) if args.readings else READINGS)
    errors: list[str] = []
    result: dict[str, Any] = {"specDigest": check_authority_pin(REPO_ROOT, ledger, errors)}
    result["layer0"] = layer0(REPO_ROOT, ledger, errors)
    validate_ledger(ledger, errors)

    if wanted & {"1", "2"} and not errors:
        with tempfile.TemporaryDirectory(prefix="aee-reading-") as raw:
            run_rail_layers(Path(raw), wanted, ledger, args, result, errors)

    if args.json:
        Path(args.json).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if errors:
        print("FAIL: the reading ledger and the corpus disagree.", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    report(result, args.fail_on_finding)
    findings = [e for e in result.get("readings", []) if e["verdict"] in ("MASKED", "UNREACHED")]
    if findings and args.fail_on_finding:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
