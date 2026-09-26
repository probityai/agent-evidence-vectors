#!/usr/bin/env python3
"""Every obligation this work claims to have newly cited, proved by a rail that
gets it wrong.

A sentence-level reading of the specification against everything that cites it
found sixteen obligation-bearing sentences and five SHOULDs that no vector, no
condition and no registry decision addressed. ``docs/UNCITED-OBLIGATIONS.md``
dispositions all twenty-one. Six turned on the corpus rather than on a wording
change: two on a vector, four on a citation. This file is what stops any of the
six from becoming the thing it was written against.

The four citations are the reason the second half of this file exists, and the
defect they carry is worth stating before the mechanism. A citation is a line
range typed into an anchor column. Adding one raises the measured coverage
immediately, and until this file grew its ratchet, NOTHING checked it. The
anchor gate says so in its own docstring -- it is "deliberately weaker than
checking the anchor against the wording of the claim beside it" -- and its
aim check is asked only of registry decisions, never of the per-vector and
condition-registry anchors the four citations were written into. So the check
was run against the corpus: an anchor reading ``L1725-1748`` was appended to
``v03547f8918e0d7dc``, a vector about a dropped corpus manifest,
naming two consumer obligations about out-of-band class pinning that this very
document rules structurally untestable by any conformance vector. The
measurement rose from 55 obligations cited to 57. The anchor gate pinned the new
span and reported 846 anchors holding, ``--sync`` reported that no anchor
addressed different text than the ledger recorded, the condition registry gate,
the distinctness gate and the regenerability gate all passed, and both rails ran
250 of 250 green. A fabricated citation and a correct one were indistinguishable
to every check in the corpus, and the fabricated one was worth two obligations
of coverage.

That is why a citation now has to be paid for the same way a vector is. Each of
the four names the vectors that force the sentence, and each is proved by
building a rail that stops enforcing exactly what the sentence says and showing
that those vectors, and no others, go red. Doing it turned up something the
citations had understated: every one of the three is forced by more vectors than
its row named. L625 is forced by ``bad-208`` as well as ``bad-201``, L1031 by
``bad-714`` as well as ``bad-106`` and ``bad-107``. Those vectors are named here
because a proof that pins the count is the only thing that notices when one of
them quietly stops forcing the rule.

The two vectors are proved the same way and were first:

``v3300d78454ab852f`` carries an unresolvable reference on a row
no gate reads. The rule is quantified over every row that carries the member
(spec L946-951), and a rail that checks references only where it needs to
resolve them -- inside the substrate-row walk -- satisfies every other vector in
the reference family, because every one of them puts the bad index on a
substrate row.

``v7400cd757fd046e9`` carries a producer-defined member whose
value is a token this predicate itself orders. Producer territory is inert to a
verifier and the ordered case is the one a verifier is tempted to read (spec
L1700-1703). A rail that folds such a member into the weakest-input method
composition refuses a statement no requirement refuses, and every other accept
vector carrying producer members carries content-free ones, so none of them
separates the two readings.

Neither vector proves anything by passing, which is the whole reason this file
exists rather than a line in the index saying the rule is covered. Each is
proved by building the wrong rail and showing the corpus goes red at the
vectors named and no others. For the two new vectors the named set was a single
id, and the argument was the sharp one: a mutation killing two vectors would
mean the new one is a duplicate, and a mutation killing none would mean it
forces nothing. That argument has since been spent, in the direction it was
meant to detect. ``scoped_refs`` now kills three, because the corpus gained two
vectors that force the same sentence in shapes the first cannot reach -- an in-
range index before the bad one, and a bad index on the row after a fully
covered substrate row -- and each dies on a scoped reader the others survive. A
duplicate is what a wider kill set could have meant and is not what it means
here; the pin is widened with the reason written beside it, which is the whole
difference between a set that was re-derived and a number that was raised. For
the four citations the named set is every vector that forces the sentence, and
the count is the load-bearing half -- the mutation proves the sentence is
forced at all, and pinning the set is what fails the day one of those vectors
is rewritten into something that no longer forces it. Every rail mutation is
hashed before and after, because a mutation that leaves the file byte-identical
proves nothing and a line count cannot see one value swapped for another. Each
of the two vectors also carries its single-fault control: the same statement
differing in the one member, landing on the opposite verdict on the rail it is
aimed at.

The ratchet is the other half, and it answers the question the mutations cannot.
A mutation proves that a citation on record is real. It says nothing about a
citation added tomorrow. So the set of obligation-bearing sentences that vector
anchors cite is recomputed here from the specification and the two index files,
and compared against a set committed below: forty-one lines this work inherited,
plus the five it paid for. A line entering that set without an entry fails the
proof and is printed with the sentence it would have silently claimed, which is
what refuses the ``L1725-1748`` anchor above. A line leaving it fails too, since
a citation deleted by a re-vendor reads exactly like one that was never there.
The sentence split is the measurement's own, and its two totals are asserted
rather than trusted: if the specification is re-vendored into a different number
of normative sentences, every line number below is suspect and this file says so
instead of comparing sets across two different documents.

That last guard has since fired, on the re-vendor from 237f83b9 to 0dbe10bc,
and what it cost is the argument for keeping it. The vendored text splits into
two more normative sentences and one more obligation than the pin named, so
every line number here was an offset into a document the corpus no longer
carried, and the file refused rather than compare two sets drawn in different
frames. Those totals are asserted below and the guard prints both sides when
they disagree, which is what makes this paragraph checkable rather than
remembered. The sets were re-derived, not re-pinned: each of the forty-five
lines on record was matched to its new line by the SENTENCE TEXT, all forty-
five survive the re-vendor verbatim, and the two sentences the re-vendor added
are dispositioned rather than absorbed -- L634 is a SHOULD newly cited by
``vd538496f284b4761``, and L1556 is a pointer to the rule stated normatively at
L931-934, which the corpus cites. Nothing was lost and nothing was smuggled in.

Reading the corpus is the half that failed silently. The row selector here named
identifiers -- ``| `bad-`` and ``| `ok-`` -- and both stopped matching: the
accept index never backticked its first cell, and the reject one became a digest
of a vector's own bytes. What the ratchet then measured was the condition
registry alone, 32 of the 46 cited obligations, while printing a total that read
like all of them. A reader keyed on a name is a reader that goes quiet when names
change, so the vector table is now found by its HEADER, the way the manifest
generator and the count gate find it, and an index yielding no vector table is a
refusal instead of a corpus that cites nothing.

Nothing here writes to the corpus. The mutated rails live in a temporary
directory and read the corpus through ``--vectors``.

The external rail is built from source into the same temporary directory
rather than read from a binary sitting beside the corpus: a stale binary
answers, and an answer from a rail that predates the vector is the failure
this whole file is about. Set AEE_EXTERNAL_VERIFIER to use one anyway.

Run: python3 scripts/uncited-obligations-proof.py
Requires: a Go toolchain, or AEE_EXTERNAL_VERIFIER naming a v0.7-capable rail.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "packaging" / "run_vectors.py"
# The mutated rails below are loaded from a temporary directory, and the rail
# imports its report module from the package beside the original; that package
# has to be importable from wherever the copy runs.
sys.path.insert(0, str(ROOT / "packaging"))
# One flat directory: a path spelling the verdict only exists while the layout
# spells it, and this corpus deliberately stopped doing that.
BAD724 = ROOT / "vectors" / "statements" / "v3300d78454ab852f.json"
OK054 = ROOT / "vectors" / "statements" / "v7400cd757fd046e9.json"
GO_RAIL = os.environ.get("AEE_EXTERNAL_VERIFIER", "")

# A rail that checks references only where a gate resolves them.
SCOPED_REFS_FROM = """        for r in st.rows:
            refs = r.get("observationRefs")
            if not isinstance(refs, list):
                continue"""
SCOPED_REFS_TO = """        for r in st.rows:
            if r.get("basis") != "substrate":
                continue
            refs = r.get("observationRefs")
            if not isinstance(refs, list):
                continue"""

# A rail that reads an ordered producer axis as a strength axis.
RANKING_CAP_FROM = (
    "        methods = [METHOD_ORDER[rv.method] "
    "for rv in covering if rv.method in METHOD_ORDER]"
)
RANKING_CAP_TO = (
    RANKING_CAP_FROM
    + """
        for rv in covering:
            for member, value in (rv.payload or {}).items():
                if (not member.startswith("aee") and isinstance(value, str)
                        and value in METHOD_ORDER):
                    methods.append(METHOD_ORDER[value])"""
)

# A rail that reads the carried result instead of evaluating the coverage
# preconditions first, which is the reading L625-629 exists to refuse.
PRECONDITION_FROM = """        if st.result not in RESULT_ORDER or recomputed != st.result:
            out.add("result-recompute-mismatch")"""
PRECONDITION_TO = """        if st.result in RESULT_ORDER and recomputed == st.result:
            out.codes = [c for c in out.codes if c != "payload-not-canonical"]
        if st.result not in RESULT_ORDER or recomputed != st.result:
            out.add("result-recompute-mismatch")"""

# A rail that reads an uncoverable substrate row as a weaker claim rather than
# as the invalid statement L1031-1033 says it makes.
UNCOVERABLE_FROM = (
    "        good_arm = self._gate1_clean_arm("
    "st, out, usable, covers_nothing, pinned_posture)\n"
    "        good_seal = self._gate1_clean_seal("
    "st, out, usable, covers_nothing, pinned_posture)\n"
    "        return good_arm + good_seal"
)
UNCOVERABLE_TO = (
    '        if not {"arming", "sealed"} <= {rv.kind for rv in usable}:\n'
    "            return []\n"
) + UNCOVERABLE_FROM

# A rail that keeps RFC 3339 and drops the two choices the profile pins at
# L1792-1795: the uppercase designators and the zero-offset spellings.
TIMESTAMP_FROM = """    if not isinstance(v, str) or not RFC3339_RE.match(v):
        return False
    key = _rfc3339_key(v)
    return key is not None and key.utcoffset() == timedelta(0)"""
TIMESTAMP_TO = """    if not isinstance(v, str) or not RFC3339_RE.match(v.upper()):
        return False
    key = _rfc3339_key(v.upper())
    return key is not None"""

# name -> (mutation source, mutation replacement, every vector that must go red)
MUTATIONS: tuple[tuple[str, str, str, list[str]], ...] = (
    # Three, where this pin named one. The corpus gained two vectors that force
    # the same sentence in shapes the first does not reach:
    # vc19ea5aaacc5b72a puts an IN-range index before the out-of-range one, so a
    # reader that stops at the first index survives v3300d78454ab852f and dies
    # here; v1a3d0ce04c3f7524 puts the bad index on the artifact row FOLLOWING a
    # fully covered substrate row, so a reader that walks until its obligations
    # are discharged survives both of the others. Every one of the three is an
    # artifact row, which is the whole point: the rule is quantified over every
    # row carrying the member, and the scoped rail reads only substrate rows.
    ("scoped_refs", SCOPED_REFS_FROM, SCOPED_REFS_TO,
     ["v3300d78454ab852f", "vc19ea5aaacc5b72a", "v1a3d0ce04c3f7524"]),
    ("ranking_cap", RANKING_CAP_FROM, RANKING_CAP_TO,
     ["v7400cd757fd046e9"]),
    # Five, where this pin named two. The exponent-notation vectors added at
    # suiteRevision 30 carry a valid result and are refused on payload
    # canonicality alone -- `1E2`, `1.0e2` and `-0e0` are values the safe range
    # admits, spelled in a form RFC 8785 never emits -- so a rail that trusts
    # the carried result before the coverage preconditions admits all three.
    # `1e21` is not among them: it is refused on its value, which this mutation
    # does not touch. Each of the three forces the sentence in its own
    # spelling, so the set is widened with them rather than read as duplicates.
    ("precondition", PRECONDITION_FROM, PRECONDITION_TO,
     ["v85caf3c6f7516ba2", "v9d1f7c44f94cb929", "vd5e0b3f3d1fabb05",
      "v97c6888cf7e88f42", "v13ede3e42645eb1a"]),
    ("uncoverable", UNCOVERABLE_FROM, UNCOVERABLE_TO,
     ["ve025b4bed04cfb68", "v132435a4d6d10043",
      "v5dcc150714259e09"]),
    ("timestamp", TIMESTAMP_FROM, TIMESTAMP_TO,
     ["v1b0b0cafb5ee8d08", "v3c527c28aa2da8db",
      "v65fa8117aa487fbe", "vc9f401685f448104",
      "v28d48cc69a324b81",
      "v7d4d7d92a346c7a5"]),
)

SPEC = ROOT / "spec" / "predicates" / "adversarial-execution-evidence.md"
KEYWORD = re.compile(r"\b(MUST NOT|MUST|REQUIRED|SHALL|SHOULD NOT|SHOULD)\b")
OBLIGATION = re.compile(r"\b(MUST|REQUIRED|SHALL)\b")
SENTENCE_END = re.compile(r"(?<!e\.g)(?<!i\.e)(?<!vs)(?<!cf)(?<!No)[.;](?=\s|$)")
FENCE = re.compile(r"^\s*(```|~~~)")
ANCHOR = re.compile(r"\bL(\d+)(?:-(\d+))?\b")
# The header cell that names an index's vector table. Both index files use it.
VECTOR_TABLE_HEADER = "vector"

# The split is the measurement's, and these are what it yields on the pinned
# specification. They are asserted because every line number below is an offset
# into that document and means nothing against a different one.
#
# Two lower on each axis until the specification was re-vendored from 237f83b9 to
# 0dbe10bc, 144 lines longer. The guard fired exactly as designed and the sets below were
# re-derived rather than re-pinned: every one of the forty-five sentences on
# record survives the re-vendor VERBATIM and maps 1:1 onto its new line, no
# obligation sentence was lost, and the two normative sentences the re-vendor
# added are both dispositioned in docs/UNCITED-OBLIGATIONS.md. L634 is a SHOULD,
# so it is not obligation-bearing and does not move the second total; it is
# newly cited by `vd538496f284b4761`. L1556 is the obligation, and it is a
# pointer to the rule stated normatively at L931-934, which the corpus does
# cite -- dispositioned (c) not normative, class restatement-elsewhere-normative
# in spec/READINGS.toml, and uncited on purpose.
NORMATIVE_SENTENCES = 76
OBLIGATION_SENTENCES = 68

# Obligation-bearing sentences a vector anchor cited before this work, in the
# coordinate frame of the vendored specification. A line here was matched to its
# pre-re-vendor self by the SENTENCE TEXT, never by arithmetic on the line
# number: a shift derived from a diff would carry a sentence that changed
# meaning across as though it had only moved.
INHERITED: frozenset[int] = frozenset({
    99, 106, 111, 113, 114, 116, 117, 136, 150, 160, 212, 237, 390, 618, 766,
    771, 779, 790, 817, 854, 931, 968, 1081, 1093, 1277, 1300, 1323, 1325,
    1330, 1334, 1337, 1396, 1398, 1431, 1471, 1539, 1619, 1636, 1688, 1695,
    1776,
})

# The lines this work added to that set, each against the mutation that pays
# for it. A line cited by nothing in this table is a claim nobody checked.
#
# L1700 is the fifth and was added after the four: a verifier MUST NOT rank the
# values of a producer-defined ordered axis nor compose it by weakest input.
# `v7400cd757fd046e9` has forced it since it was written, and the ranking_cap
# mutation below has proved that since this file was written -- the sentence was
# uncited only because the accept index carried no anchor column for an
# obligation whose sole possible instrument is an accept vector. The column
# exists now, so the citation is real and the mutation that already paid for the
# vector pays for the citation.
PAID_FOR: dict[int, str] = {
    625: "precondition",
    946: "scoped_refs",
    1031: "uncoverable",
    1700: "ranking_cap",
    1792: "timestamp",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str]) -> tuple[int, str]:
    # A mutated rail runs from a temporary directory and still has to import
    # the report package that sits beside the original.
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(ROOT / "packaging"), env.get("PYTHONPATH", "")) if p)
    proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False, env=env)
    return proc.returncode, proc.stdout + proc.stderr


def failing_vectors(output: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"^(\S+)\s+FAIL", output, re.M)]


def mutated_rail(tmp: Path, name: str, before: str, after: str) -> Path | None:
    """A copy of the harness with one behaviour changed, or None if the site
    the mutation names is not present exactly once. A mutation applied to a
    site that moved would report a clean run as evidence."""
    source = HARNESS.read_bytes()
    text = source.decode("utf-8")
    if text.count(before) != 1:
        print(f"GUARD: the {name} mutation site is not present exactly once",
              file=sys.stderr)
        return None
    path = tmp / f"run_vectors_{name}.py"
    path.write_text(text.replace(before, after), encoding="utf-8")
    was, now = sha(source), sha(path.read_bytes())
    print(f"  mutation {name}: before={was[:16]} after={now[:16]} changed={was != now}")
    if was == now:
        print(f"GUARD: the {name} mutation left the file byte-identical",
              file=sys.stderr)
        return None
    return path


def go_verdict(rail: str, statement: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(statement, handle)
        path = handle.name
    try:
        code, output = run([rail, "-json", path])
    finally:
        os.unlink(path)
    lines = output.strip().splitlines()
    if not lines:
        return code, {}
    parsed: dict[str, Any] = json.loads(lines[-1])
    return code, parsed


def load_rail(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(f"rail_{path.stem}", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ok054_single_fault(rail: Path) -> bool:
    """The control for ok-054: the shipped statement with the one ordered
    producer member dropped, the record re-signed and the batch root and the
    seal's observed set recomputed -- the reject generator's own rederive
    chain, so the control differs in that member and in nothing else. On the
    ranking rail the vector must be refused and the control admitted."""
    module = load_rail(rail)
    if module is None:
        return False
    verifier = module.ReferenceVerifier([])

    generator = load_rail(ROOT / "vectors" / "reject" / "gen_invalid_vectors.py")
    if generator is None:
        return False

    shipped: dict[str, Any] = json.loads(OK054.read_text(encoding="utf-8"))
    control: dict[str, Any] = json.loads(OK054.read_text(encoding="utf-8"))
    records = control["predicate"]["observationRecords"]
    payload = json.loads(generator.unb64(records[0]["payload"]))
    dropped = payload.pop("exampleFidelity")
    records[0] = generator.record(payload, records[0]["payloadType"])
    generator.reroot(control)

    on_vector = sorted(verifier.verify(shipped).codes)
    on_control = sorted(verifier.verify(control).codes)
    print(f"  control    : dropped exampleFidelity={dropped!r}  "
          f"vector={on_vector}  control={on_control}")
    return on_vector == ["method-cap-exceeded"] and on_control == []


def bad724_single_fault(rail: str) -> bool:
    """The control for bad-724: the same statement with the out-of-range index
    replaced by an in-range one. The external rail must flip verdicts."""
    statement: dict[str, Any] = json.loads(BAD724.read_text(encoding="utf-8"))
    refs = statement["predicate"]["attackResults"][0]["observationRefs"]
    statement["predicate"]["attackResults"][0]["observationRefs"] = [0]
    control_code, control = go_verdict(rail, statement)
    print(f"  control    : refs {refs} -> [0]  rc={control_code}  {control}")

    vector_code, vector = go_verdict(rail, json.loads(BAD724.read_text(encoding="utf-8")))
    print(f"  vector     : as shipped        rc={vector_code}  {vector}")
    return (
        control_code == 0
        and control.get("verdict") == "valid"
        and vector_code != 0
        and vector.get("primaryCode") == "ref-out-of-range"
    )


def split_block(buffer: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """One paragraph's sentences, each carrying the line its first characters
    fall on. A sentence beginning mid-line is attributed to the line the
    PREVIOUS sentence began on, which is the measurement's known off-by-one and
    is reproduced deliberately: a split that disagreed with the measurement
    would ratchet a different set of lines than the one being reported."""
    if not buffer:
        return []
    text = " ".join(t for _, t in buffer)
    offsets: list[tuple[int, int]] = []
    cursor = 0
    for line_no, t in buffer:
        offsets.append((cursor, line_no))
        cursor += len(t) + 1
    out: list[tuple[int, str]] = []
    position = 0
    for match in [*SENTENCE_END.finditer(text), None]:
        end = match.end() if match is not None else len(text)
        segment = text[position:end].strip()
        if segment:
            line_no = offsets[0][1]
            for offset, candidate in offsets:
                if offset <= position:
                    line_no = candidate
            out.append((line_no, segment))
        position = end
        if match is None:
            break
    return out


def spec_sentences() -> list[tuple[int, str]]:
    """The specification's prose sentences. Fenced code is skipped and a blank
    line ends a block. This is the measurement's own split, reproduced here
    because the measurement lives in a consuming repository and this corpus has
    to be able to check itself without reaching into one."""
    out: list[tuple[int, str]] = []
    buffer: list[tuple[int, str]] = []
    in_fence = False
    for number, raw in enumerate(SPEC.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE.match(raw):
            in_fence = not in_fence
        elif in_fence:
            continue
        elif raw.strip():
            buffer.append((number, raw.strip()))
            continue
        out += split_block(buffer)
        buffer = []
    return out + split_block(buffer)


def spans_in(text: str) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    for match in ANCHOR.finditer(text):
        start = int(match.group(1))
        found.append((start, int(match.group(2) or start)))
    return found


def vector_table_rows(text: str) -> list[str]:
    """The rows of an index's vector table, found by the table's HEADER.

    This reader used to select rows by an identifier prefix: ``| `bad-`` in the
    reject index and ``| `ok-`` in the accept one. Both selectors are dead. The
    accept index has never backticked its first cell, so that one matched
    nothing from the day it was typed; the reject one matched until identifiers
    became digests of a vector's own bytes, and matched nothing after. What the
    ratchet then read was the condition registry alone, while announcing a full
    count -- the failure it exists to catch, wearing the ratchet's own clothes.
    The figure that reading produced is in this file's module docstring, where
    it is frozen as history rather than restated as a live quantity.

    So the table is found the way ``vectors/gen_manifest.py`` and the count gate
    find it, by the header cell that names it, and never by what its rows are
    called. An index carries other tables (the reject index has a
    digest-preimage table of 64-hex rows), so the header is the only thing that
    tells a vector row from another table's row.
    """
    rows: list[str] = []
    inside = False
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            inside = False
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        first = cells[0] if cells else ""
        if first == VECTOR_TABLE_HEADER:
            inside = True
            continue
        if not inside or (first and set(first) <= {"-", ":"}):
            continue
        rows.append(line)
    return rows


def vector_spans() -> list[tuple[int, int]] | None:
    """Every specification span a vector cites: the condition registry rows and
    the per-vector anchor column of both index files. The registry decisions and
    the unforced cells are deliberately absent -- they record a reading, not a
    vector, and the question here is only what the corpus FORCES.

    None when an index yields no vector table, because a reader that has stopped
    finding one reports a corpus citing nothing exactly as it reports a corpus
    that lost every citation, and the second half of this file would then read
    the loss as a coverage collapse or, worse, read a shrunken corpus as clean.
    """
    reject = (ROOT / "vectors" / "reject" / "INDEX.md").read_text(encoding="utf-8")
    accept = (ROOT / "vectors" / "accept" / "INDEX.md").read_text(encoding="utf-8")
    rows = [line for line in reject.splitlines()
            if re.match(r"^\|\s*aee-c-\d+\s*\|", line)]
    for name, text in (("reject", reject), ("accept", accept)):
        found = vector_table_rows(text)
        if not found:
            print(f"GUARD: the {name} index yields no vector table, so this file "
                  "cannot say what the corpus cites. Fix the reader, never the set.",
                  file=sys.stderr)
            return None
        rows += found
    return [span for line in rows for span in spans_in(line)]


def coverage_ratchet(proved: set[str]) -> bool:
    """The set of obligations vector anchors cite, against the set on record.

    An anchor is free text in a table and raises the measured coverage the
    moment it is typed. This refuses a line entering the cited set without a
    mutation that pays for it, and refuses one leaving without the entry going
    with it. It also refuses a line whose paying mutation did not run or did not
    kill what it named, because a table entry pointing at a mutation that failed
    is the same unchecked claim wearing a citation's clothes."""
    sentences = spec_sentences()
    normative = [(ln, s) for ln, s in sentences if KEYWORD.search(s)]
    obligations = [(ln, s) for ln, s in normative if OBLIGATION.search(s)]
    print(f"  ratchet    : {len(normative)} normative sentences, "
          f"{len(obligations)} obligation-bearing")
    if (len(normative), len(obligations)) != (NORMATIVE_SENTENCES, OBLIGATION_SENTENCES):
        print(f"GUARD: the specification splits into {len(normative)}/{len(obligations)} "
              f"sentences, not {NORMATIVE_SENTENCES}/{OBLIGATION_SENTENCES}. Every line "
              "number in this file is an offset into the pinned document and none of "
              "them can be compared against this one.", file=sys.stderr)
        return False

    spans = vector_spans()
    if spans is None:
        return False
    text = {ln: s for ln, s in obligations}
    cited = {ln for ln, _ in obligations if any(a <= ln <= b for a, b in spans)}
    expected = INHERITED | set(PAID_FOR)
    healthy = True

    for line_no in sorted(cited - expected):
        print(f"FAIL: L{line_no} is newly cited by a vector anchor and nothing in this "
              f"file pays for it: {text[line_no][:100]}", file=sys.stderr)
        healthy = False
    for line_no in sorted(expected - cited):
        print(f"FAIL: L{line_no} is on record as cited and no vector anchor covers it "
              f"any more: {text.get(line_no, '(not an obligation sentence)')[:100]}",
              file=sys.stderr)
        healthy = False
    for line_no, mutation in sorted(PAID_FOR.items()):
        if mutation not in proved:
            print(f"FAIL: L{line_no} is paid for by the {mutation} mutation, which did "
                  "not run or did not kill the vectors it named", file=sys.stderr)
            healthy = False

    print(f"  ratchet    : {len(cited)} obligations cited by a vector anchor "
          f"({len(INHERITED)} inherited, {len(PAID_FOR)} paid for here)")
    return healthy


def build_go_rail(tmp: Path) -> str | None:
    """The external rail, built from the tree under test."""
    if GO_RAIL:
        return GO_RAIL
    target = tmp / "aee-verify"
    env = dict(os.environ, GOMAXPROCS="1")
    proc = subprocess.run(["go", "build", "-o", str(target), "./cmd/aee-verify"],
                          cwd=ROOT, capture_output=True, text=True, check=False,
                          env=env)
    if proc.returncode != 0:
        print("GUARD: the external rail did not build:\n" + proc.stderr, file=sys.stderr)
        return None
    return str(target)


def main() -> int:
    healthy = True
    with tempfile.TemporaryDirectory() as scratch:
        go_rail = build_go_rail(Path(scratch))
        if go_rail is None:
            return 2
        for label, argv in (
            ("reference", [sys.executable, str(HARNESS), "--report", "/dev/null"]),
            ("external ", [sys.executable, str(HARNESS), "--verifier",
                           f"{go_rail} -json", "--report", "/dev/null"]),
        ):
            code, output = run(argv)
            print(f"CONTROL {label} rail  rc={code}  "
                  f"{output.strip().splitlines()[-1]}")
            healthy &= code == 0

        proved: set[str] = set()
        for name, before, after, expected in MUTATIONS:
            rail = mutated_rail(Path(scratch), name, before, after)
            if rail is None:
                return 2
            code, output = run([sys.executable, str(rail),
                                "--vectors", str(ROOT / "vectors"),
                                "--report", "/dev/null"])
            observed = failing_vectors(output)
            print(f"  rail {name}: rc={code}  failures={observed}")
            # The count is compared as well as the membership: a duplicate id
            # would make a set comparison agree while the corpus killed the
            # same vector twice.
            killed = code != 0 and sorted(observed) == sorted(expected) \
                and len(observed) == len(expected)
            if killed:
                proved.add(name)
            healthy &= killed
            if name == "ranking_cap":
                healthy &= ok054_single_fault(rail)

        healthy &= bad724_single_fault(go_rail)
        healthy &= coverage_ratchet(proved)
    print("PROOF:", "PASS" if healthy else "FAIL")
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
