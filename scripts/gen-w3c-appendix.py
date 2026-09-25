#!/usr/bin/env python3
"""Render docs/W3C-V01-CONFORMANCE-APPENDIX.md from vectors-w3c-report/MANIFEST.json.

    python3 scripts/gen-w3c-appendix.py            # write the appendix
    python3 scripts/gen-w3c-appendix.py --check    # refuse when the file on disk differs

The appendix is the conformance set for v0.1 of the W3C public-agent-conformance
reporting format, in the form the editor can reference: every rejection row
with the vector that must be rejected under it and the vector that must pass,
the sentence the row binds to and that sentence's digest, the class of each row
under the handover's sort, and the proposed classification of the five rows the
handover left unclassified, each with its vector pair under it. Every
identifier in it is a function of the vectors' own bytes, so the file is
rendered from the manifest rather than typed, and the regenerability gate
refuses a copy that drifted from the corpus.
"""

# ruff: noqa: E501 -- the appendix paragraphs are written unwrapped on purpose:
# GitHub renders a hard line break literally, and this file is the one place the
# prose is authored, so the source lines are as long as the paragraphs.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "vectors-w3c-report" / "MANIFEST.json"
TARGET = REPO / "docs" / "W3C-V01-CONFORMANCE-APPENDIX.md"

ROW = {n: f"W3C-R-{n:03d}" for n in range(1, 30)}

SECTIONS = (
    ("The twelve rejection rows", [ROW[n] for n in range(1, 13)]),
    ("Rows 13 and 14, under the numbering the handover proposes", [ROW[25], ROW[26]]),
    ("The two late additions of 18 September", [ROW[13], ROW[14], ROW[15]]),
    ("The rules the freeze list and the editor's restatement carry", [ROW[n] for n in range(16, 21)]),
    ("The rules the thread settled beside the table", [ROW[n] for n in range(21, 25)]),
    ("Arity and domain, from the handover's record definitions", [ROW[27], ROW[28]]),
    ("Proposed in the v0.1 comment window", [ROW[29]]),
)

#: The five rows the handover left unclassified, each classified here with its
#: rationale read off the record definitions, in the handover's own terms.
UNCLASSIFIED = (ROW[4], ROW[10], ROW[11], ROW[12], ROW[25])

RATIONALE = {
    ROW[4]: (
        "**Consistency.** The row reads the record's own `cause` cell against its `state`, the same construction as row 3, which reads the cause value `integrity-failure` against `not-exercised`. The fact that a confinement control failed while the check ran is written as the cause value `confinement-failed-during-check`, admitted only under `void`, so the four-field record of section 1 carries no extra cell for it. That answers the question Schuurkes put on the list of how the antecedent is represented for a reader (`0076`), with the construction Rocchia proposed in reply (`0077`). Nothing is recomputed and nothing is resolved; a reader with no suite and no checker fires the row from the record alone, and the reject member below fires under a reader that resolves nothing (`resolvedRead` false in the manifest). The reject member is `inconclusive` rather than `fail`, because a verdict state carrying any cause is also row 7 and a member is rejected under one row only. What a row over declarations cannot establish, as Schuurkes noted, is that a producer disclosed every confinement control that failed. The value's name is proposed, pending the editor's v0.1 text."
    ),
    ROW[10]: (
        "**Consistency.** The row reads a declared value, `foreclosed`, against the presence of the two parameters that value must carry, the constraint set and the domain identifier. The handover's own sort settles what a presence check within one record is: rows 1 and 7 are presence checks (a non-verdict state with no cause; a verdict state with a cause) and both sit in the consistency class. Row 10 is the same reading applied to the other-verdict cell, so it takes the same class. It is not a form row, because the object's shape is fine; what contradicts is the value and its own arguments."
    ),
    ROW[11]: (
        "**Consistency.** An asserted qualifier value is read against the presence of its evidence reference, and the reference is read against the report's own evidence list: both are declared by the emitter in the same report. Whether the referenced observations then resolve is the reading table's business (rows 20, 21 and 13 read the resolved slot), not row 11's, which fires before any reader resolves anything. It is row 1 applied to a qualifier: a value asserted with the cell that should justify it left empty."
    ),
    ROW[12]: (
        "**Consistency.** The handover guessed evidence for this row because it reads a slot of a referenced object. The class is decided by what is read, not by where it lives: the slot read is `changed`, which the per-slot sort lists as declared, written by the emitter, and the object cited sits in the same report. The row catches a contradiction between two declared cells, a discrimination cell witnessed by an object that declares it changed the checker rather than the input, and needs no recomputation; the reject member below fires under a reader that resolves nothing. An evidence-class version of this row would read `changed` against a recomputed diff of the two observations' checkers, which no v0.1 slot carries."
    ),
    ROW[25]: (
        "**Evidence.** The row reads `moved`, and v0.1 fixes `moved` as recomputed over what the referenced observations actually contain, never as declared. So the row reads a declared cell, other-verdict `demonstrated`, against a recomputed slot, which is the definition of the evidence class. The corpus shows the consequence the reading table requires: the reject member fires when both references resolve with matching digests and the recomputed delta holds the fired-rule list and not the verdict; the second accept member is the identical report read by a reader that can resolve neither reference, and the row degrades rather than fires (`resolvedRead` true in the manifest)."
    ),
}

INTRO = """# Conformance appendix for v0.1 of the reporting format

This is the conformance set for v0.1 of the per-check reporting format of the W3C public-agent-conformance community group, written so that an editor can reference it by row and an implementer can run it without reading the thread. Every row of the rejection table is backed by two members of the corpus `vectors-w3c-report/` in the `agent-evidence-vectors` repository: one report that a conforming validator must reject under that row and no other, and one report, as close to it as one change allows, that the validator must accept. The corpus judges itself with two independent readers, one in Go and one in Python, and a test holds their output identical over the committed members and over deliberately broken copies. An implementation conforms to v0.1 when it rejects every reject member under the row the member names and accepts every accept member; that is the whole test, and it is runnable with nothing installed.

The rows are the group's, as the editor fixed the scope on 18 September from the handover of the same day. Rows 1 to 12 are the consolidated table of 15 September and keep their numbers. Rows 13 and 14 are carried under the numbering the handover proposes and are marked proposed, because nobody on the list has numbered them. The two late additions the editor took into sections 3 and 4, the rules the completed freeze list and the editor's restatement carry, the rules the thread settled beside the table, and the two record-definition rules of the handover (arity recomputed, domain declared once) are carried under their own identifiers with no row number, so that a later numbering costs nothing here. A row's identifier is minted by the corpus and bound to a sentence of the vendored message by digest, because the messages carry no identifiers and a message number names a position rather than a sentence. A reword of the sentence stops the corpus from building, which is the property that makes the identifier citable.

A member of the corpus is a whole report rather than one record, because two of the rules are properties of the report and not of any record in it: whether the roll-up says its checks were capable of a negative verdict, and whether the digest over the check set binds the leaf count and names the tree shape. Every report member also carries `resolves`, the store its reader resolves referenced observations against, so that the reading table's three lines are all members of the corpus rather than prose. The corpus carries the two gaps the editor recorded about the reference emitter on 18 September, that `void` had no slot and that `not-exercised` carried no cause, as members that show both closed, and it carries the 42 delta-related pairs Rocchia counted in his own corpus, each once as it was emitted before the freeze and once re-cut against v0.1. A mutation sweep, regenerated with the vectors and published beside them, relaxes each row in turn and records that only the members naming it flip.

## How to read a row

The reject member's `subject` is the report; its `expected.rejects` names the one row; the accept member differs from it by the smallest change that satisfies the row. Both cite the requirement in `requirements`, so a specification change that reworded the sentence would fail the pair by name. The class column is the handover's sort: a consistency row reads declared slots against each other and catches a contradiction; an evidence row reads a declared slot against a recomputed or resolved one and catches a falsehood; a form row is decidable from the object alone. The status column says whether the list agreed the row or this corpus proposes it. The sentence column quotes the vendored text with its line break where the sentence spans one; the digest column is the first sixteen hex digits of the SHA-256 over those bytes, and the full digest is in the manifest.
"""

CLASSIFICATION_INTRO = """
## Proposed classification of rows 4, 10, 11, 12 and 13

The handover sorts rows 1, 2, 3, 5, 6, 7, 8 and 9 into the consistency class and row 14 into the form class, and leaves five rows unclassified: 4, 10, 11, 12 and 13. Each of the five is classified here from the record definitions in the handover's own terms, with the vector pair that demonstrates the class under it. The part of the class a validator can measure is measured: every reject member of the corpus is re-judged by a reader that resolves nothing, and a row whose members stop firing reads a resolved slot (`resolvedRead` in the manifest). Rows 4, 10, 11 and 12 fire under that reader; row 13 does not.
"""

VOID = """
## The value for void

The fixed vocabulary is CAP-1's eight dispositions, a value for void, `integrity-failure` kept apart from `availability-failure`, and `precondition-unsatisfiable`, and this corpus adds one more under void, proposed with row 4: `confinement-failed-during-check`, the cause row 4 reads against the state. The list named the void slot and never its value. This corpus proposes `evidence-does-not-hold`, in the words of the message that found the gap: void is a unit that was examined and whose evidence does not hold up. The reference emitter writes it for a harness that could not establish a verdict, and family `w3c-f-gaps` carries the member. The name is proposed, not agreed; any closed identifier the list prefers replaces it in one constant on each rail.
"""

READING_TABLE = """
## The reading table, as members

Carry-or-reference is fixed as: the format permits both and requires one, the form is decidable from the object alone (row 14), and reading a well-formed object is a table rather than a row. The three lines of the table are each a member. Resolves with matching digests: the accept members of families `w3c-f-20`, `w3c-f-21` and `w3c-f-25`, where the reader's store carries the observation the reference names and `moved` recomputes from it. Resolves with a mismatch: the `w3c-f-20` reject member whose store resolves the reference to bytes with another digest, an integrity failure, beside the check-set member whose RFC 6962 root was computed with domain separation over a duplicated last leaf, which is the same failure over the set. Does not resolve: the second accept member of `w3c-f-25`, the report that a reader with the suite rejects, read by a reader without it, unchecked, with the rows that read `moved` degrading rather than firing. The Merkle line the editor took from the narrowing on the list, that binding the count is necessary and is not a general membership proof and that domain separation added while duplicate-last padding is retained does not remove the ambiguity, is the `w3c-f-15` reject member that binds its count and asserts domain separation with no tree shape declared, rejected because the producer declares the shape.
"""

TREE_SHAPES = """
## The tree shapes, as a closed set

Section 3.1 of the v0.1 draft requires a report to declare which tree shape its digest over a collection uses and leaves the vocabulary open (Q7). This corpus holds it closed, for the reason the cause vocabulary is closed: free text does not aggregate. The set is {shapes}. `RFC9162_SHA256` is the identifier RFC 9942 section 5.1 registers for the Merkle tree of RFC 9162 section 2.1.1 over SHA-256, whose tree hash is the RFC 6962 one, so the two names denote one construction and a report may use either. Its admission is proposed, following the closed, versioned set of construction identifiers Schuurkes asked for on the list, and it enters with its members: in `w3c-f-15` an accept member bound under `RFC9162_SHA256` and a reject member naming the same tree in free text, and in `w3c-f-20` a reject member whose `RFC9162_SHA256` root was computed over a duplicated last leaf with its accepting twin. Each reader maps every name in the set to its own root function and refuses any other name, so a shape outside the set can never be hashed as one inside it.
"""

COUNTS = """
## The counts on open row B, labelled as the editor labels them

Row B, whether a stated delta is bounded to one field, stays open, and the editor carries the figures with the standing each has. The 42 one-field pairs in the disensor corpus are reproducible: `tools/emitir-42.py` in `NicolasRocchia/disensor` runs the pinned checker over every vector, and this corpus's own derivation (`origin/derive_pairs.py`) and a re-run of that script on 18 September both give 42 (v0.2 4, v0.3 16, v0.4 22), 0 carried against 84 referenced, 69 errors serialised as strings, 0 vectors disagreeing with their declared expectation. The 0 (MUST-FAIL pairs with different fired-rule lists at one field) and the 132 (at two fields) come from a script that is not published, and the editor attributes those two to their author rather than presenting them as reproducible. Sankalp's 252 at v0.11.1 sits beside them with the same labelling, and it is reproducible: of the 315 reject entries across the eight manifests of `agent-evidence-vectors` at tag `v0.11.1`, 269 carry an `expected.codes` list and 252 of those hold exactly one code. Re-derive it from a clone with the tag fetched:

```
python3 - <<'EOF'
import json, subprocess
files = subprocess.run(["git", "ls-tree", "-r", "--name-only", "v0.11.1"], capture_output=True, text=True, check=True).stdout.split()
one = rejects = 0
for path in [f for f in files if f.startswith("vectors") and f.endswith("MANIFEST.json")]:
    manifest = json.loads(subprocess.run(["git", "show", f"v0.11.1:{path}"], capture_output=True, text=True, check=True).stdout)
    for entry in manifest.get("vectors", []):
        if entry.get("kind") == "reject":
            rejects += 1
            codes = (entry.get("expected") or {}).get("codes")
            one += isinstance(codes, list) and len(codes) == 1
print(rejects, one)
EOF
```

The figure is pinned to `v0.11.1` and does not track the live suite, because row B is an argument about what a corpus at a stated revision already asserts. The measurements do not contradict each other: one field is a property of how a corpus was built, not one the format can assume, and arity is therefore recomputed from the delta (`W3C-R-027`) and read by no row while the question is open.
"""

OUTRO = """
## The crosswalk from the harness's report, and the known gaps

The reference emitter in `packaging/agent_evidence_vectors/w3creport.py` writes a v0.1 report from the report the AEE harness writes, one per-check record per replayed vector, with the domain declared once at run level. The two altitudes are kept apart: the harness's `result` stays four-valued and recomputable, and the per-check record says what a consumer may conclude about the statement the vector carries. `pass` is a valid verdict with result `pass` or `pass_indirect`, the result carried as the qualifier; `fail` is a valid verdict with result `fail` or `degraded`, or an invalid verdict, with the codes carried; `not-exercised` is a manifest entry declaring `expected.unmeasurableBecause`, reported with cause `precondition-unsatisfiable` and that text, or a report member the manifest expects and the rail left absent, with cause `unavailable`; `void` is a harness that could not establish a verdict, with cause `evidence-does-not-hold` and the rail's errors or exit as detail. The report the emitter writes from the AEE corpus conforms: no row fires on it.

Two things the emitter says out loud rather than quietly fixing. The indeterminate kind, a vector whose specification admits more than one reading, is reported `inconclusive` with cause `unsupported_input`, the nearest closed disposition, and the reading the rail committed to or the readings declared as detail; the fixed vocabulary has no value for an input the specification leaves undetermined, and free text in place of a disposition is refused, so the gap is recorded here and not papered over with a value the list did not agree. And the emitted report carries no evidence objects: the harness replays each vector alone, so no record asserts a demonstrated other verdict or a demonstrated discrimination, and the roll-up's negative-capable field is answered from the run's own non-pass counts.

## Two further subjects in the same corpus

The same manifest carries members of two other subject types, judged by their own sentences in their own modules: the Run object of `draft-arsentev-agent-run-metrics-00`, twenty-two rows over the members and invariants a validator can read off one Report, and the discovery snapshot of `draft-arsentev-llm-context-discovery-00`, eleven rows over what an origin advertises and what a consumer resolves. Their tables follow the same shape and are listed after the report rows.
"""


def load() -> dict[str, Any]:
    with open(MANIFEST, encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
        return data


def members_for(manifest: dict[str, Any], row: str) -> tuple[list[str], list[str]]:
    rejects = [e["id"] for e in manifest["vectors"] if e["expected"]["rejects"] == [row]]
    accepts = [
        e["id"] for e in manifest["vectors"]
        if e["kind"] == "accept" and row in e["requirements"]
    ]
    return rejects, accepts


def ids(values: list[str]) -> str:
    return ", ".join(f"`{v}`" for v in values) or "none"


def table(manifest: dict[str, Any], rows: list[str]) -> str:
    requirements = {r["id"]: r for r in manifest["requirements"]}
    classed = any("class" in requirements[row] for row in rows)
    head = "| row | class | status | reject | accept | sentence | digest |" if classed else (
        "| row | reject | accept | sentence | digest |"
    )
    lines = [head, "|---|---|---|---|---|---|---|" if classed else "|---|---|---|---|---|"]
    for row in rows:
        req = requirements[row]
        rejects, accepts = members_for(manifest, row)
        sentence = req["sentence"].replace("\n", " ").replace("|", "\\|")
        cells = [f"`{row}` ({req['row']})"]
        if classed:
            cells += [req.get("class", "-"), req.get("status", "-")]
        cells += [ids(rejects), ids(accepts), sentence, f"`{req['sentenceDigest'][:16]}`"]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def classification(manifest: dict[str, Any]) -> str:
    requirements = {r["id"]: r for r in manifest["requirements"]}
    cites = {e["id"]: e["cites"] for e in manifest["vectors"]}
    parts = [CLASSIFICATION_INTRO]
    for row in UNCLASSIFIED:
        req = requirements[row]
        rejects, accepts = members_for(manifest, row)
        parts.append(f"\n### Row {req['row']}, `{row}`: {req['sentence'].replace(chr(10), ' ')}\n\n")
        parts.append(RATIONALE[row] + "\n\n")
        for kind, members in (("reject", rejects), ("accept", accepts)):
            for member in members:
                parts.append(f"- {kind} `{member}`: {cites[member]}\n")
    return "".join(parts)


def render(manifest: dict[str, Any]) -> str:
    parts = [INTRO]
    for heading, rows in SECTIONS:
        parts.append(f"\n## {heading}\n\n{table(manifest, rows)}\n")
    parts.append(classification(manifest))
    parts.append(VOID)
    parts.append(READING_TABLE)
    shapes = ", ".join(f"`{name}`" for name in manifest["codeRegistry"]["tree-shape"])
    parts.append(TREE_SHAPES.format(shapes=shapes))
    parts.append(COUNTS)
    parts.append(OUTRO)
    for prefix, heading in (("ARM-R-", "Run object rows"), ("LCD-R-", "Discovery snapshot rows")):
        rows = [r["id"] for r in manifest["requirements"] if r["id"].startswith(prefix)]
        parts.append(f"\n## {heading}\n\n{table(manifest, rows)}\n")
    vendored = "\n".join(
        f"| `{key}` | {pin['author']} | `{pin['sha256']}` | {pin['source']} |"
        for key, pin in manifest["specVendored"].items()
    )
    parts.append(
        "\n## The vendored text\n\n| key | author | sha256 | source |\n|---|---|---|---|\n"
        + vendored + "\n"
    )
    return "".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a file this does not emit")
    args = parser.parse_args()
    text = render(load())
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else None
        if current != text:
            print(f"FAIL: {TARGET.relative_to(REPO)} differs from what the manifest renders",
                  file=sys.stderr)
            return 1
        print(f"OK {TARGET.relative_to(REPO)} is what the manifest renders")
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
