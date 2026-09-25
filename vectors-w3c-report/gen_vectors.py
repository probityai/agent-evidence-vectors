#!/usr/bin/env python3
"""Regenerate the v0.1 per-check report conformance corpus byte-identically.

    python3 gen_vectors.py            # write vectors/, MANIFEST.json, INDEX.md, MUTATION-SWEEP.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The text this corpus tests is vendored in ``spec-vendored/`` and pinned by
digest: ten messages of the W3C public-agent-conformance list that together
fix what v0.1 of the reporting format freezes, and the two Internet-Drafts the
format's editor holds, whose Run object and discovery snapshot are judged here
as further subjects. None of them carries a requirement identifier, so each is
minted here and bound to its sentence by sha256, the way ``vectors-acs-core/``
does it: a reword stops the build rather than silently re-pointing every member
that cites it.

Every reject member names exactly one row, and the validator for its subject
type must reject it under that row and no other before the file is written;
every accept member must come back with no row at all. The generator then runs
the mutation sweep nobody on the list had run -- relax each row in turn and
confirm that only the members naming it flip -- and publishes the table beside
the vectors as ``MUTATION-SWEEP.md``.

The 84 members of family ``w3c-f-disensor`` are re-cut from the 42
delta-related pairs a list participant counted in his own corpus; their origin
is recorded on each member and in the manifest, and the pairs are derived by
``origin/derive_pairs.py`` from that repository at the named commit.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "packaging"))

from agent_evidence_vectors import contextdiscovery, runmetrics, w3creport  # noqa: E402

SUITE = w3creport.SUITE
SPEC_VERSION = "0.1"
ARCHIVE = "https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/"
DATATRACKER = "https://datatracker.ietf.org/doc/"

#: The vendored texts, keyed by the archive number or the draft name each carries.
VENDORED = {
    "0001": "spec-vendored/0001-ives-2026-09-01-coverage-block.txt",
    "0025": "spec-vendored/0025-rocchia-2026-09-13-state-cause-pair-table.txt",
    "0036": "spec-vendored/0036-arsentev-2026-09-14-discrimination-and-populations.txt",
    "0043": "spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt",
    "0050": "spec-vendored/0050-ives-2026-09-15-recomputed-delta.txt",
    "0060": "spec-vendored/0060-rocchia-2026-09-16-freeze-list.txt",
    "0062": "spec-vendored/0062-arsentev-2026-09-17-editor-freeze-list.txt",
    "0069": "spec-vendored/0069-arsentev-2026-09-18-late-additions.txt",
    "0072": "spec-vendored/0072-rocchia-2026-09-18-handover.txt",
    "0073": "spec-vendored/0073-arsentev-2026-09-18-fixed-scope.txt",
    "0076": "spec-vendored/0076-schuurkes-2026-09-22-v01-comments.txt",
    "0077": "spec-vendored/0077-rocchia-2026-09-23-v01-answers.txt",
    "draft-arsentev-agent-run-metrics-00": "spec-vendored/draft-arsentev-agent-run-metrics-00.txt",
    "draft-arsentev-llm-context-discovery-00": (
        "spec-vendored/draft-arsentev-llm-context-discovery-00.txt"
    ),
}

#: Who wrote each vendored text, so the manifest names its authors.
AUTHORS = {
    "0001": "Kenne Ives",
    "0025": "Nicolas Rocchia",
    "0036": "Evgenii Arsentev",
    "0043": "Nicolas Rocchia",
    "0050": "Kenne Ives",
    "0060": "Nicolas Rocchia",
    "0062": "Evgenii Arsentev",
    "0069": "Evgenii Arsentev",
    "0072": "Nicolas Rocchia",
    "0073": "Evgenii Arsentev",
    "0076": "Roel Schuurkes",
    "0077": "Nicolas Rocchia",
    "draft-arsentev-agent-run-metrics-00": "Evgenii Arsentev",
    "draft-arsentev-llm-context-discovery-00": "Evgenii Arsentev",
}


def source_url(key: str) -> str:
    if key.startswith("draft-"):
        return f"{DATATRACKER}{key[:-3]}/"
    return f"{ARCHIVE}{key}.html"


CONSISTENCY, EVIDENCE, FORM = "consistency", "evidence", "form"
AGREED, PROPOSED = "agreed", "proposed"


def requirement(
    ident: str,
    row: str,
    file: str,
    sentence: str,
    cls: str = CONSISTENCY,
    status: str = AGREED,
) -> dict[str, str]:
    """One requirement: its sentence, its row class and whether the list agreed it.

    The class is the handover's: a consistency row reads declared slots against
    each other and catches a contradiction; an evidence row reads a declared slot
    against a recomputed or resolved one and catches a falsehood; a form row is
    decidable from the object alone. The handover left rows 4, 10, 11, 12 and 13
    unclassified; the class given here for those five is this corpus's proposal,
    and ``resolved_read`` measures the part of it a validator can measure.
    """
    return {
        "id": ident, "row": row, "file": file, "sentence": sentence,
        "class": cls, "status": status,
    }


#: One row per requirement: the verbatim sentence, located in the vendored
#: copy and hashed. A sentence spanning a line break is quoted with the break.
W3C_REQUIREMENTS: tuple[dict[str, str], ...] = (
    requirement("W3C-R-001", "1", "0043", "a non-verdict state with no cause"),
    requirement("W3C-R-002", "2", "0043", "void with not_applicable, out_of_scope or withheld"),
    requirement("W3C-R-003", "3", "0043", "not-exercised with integrity-failure"),
    # Rows 4, 10, 11, 12 and 13 are the five the handover left unclassified;
    # their class here is proposed, and the appendix carries the rationale.
    requirement(
        "W3C-R-004", "4", "0043", "a confinement control that failed while the check ran",
        CONSISTENCY, PROPOSED,
    ),
    requirement(
        "W3C-R-005", "5", "0043", "a declared exclusion with any state but not-exercised"
    ),
    requirement("W3C-R-006", "6", "0043", "a non-verdict state carrying either qualifier"),
    requirement("W3C-R-007", "7", "0043", "a verdict state carrying a cause"),
    requirement(
        "W3C-R-008", "8", "0043", "other-verdict foreclosed with discrimination demonstrated"
    ),
    requirement(
        "W3C-R-009", "9", "0043", "discrimination demonstrated with other-verdict unknown"
    ),
    requirement(
        "W3C-R-010", "10", "0043", "foreclosed without a constraint set and a domain",
        CONSISTENCY, PROPOSED,
    ),
    requirement(
        "W3C-R-011", "11", "0043", "an asserted value without its evidence reference",
        CONSISTENCY, PROPOSED,
    ),
    requirement(
        "W3C-R-012", "12", "0043", "whose changed slot is the checker", CONSISTENCY, PROPOSED
    ),
    requirement(
        "W3C-R-013",
        "(a) roll-up",
        "0069",
        "a roll-up states whether the checks it aggregates\n"
        "were capable of a negative verdict",
        EVIDENCE,
    ),
    requirement(
        "W3C-R-014",
        "(a) prior run",
        "0069",
        "a prior discriminating run only counts where check identity survives across\nruns",
    ),
    requirement(
        "W3C-R-015",
        "(b) set binding",
        "0069",
        "digest match establishes a set only when the count of leaves is bound too,\n"
        "and a report says which tree shape it uses",
        EVIDENCE,
    ),
    requirement(
        "W3C-R-016",
        "declared slots",
        "0062",
        "an object whose moved is not contained in its declared set is\nrejected",
    ),
    requirement(
        "W3C-R-017", "roll-up denominator", "0060",
        "never emitted without its complete denominator", EVIDENCE,
    ),
    requirement(
        "W3C-R-018", "roll-up counter", "0060",
        "the counter over carried against referenced", EVIDENCE,
    ),
    requirement(
        "W3C-R-019", "closed vocabulary", "0025", "because free text does not aggregate", FORM
    ),
    requirement(
        "W3C-R-020",
        "reference mismatch",
        "0062",
        "resolves with a mismatch (an integrity failure)",
        EVIDENCE,
    ),
    requirement(
        "W3C-R-021",
        "recomputed delta",
        "0050",
        "they read moved\nas recomputed from the two observations the object names",
        EVIDENCE,
    ),
    requirement(
        "W3C-R-022",
        "coverage block",
        "0001",
        "a sampled / full_coverage flag\n"
        "with the count of scannable files recorded before the per-repo cap",
        FORM,
    ),
    requirement(
        "W3C-R-023",
        "population denominator",
        "0036",
        "a claim over an empty population is reported as not claimable, not as\nsatisfied",
        EVIDENCE,
    ),
    requirement(
        "W3C-R-024",
        "delta-related pair",
        "0036",
        "Unrelated pass and fail records in one corpus must not qualify",
    ),
    # The two rows the handover numbers 13 and 14 and marks as proposed, because
    # nobody on the list has numbered them; rows 1 to 12 keep their numbers.
    requirement(
        "W3C-R-025",
        "13 (proposed)",
        "0072",
        "other-verdict demonstrated citing an evidence object whose moved\n"
        "does not contain the verdict",
        EVIDENCE,
        PROPOSED,
    ),
    requirement(
        "W3C-R-026",
        "14 (proposed)",
        "0072",
        "14 moved asserted on an evidence object that neither carries both\n"
        "observations nor references them with digests",
        FORM,
        PROPOSED,
    ),
    # Proposed in the v0.1 comment window as an amendment to section 5.4, and
    # supported on the list, not yet in the editor's text: the control is bound
    # to the checker and the constraint set of the checks it speaks for.
    requirement(
        "W3C-R-029",
        "(a) control binding",
        "0076",
        "say that the control uses the same checker revision and relevant\n"
        "configuration and constraints as the checks whose negative\n"
        "capability is being reported",
        CONSISTENCY,
        PROPOSED,
    ),
    # Two rules of the handover's Part 1 the editor took in as agreed text.
    requirement(
        "W3C-R-027", "arity recomputed", "0072", "so arity is recomputed from the delta", FORM
    ),
    requirement(
        "W3C-R-028", "domain once", "0072", "The domain is declared once at run level", FORM
    ),
)

ARM = "draft-arsentev-agent-run-metrics-00"
ARM_REQUIREMENTS: tuple[dict[str, str], ...] = (
    requirement(
        "ARM-R-001", "5.1", ARM,
        'Reporter MUST emit "1" while conforming to this specification',
    ),
    requirement(
        "ARM-R-002", "3.1", ARM,
        'The "end" member MUST be present when "status" is "completed",\n'
        '   "failed" or "aborted", and MUST NOT be present when "status" is\n'
        '   "running"',
    ),
    requirement("ARM-R-003", "3.1", ARM, 'When present, "end" MUST NOT be earlier than "start"'),
    requirement(
        "ARM-R-004", "3.1", ARM, "a Reporter MUST NOT emit\n   a value other than the four listed"
    ),
    requirement(
        "ARM-R-005", "3.1", ARM,
        'When the "steps" array is present, "step_count" MUST be\n'
        "   greater than or equal to the length of that array",
    ),
    requirement(
        "ARM-R-006", "3.2", ARM,
        'Within one Run, "index" values MUST be unique and MUST be assigned in\n'
        "   the order in which Steps began",
    ),
    requirement(
        "ARM-R-007", "3.2", ARM,
        'When "kind" is "model_invocation", the "usage" and "model" members\n'
        "   MUST be present",
    ),
    requirement(
        "ARM-R-008", "3.2", ARM,
        'When "kind" is "tool_call", the "tool" member MUST\n'
        '   be present and the "usage" member MUST NOT be present',
    ),
    requirement(
        "ARM-R-009", "3.4", ARM, "All members of a Usage object MUST be non-negative integers"
    ),
    requirement(
        "ARM-R-010", "3.4", ARM,
        '"cache_read_tokens" is a subset of "input_tokens" and therefore\n'
        "       MUST be less than or equal to it",
    ),
    requirement(
        "ARM-R-011", "3.4", ARM,
        '"cache_read_tokens" and "cache_write_tokens"\n'
        '       denote disjoint subsets of "input_tokens" and their sum MUST be\n'
        '       less than or equal to "input_tokens"',
    ),
    requirement(
        "ARM-R-012", "3.4", ARM,
        '"totals" object MUST be, member by member, the sum of the\n'
        "   corresponding members of every Step's Usage object",
    ),
    requirement(
        "ARM-R-013", "3.5", ARM,
        'One\n   "lifetime" value MUST NOT appear in more than one element of the same\n   array',
    ),
    requirement(
        "ARM-R-014", "3.5", ARM,
        'The sum of the "tokens" members of "cache_writes" MUST equal the\n'
        '   "cache_write_tokens" member of the same Usage object',
    ),
    requirement(
        "ARM-R-015", "3.3", ARM,
        'A Reporter MUST NOT\n   emit two Steps of one Run with the same "invocation_id"',
    ),
    requirement(
        "ARM-R-016", "3.6", ARM,
        'A Run that emits "root_run_id" and has no\n'
        '      parent MUST set it equal to its own "run_id"',
    ),
    requirement(
        "ARM-R-017", "3.7", ARM,
        'The "amount" member MUST be a JSON string matching the ABNF [RFC5234]\n   rule',
    ),
    requirement(
        "ARM-R-018", "3.12", ARM,
        "Its value MUST be a JSON object whose members all\n   have string values",
    ),
    requirement(
        "ARM-R-019", "5", ARM,
        'Timestamps MUST be strings conforming to the "date-time" production\n'
        '   of [RFC3339].  They MUST use the "Z" time offset',
    ),
    requirement(
        "ARM-R-020", "5", ARM, "MUST be non-empty strings of at most 128\n   characters"
    ),
    requirement(
        "ARM-R-021", "5.1", ARM,
        "A Reporter MUST NOT use an unprefixed member\n"
        "   name for a purpose other than the one specified here",
    ),
    requirement(
        "ARM-R-022", "3.4", ARM,
        '"reasoning_tokens" is a subset of "output_tokens" and\n'
        "       therefore MUST be less than or equal to it",
    ),
)

LCD = "draft-arsentev-llm-context-discovery-00"
LCD_REQUIREMENTS: tuple[dict[str, str], ...] = (
    requirement(
        "LCD-R-001", "3.1", LCD,
        'A context file MUST NOT be served with a "Content-Type" of "text/\n   html"',
    ),
    requirement(
        "LCD-R-002", "3.2", LCD,
        "A discovery mechanism defined in Section 4 MUST point at an index\n"
        "      resource, never directly at a detail resource",
    ),
    requirement(
        "LCD-R-003", "4.1", LCD,
        "A publisher advertising a context file through this mechanism MUST\n"
        '   arrange that a GET request for "/.well-known/llm-context" on the\n'
        "   origin returns either",
    ),
    requirement("LCD-R-004", "4.3", LCD, "Its value MUST be an absolute\n   URI"),
    requirement(
        "LCD-R-005", "4.3", LCD,
        "A publisher MUST NOT use this record to advertise a context file\n"
        "   whose retrieval the same robots.txt disallows",
    ),
    requirement(
        "LCD-R-006", "4.4", LCD,
        "a consumer MUST\n   apply the following precedence, highest first",
    ),
    requirement(
        "LCD-R-007", "4.4", LCD,
        "A consumer MUST NOT retrieve more than one index resource per origin\n"
        "   per retrieval cycle",
    ),
    requirement(
        "LCD-R-008", "7.2", LCD,
        "A consumer MUST NOT attribute the content of a cross-origin index\n"
        "   resource to the advertising origin",
    ),
    requirement(
        "LCD-R-009", "7.4", LCD,
        "A consumer MUST impose its own ceiling on the size of any retrieved\n"
        "   context file",
    ),
    requirement(
        "LCD-R-010", "3.3", LCD,
        'the response MUST carry an appropriate "Content-Language"',
    ),
    requirement(
        "LCD-R-011", "4.4", LCD,
        "a consumer MUST evaluate the exclusion\n"
        "   rules of [RFC9309] against the index resource's URI before retrieving\n"
        "   it",
    ),
)

REQUIREMENTS = (*W3C_REQUIREMENTS, *ARM_REQUIREMENTS, *LCD_REQUIREMENTS)

FAMILIES = {
    "w3c-f-1": "row 1: a non-verdict state with no cause",
    "w3c-f-2": "row 2: void with a cause that describes a unit never examined",
    "w3c-f-3": "row 3: not-exercised with integrity-failure",
    "w3c-f-4": (
        "row 4: a confinement failure during the check as the cause, and the state is not void"
    ),
    "w3c-f-5": "row 5: a declared exclusion whose state is not not-exercised",
    "w3c-f-6": "row 6: a non-verdict state carrying a qualifier",
    "w3c-f-7": "row 7: a verdict state carrying a cause",
    "w3c-f-8": "row 8: other-verdict foreclosed beside discrimination demonstrated",
    "w3c-f-9": (
        "row 9: discrimination demonstrated beside an other-verdict that is not demonstrated"
    ),
    "w3c-f-10": "row 10: foreclosed without its constraint set and domain",
    "w3c-f-11": "row 11: an asserted qualifier value without its evidence reference",
    "w3c-f-12": (
        "row 12: discrimination demonstrated citing evidence whose changed slot is the checker"
    ),
    "w3c-f-13": "late addition (a): a roll-up says whether its checks could have gone negative",
    "w3c-f-14": (
        "late addition (a): a prior discriminating run binds the check identity that survived"
    ),
    "w3c-f-15": (
        "late addition (b): a digest over a set binds its leaf count and names its tree "
        "shape; domain separation alone is not the fix"
    ),
    "w3c-f-16": "declared slots: moved is contained in the declared compared set",
    "w3c-f-29": (
        "late addition (a), amended in the comment window: a control built to fail is bound "
        "to the checker and constraint set of the checks it speaks for"
    ),
    "w3c-f-17": "roll-up: the aggregate carries its complete denominator",
    "w3c-f-18": "roll-up: the counter over carried against referenced recomputes",
    "w3c-f-19": "closed vocabulary: a value outside a registry is not read",
    "w3c-f-20": (
        "carry-or-reference: a digest that resolves with a mismatch is an integrity failure, "
        "over the check set and over a referenced observation alike"
    ),
    "w3c-f-21": (
        "recomputed delta: moved is read as recomputed over the observations, not as declared"
    ),
    "w3c-f-22": (
        "coverage block: scope disclosure in controlled fields, with the pre-cap file count"
    ),
    "w3c-f-23": "population denominator: a completeness claim carries the size of its population",
    "w3c-f-24": "delta-related pair: unrelated pass and fail records do not witness discrimination",
    "w3c-f-25": (
        "row 13 (proposed): other-verdict demonstrated citing an object whose recomputed moved "
        "does not contain the verdict; unresolvable, the row degrades"
    ),
    "w3c-f-26": (
        "row 14 (proposed): moved asserted on an object that neither carries its observations "
        "nor references them with digests"
    ),
    "w3c-f-27": "arity: recomputed from the delta, never declared",
    "w3c-f-28": "domain: declared once at run level, named by identifier and never restated",
    "w3c-f-gaps": (
        "the two known gaps of the reference emitter, closed: void has a slot and "
        "not-exercised carries a cause"
    ),
    "w3c-f-disensor": (
        "the 42 delta-related pairs of the disensor corpus at 1e36257, re-cut against v0.1"
    ),
    "arm-f-run": "agent run metrics: the Run object's own members",
    "arm-f-steps": "agent run metrics: the Step objects and their order",
    "arm-f-usage": "agent run metrics: the Usage invariants and the cache-write ledger",
    "arm-f-totals": "agent run metrics: the totals as the sum of the steps",
    "arm-f-serialization": (
        "agent run metrics: timestamps, identifiers, labels, cost and extensions"
    ),
    "lcd-f-publisher": "context discovery: what the origin advertises and serves",
    "lcd-f-consumer": "context discovery: what a consumer resolves, retrieves and attributes",
}

ORIGIN_FILE = "origin/disensor-1e36257-pairs.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as handle:
        return handle.read()


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """The digest this corpus publishes, recomputed from the files on disk.

    Imported by scripts/release-digests.py rather than restated there.
    """
    return w3creport.corpus_digest(manifest, root)


def locate(row: dict[str, str]) -> tuple[int, str]:
    rel = VENDORED[row["file"]]
    text = read(rel).decode("utf-8")
    needle = row["sentence"]
    if any(ord(ch) > 0x7F for ch in needle):
        raise SystemExit(f"FAIL: {row['id']} quotes a non-ASCII sentence")
    index = text.find(needle)
    if index < 0:
        raise SystemExit(f"FAIL: {row['id']} quotes a sentence that is not in {rel}")
    if text.find(needle, index + 1) >= 0:
        raise SystemExit(f"FAIL: {row['id']} quotes a sentence appearing more than once in {rel}")
    return text.count("\n", 0, index) + 1, sha(needle.encode("utf-8"))


# --------------------------------------------------------------------------
# Report builders. A report built here is internally consistent unless a
# member deliberately breaks one thing, and the one thing is the row.
# --------------------------------------------------------------------------

DOMAIN = {"id": "d-run", "description": "the run's declared domain, referenced by identifier"}
DISENSOR_DOMAIN = {
    "id": "d-disensor",
    "description": (
        "the disensor corpus at the pinned commit: its vectors under each schema version"
    ),
}
FIXED = {"checker": "checker-1", "constraint-set": "cs-1", "domain": "d-run"}
DECLARED = ["verdict", "fired-rule list"]
WITH_ERRORS = ["verdict", "fired-rule list", "error list"]


def check(
    ident: str,
    state: str,
    cause: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {"check": ident, "state": state}
    if cause is not None:
        record["cause"] = cause
    if extra:
        record.update(extra)
    return record


def with_slots(record: dict[str, Any], **slots: dict[str, Any]) -> dict[str, Any]:
    """A copy of a record carrying qualifier slots, keyed as the record spells them."""
    out = dict(record)
    for key, value in slots.items():
        out[key.replace("_", "-")] = value
    return out


Outcomes = tuple[tuple[str, list[str]], tuple[str, list[str]]]
PASS_FAIL: Outcomes = (("pass", []), ("fail", ["R-1"]))
DELTA = {"changes": [{"field": "artifact/field", "before": 1, "after": 2}]}


def evidence(
    ident: str,
    changed: str = "input artifact",
    moved: list[str] | None = None,
    compared: list[str] | None = None,
) -> dict[str, Any]:
    """An evidence object referencing its two observations by locator and digest.

    A reference carries no outcome: what the observation contains is what the
    reader resolves it to, through the member's ``resolves`` store (``store()``).
    """
    return {
        "id": ident,
        "changed": changed,
        "fixed": dict(FIXED),
        "compared": list(compared or DECLARED),
        "moved": list(moved or DECLARED),
        "delta": copy.deepcopy(DELTA),
        "observations": [
            {"reference": {"vector": "obs-pass", "sha256": sha(b"obs-pass")}},
            {"reference": {"vector": "obs-fail", "sha256": sha(b"obs-fail")}},
        ],
    }


def store(outcomes: Outcomes = PASS_FAIL) -> dict[str, Any]:
    """What a reader holding the suite resolves ``obs-pass`` and ``obs-fail`` to."""
    resolved = {}
    for locator, (verdict, rules) in zip(("obs-pass", "obs-fail"), outcomes, strict=True):
        resolved[locator] = {"sha256": sha(locator.encode()), "verdict": verdict, "rules": rules}
    return resolved


def qualifier(value: str, ref: str | None = None, bounded: bool = False) -> dict[str, Any]:
    slot: dict[str, Any] = {"value": value}
    if ref is not None:
        slot["ref"] = ref
    if bounded:
        slot["constraint-set"] = "cs-1"
        slot["domain"] = "d-run"
    return slot


PASS = check("c-pass", "pass")
PASS_2 = check("c-pass-2", "pass")
FAIL = check("c-fail", "fail")
EXCLUDED = check(
    "c-excluded",
    "not-exercised",
    {"code": "out_of_scope", "detail": "excluded by the run's declaration"},
    {"declared-exclusion": True},
)
INCONCLUSIVE = check(
    "c-inconclusive",
    "inconclusive",
    {"code": "unsupported_input", "detail": "reading committed: record-undecodable"},
)
VOID = check(
    "c-void",
    "void",
    {"code": "integrity-failure", "detail": "the evidence signature does not verify"},
)
ALL_PASS = [PASS, PASS_2]


def report(
    checks: list[dict[str, Any]],
    evidence_list: list[dict[str, Any]] | None = None,
    shape: str = "flat",
    negative: dict[str, Any] | None = None,
    domain: dict[str, Any] | None = None,
    fixed: dict[str, str] | None = None,
) -> dict[str, Any]:
    checks = copy.deepcopy(checks)
    evidence_list = copy.deepcopy(evidence_list or [])
    counts = w3creport._counts(checks)
    carried = sum(1 for e in evidence_list for o in e["observations"] if "carried" in o)
    referenced = sum(1 for e in evidence_list for o in e["observations"] if "reference" in o)
    if negative is None:
        negative = {"kind": "shown-by-run"} if counts["fail"] else {"kind": "nothing"}
    rollup: dict[str, Any] = dict(counts, carried=carried, referenced=referenced)
    rollup["negative-capable"] = negative
    built: dict[str, Any] = {
        "format": w3creport.FORMAT,
        "domain": dict(domain or DOMAIN),
        "checks": checks,
        "evidence": evidence_list,
        "roll-up": rollup,
        "check-set": {
            "sha256": w3creport.check_set_root(checks, shape),
            "leaf-count": len(checks),
            "tree-shape": shape,
        },
    }
    if fixed is not None:
        # The checker and constraint set the run's declared checks ran under,
        # declared once at run level, as the domain is.
        built["fixed"] = dict(fixed)
    return built


class Members:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def add(
        self,
        *,
        kind: str,
        family: str,
        requirements: list[str],
        subject: dict[str, Any],
        cites: str,
        subject_type: str = "report",
        origin: dict[str, Any] | None = None,
        resolves: dict[str, Any] | None = None,
    ) -> None:
        member: dict[str, Any] = {
            "kind": kind,
            "family": family,
            "requirements": requirements,
            "specVersion": SPEC_VERSION,
            "subjectType": subject_type,
            "subject": subject,
            "expected": {"verdict": kind, "rejects": requirements if kind == "reject" else []},
            "cites": cites,
        }
        if subject_type == "report":
            # What this member's reader resolves referenced observations to.
            # Every report member carries a store, so that a reader with the
            # suite and a reader without it are both members of the corpus.
            member["resolves"] = store() if resolves is None else resolves
        if origin is not None:
            member["origin"] = origin
        self.items.append(member)

    def reject(
        self,
        family: str,
        req: str,
        subject: dict[str, Any],
        cites: str,
        resolves: dict[str, Any] | None = None,
    ) -> None:
        self.add(kind="reject", family=family, requirements=[req], subject=subject, cites=cites,
                 resolves=resolves)

    def accept(
        self,
        family: str,
        req: str,
        subject: dict[str, Any],
        cites: str,
        resolves: dict[str, Any] | None = None,
    ) -> None:
        self.add(kind="accept", family=family, requirements=[req], subject=subject, cites=cites,
                 resolves=resolves)

    def pair(
        self,
        family: str,
        req: str,
        rejected: dict[str, Any],
        accepted: dict[str, Any],
        why_reject: str,
        why_accept: str,
        resolves: dict[str, Any] | None = None,
    ) -> None:
        self.reject(family, req, rejected, why_reject, resolves)
        self.accept(family, req, accepted, why_accept, resolves)

    def typed_pair(
        self,
        subject_type: str,
        family: str,
        req: str,
        rejected: dict[str, Any],
        accepted: dict[str, Any],
        why_reject: str,
        why_accept: str,
    ) -> None:
        self.add(kind="reject", family=family, requirements=[req], subject=rejected,
                 cites=why_reject, subject_type=subject_type)
        self.add(kind="accept", family=family, requirements=[req], subject=accepted,
                 cites=why_accept, subject_type=subject_type)


def build_rows_1_to_7(m: Members) -> None:
    inc_no_cause = {k: v for k, v in INCONCLUSIVE.items() if k != "cause"}
    m.pair(
        "w3c-f-1", "W3C-R-001",
        report([PASS, inc_no_cause]), report([PASS, INCONCLUSIVE]),
        "an inconclusive record with no cause slot",
        "the same record carrying the reading the rail committed to as its cause",
    )
    m.pair(
        "w3c-f-2", "W3C-R-002",
        report([PASS, check("c-void", "void", {"code": "out_of_scope"})]), report([PASS, VOID]),
        "a void record whose cause says the unit was never examined",
        "a void record whose cause is an integrity failure of examined evidence",
    )
    m.pair(
        "w3c-f-3", "W3C-R-003",
        report([PASS, check("c-nx", "not-exercised", {"code": "integrity-failure"})]),
        report([PASS, check("c-nx", "not-exercised", {"code": "out_of_scope"})]),
        "a not-exercised record whose cause is a failure of evidence it never examined",
        "the same record with a cause that describes a unit left out of the count",
    )
    # Row 4 reads the cause cell against the state, as row 3 does, so the fact
    # that confinement failed during the check is a cause value admitted only
    # under void and nothing is added to the record. The reject member is
    # inconclusive rather than fail: a verdict state carrying any cause is also
    # row 7, and a member is rejected under one row only.
    confined = {
        "code": w3creport.CONFINEMENT_CAUSE,
        "detail": "the sandbox's egress control failed while the check ran",
    }
    m.pair(
        "w3c-f-4", "W3C-R-004",
        report([PASS, check("c-confined", "inconclusive", confined)]),
        report([PASS, check("c-confined", "void", confined)]),
        "a confinement failure during the check recorded as its cause while the state is "
        "inconclusive",
        "the same record reported void, the only state that cause is admitted under",
    )
    m.pair(
        "w3c-f-5", "W3C-R-005",
        report([check("c-x", "pass", None, {"declared-exclusion": True})]),
        report([PASS, EXCLUDED]),
        "a declared exclusion reported as a pass",
        "a declared exclusion reported as not-exercised with its cause",
    )
    m.pair(
        "w3c-f-6", "W3C-R-006",
        report([PASS, with_slots(INCONCLUSIVE, other_verdict=qualifier("unknown"))]),
        report([PASS, with_slots(FAIL, other_verdict=qualifier("possible-not-demonstrated"))]),
        "an inconclusive record carrying an other-verdict slot",
        "a fail record carrying the same slot, which a verdict state may",
    )
    m.pair(
        "w3c-f-7", "W3C-R-007",
        report([check("c-pass", "pass", {"code": "out_of_scope"})]), report([PASS]),
        "a pass carrying a cause",
        "the same pass with no cause slot",
    )


def build_rows_8_to_12(m: Members) -> None:
    e1 = evidence("e-1")
    foreclosed = qualifier("foreclosed", "e-1", True)
    m.pair(
        "w3c-f-8", "W3C-R-008",
        report([PASS, with_slots(FAIL, other_verdict=foreclosed,
                                 discrimination=qualifier("demonstrated", "e-1"))], [e1]),
        report([PASS, with_slots(FAIL, other_verdict=foreclosed,
                                 discrimination=qualifier("unknown"))], [e1]),
        "foreclosed and demonstrated on one record, which cannot both hold",
        "foreclosed with discrimination left unknown",
    )
    m.pair(
        "w3c-f-9", "W3C-R-009",
        report([PASS, with_slots(FAIL, other_verdict=qualifier("possible-not-demonstrated"),
                                 discrimination=qualifier("demonstrated", "e-1"))], [e1]),
        report([PASS, with_slots(FAIL, other_verdict=qualifier("demonstrated", "e-1"),
                                 discrimination=qualifier("demonstrated", "e-1"))], [e1]),
        "discrimination demonstrated while the other verdict is only possible",
        "discrimination demonstrated beside the other verdict demonstrated by the same evidence",
    )
    m.pair(
        "w3c-f-10", "W3C-R-010",
        report([with_slots(PASS, other_verdict=qualifier("foreclosed", "e-1"))], [e1]),
        report([with_slots(PASS, other_verdict=foreclosed)], [e1]),
        "foreclosed with neither a constraint set nor a domain",
        "foreclosed naming both, by identifier",
    )
    m.pair(
        "w3c-f-11", "W3C-R-011",
        report([PASS, with_slots(FAIL, other_verdict=qualifier("demonstrated"))], [e1]),
        report([PASS, with_slots(FAIL, other_verdict=qualifier("demonstrated", "e-1"))], [e1]),
        "demonstrated asserted with no evidence reference",
        "demonstrated with the reference that carries it",
    )
    both = with_slots(
        FAIL,
        other_verdict=qualifier("demonstrated", "e-1"),
        discrimination=qualifier("demonstrated", "e-2"),
    )
    m.pair(
        "w3c-f-12", "W3C-R-012",
        report([PASS, both], [e1, evidence("e-2", changed="checker rule")]),
        report([PASS, both], [e1, evidence("e-2")]),
        "discrimination cites an object whose changed slot is the checker: "
        "attribution in a discrimination cell",
        "the same cell citing an object whose changed slot is the input artifact",
    )


def build_roll_up(m: Members) -> None:
    """Late addition (a): the roll-up's negative-capable field, and its prior-run form."""
    silent = report(ALL_PASS)
    del silent["roll-up"]["negative-capable"]
    m.reject("w3c-f-13", "W3C-R-013", silent,
             "an all-pass roll-up with the field absent: silence, which the text disallows")
    m.reject("w3c-f-13", "W3C-R-013", report(ALL_PASS, negative={"kind": "shown-by-run"}),
             "shown-by-run asserted on a run whose counts show no non-pass")
    m.accept("w3c-f-13", "W3C-R-013", report(ALL_PASS, negative={"kind": "nothing"}),
             "nothing, which is a permitted answer")
    control = {"kind": "control-failed",
               "control": {"checks": ["c-pass", "c-pass-2"], "state": "fail"}}
    m.accept("w3c-f-13", "W3C-R-013", report(ALL_PASS, negative=control),
             "a control built to fail that did fail, over the run's own declared checks")
    m.accept("w3c-f-13", "W3C-R-013", report([PASS, FAIL]),
             "a run that already shows a non-pass, so the counts carry the answer")
    # A negative verdict, not any non-pass: an inconclusive check ran and reached
    # no conclusion, which shows nothing about whether the checks can reject.
    m.reject("w3c-f-13", "W3C-R-013",
             report([PASS, INCONCLUSIVE], negative={"kind": "shown-by-run"}),
             "shown-by-run asserted on a run whose only non-pass is inconclusive: a non-pass "
             "that is not a fail verdict")
    inconclusive_control = {"kind": "control-failed",
                            "control": {"checks": ["c-pass", "c-pass-2"],
                                        "state": "inconclusive"}}
    m.reject("w3c-f-13", "W3C-R-013", report(ALL_PASS, negative=inconclusive_control),
             "a control built to fail that ran and reached no conclusion: failing to execute "
             "does not show the check can reject the input")
    prior_ref = {"sha256": sha(b"prior-run"), "leaf-count": 2, "tree-shape": "flat"}
    prior = {"kind": "prior-discriminating-run", "reference": prior_ref}
    m.reject("w3c-f-14", "W3C-R-014", report(ALL_PASS, negative=prior),
             "a prior run offered with no binding of which declared checks survived into it")
    m.accept("w3c-f-14", "W3C-R-014",
             report(ALL_PASS, negative=dict(prior, **{"check-identity": ["c-pass", "c-pass-2"]})),
             "the same prior run binding the check identity that survived across runs")


#: What the run's declared checks ran under, in the evidence object's own keys.
RUN_FIXED = {"checker": "checker-1", "constraint-set": "cs-1"}


def build_control_binding(m: Members) -> None:
    """A control built to fail binds the checker and constraint set it ran under.

    The case the list gave: a check keeps its identifier while its threshold
    changes, so a control rejected under the stricter setting is evidence about
    that setting and not about the one the run reports. A control that declares
    no binding is not refused here; only a binding that differs from the run's.
    """
    def control(checker: str, constraint_set: str) -> dict[str, Any]:
        return {"kind": "control-failed", "control": {
            "checks": ["c-pass", "c-pass-2"], "state": "fail",
            "fixed": {"checker": checker, "constraint-set": constraint_set},
        }}

    m.reject("w3c-f-29", "W3C-R-029",
             report(ALL_PASS, negative=control("checker-1", "cs-2"), fixed=RUN_FIXED),
             "a control that failed under constraint set cs-2, offered for checks that ran "
             "under cs-1: the check kept its identifier and its configuration changed, so "
             "the failure is evidence about another configuration")
    m.reject("w3c-f-29", "W3C-R-029",
             report(ALL_PASS, negative=control("checker-2", "cs-1"), fixed=RUN_FIXED),
             "a control that failed under another checker than the one the reported checks "
             "ran under")
    m.accept("w3c-f-29", "W3C-R-029",
             report(ALL_PASS, negative=control("checker-1", "cs-1"), fixed=RUN_FIXED),
             "the same control bound to the checker and constraint set the reported checks "
             "ran under")
    m.accept("w3c-f-29", "W3C-R-029",
             report(ALL_PASS, negative=control("checker-1", "cs-2")),
             "a control that declares its binding in a run that declares none: nothing to "
             "compare, and the proposal does not yet require the run's slot")


def build_set_binding(m: Members) -> None:
    """Late addition (b): a digest over a set binds its count and names its shape."""
    unbound = report(ALL_PASS)
    del unbound["check-set"]["leaf-count"]
    m.reject("w3c-f-15", "W3C-R-015", unbound,
             "a set digest with no leaf count: a match establishes nothing")
    miscounted = report(ALL_PASS)
    miscounted["check-set"]["leaf-count"] = 3
    m.reject("w3c-f-15", "W3C-R-015", miscounted,
             "a leaf count that does not equal the checks the report carries")
    prior_unbound = {"kind": "prior-discriminating-run",
                     "reference": {"sha256": sha(b"prior-run")}, "check-identity": ["c-pass"]}
    m.reject("w3c-f-15", "W3C-R-015", report(ALL_PASS, negative=prior_unbound),
             "a prior run referenced as a set of observations with no count and no shape")
    separated = report(ALL_PASS, shape="rfc6962")
    del separated["check-set"]["tree-shape"]
    separated["check-set"]["domain-separation"] = True
    m.reject("w3c-f-15", "W3C-R-015", separated,
             "a count bound and domain separation asserted, with no tree shape declared: "
             "domain separation alone is not the fix, because RFC 6962 also uses a different "
             "tree shape, so the producer declares the shape")
    m.accept("w3c-f-15", "W3C-R-015", report(ALL_PASS, shape="rfc6962"),
             "the check set bound under the RFC 6962 tree shape, with its count")
    m.accept("w3c-f-15", "W3C-R-015", report([PASS, FAIL], shape="flat"),
             "the check set bound under the flat shape, with its count")
    # RFC9162_SHA256 is the RFC 9942 registry identifier for the Merkle tree of
    # RFC 9162 section 2.1.1 over SHA-256. The pair differs in the spelling of
    # the shape alone: the root and the count are the same bytes in both.
    registered = report(ALL_PASS, shape="RFC9162_SHA256")
    free_text = copy.deepcopy(registered)
    free_text["check-set"]["tree-shape"] = "RFC 9162 SHA-256"
    m.reject("w3c-f-15", "W3C-R-015", free_text,
             "the RFC 9162 tree named in free text: the closed set admits the registry "
             "identifier and nothing else, because free text does not aggregate")
    m.accept("w3c-f-15", "W3C-R-015", registered,
             "the check set bound under RFC9162_SHA256, the RFC 9942 identifier for the "
             "RFC 9162 Merkle tree over SHA-256, with its count")


def build_rules(m: Members) -> None:
    """The declared-slot rule, the roll-up rules, the vocabulary rule, the mismatch rule."""
    demonstrated = with_slots(FAIL, other_verdict=qualifier("demonstrated", "e-1"))
    m.pair(
        "w3c-f-16", "W3C-R-016",
        report([PASS, demonstrated], [evidence("e-1", moved=WITH_ERRORS)]),
        report([PASS, demonstrated], [evidence("e-1", moved=WITH_ERRORS, compared=WITH_ERRORS)]),
        "moved names the error list and the declared compared set does not hold it",
        "the error list declared compared, so moved is contained; no row reads the opaque slot",
    )
    short = report([PASS, FAIL, EXCLUDED])
    short["roll-up"]["exercised"] = 3
    m.pair(
        "w3c-f-17", "W3C-R-017", short, report([PASS, FAIL, EXCLUDED]),
        "an exercised count that includes the not-exercised check",
        "the denominator recomputed from the records",
    )
    mixed = evidence("e-1")
    mixed["observations"][0] = {"carried": {"vector": "obs-pass", "verdict": "pass", "rules": []}}
    miscounted = report([PASS, demonstrated], [mixed])
    miscounted["roll-up"]["carried"] = 0
    miscounted["roll-up"]["referenced"] = 2
    m.pair(
        "w3c-f-18", "W3C-R-018", miscounted, report([PASS, demonstrated], [mixed]),
        "the counter says two referenced while one observation is carried",
        "one carried against one referenced, as the evidence holds them",
    )
    free_text = {"code": "the proxy blocked it"}
    registry = {"code": "unavailable", "detail": "the proxy blocked it"}
    m.pair(
        "w3c-f-19", "W3C-R-019",
        report([PASS, check("c-nx", "not-exercised", free_text)]),
        report([PASS, check("c-nx", "not-exercised", registry)]),
        "a cause written as free text in place of a disposition",
        "the same cause as a registry value with the text carried as detail",
    )
    three = [PASS, PASS_2, check("c-pass-3", "pass")]
    padded = report(three, shape="rfc6962")
    padded["check-set"]["sha256"] = w3creport.rfc6962_root(
        [w3creport.compact(c) for c in [*three, three[-1]]]
    )
    m.pair(
        "w3c-f-20", "W3C-R-020", padded, report(three, shape="rfc6962"),
        "a root computed with RFC 6962 domain separation over the leaf set with its last leaf "
        "repeated: the count says three and the digest does not recompute, so domain "
        "separation retained beside duplicate-last padding is still a mismatch",
        "the root recomputed over exactly the three leaves the count binds",
    )
    padded_9162 = report(three, shape="RFC9162_SHA256")
    padded_9162["check-set"]["sha256"] = w3creport.check_set_root(
        [*three, three[-1]], "RFC9162_SHA256"
    )
    m.pair(
        "w3c-f-20", "W3C-R-020", padded_9162, report(three, shape="RFC9162_SHA256"),
        "a root declared RFC9162_SHA256 and computed over the leaf set with its last leaf "
        "repeated: the count says three and the RFC 9162 tree over three leaves does not "
        "recompute to it",
        "the RFC 9162 tree recomputed over exactly the three leaves the count binds",
    )
    demonstrated_pair = report([PASS, demonstrated], [evidence("e-1")])
    mismatched = store()
    mismatched["obs-fail"]["sha256"] = sha(b"obs-fail, another revision")
    m.reject(
        "w3c-f-20", "W3C-R-020", demonstrated_pair,
        "a referenced observation that resolves to bytes whose digest is not the one the "
        "reference carries: the reading table's second line, an integrity failure",
        resolves=mismatched,
    )
    m.accept(
        "w3c-f-20", "W3C-R-020", demonstrated_pair,
        "the same reference resolving to the bytes it was written against, "
        "which is the reading table's first line",
    )


COVERAGE = {
    "surface": "repository",
    "scan-depth": "repo-only",
    "point-in-time": "2026-09-18T00:00:00Z",
    "snapshots": [
        {"name": "osv", "date": "2026-09-17"},
        {"name": "deps.dev", "date": "2026-09-17"},
    ],
    "live-observed": False,
    "linked-repo": "git+https://example.invalid/repo@1e36257",
    "sampled": True,
    "scannable-files": 4120,
    "scanned-files": 2000,
}


def build_people_rules(m: Members) -> None:
    """The recomputed-delta rule, the coverage block, the population rule, the pair rule."""
    two_fails: tuple[tuple[str, list[str]], tuple[str, list[str]]] = (
        ("fail", ["R-A"]), ("fail", ["R-B"]),
    )
    possible = with_slots(FAIL, other_verdict=qualifier("possible-not-demonstrated"))
    m.pair(
        "w3c-f-21", "W3C-R-021",
        report([PASS, possible], [evidence("e-1", moved=["verdict"])]),
        report([PASS, possible], [evidence("e-1", moved=["fired-rule list"])]),
        "fail with A beside fail with B, moved declared as the verdict: read the field and it "
        "passes, recompute the delta and it is rejected",
        "the same two observations with moved recomputed: the fired-rule list moved and the "
        "verdict did not",
        resolves=store(two_fails),
    )
    partial = report(ALL_PASS)
    partial["coverage"] = {k: v for k, v in COVERAGE.items() if k != "scannable-files"}
    full = report(ALL_PASS)
    full["coverage"] = dict(COVERAGE)
    m.pair(
        "w3c-f-22", "W3C-R-022", partial, full,
        "a sampled scan with no count of scannable files, so the partial flag hides its size",
        "the coverage block with every controlled field and the pre-cap count",
    )
    undated = report(ALL_PASS)
    undated["coverage"] = dict(COVERAGE, snapshots=[{"name": "osv"}])
    unsampled = report(ALL_PASS)
    unsampled["coverage"] = dict(COVERAGE, sampled=False)
    del unsampled["coverage"]["scanned-files"]
    m.pair(
        "w3c-f-22", "W3C-R-022", undated, unsampled,
        "a database snapshot with no date",
        "a full scan, which needs no scanned count beside the scannable one",
    )
    zero = [EXCLUDED, check("c-excluded-2", "not-exercised", {"code": "out_of_scope"},
                            {"declared-exclusion": True})]
    claimed = report(zero)
    claimed["roll-up"]["completeness"] = {
        "accounting": {"population": 2, "claim": "satisfied"},
        "execution": {"population": 2, "claim": "not-satisfied"},
        "evidence": {"population": 0, "claim": "satisfied"},
    }
    honest = report(zero)
    honest["roll-up"]["completeness"] = {
        "accounting": {"population": 2, "claim": "satisfied"},
        "execution": {"population": 2, "claim": "not-satisfied"},
        "evidence": {"population": 0, "claim": "not-claimable"},
    }
    m.pair(
        "w3c-f-23", "W3C-R-023", claimed, honest,
        "the zero-verdict run: evidence completeness claimed satisfied over a population of none",
        "the same run reporting the empty population as not claimable",
    )
    miscounted = report([PASS, FAIL])
    miscounted["roll-up"]["completeness"] = {
        "accounting": {"population": 3, "claim": "satisfied"},
        "execution": {"population": 2, "claim": "satisfied"},
        "evidence": {"population": 2, "claim": "not-satisfied"},
    }
    counted = report([PASS, FAIL])
    counted["roll-up"]["completeness"] = {
        "accounting": {"population": 2, "claim": "satisfied"},
        "execution": {"population": 2, "claim": "satisfied"},
        "evidence": {"population": 2, "claim": "not-satisfied"},
    }
    m.pair(
        "w3c-f-23", "W3C-R-023", miscounted, counted,
        "an accounting claim over a population the report does not carry",
        "each claim carrying the count of the population it quantifies over",
    )
    unrelated = evidence("e-1")
    del unrelated["delta"]
    witnessed = with_slots(FAIL, other_verdict=qualifier("demonstrated", "e-1"),
                           discrimination=qualifier("demonstrated", "e-1"))
    m.pair(
        "w3c-f-24", "W3C-R-024",
        report([PASS, witnessed], [unrelated]), report([PASS, witnessed], [evidence("e-1")]),
        "discrimination demonstrated by a pass and a fail with no stated delta between them",
        "the same pair related by a stated delta under one pinned checker, constraints and domain",
    )


def build_proposed_rows(m: Members) -> None:
    """Rows 13 and 14 under the handover's proposed numbering, and arity and domain."""
    demonstrated = with_slots(FAIL, other_verdict=qualifier("demonstrated", "e-1"))
    two_fails: Outcomes = (("fail", ["R-A"]), ("fail", ["R-B"]))
    rules_only = report([PASS, demonstrated], [evidence("e-1", moved=["fired-rule list"])])
    m.reject(
        "w3c-f-25", "W3C-R-025", rules_only,
        "the other verdict asserted demonstrated by an object whose two observations both "
        "fail: moved, recomputed, holds the fired-rule list and not the verdict",
        resolves=store(two_fails),
    )
    m.accept(
        "w3c-f-25", "W3C-R-025", report([PASS, demonstrated], [evidence("e-1")]),
        "the same assertion citing an object whose observations pass and fail, so the "
        "verdict is in moved",
    )
    m.accept(
        "w3c-f-25", "W3C-R-025", rules_only,
        "the rejected report read by a reader that cannot resolve either reference: "
        "unchecked, so the row reading moved degrades and does not fire",
        resolves={},
    )
    undigested = evidence("e-1")
    del undigested["observations"][1]["reference"]["sha256"]
    carried = evidence("e-1")
    carried["observations"] = [
        {"carried": {"vector": "obs-pass", "verdict": "pass", "rules": []}},
        {"carried": {"vector": "obs-fail", "verdict": "fail", "rules": ["R-1"]}},
    ]
    m.pair(
        "w3c-f-26", "W3C-R-026",
        report([PASS, demonstrated], [undigested]), report([PASS, demonstrated], [carried]),
        "moved asserted while one observation is referenced with no digest: decidable from the "
        "object alone, before any reader resolves anything",
        "both observations carried, so moved recomputes from what the object holds",
    )
    declared_arity = evidence("e-1")
    declared_arity["delta"]["arity"] = 1
    two_fields = evidence("e-1")
    two_fields["delta"]["changes"].append({"field": "artifact/other", "before": "a", "after": "b"})
    m.pair(
        "w3c-f-27", "W3C-R-027",
        report([PASS, demonstrated], [declared_arity]),
        report([PASS, demonstrated], [two_fields]),
        "a delta declaring its arity: forgeable the same way a declared moved is",
        "a delta listing two changes and declaring nothing: arity recomputes as two, and no "
        "row reads it while what counts as one field is open",
    )
    restated = evidence("e-1")
    restated["fixed"]["domain"] = dict(DOMAIN)
    m.pair(
        "w3c-f-28", "W3C-R-028",
        report([PASS, demonstrated], [restated]),
        report([PASS, demonstrated], [evidence("e-1")]),
        "the fixed slot restating the domain as an object instead of naming the run's by "
        "identifier",
        "the fixed slot naming the run's domain by identifier, declared once at run level",
    )


def build_gaps(m: Members) -> None:
    """The two gaps the editor recorded about the reference emitter, as closed."""
    harness_void = check(
        "vector-x", "void",
        {"code": w3creport.VOID_CAUSE,
         "detail": "rail invocation: exit 2: the verifier could not be started"},
    )
    m.add(kind="accept", family="w3c-f-gaps", requirements=["W3C-R-001", "W3C-R-002"],
          subject=report([PASS, harness_void]),
          cites="the emitter's void slot populated by a rail that did not run, "
                "with the exit as cause")
    excluded = check(
        "acs-revoked-mandate", "not-exercised",
        {"code": "precondition-unsatisfiable",
         "detail": "the specification carries no revocation mechanism at the pinned commit"},
        {"declared-exclusion": True},
    )
    m.add(kind="accept", family="w3c-f-gaps", requirements=["W3C-R-001", "W3C-R-005"],
          subject=report([PASS, excluded]),
          cites="a declared exclusion read from a manifest's unmeasurableBecause, reported "
                "not-exercised with that reason as cause")


def pair_object(origin: dict[str, Any], pair: dict[str, Any]) -> dict[str, Any]:
    """The evidence object for one delta-related pair, referencing both observations."""
    version = pair["version"]
    checker = f"{origin['checker']}@{origin['commit'][:7]}"
    observations = []
    for side in ("pass", "fail"):
        ident = f"{version}/{pair[side]}"
        observations.append({"reference": {
            "repository": origin["repository"], "commit": origin["commit"], "vector": ident,
            "sha256": origin["records"][ident]["sha256"],
        }})
    return {
        "id": "e-pair",
        "changed": "input artifact",
        "fixed": {
            "checker": checker, "constraint-set": f"residue/{version}",
            "domain": DISENSOR_DOMAIN["id"],
        },
        "compared": list(DECLARED),
        "moved": list(DECLARED),
        "delta": {"changes": [
            {"field": pair["field"], "before": pair["before"], "after": pair["after"]},
        ]},
        "observations": observations,
    }


def pair_store(origin: dict[str, Any], pair: dict[str, Any]) -> dict[str, Any]:
    """What the pinned checker at the named commit resolves the two references to."""
    resolved = {}
    for side in ("pass", "fail"):
        ident = f"{pair['version']}/{pair[side]}"
        record = origin["records"][ident]
        resolved[ident] = {
            "sha256": record["sha256"], "verdict": record["verdict"], "rules": record["rules"],
        }
    return resolved


def build_disensor(m: Members) -> None:
    """The 42 pairs, each as it was emitted and as v0.1 re-cuts it."""
    origin = json.loads(read(ORIGIN_FILE))
    for pair in origin["pairs"]:
        version = pair["version"]
        pass_id, fail_id = f"{version}/{pair['pass']}", f"{version}/{pair['fail']}"
        obj = pair_object(origin, pair)
        checks = [
            check(pass_id, "pass"),
            with_slots(check(fail_id, "fail"),
                       other_verdict=qualifier("demonstrated", "e-pair"),
                       discrimination=qualifier("demonstrated", "e-pair")),
        ]
        as_emitted = dict(obj, moved=list(WITH_ERRORS))
        provenance = {
            "repository": origin["repository"], "commit": origin["commit"],
            "author": AUTHORS["0043"],
            "pair": {"pass": pass_id, "fail": fail_id, "field": pair["field"]},
        }
        resolves = pair_store(origin, pair)
        m.add(
            kind="reject", family="w3c-f-disensor", requirements=["W3C-R-016"],
            subject=report(checks, [as_emitted], domain=DISENSOR_DOMAIN), resolves=resolves,
            cites="the pair as emitted on 2026-09-16: moved names the error list the checker "
                  "produced, which the compared vocabulary does not hold, so the object is "
                  "rejected under the declared-slot rule",
            origin=dict(provenance, cause="moved asserts the recompute-opaque error list "
                                          "outside the declared compared set"),
        )
        m.add(
            kind="accept", family="w3c-f-disensor", requirements=["W3C-R-016"],
            subject=report(checks, [obj], domain=DISENSOR_DOMAIN), resolves=resolves,
            cites="the same pair re-cut against v0.1: moved recomputed over the declared slots, "
                  "the verdict in it, both observations referenced by commit, vector and digest",
            origin=dict(provenance, cause="none: moved is contained in the declared set and "
                                          "the verdict moved"),
        )


# --------------------------------------------------------------------------
# The Run object of draft-arsentev-agent-run-metrics-00.
# --------------------------------------------------------------------------

T0 = "2026-09-18T10:00:00.000Z"
T1 = "2026-09-18T10:00:30.000Z"
T2 = "2026-09-18T10:01:00.000Z"
USAGE = {
    "input_tokens": 100, "output_tokens": 30, "cache_read_tokens": 20, "cache_write_tokens": 10,
    "reasoning_tokens": 5, "cache_writes": [{"lifetime": "PT5M", "tokens": 10}],
}
TOTALS = {
    "input_tokens": 100, "output_tokens": 30, "cache_read_tokens": 20, "cache_write_tokens": 10,
    "reasoning_tokens": 5,
}


def run(**changes: Any) -> dict[str, Any]:
    """A conformant Run object, with top-level members replaced by ``changes``."""
    base: dict[str, Any] = {
        "version": "1",
        "run_id": "run-1",
        "start": T0,
        "end": T2,
        "status": "completed",
        "step_count": 2,
        "totals": copy.deepcopy(TOTALS),
        "steps": [
            {"index": 0, "kind": "model_invocation", "start": T0, "end": T1,
             "usage": copy.deepcopy(USAGE), "model": {"id": "model-a"}, "invocation_id": "inv-1"},
            {"index": 1, "kind": "tool_call", "start": T1, "end": T2,
             "tool": {"name": "search", "outcome": "ok"}},
        ],
    }
    for key, value in changes.items():
        if value is None:
            base.pop(key, None)
        else:
            base[key] = value
    return base


def run_with_usage(**usage_changes: Any) -> dict[str, Any]:
    """A Run whose first step's Usage and whose totals both carry ``usage_changes``."""
    document = run()
    for target in (document["steps"][0]["usage"], document["totals"]):
        for key, value in usage_changes.items():
            if value is None:
                target.pop(key, None)
            else:
                target[key] = value
    return document


def build_run_metrics(m: Members) -> None:
    arm = "agent-run-metrics"
    m.typed_pair(arm, "arm-f-run", "ARM-R-001", run(version="2"), run(),
                 'a version other than "1"', 'the version this specification assigns, "1"')
    m.typed_pair(arm, "arm-f-run", "ARM-R-002", run(end=None), run(status="running", end=None),
                 "a completed Run with no end", "a running Run, which carries no end")
    m.typed_pair(arm, "arm-f-run", "ARM-R-003", run(end="2026-09-18T09:00:00.000Z"), run(),
                 "an end earlier than the start", "an end after the start")
    m.typed_pair(arm, "arm-f-run", "ARM-R-004", run(status="done"), run(status="failed"),
                 "a status outside the closed enumeration", "one of the four listed values")
    m.typed_pair(arm, "arm-f-run", "ARM-R-005", run(step_count=1), run(step_count=3),
                 "a step count smaller than the steps array",
                 "a step count larger than the array, which accounts for omitted Steps")
    m.typed_pair(arm, "arm-f-run", "ARM-R-016",
                 run(root_run_id="run-0"), run(root_run_id="run-1"),
                 "a root run identifier that is not the Run's own, with no parent",
                 "a parentless Run naming itself as root")
    unordered = run()
    unordered["steps"][0]["index"], unordered["steps"][1]["index"] = 1, 0
    m.typed_pair(arm, "arm-f-steps", "ARM-R-006", unordered, run(),
                 "index values not assigned in the order the Steps began",
                 "indexes unique and in start order")
    no_model = run()
    del no_model["steps"][0]["model"]
    m.typed_pair(arm, "arm-f-steps", "ARM-R-007", no_model, run(),
                 "a model invocation with no model member",
                 "a model invocation carrying usage and model")
    no_tool = run()
    del no_tool["steps"][1]["tool"]
    m.typed_pair(arm, "arm-f-steps", "ARM-R-008", no_tool, run(),
                 "a tool call with no tool member", "a tool call carrying its tool and no usage")
    repeated = run(step_count=3)
    repeated["steps"].append({
        "index": 2, "kind": "model_invocation", "start": T2, "invocation_id": "inv-1",
        "usage": {"input_tokens": 0, "output_tokens": 0}, "model": {"id": "model-a"},
    })
    distinct = copy.deepcopy(repeated)
    distinct["steps"][2]["invocation_id"] = "inv-2"
    m.typed_pair(arm, "arm-f-steps", "ARM-R-015", repeated, distinct,
                 "two Steps of one Run with the same invocation identifier",
                 "each invocation identified once")
    m.typed_pair(arm, "arm-f-usage", "ARM-R-009",
                 run_with_usage(output_tokens=-1),
                 run_with_usage(output_tokens=0, reasoning_tokens=0),
                 "a negative counter", "a zero counter, which is a non-negative integer")
    m.typed_pair(arm, "arm-f-usage", "ARM-R-010",
                 run_with_usage(cache_read_tokens=101, cache_write_tokens=0, cache_writes=None),
                 run_with_usage(cache_read_tokens=100, cache_write_tokens=0, cache_writes=None),
                 "cached reads exceeding the input tokens they are a subset of",
                 "cached reads equal to the input tokens")
    m.typed_pair(arm, "arm-f-usage", "ARM-R-011",
                 run_with_usage(cache_read_tokens=60, cache_write_tokens=50, cache_writes=None),
                 run_with_usage(cache_read_tokens=60, cache_write_tokens=40, cache_writes=None),
                 "reads and writes that together exceed the input they partition",
                 "reads and writes summing to the input")
    duplicated = run_with_usage(cache_writes=[{"lifetime": "PT5M", "tokens": 5},
                                               {"lifetime": "PT5M", "tokens": 5}])
    two_lifetimes = run_with_usage(cache_writes=[{"lifetime": "PT5M", "tokens": 5},
                                                  {"lifetime": "PT1H", "tokens": 5}])
    m.typed_pair(arm, "arm-f-usage", "ARM-R-013", duplicated, two_lifetimes,
                 "one lifetime value in two elements of the ledger",
                 "each lifetime once, summing to the aggregate")
    m.typed_pair(arm, "arm-f-usage", "ARM-R-014",
                 run_with_usage(cache_writes=[{"lifetime": "PT5M", "tokens": 8}]),
                 run_with_usage(cache_writes=None),
                 "a ledger that does not sum to the aggregate counter",
                 "the ledger omitted where the source does not reconcile")
    m.typed_pair(arm, "arm-f-usage", "ARM-R-022",
                 run_with_usage(reasoning_tokens=40), run_with_usage(reasoning_tokens=30),
                 "reasoning tokens exceeding the output they are a subset of",
                 "reasoning tokens equal to the output")
    m.typed_pair(arm, "arm-f-totals", "ARM-R-012",
                 run(totals=dict(TOTALS, input_tokens=999)), run(),
                 "totals that are not the sum of the Steps' usage",
                 "totals recomputed member by member from every Step")
    m.typed_pair(arm, "arm-f-serialization", "ARM-R-017",
                 run(cost={"currency": "USD", "amount": "1,5", "basis": "metered"}),
                 run(cost={"currency": "USD", "amount": "1.5", "basis": "metered"}),
                 "an amount that does not match the decimal rule",
                 "an amount as a decimal string")
    m.typed_pair(arm, "arm-f-serialization", "ARM-R-018",
                 run(labels={"env": 1}), run(labels={"env": "prod"}),
                 "a label whose value is not a string", "labels with string values")
    m.typed_pair(arm, "arm-f-serialization", "ARM-R-019",
                 run(start="2026-09-18T12:00:00+02:00", end="2026-09-18T12:01:00+02:00"), run(),
                 "timestamps carrying a local offset", "timestamps in the Z offset")
    m.typed_pair(arm, "arm-f-serialization", "ARM-R-020", run(run_id=""), run(run_id="r" * 128),
                 "an empty run identifier", "an identifier of exactly the longest permitted length")
    m.typed_pair(arm, "arm-f-serialization", "ARM-R-021",
                 run(vendor_note="a member this specification does not define"),
                 run(**{"x-example.invalid-note": "a prefixed extension member"}),
                 "an unprefixed member the specification does not define",
                 "the same member under the extension prefix")


# --------------------------------------------------------------------------
# The discovery snapshot of draft-arsentev-llm-context-discovery-00.
# --------------------------------------------------------------------------

ORIGIN = "https://example.invalid"
INDEX = ORIGIN + "/llms.txt"
DETAIL = ORIGIN + "/llms-full.txt"
WK = ORIGIN + "/.well-known/llm-context"
PRIVATE = ORIGIN + "/private/llms.txt"
LINKED = ORIGIN + "/context/index.txt"
FOREIGN = "https://other.invalid/llms.txt"
RESOURCES = {
    INDEX: {"role": "index", "octets": 4000},
    DETAIL: {"role": "detail", "octets": 90000},
    WK: {"role": "index", "octets": 4000},
    PRIVATE: {"role": "index", "octets": 4000},
    LINKED: {"role": "index", "octets": 4000},
    FOREIGN: {"role": "index", "octets": 4000},
}


def snapshot(
    well_known: dict[str, Any] | None = None,
    link: dict[str, Any] | None = None,
    records: list[dict[str, Any]] | None = None,
    resolved: str | None = INDEX,
    retrieved: list[str] | None = None,
    attributed: str = ORIGIN,
    ceiling: int | None = 1000000,
) -> dict[str, Any]:
    if well_known is None:
        well_known = {"status": 307, "content-type": None, "location": INDEX}
    if records is None:
        records = [{"name": "LLM-Context", "value": INDEX}]
    consumer: dict[str, Any] = {
        "resolved": resolved,
        "retrieved": [resolved] if retrieved is None and resolved else retrieved or [],
        "attributed-to": attributed,
    }
    if ceiling is not None:
        consumer["ceiling-octets"] = ceiling
    return {
        "origin": ORIGIN,
        "resources": copy.deepcopy(RESOURCES),
        "well-known": well_known,
        "link": link,
        "robots": {"disallow": ["/private/"], "records": records},
        "consumer": consumer,
    }


def served(content_type: str, **extra: Any) -> dict[str, Any]:
    return {"status": 200, "content-type": content_type, "location": None, **extra}


def build_context_discovery(m: Members) -> None:
    lcd = "llm-context-discovery"
    pub, con = "lcd-f-publisher", "lcd-f-consumer"
    m.typed_pair(lcd, pub, "LCD-R-001",
                 snapshot(served("text/html; charset=utf-8"), resolved=WK),
                 snapshot(served("text/markdown;charset=UTF-8"), resolved=WK),
                 "the well-known resource served as HTML",
                 "the well-known resource served as Markdown")
    m.typed_pair(lcd, pub, "LCD-R-002",
                 snapshot({"status": 307, "content-type": None, "location": DETAIL},
                          resolved=DETAIL),
                 snapshot(),
                 "a mechanism pointing at a detail resource",
                 "every mechanism pointing at the index")
    m.typed_pair(lcd, pub, "LCD-R-003",
                 snapshot({"status": 500, "content-type": None, "location": None}),
                 snapshot({"status": 404, "content-type": None, "location": None}),
                 "a well-known request answered with neither the index nor a redirect",
                 "a 404, which advertises nothing by this mechanism and is not an error")
    m.typed_pair(lcd, pub, "LCD-R-004",
                 snapshot(records=[{"name": "LLM-Context", "value": "/llms.txt"}]),
                 snapshot(records=[{"name": "llm-context", "value": INDEX}]),
                 "a robots record whose value is a relative reference",
                 "a robots record with an absolute URI, the name compared case-insensitively")
    m.typed_pair(lcd, pub, "LCD-R-005",
                 snapshot(records=[{"name": "LLM-Context", "value": PRIVATE}]),
                 snapshot(),
                 "a robots record advertising a file the same robots.txt disallows",
                 "a robots record advertising a file its exclusion rules allow")
    m.typed_pair(lcd, pub, "LCD-R-010",
                 snapshot(served("text/markdown;charset=UTF-8", negotiated=True), resolved=WK),
                 snapshot(served("text/markdown;charset=UTF-8", negotiated=True,
                                 **{"content-language": "en"}), resolved=WK),
                 "a negotiated response with no Content-Language",
                 "a negotiated response naming its language")
    m.typed_pair(lcd, con, "LCD-R-006",
                 snapshot(link={"target": LINKED}, resolved=INDEX),
                 snapshot(link={"target": LINKED}, resolved=LINKED),
                 "the well-known target taken while a Link relation was in hand",
                 "the Link relation taken first, as the precedence lists it")
    m.typed_pair(lcd, con, "LCD-R-007",
                 snapshot(retrieved=[INDEX, LINKED]), snapshot(retrieved=[INDEX, DETAIL]),
                 "two index resources retrieved from one origin in one cycle",
                 "one index retrieved, plus a detail resource it links to")
    m.typed_pair(lcd, con, "LCD-R-008",
                 snapshot({"status": 307, "content-type": None, "location": FOREIGN},
                          resolved=FOREIGN),
                 snapshot({"status": 307, "content-type": None, "location": FOREIGN},
                          resolved=FOREIGN, attributed="https://other.invalid"),
                 "a cross-origin index attributed to the advertising origin",
                 "the cross-origin index attributed to the origin that serves it")
    m.typed_pair(lcd, con, "LCD-R-009", snapshot(ceiling=0), snapshot(ceiling=100000),
                 "a consumer with no ceiling on what it will retrieve",
                 "a consumer that bounds a retrieval")
    m.typed_pair(lcd, con, "LCD-R-011",
                 snapshot(link={"target": PRIVATE}, resolved=PRIVATE),
                 snapshot(link={"target": PRIVATE}, resolved=PRIVATE, retrieved=[]),
                 "an advertised index retrieved without evaluating the exclusion that covers it",
                 "the same advertisement left unretrieved because the exclusion covers it")


def build() -> list[dict[str, Any]]:
    m = Members()
    build_rows_1_to_7(m)
    build_rows_8_to_12(m)
    build_roll_up(m)
    build_control_binding(m)
    build_set_binding(m)
    build_rules(m)
    build_people_rules(m)
    build_proposed_rows(m)
    build_gaps(m)
    build_disensor(m)
    build_run_metrics(m)
    build_context_discovery(m)
    return m.items


# --------------------------------------------------------------------------
# The mutation sweep: relax each row in turn; only the members naming it flip.
# --------------------------------------------------------------------------


def judged_ok(member: dict[str, Any], relax: frozenset[str]) -> bool:
    observed = w3creport.subject_rejections(
        member["subjectType"], member["subject"], relax, member.get("resolves")
    )
    return observed == sorted(member["expected"]["rejects"])


def resolved_read(members: list[dict[str, Any]], row: str) -> bool | None:
    """Whether a row reads a resolved observation, measured rather than asserted.

    A row's reject members are re-judged by a reader that resolves nothing. A row
    is measured as reading a resolved slot when any member of it stops firing
    (the reference-mismatch row fires from the report's own check set and from a
    resolved observation, and reads a resolved slot); a row whose members all
    still fire reads declared slots only. None where the row has no report
    member.
    """
    naming = [
        x for x in members
        if x["expected"]["rejects"] == [row] and x["subjectType"] == "report"
    ]
    if not naming:
        return None
    return not all(
        row in w3creport.rejections(x["subject"], frozenset(), {}) for x in naming
    )


def mutation_sweep(members: list[dict[str, Any]], rows: list[str]) -> list[dict[str, Any]]:
    table = []
    for row in rows:
        naming = [x for x in members if x["expected"]["rejects"] == [row]]
        relax = frozenset([row])
        flipped_naming = sum(1 for x in naming if not judged_ok(x, relax))
        others = [x for x in members if x["expected"]["rejects"] != [row]]
        flipped_others = sum(1 for x in others if not judged_ok(x, relax))
        table.append({
            "row": row, "naming": len(naming), "flipped": flipped_naming,
            "flippedElsewhere": flipped_others,
            "verdict": "isolated" if flipped_naming == len(naming) and not flipped_others
            else "LEAK",
        })
    return table


def render_sweep(table: list[dict[str, Any]], total: int) -> str:
    rows = "\n".join(
        "| `{row}` | {naming} | {flipped} | {flippedElsewhere} | {verdict} |".format(**entry)
        for entry in table
    )
    leaks = sum(1 for entry in table if entry["verdict"] == "LEAK")
    return f"""# Mutation sweep

Relax each row in turn and replay the whole corpus against the validator with
that row switched off. A member FLIPS when its judgement changes: a reject
member that stops being rejected, or an accept member that starts being. The
claim the table makes is the one a rejection corpus owes and nobody on the list
had measured: relaxing a row flips every member that names it and no member
that does not. A row whose members did not all flip is a row the corpus does
not force; a row that flipped a member elsewhere is a member carrying a second
fault under the name of a first.

Emitted by `gen_vectors.py` on every regeneration, over every member of the
corpus and every row of its manifest. Rows that leak: {leaks}.

| row | members naming it | flipped | flipped elsewhere | verdict |
|---|---|---|---|---|
{rows}
"""


# --------------------------------------------------------------------------


def render_index(manifest: dict[str, Any]) -> str:
    rows = "\n".join(
        "| `{id}` | {kind} | {subject} | {family} | {reqs} | {rejects} |".format(
            id=entry["id"], kind=entry["kind"], subject=entry["subjectType"],
            family=entry["family"], reqs=", ".join(entry["requirements"]),
            rejects=", ".join(entry["expected"]["rejects"]) or "none",
        )
        for entry in manifest["vectors"]
    )
    requirements = "\n".join(
        "| `{id}` | {row} | {cls} | {status} | `{file}` | `{digest}` | {sentence} |".format(
            id=row["id"], row=row["row"], file=row["vendored"],
            cls=row.get("class", "-"), status=row.get("status", "-"),
            digest=row["sentenceDigest"][:16],
            sentence=row["sentence"].replace("\n", " ").replace("|", "\\|"),
        )
        for row in manifest["requirements"]
    )
    families = "\n".join(f"| `{key}` | {value} |" for key, value in manifest["families"].items())
    vendored = "\n".join(
        f"| `{key}` | {pin['author']} | `{pin['path']}` | `{pin['sha256'][:16]}` | "
        f"{pin['source']} |"
        for key, pin in manifest["specVendored"].items()
    )
    accept, reject = manifest["counts"]["accept"], manifest["counts"]["reject"]
    total = len(manifest["vectors"])
    origin = manifest["origin"]
    by_subject = {
        kind: sum(1 for e in manifest["vectors"] if e["subjectType"] == kind)
        for kind in w3creport.SUBJECT_TYPES
    }
    messages = sum(1 for key in manifest["specVendored"] if not key.startswith("draft-"))
    texts = len(manifest["specVendored"])
    return f"""# Conformance vectors (v0.1 per-check report)

Every member of this suite in one table, rejected and accepted alike. Ground
truth: {texts} texts vendored in `spec-vendored/` and pinned by sha256 in
`MANIFEST.json`: {messages} messages of the W3C public-agent-conformance list that
together fix what v0.1 of the reporting format freezes, and the two
Internet-Drafts the format's editor holds.

This corpus is {total} vectors, of which {accept} a conformant verifier must not fail closed
on and {reject} it must reject.

**Three subject types, one manifest.** {by_subject["report"]} members are whole
v0.1 reports, judged by the rows of the format; {by_subject["agent-run-metrics"]}
are Run objects of the agent-run-metrics draft; {by_subject["llm-context-discovery"]}
are discovery snapshots of the context-discovery draft. Each member names its
subject type and the reader selects the validator by it.

**A report member is a whole report**, not one record, because two of the rules
v0.1 carries are properties of the report: whether its roll-up says its checks
could have gone negative, and whether the digest over its check set binds the
leaf count and names the tree shape. A record-level corpus could not express
either.

**Every reject member names exactly one row.** The generator runs the validator
over each member before writing it and refuses a reject that fires two rows or
an accept that fires one, so a member here demonstrates which requirement is
live rather than the fact of rejection. `MUTATION-SWEEP.md`, regenerated with
the vectors, relaxes each row in turn and records that only the members naming
it flip.

**Identifiers are minted here and bound to a sentence.** The texts carry no
requirement identifiers, so each row below quotes its sentence, the generator
locates it in the vendored copy and hashes it, and a reword stops the build.

**The {2 * origin["pairs"]} members of family `w3c-f-disensor`** are re-cut from the
{origin["pairs"]} delta-related pairs {origin["author"]} counted in his own corpus at
`{origin["repository"]}@{origin["commit"][:7]}`: each pair appears once as
emitted before the freeze, rejected under the declared-slot rule with its cause,
and once re-cut against v0.1, accepted. `origin/derive_pairs.py` derives the
pairs from that repository and `origin/disensor-1e36257-pairs.json` is what it
wrote.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-w3c-report/` from the repository root, or
`python3 packaging/run_vectors.py --corpus vectors-w3c-report`; the two print
the same lines.

## Vendored text

| key | author | path | sha256 | source |
|---|---|---|---|---|
{vendored}

## Requirements

The class column is the handover's sort of the rows: consistency rows read
declared slots against each other, evidence rows read a declared slot against
a recomputed or resolved one, form rows are decidable from the object alone.
The status column says whether the list agreed the row or this corpus proposes
it (the numbering of rows 13 and 14, and the class of rows 4, 10, 11, 12 and
13, which the handover left unclassified).

| id | row | class | status | vendored in | sentence digest | normative sentence |
|---|---|---|---|---|---|---|
{requirements}

## Families

| id | what the family is |
|---|---|
{families}

## Vectors

| id | kind | subject | family | requirements | rejected under |
|---|---|---|---|---|---|
{rows}
"""


def member_document(vid: str, member: dict[str, Any]) -> dict[str, Any]:
    document = {
        "id": vid, "suite": SUITE, "specVersion": SPEC_VERSION, "family": member["family"],
        "requirements": member["requirements"], "kind": member["kind"],
        "subjectType": member["subjectType"], "expected": member["expected"],
        "subject": member["subject"],
    }
    if "resolves" in member:
        document["resolves"] = member["resolves"]
    if "origin" in member:
        document["origin"] = member["origin"]
    return document


def manifest_entry(vid: str, rel: str, member: dict[str, Any]) -> dict[str, Any]:
    entry = {
        "id": vid, "kind": member["kind"], "file": rel, "family": member["family"],
        "requirements": member["requirements"], "specVersion": SPEC_VERSION,
        "subjectType": member["subjectType"], "expected": member["expected"],
        "cites": member["cites"],
    }
    if "origin" in member:
        entry["origin"] = member["origin"]
    return entry


def self_check(vid: str, member: dict[str, Any], known: set[str]) -> None:
    """Refuse a member the validator does not answer exactly as the member claims."""
    if missing := [r for r in member["requirements"] if r not in known]:
        raise SystemExit(f"FAIL: {vid} cites requirements that do not exist: {missing}")
    if shape := w3creport.subject_shape_errors(member["subjectType"], member["subject"]):
        raise SystemExit(f"FAIL: {vid} is not the shape of its subject: {shape}")
    observed = w3creport.subject_rejections(
        member["subjectType"], member["subject"], resolves=member.get("resolves")
    )
    if observed != sorted(member["expected"]["rejects"]):
        raise SystemExit(
            f"FAIL: {vid} ({member['family']}, {member['cites'][:60]}) expects "
            f"{member['expected']['rejects']} and the validator rejects under {observed}"
        )


def build_requirements(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in REQUIREMENTS:
        line, digest = locate(row)
        entry: dict[str, Any] = {
            "id": row["id"], "row": row["row"], "file": row["file"],
            "vendored": VENDORED[row["file"]], "line": line, "sentence": row["sentence"],
            "sentenceDigest": digest, "specVersion": SPEC_VERSION,
        }
        if row["id"].startswith("W3C-R-"):
            entry["class"] = row["class"]
            entry["status"] = row["status"]
            measured = resolved_read(members, row["id"])
            if measured is not None:
                entry["resolvedRead"] = measured
                if measured and row["class"] != EVIDENCE:
                    raise SystemExit(f"FAIL: {row['id']} reads a resolved slot and is classed "
                                     f"{row['class']}")
                if not measured and row["class"] == EVIDENCE and row["id"] in RESOLVED_CLASS:
                    raise SystemExit(f"FAIL: {row['id']} is classed evidence and fires with "
                                     "nothing resolved")
        out.append(entry)
    return out


#: The evidence rows whose recomputed slot is a resolved observation, so the
#: measurement above must agree with the class; the other evidence rows
#: recompute from the report's own records (counts, roots, populations).
RESOLVED_CLASS = frozenset({"W3C-R-020", "W3C-R-021", "W3C-R-025"})


def build_manifest() -> tuple[dict[str, Any], dict[str, bytes]]:
    members = build()
    requirements = build_requirements(members)
    known = {row["id"] for row in requirements}
    origin = json.loads(read(ORIGIN_FILE))
    origin["author"] = AUTHORS["0043"]
    seen: set[str] = set()
    files: dict[str, bytes] = {}
    entries = []
    for member in members:
        vid = w3creport.identify(member)
        if vid in seen:
            raise SystemExit(f"FAIL: duplicate identifier {vid}")
        seen.add(vid)
        self_check(vid, member, known)
        rel = f"vectors/{vid}.json"
        document = member_document(vid, member)
        files[rel] = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        entries.append(manifest_entry(vid, rel, member))
    entries.sort(key=lambda entry: entry["id"])
    counts = {kind: sum(1 for e in entries if e["kind"] == kind) for kind in ("accept", "reject")}
    sweep = mutation_sweep(members, [row["id"] for row in requirements])
    if any(entry["verdict"] == "LEAK" for entry in sweep):
        leaks = [entry["row"] for entry in sweep if entry["verdict"] == "LEAK"]
        raise SystemExit(
            f"FAIL: the mutation sweep found rows the corpus does not isolate: {leaks}"
        )
    manifest = {
        "suite": SUITE,
        "specName": "W3C public-agent-conformance reporting format, per-check record",
        "specVersion": SPEC_VERSION,
        "specAuthority": "specDigest",
        "subjectTypes": list(w3creport.SUBJECT_TYPES),
        "specVendored": {
            key: {"path": rel, "sha256": sha(read(rel)), "author": AUTHORS[key],
                  "source": source_url(key)}
            for key, rel in VENDORED.items()
        },
        "identifierPolicy": (
            "A requirement identifier is minted by this corpus and bound to the normative "
            "sentence by sha256 over its bytes. The texts this corpus cites carry no "
            "identifiers, and a message number or a section number names a position rather "
            "than a sentence."
        ),
        "codeRegistry": {
            "state": list(w3creport.STATES),
            "cause": list(w3creport.CAUSES),
            "other-verdict": list(w3creport.OTHER_VERDICT),
            "discrimination": list(w3creport.DISCRIMINATION),
            "negative-capable": list(w3creport.NEGATIVE_CAPABLE),
            "tree-shape": list(w3creport.TREE_SHAPES),
            "changed": list(w3creport.CHANGED),
            "slot": list(w3creport.SLOTS),
            "claim": list(w3creport.CLAIMS),
            "run-status": list(runmetrics.STATUSES),
            "step-kind": list(runmetrics.STEP_KINDS),
            "redirect-status": list(contextdiscovery.REDIRECTS),
        },
        "families": FAMILIES,
        "origin": {
            "repository": origin["repository"], "commit": origin["commit"],
            "author": AUTHORS["0043"], "checker": origin["checker"],
            "pairingRule": origin["pairingRule"], "pairs": len(origin["pairs"]),
            "derivedBy": "origin/derive_pairs.py", "data": ORIGIN_FILE,
            "reproducibleBy": "tools/emitir-42.py in the same repository, published 2026-09-18",
            "note": (
                "The twelve rejection rows and the record definition are the author's, "
                "consolidated on the list on 2026-09-15 and handed over on 2026-09-18. The "
                "pairs were counted at this commit as 42 (v0.2 4, v0.3 16, v0.4 22); the "
                "objects are re-emitted here from the same bytes under the recipe the handover "
                "fixes: each observation referenced by commit, vector and digest, the "
                "outcome resolved through the member's store and never declared in the "
                "reference, moved recomputed from the two, the domain declared once."
            ),
        },
        "mutationSweep": {"file": "MUTATION-SWEEP.md", "rows": len(sweep), "leaks": 0},
        "observedRuns": [],
        "requirements": requirements,
        "counts": counts,
        "corpusDigest": sha(b"".join(files[entry["file"]] for entry in entries)),
        "note": (
            "A member is a whole subject: a v0.1 report, a Run object, or a discovery "
            "snapshot. Each reject member is rejected under exactly one requirement and has "
            "an accepting twin in its family, so a validator that refuses every subject scores "
            "zero rather than full marks."
        ),
        "vectors": entries,
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2).encode("utf-8") + b"\n"
    files["INDEX.md"] = render_index(manifest).encode("utf-8")
    files["MUTATION-SWEEP.md"] = render_sweep(sweep, len(members)).encode("utf-8")
    return manifest, files


def verify_tree(files: dict[str, bytes]) -> int:
    bad = []
    for rel, payload in sorted(files.items()):
        path = os.path.join(HERE, rel)
        if not os.path.exists(path):
            bad.append(f"{rel} is missing")
            continue
        with open(path, "rb") as handle:
            if handle.read() != payload:
                bad.append(f"{rel} differs from what the generator emits")
    root = os.path.join(HERE, "vectors")
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            if f"vectors/{name}" not in files:
                bad.append(f"vectors/{name} is on disk and the generator emits no such file")
    if bad:
        for line in bad:
            print("FAIL", line, file=sys.stderr)
        print("\nRun `python3 gen_vectors.py` to rebuild, and commit the diff.", file=sys.stderr)
        return 1
    print(f"OK generator reproduces {len(files)} file(s) byte-identically")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a tree this does not emit")
    check_only = parser.parse_args().check
    manifest, files = build_manifest()
    if check_only:
        return verify_tree(files)
    os.makedirs(os.path.join(HERE, "vectors"), exist_ok=True)
    for name in sorted(os.listdir(os.path.join(HERE, "vectors"))):
        if f"vectors/{name}" not in files:
            os.unlink(os.path.join(HERE, "vectors", name))
    for rel, payload in sorted(files.items()):
        with open(os.path.join(HERE, rel), "wb") as handle:
            handle.write(payload)
    counts = manifest["counts"]
    print(
        f"wrote {len(files)} file(s): {counts['accept']} accept, {counts['reject']} reject, "
        f"{len(manifest['requirements'])} requirements, corpus {manifest['corpusDigest'][:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
