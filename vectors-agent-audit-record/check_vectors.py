#!/usr/bin/env python3
"""Does the committed corpus behave as MANIFEST.json claims, and is every rule
in the reference reader load-bearing?

    uv run --extra generators python vectors-agent-audit-record/check_vectors.py

Three checks, each able to fail on its own.

1. The corpus judge: the packaged reader (agent_evidence_vectors.auditrecord,
   the one ``uvx agent-evidence-vectors --corpus vectors-agent-audit-record``
   runs) reaches every member's declared verdict and first refusal, and the
   counts, parents and corpus digest hold.
2. A second signature path: every member the manifest says must not be refused
   carries a signature that verifies under the ``cryptography`` library over
   the RFC 8785 bytes this directory's own canonicalizer derives, and T2 does
   not. The reader borrows the rail's Ed25519, so without this check one
   Ed25519 implementation would be grading itself.
3. The mutation sweep: disabling any one rule of the reader must turn at least
   one reject member into a non-refusal, must never turn an accept member into
   a refusal, and must never move an indeterminate member to a verdict none of
   its readings lists. A rule whose removal changes no verdict measures nothing.

4. The section sweep: each weakened reading of Sections 5.4 and 5.5 below (a
   closed set cut to the one value Appendix B's accept rows carry, an optional
   member made required, a sub-check dropped) must fail the corpus on exactly
   the members that test that sentence. The rule sweep in 3 turns off a whole
   rule; this one turns off one sentence of a rule, which the rule sweep cannot
   see.

An indeterminate member (N1, N2) is scored on its readings: any verdict it lists
conforms, and it carries no expected.verdict. scripts/indeterminate-readers-test.py
deletes each listed reading in turn and requires the judge to refuse the result.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime
import json
import os
import sys
from collections.abc import Callable, Iterator
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "packaging"))

import run_vectors  # noqa: E402,F401  (the reader resolves the rail's Ed25519 through it)
from agent_evidence_vectors import auditrecord  # noqa: E402
from canonical import canonical_bytes  # noqa: E402


def _manifest() -> dict[str, object]:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        loaded: dict[str, object] = json.load(fh)
    return loaded


def _raw(entry: dict[str, object]) -> bytes:
    with open(os.path.join(HERE, str(entry["file"])), "rb") as fh:
        return fh.read()


def _second_signature_path(manifest: dict[str, object]) -> list[str]:
    keys = manifest["keys"]
    assert isinstance(keys, dict)
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys["observer"]["publicKey"]))
    out: list[str] = []
    entries = manifest["vectors"]
    assert isinstance(entries, list)
    for entry in entries:
        must_hold = entry["kind"] != "reject" or entry["draftId"] == "T2"
        if not must_hold:
            continue
        envelope = json.loads(_raw(entry))
        payload = base64.b64decode(envelope["payload"])
        canonical = canonical_bytes(json.loads(payload))
        message = auditrecord.pae(auditrecord.PAYLOAD_TYPE, canonical)
        sig = base64.b64decode(envelope["signatures"][0]["sig"])
        try:
            public.verify(sig, message)
            holds = True
        except InvalidSignature:
            holds = False
        if entry["draftId"] == "T2" and holds:
            out.append("T2: the signature verifies over the RFC 8785 bytes, so T2 tests nothing")
        elif entry["draftId"] != "T2" and not holds:
            out.append(f"{entry['draftId']}: the signature does not verify under a second library")
    return out


def _mutation_sweep(manifest: dict[str, object]) -> tuple[list[str], list[str]]:
    """Findings, and notes for rules another rule backs up.

    A rule is load-bearing when disabling it changes what at least one reject
    member is refused FOR. Where the verdict still holds because a later rule
    refuses the same member, that is printed: the Appendix B row does not isolate
    the rule, which is a property of the draft's corpus and worth knowing.
    """
    policy = auditrecord.policy_for(manifest)
    entries = manifest["vectors"]
    assert isinstance(entries, list)
    bodies = [(entry, _raw(entry), auditrecord.verify(_raw(entry), policy)) for entry in entries]
    findings: list[str] = []
    notes: list[str] = []
    swept = [n for n in auditrecord.rule_names() if n not in auditrecord.UNREACHED_BY_CORPUS]
    for name in ["signature", *swept]:
        moved, flipped = [], []
        for entry, raw, full in bodies:
            report = auditrecord.verify(raw, policy, disabled=name)
            if entry["kind"] == "accept" and report.verdict != "valid":
                findings.append(f"disabling {name} refuses accept member {entry['draftId']}")
            open_member = entry["kind"] == "indeterminate"
            if open_member and report.verdict not in auditrecord.conforming_verdicts(entry):
                findings.append(
                    f"disabling {name} moves indeterminate member {entry['draftId']} to "
                    f"{report.verdict!r}, which none of its readings lists"
                )
            if entry["kind"] != "reject":
                continue
            if report.verdict == "valid":
                flipped.append(entry["draftId"])
            elif report.codes != full.codes:
                moved.append(f"{entry['draftId']} -> {report.codes[0]}")
        if not moved and not flipped:
            findings.append(f"rule {name} is inert: disabling it changes no reject member")
        elif not flipped:
            notes.append(f"rule {name}: a later check still refuses {', '.join(moved)}")
    return findings, notes


Rule = Callable[[Any], None]


@dataclasses.dataclass(frozen=True)
class _Freshness:
    """The freshness sentences of Section 5.4 as a reader might take them."""

    reference: str = "reportedAt"
    inclusive: bool = True
    skew: datetime.timedelta | None = auditrecord.SKEW_TOLERANCE
    never_held_unavailable: bool = True
    refuse_negative: bool = True
    refuse_extra: bool = True
    refuse_repeat: bool = True

    def shape(self, entry: dict[str, Any], seen: set[str]) -> None:
        if self.refuse_extra and set(entry) - auditrecord.ENTRY_MEMBERS:
            raise auditrecord.Malformed("evaluation-entry-malformed")
        if entry["input"] not in auditrecord.EVALUATION_INPUTS:
            raise auditrecord.Malformed("value-outside-vocabulary")
        if self.refuse_negative and entry["maxAge"] < 0:
            raise auditrecord.Malformed("evaluation-entry-malformed")
        if self.refuse_repeat and entry["input"] in seen:
            raise auditrecord.Malformed("evaluation-input-repeated")
        seen.add(entry["input"])

    def unavailable(self, entry: dict[str, Any], reported_at: datetime.datetime) -> bool:
        if entry["lastResult"] == auditrecord.NEVER_HELD:
            return self.never_held_unavailable
        produced = auditrecord._instant(entry["lastResult"])
        if self.skew is not None and produced - reported_at > self.skew:
            raise auditrecord.Malformed("evaluation-result-after-decision")
        age = (reported_at - produced).total_seconds()
        return age > entry["maxAge"] or (not self.inclusive and age == entry["maxAge"])

    def derive(self, pred: dict[str, Any]) -> list[str]:
        moment = (
            pred["issuedAt"] if self.reference == "issuedAt" else pred["decision"]["reportedAt"]
        )
        reported_at = auditrecord._instant(moment)
        seen: set[str] = set()
        out: list[str] = []
        for entry in pred["evaluation"]["inputs"]:
            self.shape(entry, seen)
            if self.unavailable(entry, reported_at):
                out.append(entry["input"])
        return out


def _evaluation_reading(
    *,
    refuse_empty: bool = True,
    refuse_repeat: bool = True,
    wrap_string: bool = False,
    evaluated_by_truth: bool = False,
    evaluated_by_entries: bool = True,
    match_entries: bool = True,
    derive: Callable[[dict[str, Any]], list[str]] | None = None,
) -> Rule:
    """Section 5.4 as a reader might take it, one sentence at a time."""

    def rule(state: Any) -> None:
        evaluation = state.predicate["evaluation"]
        derived = (derive or auditrecord.derive_unavailable)(state.predicate)
        if evaluation["status"] == "evaluated":
            carried = (
                bool(evaluation.get("unavailableInput"))
                if evaluated_by_truth
                else "unavailableInput" in evaluation
            )
            if carried or (evaluated_by_entries and derived):
                raise auditrecord.Malformed("evaluation-inconsistent")
            return
        inputs = evaluation.get("unavailableInput")
        if wrap_string and isinstance(inputs, str):
            inputs = [inputs]
        if not isinstance(inputs, list) or (refuse_empty and not inputs):
            raise auditrecord.Malformed("evaluation-inconsistent")
        for value in inputs:
            if value not in auditrecord.UNAVAILABLE_INPUTS:
                raise auditrecord.Malformed("value-outside-vocabulary")
        if refuse_repeat and len(set(inputs)) != len(inputs):
            raise auditrecord.Malformed("evaluation-inconsistent")
        if match_entries and set(inputs) != set(derived):
            raise auditrecord.Malformed("evaluation-inconsistent")

    return rule


def _freshness(**knobs: Any) -> contextlib.AbstractContextManager[None]:
    return _swapped_rule("evaluation", _evaluation_reading(derive=_Freshness(**knobs).derive))


def _oversight_reading(*, act_required: bool = True, digest_required: bool = False) -> Rule:
    """Section 5.5 as a reader might take it."""

    def rule(state: Any) -> None:
        if "oversight" not in state.predicate:
            return
        oversight = state.predicate["oversight"]
        if act_required and "act" not in oversight:
            raise auditrecord.Malformed("member-missing")
        if digest_required and "recordDigest" not in oversight:
            raise auditrecord.Malformed("oversight-malformed")
        if set(oversight) - auditrecord.OVERSIGHT_MEMBERS:
            raise auditrecord.Malformed("oversight-malformed")

    return rule


@contextlib.contextmanager
def _swapped_rule(name: str, replacement: Rule) -> Iterator[None]:
    index = auditrecord.rule_names().index(name)
    original = auditrecord.RULES[index]
    auditrecord.RULES[index] = (name, replacement)
    try:
        yield
    finally:
        auditrecord.RULES[index] = original


@contextlib.contextmanager
def _narrowed_inputs(values: frozenset[str]) -> Iterator[None]:
    original = auditrecord.UNAVAILABLE_INPUTS
    auditrecord.UNAVAILABLE_INPUTS = values
    try:
        yield
    finally:
        auditrecord.UNAVAILABLE_INPUTS = original


@contextlib.contextmanager
def _narrowed_vocabulary(path: str, values: frozenset[str]) -> Iterator[None]:
    original = auditrecord.VOCABULARIES[path]
    auditrecord.VOCABULARIES[path] = values
    try:
        yield
    finally:
        auditrecord.VOCABULARIES[path] = original


#: Each weakened reading, and the members that must catch it and no others.
SECTION_READINGS: list[tuple[str, Callable[[], contextlib.AbstractContextManager[None]], str]] = [
    (
        "unavailableInput known only as standing-source",
        lambda: _narrowed_inputs(frozenset({"standing-source"})),
        "A12,A13,A14",
    ),
    (
        "oversight.act known only as check",
        lambda: _narrowed_vocabulary("oversight.act", frozenset({"check"})),
        "A15,A16,A17",
    ),
    (
        "an empty unavailableInput accepted",
        lambda: _swapped_rule("evaluation", _evaluation_reading(refuse_empty=False)),
        "EV14",
    ),
    (
        "a repeated unavailableInput accepted",
        lambda: _swapped_rule("evaluation", _evaluation_reading(refuse_repeat=False)),
        "EV6",
    ),
    (
        "a bare string read as a one-element unavailableInput",
        lambda: _swapped_rule("evaluation", _evaluation_reading(wrap_string=True)),
        "EV7",
    ),
    (
        "evaluated refusing only a non-empty unavailableInput",
        lambda: _swapped_rule("evaluation", _evaluation_reading(evaluated_by_truth=True)),
        "EV8,EV9,EV10",
    ),
    (
        "an age measured to issuedAt rather than decision.reportedAt",
        lambda: _freshness(reference="issuedAt"),
        "FR2,FR9",
    ),
    (
        "an age equal to maxAge read as stale",
        lambda: _freshness(inclusive=False),
        "FR2",
    ),
    (
        "a lastResult after decision.reportedAt accepted however late",
        lambda: _freshness(skew=None),
        "FR9",
    ),
    (
        "a lastResult after decision.reportedAt refused with no skew tolerance",
        lambda: _freshness(skew=datetime.timedelta(0)),
        "FR16",
    ),
    (
        "a lastResult of none read as fresh",
        lambda: _freshness(never_held_unavailable=False),
        "FR4",
    ),
    (
        "a negative maxAge accepted",
        lambda: _freshness(refuse_negative=False),
        "FR13b",
    ),
    (
        "an entry member the draft does not define accepted",
        lambda: _freshness(refuse_extra=False),
        "FR11",
    ),
    (
        "one input named in two entries accepted",
        lambda: _freshness(refuse_repeat=False),
        "FR10",
    ),
    (
        "unavailableInput not matched against the entries",
        lambda: _swapped_rule("evaluation", _evaluation_reading(match_entries=False)),
        "FR7",
    ),
    (
        "evaluated not checked against the entries",
        lambda: _swapped_rule("evaluation", _evaluation_reading(evaluated_by_entries=False)),
        "FR8,FR15c",
    ),
    (
        "oversight without act accepted",
        lambda: _swapped_rule("oversight", _oversight_reading(act_required=False)),
        "OV3",
    ),
    (
        "oversight.recordDigest required",
        lambda: _swapped_rule("oversight", _oversight_reading(digest_required=True)),
        "A16",
    ),
]


def _failing(manifest: dict[str, object]) -> str:
    policy = auditrecord.policy_for(manifest)
    entries = manifest["vectors"]
    assert isinstance(entries, list)
    failing = []
    for entry in entries:
        verdict = auditrecord.verify(_raw(entry), policy).verdict
        if verdict not in auditrecord.conforming_verdicts(entry):
            failing.append(str(entry["draftId"]))
    return ",".join(failing)


def _section_sweep(manifest: dict[str, object]) -> list[str]:
    findings = []
    if _failing(manifest):
        return ["the section sweep needs a clean corpus to start from"]
    for label, weaken, want in SECTION_READINGS:
        with weaken():
            got = _failing(manifest)
        if got != want:
            findings.append(f"{label}: caught by [{got}], want [{want}]")
    return findings


def main() -> int:
    judged = auditrecord.judge(HERE)
    sys.stdout.write(auditrecord.render(judged, auditrecord.SUITE))
    manifest = _manifest()
    swept, notes = _mutation_sweep(manifest)
    findings = _second_signature_path(manifest) + swept + _section_sweep(manifest)
    for note in notes:
        print(f"note: {note}")
    for finding in findings:
        print(f"FAIL check: {finding}")
    if judged.ok() and not findings:
        print(
            "check: a second Ed25519 library agrees, every rule is load-bearing, and "
            f"each of {len(SECTION_READINGS)} weakened section readings fails its own members"
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
