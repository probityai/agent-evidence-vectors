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

4. The dating sweep: disabling any one rule of the dating check of Section
   4.7.1 must move at least one retained member (R1 to R9) off its declared
   dating result, and must never move its record verdict.

6. The aggregation check: FR14 lists the two values of one input a decision
   depended on. The reference aggregation must reproduce FR14's entry, and the
   revision 00 aggregation must instead write FR15's, which the reader refuses.

5. The section sweep: each weakened reading of Sections 5.4 and 5.5 below (a
   closed set cut to the one value Appendix B's accept rows carry, an optional
   member made required, a sub-check dropped) must fail the corpus on exactly
   the members that test that sentence. The rule sweep in 3 turns off a whole
   rule; this one turns off one sentence of a rule, which the rule sweep cannot
   see.

An indeterminate member (N2) is scored on its readings: any verdict it lists
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


def _retained(entry: dict[str, object]) -> bool:
    expected = entry.get("expected")
    return isinstance(expected, dict) and "dating" in expected


def _set(entry: dict[str, object]) -> bool:
    expected = entry.get("expected")
    return isinstance(expected, dict) and "set" in expected


def _envelopes(entry: dict[str, object]) -> list[bytes]:
    """Every envelope a member carries: a set member's records, else the one."""
    if _set(entry):
        try:
            return auditrecord.set_records(_raw(entry))
        except (auditrecord.Malformed, ValueError, KeyError, TypeError):
            return []
    return [_envelope_bytes(entry)]


def _envelope_bytes(entry: dict[str, object]) -> bytes:
    """The envelope a member carries: the whole file, or a retained member's
    envelope beside its retention entry."""
    raw = _raw(entry)
    if _retained(entry):
        return json.dumps(json.loads(raw)["envelope"]).encode()
    return raw


def _verify(
    entry: dict[str, object],
    policy: auditrecord.Policy,
    disabled: str | None = None,
) -> auditrecord.Report:
    if _retained(entry):
        with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
            heads = auditrecord.tree_heads(json.load(fh))
        return auditrecord.verify_retained(_raw(entry), policy, heads, disabled=disabled)[0]
    return auditrecord.verify(_envelope_bytes(entry), policy, disabled=disabled)


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
        holds = True
        for raw_envelope in _envelopes(entry):
            envelope = json.loads(raw_envelope)
            payload = base64.b64decode(envelope["payload"])
            canonical = canonical_bytes(json.loads(payload))
            message = auditrecord.pae(auditrecord.PAYLOAD_TYPE, canonical)
            sig = base64.b64decode(envelope["signatures"][0]["sig"])
            try:
                public.verify(sig, message)
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
    bodies = [
        (entry, raw, auditrecord.verify(raw, policy))
        for entry in entries
        for raw in _envelopes(entry)
    ]
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
        extra = set(entry) - auditrecord.ENTRY_MEMBERS - auditrecord.ENTRY_OPTIONAL
        if self.refuse_extra and extra:
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
    closed: bool = True,
    derive: Callable[[dict[str, Any]], list[str]] | None = None,
) -> Rule:
    """Section 5.4 as a reader might take it, one sentence at a time."""

    def rule(state: Any) -> None:
        evaluation = state.predicate["evaluation"]
        if closed and set(evaluation) - auditrecord.EVALUATION_MEMBERS:
            raise auditrecord.Malformed("evaluation-malformed")
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
        _not_evaluated(inputs, derived, refuse_empty, refuse_repeat, match_entries)

    return rule


def _not_evaluated(
    inputs: Any, derived: list[str], refuse_empty: bool, refuse_repeat: bool, match: bool
) -> None:
    """The not-evaluated half of Section 5.4 under the readings above."""
    if not isinstance(inputs, list) or (refuse_empty and not inputs):
        raise auditrecord.Malformed("evaluation-inconsistent")
    for value in inputs:
        if value not in auditrecord.UNAVAILABLE_INPUTS:
            raise auditrecord.Malformed("value-outside-vocabulary")
    if refuse_repeat and len(set(inputs)) != len(inputs):
        raise auditrecord.Malformed("evaluation-inconsistent")
    if match and set(inputs) != set(derived):
        raise auditrecord.Malformed("evaluation-inconsistent")


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
def _coverage_reading(*, clause: str, refuse_contradiction: bool | str) -> Iterator[None]:
    """Section 5.7 as a reader might take it: the tier's coverage clause as
    revision 00 or 01 states it, and the refusal of a gap inside pathScope
    beside scopeComplete of true kept, dropped, or applied only at one tier."""

    def coverage(state: Any) -> None:
        pred = state.predicate
        if refuse_contradiction is False:
            return
        if isinstance(refuse_contradiction, str) and pred["tier"] != refuse_contradiction:
            return
        if pred["observation"]["coverage"]["scopeComplete"] is True and (
            auditrecord.gaps_inside_scope(pred)
        ):
            raise auditrecord.Malformed("coverage-inconsistent")

    def clause_fails(pred: dict[str, Any]) -> bool:
        complete = pred["observation"]["coverage"]["scopeComplete"] is True
        if clause == "00":
            return not complete and auditrecord.gaps_inside_scope(pred)
        return not complete

    original = auditrecord.coverage_clause_fails
    auditrecord.coverage_clause_fails = clause_fails
    try:
        with _swapped_rule("coverage", coverage):
            yield
    finally:
        auditrecord.coverage_clause_fails = original


def _aggregation_check(manifest: dict[str, object]) -> list[str]:
    """Section 5.4 of revision 01 on the producer's side. FR14 lists two values
    of one input; the reference aggregation must reproduce its entry, and the
    revision 00 aggregation (the oldest lastResult beside the smallest maxAge,
    from different values) must not, and must write FR15's entry instead, which
    the reader refuses. A verifier holding only a record cannot tell the two
    aggregations apart, so without this check FR14 would test nothing about how
    the entry was made."""
    entries = manifest["vectors"]
    assert isinstance(entries, list)
    by_draft = {str(e["draftId"]): e for e in entries}
    carrying = [e for e in entries if "aggregation" in e]
    if not carrying:
        return ["no member carries an aggregation block, so Section 5.4's pairing is untested"]
    findings = []
    for entry in carrying:
        findings.extend(auditrecord.aggregation_findings(entry, _raw(entry)))

    def independent_minima(values: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "lastResult": min(v["lastResult"] for v in values),
            "maxAge": min(v["maxAge"] for v in values),
        }

    original = auditrecord.aggregate_values
    auditrecord.aggregate_values = independent_minima
    try:
        for entry in carrying:
            if not auditrecord.aggregation_findings(entry, _raw(entry)):
                findings.append(
                    f"{entry['draftId']}: the revision 00 aggregation reproduces its entry, "
                    "so the member does not distinguish the two rules"
                )
        fr15 = by_draft.get("FR15")
        if fr15 is None:
            findings.append("FR15, the record the revision 00 aggregation writes, is missing")
        else:
            moved = dict(fr15, aggregation=by_draft["FR14"]["aggregation"])
            if auditrecord.aggregation_findings(moved, _raw(fr15)):
                findings.append("FR15 does not carry the entry the revision 00 aggregation writes")
    finally:
        auditrecord.aggregate_values = original
    return findings


@contextlib.contextmanager
def _without_check(name: str) -> Iterator[None]:
    """The consumption rule with one of its sentences dropped."""
    original = auditrecord.CONSUMPTION_CHECKS
    auditrecord.CONSUMPTION_CHECKS = original - {name}
    try:
        yield
    finally:
        auditrecord.CONSUMPTION_CHECKS = original


@contextlib.contextmanager
def _without_chain_join() -> Iterator[None]:
    """The set checks over one limitDigest each, a replacement no longer joining
    the limit documents it links into one ledger."""
    auditrecord.SET_GROUPING["chain"] = False
    try:
        yield
    finally:
        auditrecord.SET_GROUPING["chain"] = True


@contextlib.contextmanager
def _group_every_record() -> Iterator[None]:
    """The set checks over one ledger of every record, whatever its limitDigest
    and whether or not a supersedes links it."""
    auditrecord.SET_GROUPING["all"] = True
    try:
        yield
    finally:
        auditrecord.SET_GROUPING["all"] = False


@contextlib.contextmanager
def _retry_by_request_digest() -> Iterator[None]:
    """A retry identified by the request digest rather than the operation key."""

    def held_for(consumption: dict[str, Any], decision: dict[str, Any]) -> Any:
        for held in consumption["held"]:
            if held["requestDigest"] == decision["requestDigest"]:
                return held
        return None

    original = auditrecord.held_for
    auditrecord.held_for = held_for
    try:
        yield
    finally:
        auditrecord.held_for = original


def _stale_by_digest(group: list[dict[str, Any]]) -> bool:
    """The stale-state check keyed on the request digest, as a reader that
    identifies an operation by its content would write it."""
    for later in group:
        for earlier in group:
            if later is earlier or auditrecord._revision(later) >= auditrecord._revision(earlier):
                continue
            if later["decision"]["reported"] not in auditrecord.PERMITS:
                continue
            seen = {h["requestDigest"] for h in auditrecord.consumption_of(later)["held"]}  # type: ignore[index]
            seen.add(later["decision"]["requestDigest"])
            if any(
                h["requestDigest"] not in seen
                for h in auditrecord.consumption_of(earlier)["held"]  # type: ignore[index]
            ):
                return True
    return False


@contextlib.contextmanager
def _set_checks(drop: str | None = None, by_request_digest: bool = False) -> Iterator[None]:
    """The set checks with one dropped (or all of them), or the stale-revision
    check keyed on the request digest."""
    original = list(auditrecord.SET_RULES)
    kept = []
    for name, code, check in original:
        if name == drop or (drop is None and not by_request_digest):
            continue
        kept.append(
            (
                name,
                code,
                _stale_by_digest if by_request_digest and name == "stale-revision" else check,
            )
        )
    auditrecord.SET_RULES[:] = kept
    claim = auditrecord.CLAIM_READING["check"]
    if drop is None and not by_request_digest:
        auditrecord.CLAIM_READING["check"] = False
    try:
        yield
    finally:
        auditrecord.SET_RULES[:] = original
        auditrecord.CLAIM_READING["check"] = claim


@contextlib.contextmanager
def _reading(table: dict[str, bool], name: str, value: bool) -> Iterator[None]:
    """One knob of a set reading (CLAIM_READING, ASSET_MATCH) set to value."""
    original = table[name]
    table[name] = value
    try:
        yield
    finally:
        table[name] = original


@contextlib.contextmanager
def _without_sequence_check(name: str) -> Iterator[None]:
    auditrecord.SEQUENCE_SET_CHECKS[name] = False
    try:
        yield
    finally:
        auditrecord.SEQUENCE_SET_CHECKS[name] = True


def _sequence_reading(*, refuse_extra: bool = True, positive: bool = True) -> Rule:
    """The sequence rule as a reader might take it: tolerating other members, or
    any integer seq."""

    def rule(state: Any) -> None:
        sequence = state.predicate.get("sequence")
        if sequence is None:
            return
        if refuse_extra and set(sequence) != auditrecord.SEQUENCE_MEMBERS:
            raise auditrecord.Malformed("sequence-malformed")
        seq = sequence["seq"]
        if not isinstance(seq, int) or (positive and seq < 1):
            raise auditrecord.Malformed("sequence-malformed")

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
        "A12,A13,A14,A18,A19,A20",
    ),
    (
        "agent.authentication without api-key",
        lambda: _narrowed_vocabulary(
            "agent.authentication",
            auditrecord.VOCABULARIES["agent.authentication"] - {"api-key"},
        ),
        "A21",
    ),
    (
        "a sequence member carrying an undefined member accepted",
        lambda: _swapped_rule("sequence", _sequence_reading(refuse_extra=False)),
        "SQ2",
    ),
    (
        "a sequence seq of 0 accepted",
        lambda: _swapped_rule("sequence", _sequence_reading(positive=False)),
        "SQ3",
    ),
    (
        "two records at one place in a series accepted",
        lambda: _without_sequence_check("duplicate"),
        "SQ5",
    ),
    (
        "a number missing below the highest held left unnamed",
        lambda: _without_sequence_check("gap"),
        "SQ4",
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
        "FR18",
    ),
    (
        "a lastResult of none read as fresh",
        lambda: _freshness(never_held_unavailable=False),
        "A18,A20,FR4",
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
        "FR8,FR17c,FR15",
    ),
    (
        "an evaluation member the draft does not define accepted",
        lambda: _swapped_rule("evaluation", _evaluation_reading(closed=False)),
        "EV12",
    ),
    (
        "unavailableInput without policy-source",
        lambda: _narrowed_inputs(frozenset({"standing-source", "key-source", "consumption-state"})),
        "A18,A20",
    ),
    (
        "revision 00's coverage clause: scopeComplete of true or every gap outside "
        "pathScope, and no refusal of a gap inside pathScope beside scopeComplete of true",
        lambda: _coverage_reading(clause="00", refuse_contradiction=False),
        "TI6,V4,V5",
    ),
    (
        "revision 00's coverage clause alone, the contradiction still refused",
        lambda: _coverage_reading(clause="00", refuse_contradiction=True),
        "TI6",
    ),
    (
        "a gap inside pathScope beside scopeComplete of true refused only when the "
        "record declares authoritative",
        lambda: _coverage_reading(clause="01", refuse_contradiction="authoritative"),
        "V5",
    ),
    (
        "a retry identified by the request digest rather than the operation key",
        _retry_by_request_digest,
        "CS10,CS12",
    ),
    (
        "consumption outside a consumption-state entry accepted",
        lambda: _without_check("misplaced"),
        "CS6",
    ),
    (
        "reserved not held to the sum of the held amounts",
        lambda: _without_check("reserved"),
        "CS3",
    ),
    (
        "two held entries under one operation key accepted",
        lambda: _without_check("distinct-keys"),
        "CS13",
    ),
    (
        "a decision with no operation key accepted beside consumption",
        lambda: _without_check("operation-key"),
        "CS14",
    ),
    (
        "a negative amount accepted",
        lambda: _without_check("counts"),
        "CS5",
    ),
    (
        "stateRevision optional",
        lambda: _without_check("state-revision"),
        "CS9",
    ),
    (
        "one operation key reused for a different request accepted",
        lambda: _without_check("key-reuse"),
        "CS10",
    ),
    (
        "a supersedes that is not a digest accepted",
        lambda: _without_check("supersedes-digest"),
        "CS24",
    ),
    (
        "a supersedes that names the record's own limitDigest accepted",
        lambda: _without_check("supersedes-self"),
        "CS23",
    ),
    (
        "no check across the records of a set",
        lambda: _set_checks(),
        "CS7,CS8,CS17,CS20,CS21,CS30,CS31,CS32,CS38,CS39",
    ),
    (
        "a record that read an older state and omits a held permit accepted",
        lambda: _set_checks("stale-revision"),
        "CS7,CS17,CS21",
    ),
    (
        "a held permit released with no record of the operation accepted",
        lambda: _set_checks("release-unshown"),
        "CS8,CS20,CS30",
    ),
    (
        "the set checks read per limitDigest, a replacement not joining the limits it links",
        _without_chain_join,
        "CS20,CS21,CS30",
    ),
    (
        "a retry presented as a new operation accepted",
        lambda: _reading(auditrecord.CLAIM_READING, "check", False),
        "CS31,CS32",
    ),
    (
        "a held claim keyed by the limit document, so an unlinked limit drops it",
        lambda: _reading(auditrecord.CLAIM_READING, "ledger", True),
        "CS32",
    ),
    (
        "a held claim read without its principal and agent key",
        lambda: _reading(auditrecord.CLAIM_READING, "scope", False),
        "CS33",
    ),
    (
        "a record of the operation showing none not ending its claim",
        lambda: _reading(auditrecord.CLAIM_READING, "release", False),
        "CS28",
    ),
    (
        "an asset id that is not CAIP-19 accepted",
        lambda: _without_check("asset-id"),
        "CS35",
    ),
    (
        "an asset decimals beyond a count accepted",
        lambda: _without_check("asset-decimals"),
        "CS36",
    ),
    (
        "a record carrying both unit and asset accepted",
        lambda: _without_check("asset-exclusive"),
        "CS37",
    ),
    (
        "one ledger counting two denominations accepted",
        lambda: _set_checks("asset-mismatch"),
        "CS38,CS39",
    ),
    (
        "an asset matched by its id alone, its decimals ignored",
        lambda: _reading(auditrecord.ASSET_MATCH, "decimals", False),
        "CS39",
    ),
    (
        "every record of a set grouped into one ledger whatever its limitDigest",
        _group_every_record,
        "CS25,CS40",
    ),
    (
        "the stale-state check keyed on the request digest rather than the operation key",
        lambda: _set_checks(by_request_digest=True),
        "CS17",
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


def _dating_sweep(manifest: dict[str, object]) -> list[str]:
    """Disabling one dating rule must move some retained member's dating result
    and no retained member's record verdict."""
    policy = auditrecord.policy_for(manifest)
    heads = auditrecord.tree_heads(manifest)
    entries = [e for e in manifest["vectors"] if _retained(e)]  # type: ignore[union-attr]
    if not entries:
        return ["the corpus carries no retained member, so the dating check is untested"]
    findings: list[str] = []
    swept = [n for n in auditrecord.dating_rule_names() if n not in auditrecord.DATING_UNREACHED]
    for name in swept:
        moved = []
        for entry in entries:
            report, dated = auditrecord.verify_retained(_raw(entry), policy, heads, disabled=name)
            if report.verdict != entry["expected"]["verdict"]:
                findings.append(f"disabling dating rule {name} moves {entry['draftId']}'s verdict")
            if auditrecord.dating_dict(dated) != entry["expected"]["dating"]:
                moved.append(str(entry["draftId"]))
        if not moved:
            findings.append(f"dating rule {name} is inert: disabling it moves no retained member")
    return findings


def _failing(manifest: dict[str, object]) -> str:
    policy = auditrecord.policy_for(manifest)
    entries = manifest["vectors"]
    assert isinstance(entries, list)
    failing = []
    for entry in entries:
        if _fails(entry, policy):
            failing.append(str(entry["draftId"]))
    return ",".join(failing)


def _fails(entry: dict[str, object], policy: auditrecord.Policy) -> bool:
    """A member fails a weakened reader when a record's verdict leaves the ones
    it conforms to, when the withinLimit it derives is not the declared one, or
    when a set of records reaches another verdict than the member declares."""
    expected = entry["expected"]
    assert isinstance(expected, dict)
    if _set(entry):
        reports, joint = auditrecord.verify_set(_raw(entry), policy)
        declared = expected["set"]
        limits = [
            auditrecord.within_limit(json.loads(auditrecord._envelope_payload(env)[1])["predicate"])
            for env in _envelopes(entry)
        ]
        return (
            any(r.verdict != expected["verdict"] for r in reports)
            or joint.verdict != declared["verdict"]
            or limits != declared.get("withinLimit", [None] * len(limits))
            or joint.missing != declared.get("missing", [])
        )
    verdict = _verify(entry, policy).verdict
    if verdict not in auditrecord.conforming_verdicts(entry):
        return True
    if "withinLimit" in expected:
        pred = json.loads(auditrecord._envelope_payload(_envelope_bytes(entry))[1])["predicate"]
        return bool(auditrecord.within_limit(pred) != expected["withinLimit"])
    return False


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


def _set_bundle_profile() -> list[str]:
    """A set bundle is read under the JSON profile and must carry a records array."""
    findings = []
    for name, raw in [
        ("records is an empty object", b'{"records":{}}'),
        ("records is an empty string", b'{"records":""}'),
        ("bundle is an array", b"[]"),
        ("records carries a float token", b'{"records":[],"n":1.0}'),
    ]:
        try:
            auditrecord.set_records(raw)
        except (auditrecord.Malformed, ValueError, KeyError, TypeError):
            continue
        findings.append(f"set_records accepts a set bundle where {name}")
    return findings


def main() -> int:
    judged = auditrecord.judge(HERE)
    sys.stdout.write(auditrecord.render(judged, auditrecord.SUITE))
    manifest = _manifest()
    swept, notes = _mutation_sweep(manifest)
    findings = (
        _second_signature_path(manifest)
        + swept
        + _dating_sweep(manifest)
        + _section_sweep(manifest)
        + _aggregation_check(manifest)
        + _set_bundle_profile()
    )
    for note in notes:
        print(f"note: {note}")
    for finding in findings:
        print(f"FAIL check: {finding}")
    if judged.ok() and not findings:
        print(
            "check: a second Ed25519 library agrees, every rule and dating rule is "
            "load-bearing, and "
            f"each of {len(SECTION_READINGS)} weakened section readings fails its own members"
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
