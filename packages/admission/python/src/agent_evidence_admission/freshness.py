"""Time bounds, each with its own allowance, and the audit-record freshness rule set.

A freshness rule has two bounds and they are not symmetric. The past bound is the window the
record states (``maxAge``) plus any uncertainty the format carries; the future bound is the skew
tolerance alone. A verifier that checks ``|age| <= maxAge`` admits a result produced an hour after
the decision it fed, because the window is wide; the future bound must never borrow the window or
the uncertainty. The uncertainty itself is capped, so a record cannot widen its own past bound by
declaring a large dispersion. Every time member is range-checked before any arithmetic: an integer
outside +-(2**53 - 1) reads differently in a double-based verifier, and a value past the calendar
breaks the arithmetic of some languages and not others.

:func:`judge` is that rule for one value. :func:`late` is the bound on an event that must follow a
start within a window, with the allowance that bound takes (an OpenTimestamps block time is late
by confirmation latency, so its comparison allows 7200 seconds where a clock reading allows the
skew tolerance). Each bound gets its own pair of boundary vectors: the last admitted second and the
first refused one.
"""

from __future__ import annotations

import datetime
import re
from typing import Any

from .rules import Check, Context, RuleSet, register, statement_of
from .strict_json import MAX_SAFE_INTEGER, Refusal

SKEW_TOLERANCE_SECONDS = 300
OTS_TOLERANCE_SECONDS = 7200
#: The largest uncertainty a record may declare; a consumer may set a smaller cap.
DEFAULT_MAX_UNCERTAINTY_SECONDS = 3600

#: RFC 3339 section 5.6. The offset's hour is 00 to 23 and its minute 00 to 59: ``+00:60`` is read
#: as one hour by some parsers and refused by others, so it is refused here.
_INSTANT = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})(?P<frac>\.[0-9]{1,9})?"
    r"(?P<zone>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
NANOS = 1_000_000_000
_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def instant(text: Any, where: str) -> int:
    """An RFC 3339 instant as nanoseconds since the epoch.

    ASCII digits only, an explicit zone, nothing after it: a timestamp written with non-ASCII
    digits or a trailing newline is one some parsers accept and others refuse. Every fraction digit
    the format allows (nine) is kept: a reader that truncates to microseconds admits a result
    300.0000009 seconds after the reference under a 300-second bound, which a nanosecond reader
    (Go's ``time``) refuses.
    """
    if not isinstance(text, str) or not text.isascii():
        raise Refusal("instant-malformed", where, "not an ASCII RFC 3339 string")
    match = _INSTANT.fullmatch(text)
    if match is None:
        raise Refusal("instant-malformed", where, f"{text!r} is not an RFC 3339 instant")
    nanos = int((match["frac"] or ".")[1:].ljust(9, "0"))
    zone = "+00:00" if match["zone"] == "Z" else match["zone"]
    try:
        moment = datetime.datetime.fromisoformat(f"{match['date']}T{match['time']}{zone}")
    except ValueError as error:
        raise Refusal("instant-malformed", where, str(error)) from error
    elapsed = moment - _EPOCH
    return (elapsed.days * 86400 + elapsed.seconds) * NANOS + nanos


def seconds(value: Any, where: str, name: str) -> int:
    """A non-negative whole number of seconds inside the I-JSON range, or a refusal."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise Refusal("time-member-malformed", where, f"{name} is not an integer")
    if value < 0:
        raise Refusal("time-member-malformed", where, f"{name} is negative")
    if value > MAX_SAFE_INTEGER:
        raise Refusal("time-member-out-of-range", where, f"{name} is outside 0..2**53 - 1")
    return value


def judge(
    produced: int,
    reference: int,
    max_age: int,
    skew: int = SKEW_TOLERANCE_SECONDS,
    uncertainty: int = 0,
    max_uncertainty: int = DEFAULT_MAX_UNCERTAINTY_SECONDS,
    where: str = "",
    inclusive: bool = True,
) -> bool:
    """True when a value produced at ``produced`` is fresh at ``reference`` (both nanoseconds).

    The future bound is ``skew`` alone: a value produced later than the reference by more than the
    skew is refused (``result-after-reference``), whatever its window. The past bound is
    ``max_age`` plus ``uncertainty``, and an age equal to the bound is fresh. With
    ``inclusive=False`` a value is fresh only while its age is less than the bound, so an age equal
    to it is stale (the audit record's rule since revision 05). ``uncertainty`` past
    ``max_uncertainty`` is refused (``uncertainty-over-cap``).
    """
    max_age = seconds(max_age, where, "maxAge")
    skew = seconds(skew, where, "skew")
    uncertainty = seconds(uncertainty, where, "uncertainty")
    if uncertainty > seconds(max_uncertainty, where, "the uncertainty cap"):
        raise Refusal("uncertainty-over-cap", where, f"uncertainty {uncertainty} s is over the cap of {max_uncertainty} s")
    if produced - reference > skew * NANOS:
        raise Refusal("result-after-reference", where, "produced later than the reference by more than the skew tolerance")
    age, bound = reference - produced, (max_age + uncertainty) * NANOS
    return age <= bound if inclusive else age < bound


def late(start: int, event: int, window: int, allowance: int, where: str = "") -> bool:
    """True when ``event`` falls after ``start`` (both nanoseconds) by more than ``window`` plus
    ``allowance`` seconds."""
    window = seconds(window, where, "window")
    allowance = seconds(allowance, where, "allowance")
    return event - start > (window + allowance) * NANOS


# --------------------------------------------------------------------------
# The audit-record rule set (draft-gilda-audit-agent-audit-record, Section 5.4).
# --------------------------------------------------------------------------

NEVER_HELD = "none"
ENTRY_MEMBERS = frozenset({"input", "lastResult", "maxAge"})
#: Revision 01 adds ``consumption`` to an entry: the cumulative-limit state the decision point read.
#: It is an object; its members are the audit-record reader's to judge, not this rule set's.
ENTRY_OPTIONAL = frozenset({"consumption"})
EVALUATION_MEMBERS = frozenset({"status", "inputs", "unavailableInput"})
#: Section 5.4's closed vocabulary: a reader that knows these two must not guess at a third.
STATUSES = frozenset({"evaluated", "not-evaluated"})


def _predicate(context: Context) -> tuple[dict[str, Any], str]:
    statement, prefix = statement_of(context)
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise Refusal("member-missing", f"{prefix}/predicate", "no predicate object")
    return predicate, f"{prefix}/predicate"


def _reference(context: Context) -> int:
    """The time every entry's age is measured to: ``decision.evaluatedAt`` when the record carries
    it, ``decision.reportedAt`` otherwise (revision 05). A decision is not reported before it is
    evaluated, so an ``evaluatedAt`` later than ``reportedAt`` by more than the skew tolerance is
    refused, and one exactly at the tolerance is not."""
    predicate, where = _predicate(context)
    decision = predicate.get("decision")
    if not isinstance(decision, dict) or "reportedAt" not in decision:
        raise Refusal("member-missing", f"{where}/decision/reportedAt", "no reference time to measure any age to")
    reported = instant(decision["reportedAt"], f"{where}/decision/reportedAt")
    if "evaluatedAt" not in decision:
        return reported
    evaluated = instant(decision["evaluatedAt"], f"{where}/decision/evaluatedAt")
    if evaluated - reported > _skew(context) * NANOS:
        raise Refusal(
            "evaluation-result-after-decision",
            f"{where}/decision/evaluatedAt",
            "evaluatedAt is later than reportedAt by more than the skew tolerance",
        )
    return evaluated


def _entries(context: Context) -> list[tuple[str, dict[str, Any]]]:
    predicate, where = _predicate(context)
    evaluation = predicate.get("evaluation")
    inputs = evaluation.get("inputs") if isinstance(evaluation, dict) else None
    if not isinstance(inputs, list):
        raise Refusal("member-missing", f"{where}/evaluation/inputs", "no evaluation entries")
    out = []
    for index, entry in enumerate(inputs):
        path = f"{where}/evaluation/inputs/{index}"
        if not isinstance(entry, dict) or not ENTRY_MEMBERS <= set(entry):
            raise Refusal("member-missing", path, "an entry lacks input, lastResult or maxAge")
        out.append((path, entry))
    return out


def _check_reference(context: Context) -> None:
    _reference(context)


def _check_entry_shape(context: Context) -> None:
    seen: set[str] = set()
    for path, entry in _entries(context):
        if set(entry) - ENTRY_MEMBERS - ENTRY_OPTIONAL:
            raise Refusal("evaluation-entry-malformed", path, "an entry carries a member the format does not define")
        if "consumption" in entry and not isinstance(entry["consumption"], dict):
            raise Refusal("evaluation-entry-malformed", f"{path}/consumption", "consumption is an object")
        if not isinstance(entry["input"], str) or not entry["input"]:
            raise Refusal("evaluation-entry-malformed", f"{path}/input", "input names an input: a non-empty string")
        if entry["input"] in seen:
            raise Refusal("evaluation-input-repeated", f"{path}/input", f"{entry['input']!r} is named twice")
        seen.add(entry["input"])
        try:
            seconds(entry["maxAge"], f"{path}/maxAge", "maxAge")
        except Refusal as refusal:
            code = "unsafe-integer" if refusal.code == "time-member-out-of-range" else "evaluation-entry-malformed"
            raise Refusal(code, refusal.at, refusal.detail) from refusal
        if entry["lastResult"] != NEVER_HELD:
            instant(entry["lastResult"], f"{path}/lastResult")


def _derive(context: Context, future_bound: bool) -> list[str] | None:
    """The inputs the entries derive as unavailable, or None when the record is not well enough
    formed to derive them (the reference-time and entry-shape checks report why).

    Without ``future_bound`` a result produced after the reference reads as fresh, the way a
    verifier that checks only the past bound reads it."""
    try:
        reference = _reference(context)
        entries = _entries(context)
        produced = {path: None if e["lastResult"] == NEVER_HELD else instant(e["lastResult"], path) for path, e in entries}
        for path, entry in entries:
            seconds(entry["maxAge"], path, "maxAge")
    except Refusal:
        return None
    skew = _skew(context) if future_bound else MAX_SAFE_INTEGER
    out = []
    for path, entry in entries:
        moment = produced[path]
        if moment is None:
            out.append(entry["input"])
            continue
        try:
            fresh = judge(moment, reference, entry["maxAge"], skew=skew, where=path, inclusive=False)
        except Refusal as refusal:
            raise Refusal("evaluation-result-after-decision", f"{path}/lastResult", refusal.detail) from refusal
        if not fresh:
            out.append(entry["input"])
    return out


def _skew(context: Context) -> int:
    """The ``skew`` option: a whole number of seconds in 0..2**53 - 1. Any other value is the
    caller's error (``option-malformed``), never coerced: ``int()`` would read ``"300"``, ``true``
    and ``1.5`` as tolerances nobody chose, and a negative one would refuse the record under a code
    that blames the record."""
    value = context.options.get("skew", SKEW_TOLERANCE_SECONDS)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
        raise Refusal("option-malformed", "", f"the option skew is a whole number of seconds in 0..2**53 - 1, not {value!r}")
    return value


def _check_future_bound(context: Context) -> None:
    _skew(context)
    _derive(context, future_bound=True)


def _check_status(context: Context) -> None:
    """The status is one of the two the format defines, the evaluation carries no other member, and
    the status and ``unavailableInput`` are what the entries derive: ``evaluated`` derives none and
    names none; ``not-evaluated`` names the derived set, once each, and the set is not empty. A
    record that reports ``not-evaluated`` while every input is fresh contradicts itself as surely
    as one that reports ``evaluated`` beside a stale input."""
    predicate, where = _predicate(context)
    evaluation = predicate.get("evaluation")
    if not isinstance(evaluation, dict):
        return  # entry-shape reports the missing evaluation
    if set(evaluation) - EVALUATION_MEMBERS:
        extra = sorted(set(evaluation) - EVALUATION_MEMBERS)
        raise Refusal("evaluation-malformed", f"{where}/evaluation", f"members the format does not define: {extra}")
    status = evaluation.get("status")
    if status not in STATUSES:
        raise Refusal("value-outside-vocabulary", f"{where}/evaluation/status", f"status {status!r} is not evaluated or not-evaluated")
    derived = _derive(context, future_bound=False)
    if derived is None:
        return
    if status == "evaluated":
        if derived or "unavailableInput" in evaluation:
            raise Refusal("evaluation-inconsistent", f"{where}/evaluation", f"evaluated beside unavailable inputs {derived}")
        return
    named = evaluation.get("unavailableInput")
    if not isinstance(named, list) or not named or not all(isinstance(n, str) for n in named):
        raise Refusal("evaluation-inconsistent", f"{where}/evaluation/unavailableInput", "not-evaluated names a non-empty list of inputs")
    if len(set(named)) != len(named) or set(named) != set(derived):
        raise Refusal("evaluation-inconsistent", f"{where}/evaluation", f"unavailableInput {named} is not the derived set {derived}")


AUDIT_FRESHNESS = register(
    RuleSet(
        name="audit-freshness",
        summary="audit record: every evaluation entry range-checked, then fresh or stale under asymmetric bounds",
        checks=(
            Check("reference-time", "decision.reportedAt is present, and decision.evaluatedAt when present is an RFC 3339 instant no later than it by more than the skew tolerance", _check_reference),
            Check("entry-shape", "each entry is input, lastResult and maxAge, maxAge in 0..2**53 - 1", _check_entry_shape),
            Check("future-bound", "no lastResult later than the reference time by more than the skew tolerance", _check_future_bound),
            Check("status", "status is evaluated or not-evaluated and, with unavailableInput, equals what the entries derive", _check_status),
        ),
        option_help={"skew": "the skew tolerance in seconds (default 300)"},
    )
)
