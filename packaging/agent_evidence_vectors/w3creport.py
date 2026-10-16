"""The v0.1 per-check report of the W3C public-agent-conformance group.

Three things live here, and they are kept in one stdlib-only module for the
same reason ``run_vectors.py`` is one file: a relying party runs it with
nothing installed.

1. A VALIDATOR for a v0.1 report: ``rejections(report)`` returns the sorted
   requirement identifiers the report is rejected under, an empty list for a
   report that conforms. Each identifier is minted by ``vectors-w3c-report/``
   and bound by digest to a sentence of the list messages that fixed v0.1.
2. A JUDGE for the corpus that holds the conformance set: ``judge(directory)``
   reads ``vectors-w3c-report/MANIFEST.json`` and says of every member whether
   the validator rejects it under exactly the row the manifest expects. Its
   printed form is byte-identical to what ``aee-verify <dir>`` prints from the
   Go reader in ``corpora/w3creport.go``, and ``scripts/w3c-rails-parity-test.py``
   holds the two together over the committed corpus and over mutated copies.
3. An EMITTER: ``emit(conformance_report)`` turns the report the AEE harness
   writes into a v0.1 report, one per-check record per replayed vector, with
   the crosswalk stated in ``CROSSWALK`` below rather than left to a reader.

The record shape, the five states, the cause rule, the two qualifier slots and
the fourteen rejection rows are the group's, as the v0.1 text of 2026-09-30
states them: rows 1 to 12 keep their numbers and rows 13 and 14 are W3C-R-025
and W3C-R-026; the rules v0.1 states outside the table, in sections 1, 2, 3,
3.1 and 5, are carried under their own identifiers without a row number,
because the text does not number them. A referenced observation is read through
the reading table: resolves with a matching digest, resolves with a mismatch,
does not resolve. Nothing here is a product and no field is ours.
"""

from __future__ import annotations

import argparse
import decimal
import hashlib
import json
import math
import os
import sys
from collections.abc import Callable
from typing import Any

if __package__ in (None, ""):
    # Run as a script from a checkout: make the package importable by name.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_evidence_vectors import contextdiscovery, runmetrics  # noqa: E402

SUITE = "w3c-report-v01-conformance"
#: What a member of the corpus is a report OF. A report is judged by the rows
#: of v0.1; the two Internet-Drafts the editor holds are judged by their own
#: sentences in their own modules, and the manifest names which by member.
SUBJECT_TYPES = ("report", "agent-run-metrics", "llm-context-discovery")
FORMAT = "public-agent-conformance/report/v0.1"

# --------------------------------------------------------------------------
# Vocabularies. Closed within a version, revised by version; a value outside
# any of them is rejected under the free-text rule rather than read.
# --------------------------------------------------------------------------

STATES = ("pass", "fail", "inconclusive", "not-exercised", "void")
VERDICT_STATES = ("pass", "fail")
NON_VERDICT_STATES = ("inconclusive", "not-exercised", "void")

#: The cause vocabulary of v0.1 section 1.2: CAP-1's eight closed
#: dispositions, ``evidence-does-not-hold`` as the value for void,
#: integrity-failure kept apart from availability-failure,
#: precondition-unsatisfiable, and confinement-failed-during-check, admitted
#: only under void. Nothing else
#: is admitted: an emitter with a case the vocabulary cannot name says so in
#: the detail beside the nearest disposition, and records the gap.
CAUSES = (
    "not_applicable",
    "disabled_by_policy",
    "unsupported_input",
    "resource_exhausted",
    "failed",
    "unavailable",
    "out_of_scope",
    "withheld",
    "evidence-does-not-hold",
    "integrity-failure",
    "availability-failure",
    "precondition-unsatisfiable",
    "confinement-failed-during-check",
)
#: The value for void, v0.1 section 1.2; see CAUSES.
VOID_CAUSE = "evidence-does-not-hold"
#: Row 4's antecedent, as a cause value admitted only under void. A confinement
#: control that failed while the check ran is written in the record's own cause
#: cell, so row 4 reads cause against state the way row 3 does and nothing is
#: added to the four-field record (v0.1 sections 1.2 and 4).
CONFINEMENT_CAUSE = "confinement-failed-during-check"
#: Row 2: a unit that was never examined has no evidence that can fail to hold up.
NEVER_EXAMINED = ("not_applicable", "out_of_scope", "withheld")

OTHER_VERDICT = ("unknown", "possible-not-demonstrated", "demonstrated", "foreclosed")
DISCRIMINATION = ("unknown", "demonstrated")
NEGATIVE_CAPABLE = ("shown-by-run", "control-failed", "prior-discriminating-run", "nothing")
CHANGED = ("input artifact", "checker rule", "constraint")
#: What an evidence object may declare it compared or found moved. The error
#: list is the recompute-opaque slot the editor recorded as a fourth kind
#: that no rejection row reads (v0.1 section 2.1); it is named so an object
#: can declare it, and a declaration of it never carries a rejection.
SLOTS = ("verdict", "fired-rule list", "error list")

#: Requirement identifiers, minted by the corpus. The sentence each binds to
#: is in vectors-w3c-report/MANIFEST.json and the corpus's INDEX.md.
R = {n: f"W3C-R-{n:03d}" for n in (*range(1, 30), 33)}


# --------------------------------------------------------------------------
# Digests over a JSON value. The v0.1 text does not say which bytes enter one,
# and the list proposed RFC 8785 under the identifier jcs-sha256 (2026Oct/0038)
# with a numeric profile (0040, 0041). This module implements it, and so do the
# Go reader (corpora/w3cjcs.go) and the Rust reader (readers/w3c-report-rs);
# corpora/testdata/json-encodings.json holds the three to the same bytes.
#
#   jcs-sha256  a report's own digests over JSON values, each check-set leaf:
#               the RFC 8785 canonical form, every number an integer of
#               magnitude below 2^53 by its exact value. A number outside that
#               profile has no jcs-sha256 form, and the report is rejected
#               under W3C-R-020 with the cause named.
#   rfc8785     a member identifier: RFC 8785 as written, numbers as IEEE 754
#               doubles. A member rejected for carrying a number outside the
#               profile still needs a name, so the corpus's naming takes none.
#
# Both coincide with the compact, sorted-key, ASCII-escaped JSON this module
# used before on every member committed before them: none carries a non-ASCII
# character, U+007F, a float, -0 or an integer outside the profile.
# --------------------------------------------------------------------------

#: The closed set of digest encodings a set binding may declare (proposed, not
#: in v0.1). A binding that declares none is digested under jcs-sha256.
JCS_SHA256 = "jcs-sha256"
DIGEST_ENCODINGS = (JCS_SHA256,)

#: Integers of magnitude below this have an exact IEEE 754 double, which is what
#: RFC 8785 serialises: the range 0040 writes as -(2^53-1) to 2^53-1.
SAFE_INTEGER = 2**53

#: The causes a rejection from a set binding names: W3C-R-020 when the digest
#: over the check set does not hold, W3C-R-015 for a declared encoding outside
#: the closed set. A member's expected cause is one of these.
DIGESTS_DIFFER = "digests-differ"
NON_INTEGER = "non-integer-number"
OUTSIDE_SAFE_RANGE = "integer-outside-safe-range"
UNSUPPORTED_ENCODING = "unsupported-digest-encoding"
CAUSE_CODES = (DIGESTS_DIFFER, NON_INTEGER, OUTSIDE_SAFE_RANGE, UNSUPPORTED_ENCODING)
#: A number RFC 8785 itself has no form for: a member identifier refuses it.
NOT_FINITE = "number-not-finite"

#: The rules of the two encodings the generator's mutation sweep weakens one at
#: a time, to show which members rest on which rule. A reader never weakens one.
WEAKENABLE = (
    "utf16-member-order",  # members ordered by UTF-16 code unit, not code point
    "raw-u007f",  # U+007F written as itself, not as an escape
    "raw-non-ascii",  # a character above U+007F written as UTF-8, not escaped
    "number-by-value",  # an admitted number written as its value, not its token
    "integers-only",  # a number whose exact value is not an integer is refused
    "safe-range",  # an integer of magnitude 2^53 or more is refused
    "closed-encoding-set",  # a declared encoding outside the set is refused
)
NO_WEAKENING: frozenset[str] = frozenset()


class DigestRefused(ValueError):
    """A value with no form under an encoding: ``cause`` is a code, ``token`` the number."""

    def __init__(self, cause: str, token: str) -> None:
        super().__init__(f"{cause}: {token}")
        self.cause = cause
        self.token = token


class IntToken(int):
    """An integer that keeps the token it was written as, so -0 is still -0 here."""

    token: str

    def __new__(cls, text: str) -> IntToken:
        made = super().__new__(cls, text)
        made.token = text
        return made


class NumberToken(decimal.Decimal):
    """A number written with a fraction or an exponent: its exact value and its token."""

    token: str

    def __new__(cls, text: str) -> NumberToken:
        made = super().__new__(cls, text)
        made.token = text
        return made


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def load_json(raw: bytes | str) -> Any:
    """Parse JSON the way this reader reads it: every number keeps its token.

    An integer parses to IntToken and any other number to NumberToken, an exact
    Decimal, so a digest decides on the value the token denotes and a refusal
    names the token as it was written. NaN and Infinity are not JSON.
    """
    return json.loads(
        raw, parse_int=IntToken, parse_float=NumberToken, parse_constant=_refuse_constant
    )


def _token(value: int | decimal.Decimal) -> str:
    token: Any = getattr(value, "token", None)
    return token if isinstance(token, str) else str(value)


_SHORT_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _utf16_units(text: str) -> list[int]:
    data = text.encode("utf-16-be")
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]


def _jcs_string(text: str, weaken: frozenset[str]) -> str:
    """RFC 8785 section 3.2.2.2: escape the quote, the backslash and U+0000 to U+001F."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append(_SHORT_ESCAPES.get(code, f"\\u{code:04x}"))
        elif code == 0x7F and "raw-u007f" in weaken:
            out.append("\\u007f")
        elif code > 0x7F and "raw-non-ascii" in weaken:
            out.append("".join(f"\\u{unit:04x}" for unit in _utf16_units(ch)))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es6(value: float) -> str:
    """ECMAScript Number::toString of a finite double (RFC 8785 section 3.2.2.3).

    repr() gives the shortest digits that round-trip, which is the digit string
    ECMAScript chooses; the layout around them is ECMAScript's, not Python's.
    """
    if value == 0:
        return "0"
    shortest = decimal.Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(str(d) for d in shortest.digits)
    # A finite double's tuple has an integer exponent.
    k, n = len(digits), int(shortest.exponent) + len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + digits
    else:
        e = n - 1
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + ("e+" if e >= 0 else "e-")
        body += str(abs(e))
    return ("-" if value < 0 else "") + body


def _double(value: int | decimal.Decimal) -> str:
    """The number RFC 8785 writes for a token: the IEEE 754 double it parses to."""
    try:
        parsed = float(value)
    except OverflowError:
        raise DigestRefused(NOT_FINITE, _token(value)) from None
    if not math.isfinite(parsed):
        raise DigestRefused(NOT_FINITE, _token(value))
    return _es6(parsed)


def _profile_number(value: int | decimal.Decimal, weaken: frozenset[str]) -> str:
    """A number under the jcs-sha256 profile: an integer below 2^53 by exact value."""
    integral = not isinstance(value, decimal.Decimal) or value == value.to_integral_value()
    if not integral:
        if "integers-only" in weaken:
            return _double(value)
        raise DigestRefused(NON_INTEGER, _token(value))
    if not -SAFE_INTEGER < value < SAFE_INTEGER:
        if "safe-range" in weaken:
            return _double(value)
        raise DigestRefused(OUTSIDE_SAFE_RANGE, _token(value))
    if "number-by-value" in weaken:
        return _token(value)
    return str(int(value))


def _plain_number(value: int | decimal.Decimal) -> str:
    """A number under RFC 8785 as written: the double it parses to, any magnitude."""
    if not isinstance(value, decimal.Decimal) and -SAFE_INTEGER < value < SAFE_INTEGER:
        return str(int(value))
    return _double(value)


def _jcs(value: Any, profile: bool, weaken: frozenset[str]) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value, weaken)
    if isinstance(value, (int, decimal.Decimal)):
        return _profile_number(value, weaken) if profile else _plain_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item, profile, weaken) for item in value) + "]"
    if isinstance(value, dict):
        if "utf16-member-order" in weaken:
            names = sorted(value)
        else:
            names = sorted(value, key=lambda name: name.encode("utf-16-be"))
        return "{" + ",".join(
            _jcs_string(name, weaken) + ":" + _jcs(value[name], profile, weaken) for name in names
        ) + "}"
    # A float built in Python rather than parsed has lost its token, and its
    # repr is not necessarily what the producer wrote: refuse rather than guess.
    raise TypeError(f"{type(value).__name__} has no RFC 8785 form here")


def jcs_sha256(value: Any, weaken: frozenset[str] = NO_WEAKENING) -> bytes:
    """The bytes a jcs-sha256 digest is taken over: RFC 8785 under the integer profile."""
    return _jcs(value, True, weaken).encode("utf-8")


def rfc8785(value: Any) -> bytes:
    """RFC 8785 as written, numbers as IEEE 754 doubles: what a member identifier names."""
    return _jcs(value, False, NO_WEAKENING).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def flat_root(leaves: list[bytes]) -> str:
    """SHA-256 over the concatenated SHA-256 of each leaf, in order."""
    return sha(b"".join(hashlib.sha256(leaf).digest() for leaf in leaves))


def rfc6962_root(leaves: list[bytes]) -> str:
    """The Merkle tree hash of RFC 6962 section 2.1, with its domain separation.

    The split is the RFC's own: the left subtree holds the largest power of two
    strictly smaller than the count. That recursive shape is what a
    duplicate-last-leaf tree lacks, and it is why the shape is named rather
    than assumed.
    """
    return _mth(leaves).hex()


def _mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


class UnregisteredShape(ValueError):
    """A tree shape outside the closed set, refused rather than hashed as another."""


#: The closed set of tree shapes, and the construction each name denotes. The
#: set IS this table's keys, so a name cannot enter the set without a root
#: function, and a name outside it has none to fall through to.
ROOTS: dict[str, Callable[[list[bytes]], str]] = {
    "flat": flat_root,
    "rfc6962": rfc6962_root,
    # RFC 9942 section 5.1 registers RFC9162_SHA256 as "a Merkle Tree where
    # SHA256 is used as the hash algorithm", pointing at RFC 9162 section 2.1.1,
    # whose Merkle Tree Hash is the RFC 6962 one: the same leaf and node
    # prefixes and the same split. Two names, one construction.
    "RFC9162_SHA256": rfc6962_root,
}
TREE_SHAPES = tuple(ROOTS)


def check_set_root(
    checks: list[dict[str, Any]], shape: str, weaken: frozenset[str] = NO_WEAKENING
) -> str:
    """The root over the check set: each check's jcs-sha256 bytes, under the named shape."""
    root = ROOTS.get(shape)
    if root is None:
        raise UnregisteredShape(f"tree shape {shape!r} is not in the closed set {TREE_SHAPES}")
    return root([jcs_sha256(check, weaken) for check in checks])


# --------------------------------------------------------------------------
# Shape. A report that is not the shape the record definition gives is not
# judged against the rows: the finding names the shape defect instead, so a
# malformed report never reads as "conforming, no row fired".
# --------------------------------------------------------------------------


def _get(obj: dict[str, Any], key: str) -> Any:
    """A member read as Any, so a checker does not narrow it to Optional."""
    return obj.get(key)


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_obj(value: Any) -> bool:
    return isinstance(value, dict)


def _shape_slots(check: dict[str, Any], where: str, out: list[str]) -> None:
    for slot in ("cause", "other-verdict", "discrimination"):
        if slot in check and not _is_obj(check[slot]):
            out.append(f"{where}.{slot} is present and is not an object")
    cause = _get(check, "cause")
    if _is_obj(cause) and not _is_str(cause.get("code")):
        out.append(f"{where}.cause carries no string code")
    for slot in ("other-verdict", "discrimination"):
        value = _get(check, slot)
        if _is_obj(value) and not _is_str(value.get("value")):
            out.append(f"{where}.{slot} carries no string value")


def _shape_check(check: Any, index: int, out: list[str]) -> None:
    where = f"checks[{index}]"
    if not _is_obj(check):
        out.append(f"{where} is not an object")
        return
    if not _is_str(check.get("check")):
        out.append(f"{where} carries no string check identity")
    if not _is_str(check.get("state")):
        out.append(f"{where} carries no string state")
    _shape_slots(check, where, out)
    if "declared-exclusion" in check and not isinstance(check["declared-exclusion"], bool):
        out.append(f"{where}.declared-exclusion is present and is not a boolean")


def _shape_evidence(item: Any, index: int, out: list[str]) -> None:
    where = f"evidence[{index}]"
    if not _is_obj(item):
        out.append(f"{where} is not an object")
        return
    if not _is_str(item.get("id")):
        out.append(f"{where} carries no string id")
    if not _is_str(item.get("changed")):
        out.append(f"{where} carries no string changed slot")
    if not _is_obj(item.get("fixed")):
        out.append(f"{where} carries no fixed object")
    for slot in ("compared", "moved"):
        values = item.get(slot)
        if not isinstance(values, list) or not all(_is_str(v) for v in values):
            out.append(f"{where}.{slot} is not a list of strings")
    _shape_delta(item, where, out)
    _shape_observations(item.get("observations"), where, out)


def _shape_delta(item: dict[str, Any], where: str, out: list[str]) -> None:
    """A delta is an object listing its changes as an array of objects (0087 section 1.3)."""
    if "delta" not in item:
        return
    delta = item["delta"]
    if not _is_obj(delta):
        out.append(f"{where}.delta is present and is not an object")
        return
    if "changes" not in delta:
        return
    changes = delta["changes"]
    if not isinstance(changes, list):
        out.append(f"{where}.delta.changes is not an array")
        return
    for j, change in enumerate(changes):
        if not _is_obj(change):
            out.append(f"{where}.delta.changes[{j}] is not an object")


def _shape_observations(observations: Any, where: str, out: list[str]) -> None:
    """Each observation is exactly one of reference or carried, and that one is an object."""
    if not isinstance(observations, list):
        out.append(f"{where}.observations is not a list")
        return
    for j, observation in enumerate(observations):
        if not _is_obj(observation) or (("reference" in observation) == ("carried" in observation)):
            out.append(f"{where}.observations[{j}] is not exactly one of reference or carried")
        elif not _is_obj(observation.get("reference", observation.get("carried"))):
            out.append(f"{where}.observations[{j}] carries a form that is not an object")


def _duplicate_ids(items: list[Any], key: str) -> bool:
    ids = [item.get(key) for item in items if _is_obj(item)]
    return len(set(ids)) != len(ids)


def _shape_lists(report: dict[str, Any], out: list[str]) -> None:
    checks = report.get("checks")
    if not isinstance(checks, list):
        out.append("checks is not a list")
        checks = []
    for i, check in enumerate(checks):
        _shape_check(check, i, out)
    if _duplicate_ids(checks, "check"):
        out.append("two checks carry one identity")
    evidence = report.get("evidence", [])
    if not isinstance(evidence, list):
        out.append("evidence is present and is not a list")
        evidence = []
    for i, item in enumerate(evidence):
        _shape_evidence(item, i, out)
    if _duplicate_ids(evidence, "id"):
        out.append("two evidence objects carry one id")


def _shape_domain(report: dict[str, Any], out: list[str]) -> None:
    """The domain is declared once, at run level, and every slot names it by identifier.

    A slot naming a domain the run does not declare is a dangling reference and
    not a row: the row that read a foreclosure over another domain became
    unwritable once the domain is a declared object referenced by identifier.
    """
    domain = _get(report, "domain")
    if not _is_obj(domain) or not _is_str(domain.get("id")):
        out.append("the report declares no domain object with a string id")
        return
    declared = domain["id"]
    checks: list[Any] = report["checks"] if isinstance(report.get("checks"), list) else []
    for i, check in enumerate(checks):
        other: Any = check.get("other-verdict") if _is_obj(check) else None
        named: Any = other.get("domain") if _is_obj(other) else None
        if _is_str(named) and named != declared:
            out.append(f"checks[{i}].other-verdict names a domain the run does not declare")
    evidence: list[Any] = report["evidence"] if isinstance(report.get("evidence"), list) else []
    for i, item in enumerate(evidence):
        fixed: Any = item.get("fixed") if _is_obj(item) else None
        named = fixed.get("domain") if _is_obj(fixed) else None
        if _is_str(named) and named != declared:
            out.append(f"evidence[{i}].fixed names a domain the run does not declare")


def shape_errors(report: Any) -> list[str]:
    """Every way the report fails to be a v0.1 report at all."""
    out: list[str] = []
    if not _is_obj(report):
        return ["the report is not a JSON object"]
    if report.get("format") != FORMAT:
        out.append(f"the report does not declare format '{FORMAT}'")
    _shape_lists(report, out)
    _shape_domain(report, out)
    for slot in ("roll-up", "check-set", "fixed"):
        if slot in report and not _is_obj(report[slot]):
            out.append(f"{slot} is present and is not an object")
    return out


# --------------------------------------------------------------------------
# The rows. Each function adds the identifiers of the rows a record or a
# report is rejected under. Rows are read off fields, never inferred.
# --------------------------------------------------------------------------


def _row_cause(check: dict[str, Any], state: str, out: set[str]) -> None:
    cause = check.get("cause")
    if state in NON_VERDICT_STATES and cause is None:
        out.add(R[1])
    if state in VERDICT_STATES and cause is not None:
        out.add(R[7])
    if cause is None:
        return
    code = cause["code"]
    if code not in CAUSES:
        out.add(R[19])
    if state == "void" and code in NEVER_EXAMINED:
        out.add(R[2])
    if state == "not-exercised" and code == "integrity-failure":
        out.add(R[3])
    if code == CONFINEMENT_CAUSE and state != "void":
        out.add(R[4])


def _row_pairs(check: dict[str, Any], state: str, out: set[str]) -> None:
    if check.get("declared-exclusion") is True and state != "not-exercised":
        out.add(R[5])


def _resolves(ref: Any, evidence: dict[str, dict[str, Any]]) -> bool:
    return _is_str(ref) and ref in evidence


# --------------------------------------------------------------------------
# The reading table for carry-or-reference. A carried observation is read as
# carried. A referenced one is read through what the reader can resolve:
# resolves with a matching digest, the outcome is read and moved recomputes;
# resolves with a mismatch, an integrity failure; does not resolve, unchecked,
# and the rows that read moved degrade rather than fire.
# --------------------------------------------------------------------------

Outcome = tuple[str, list[str]]
MISMATCH = "mismatch"


def _outcome_of(body: Any) -> Outcome | None:
    if not _is_obj(body):
        return None
    verdict, rules = body.get("verdict"), body.get("rules")
    if not _is_str(verdict) or not isinstance(rules, list) or not all(_is_str(r) for r in rules):
        return None
    return verdict, sorted(rules)


def _read_observation(
    observation: dict[str, Any], resolves: dict[str, Any]
) -> Outcome | str | None:
    """A carried outcome, a resolved one, MISMATCH, or None when it cannot be read."""
    if "carried" in observation:
        return _outcome_of(observation["carried"])
    reference: Any = observation.get("reference")
    if not _is_obj(reference) or not _is_str(reference.get("sha256")):
        return None
    locator: Any = reference.get("vector")
    if not _is_str(locator) or locator not in resolves:
        return None
    resolved: Any = resolves[locator]
    if not _is_obj(resolved) or resolved.get("sha256") != reference["sha256"]:
        return MISMATCH
    return _outcome_of(resolved)


def _recomputed_moved(item: dict[str, Any], resolves: dict[str, Any]) -> set[str] | str | None:
    """The slots that moved between the two observations, MISMATCH, or None if unread."""
    observations = item["observations"]
    if len(observations) != 2:
        return None
    read = [_read_observation(o, resolves) for o in observations]
    if any(r == MISMATCH for r in read):
        return MISMATCH
    if read[0] is None or read[1] is None or isinstance(read[0], str) or isinstance(read[1], str):
        return None
    first, second = read[0], read[1]
    moved = set()
    if first[0] != second[0]:
        moved.add("verdict")
    if first[1] != second[1]:
        moved.add("fired-rule list")
    return moved


def _row_other_verdict(
    other: dict[str, Any],
    ov: str,
    evidence: dict[str, dict[str, Any]],
    resolves: dict[str, Any],
    out: set[str],
) -> None:
    has_domain = "domain" in other
    if has_domain and not _is_str(other["domain"]):
        out.add(R[28])
    if ov == "foreclosed" and not (_is_str(other.get("constraint-set")) and has_domain):
        out.add(R[10])
    ref: Any = other.get("ref")
    if ov in ("demonstrated", "foreclosed") and not _resolves(ref, evidence):
        out.add(R[11])
        return
    if ov == "demonstrated":
        moved = _recomputed_moved(evidence[ref], resolves)
        if isinstance(moved, set) and "verdict" not in moved:
            out.add(R[25])


def _delta_changes(item: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The concrete changes a stated delta lists, or None when it states none."""
    delta = _get(item, "delta")
    if not _is_obj(delta):
        return None
    changes: Any = delta.get("changes")
    if not isinstance(changes, list) or not changes:
        return None
    if not all(_is_obj(c) and _is_str(c.get("field")) and bool(c["field"]) for c in changes):
        return None
    typed: list[dict[str, Any]] = changes
    return typed


def arity(item: dict[str, Any]) -> int:
    """How many fields the delta moves, recomputed from the delta and never declared."""
    changes = _delta_changes(item)
    return 0 if changes is None else len(changes)


def _delta_related(item: dict[str, Any]) -> bool:
    """Two observations, a stated delta, and the checker, constraints and domain pinned."""
    fixed = item["fixed"]
    pinned = all(
        _is_str(fixed.get(k)) and bool(fixed[k]) for k in ("checker", "constraint-set", "domain")
    )
    return len(item["observations"]) == 2 and _delta_changes(item) is not None and pinned


def _row_discrimination(
    disc: dict[str, Any], evidence: dict[str, dict[str, Any]], out: set[str]
) -> None:
    ref: Any = disc.get("ref")
    if not _resolves(ref, evidence):
        out.add(R[11])
        return
    if evidence[ref].get("changed") == "checker rule":
        out.add(R[12])
    if not _delta_related(evidence[ref]):
        out.add(R[24])


def _row_recomputed_moved(item: dict[str, Any], resolves: dict[str, Any], out: set[str]) -> None:
    """Rules 16 and 21: moved is read as recomputed from the two observations, never as declared.

    Section 2 of v0.1: "moved is recomputed, not declared. It is recomputed over
    what the referenced observations actually contain, and an object whose moved
    is not contained in its declared compared set is rejected." So rule 16 holds
    the recomputed moved against the declared compared set, and rule 21 the
    declared moved against the recomputed one. Both read only the slots a reader
    recomputes, verdict and fired-rule list: the error list is recomputed-opaque
    and no rejection row reads it (section 2.1). Where the observations cannot be
    read, neither row fires.
    """
    recomputed = _recomputed_moved(item, resolves)
    if recomputed == MISMATCH:
        out.add(R[20])
        return
    if not isinstance(recomputed, set):
        return
    if not recomputed <= set(item["compared"]):
        out.add(R[16])
    declared = {v for v in item["moved"] if v in ("verdict", "fired-rule list")}
    if declared != recomputed:
        out.add(R[21])


def _row_qualifiers(
    check: dict[str, Any],
    state: str,
    evidence: dict[str, dict[str, Any]],
    resolves: dict[str, Any],
    out: set[str],
) -> None:
    other: dict[str, Any] = check.get("other-verdict") or {}
    disc: dict[str, Any] = check.get("discrimination") or {}
    if state in NON_VERDICT_STATES and ("other-verdict" in check or "discrimination" in check):
        out.add(R[6])
    ov = other.get("value", "unknown")
    dv = disc.get("value", "unknown")
    if ov not in OTHER_VERDICT or dv not in DISCRIMINATION:
        out.add(R[19])
        return
    if ov == "foreclosed" and dv == "demonstrated":
        out.add(R[8])
    if dv == "demonstrated" and ov in ("unknown", "possible-not-demonstrated"):
        out.add(R[9])
    _row_other_verdict(other, ov, evidence, resolves, out)
    if dv == "demonstrated":
        _row_discrimination(disc, evidence, out)


def _digest_referenced(observation: dict[str, Any]) -> bool:
    """Form: an observation is carried, or referenced with a digest."""
    if "carried" in observation:
        return True
    reference: Any = observation.get("reference")
    return _is_obj(reference) and _is_str(reference.get("sha256"))


def _rows_evidence_form(item: dict[str, Any], out: set[str]) -> None:
    """The form rows, decidable from the object alone: 14, arity, domain."""
    if item["moved"] and not all(_digest_referenced(o) for o in item["observations"]):
        out.add(R[26])
    delta: Any = item.get("delta")
    if "arity" in item or (_is_obj(delta) and "arity" in delta):
        out.add(R[27])
    if not _is_str(item["fixed"].get("domain")):
        out.add(R[28])


def _rows_evidence(item: dict[str, Any], resolves: dict[str, Any], out: set[str]) -> None:
    if item["changed"] not in CHANGED:
        out.add(R[19])
    compared, moved = item["compared"], item["moved"]
    if any(v not in SLOTS for v in compared + moved):
        out.add(R[19])
    _rows_evidence_form(item, out)
    _row_recomputed_moved(item, resolves, out)


def _counts(checks: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"declared": len(checks), "exercised": 0}
    for state in STATES:
        counts[state] = 0
    for check in checks:
        state = check["state"]
        if state in counts:
            counts[state] += 1
        if state != "not-exercised":
            counts["exercised"] += 1
    return counts


def _binding_refusal(ref: Any, weaken: frozenset[str] = NO_WEAKENING) -> str | None:
    """Why a set binding does not bind (rule (b)), or None when it binds.

    A digest over a set carries its leaf count and its tree shape, and an
    encoding it declares is one from the closed set (proposed: 2026Oct/0038). Only
    the last refusal is a coded cause; the others are this reader's own words.
    """
    if not _is_obj(ref) or not _is_str(ref.get("sha256")):
        return "no digest"
    count = ref.get("leaf-count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return "no leaf count"
    if ref.get("tree-shape") not in TREE_SHAPES:
        return "no tree shape from the closed set"
    if (
        "digest-encoding" in ref
        and ref["digest-encoding"] not in DIGEST_ENCODINGS
        and "closed-encoding-set" not in weaken
    ):
        return UNSUPPORTED_ENCODING
    return None


def _set_binding(ref: Any, out: set[str], weaken: frozenset[str] = NO_WEAKENING) -> bool:
    """Rule (b): a digest over a set carries its leaf count and its tree shape."""
    if _binding_refusal(ref, weaken) is not None:
        out.add(R[15])
        return False
    return True


def _identity(checks: Any, ids: set[str]) -> bool:
    if not isinstance(checks, list) or not checks:
        return False
    return all(_is_str(c) and c in ids for c in checks)


#: The slots a control's binding and the run's declaration are compared on.
BINDING_SLOTS = ("checker", "constraint-set")


def _row_control(
    field: dict[str, Any], ids: set[str], run_fixed: Any, out: set[str]
) -> None:
    control = _get(field, "control")
    if not _is_obj(control) or not _identity(control.get("checks"), ids):
        out.add(R[13])
    elif control.get("state") != "fail":
        out.add(R[13])
    else:
        _row_binding(control.get("fixed"), run_fixed, R[29], out)


def _row_binding(bound: Any, run_fixed: Any, row: str, out: set[str]) -> None:
    """A filling of section 5.4 bound to the checker and constraint set it speaks for.

    Rule 29 reads a control's binding and rule 33 a prior run's, both against
    the run's own. Read only where both declare the binding: a binding that
    differs from the run's is refused, and a missing one is not, because v0.1
    fixes no slot for the run's binding (section 5.5, open item O7).
    """
    if not (_is_obj(bound) and _is_obj(run_fixed)):
        return
    if any(bound.get(slot) != run_fixed.get(slot) for slot in BINDING_SLOTS):
        out.add(row)


def _rows_negative_capable(
    rollup: dict[str, Any],
    counts: dict[str, int],
    ids: set[str],
    run_fixed: Any,
    out: set[str],
    weaken: frozenset[str],
) -> None:
    field = _get(rollup, "negative-capable")
    if not _is_obj(field) or not _is_str(field.get("kind")):
        out.add(R[13])
        return
    kind = field["kind"]
    if kind not in NEGATIVE_CAPABLE:
        out.add(R[19])
    elif kind == "shown-by-run" and counts["fail"] < 1:
        out.add(R[13])
    elif kind == "control-failed":
        _row_control(field, ids, run_fixed, out)
    elif kind == "prior-discriminating-run":
        if not _identity(field.get("check-identity"), ids):
            out.add(R[14])
        _set_binding(field.get("reference"), out, weaken)
        _row_binding(field.get("fixed"), run_fixed, R[33], out)


COVERAGE_STRINGS = ("surface", "scan-depth", "point-in-time", "linked-repo")


def _count_field(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _coverage_well_formed(coverage: dict[str, Any]) -> bool:
    if not all(_is_str(coverage.get(k)) for k in COVERAGE_STRINGS):
        return False
    snapshots = coverage.get("snapshots")
    if not isinstance(snapshots, list):
        return False
    if not all(_is_obj(s) and _is_str(s.get("name")) and _is_str(s.get("date")) for s in snapshots):
        return False
    if not isinstance(coverage.get("live-observed"), bool):
        return False
    if not isinstance(coverage.get("sampled"), bool):
        return False
    scannable: Any = coverage.get("scannable-files")
    if not _count_field(scannable):
        return False
    if coverage["sampled"]:
        scanned: Any = coverage.get("scanned-files")
        if not _count_field(scanned) or scanned > scannable:
            return False
    return True


def _rows_coverage(report: dict[str, Any], out: set[str]) -> None:
    """Rule 22: a coverage block, when carried, states its scope in controlled fields."""
    coverage = _get(report, "coverage")
    if coverage is None:
        return
    if not _is_obj(coverage) or not _coverage_well_formed(coverage):
        out.add(R[22])


CLAIMS = ("satisfied", "not-satisfied", "not-claimable")
#: The fourth completeness claim of v0.1 section 5.2, "no declared check is
#: void": its population is the declared checks and it is satisfied when the
#: void count is zero. Judged when a report makes it; the three claims of 0036
#: stay required as before, so no member that already shipped changes verdict.
NO_VOID = "no-void"


def _claim_holds(
    name: str, claim: dict[str, Any], checks: list[dict[str, Any]], counts: dict[str, int]
) -> bool:
    populations = {
        "accounting": counts["declared"],
        "execution": counts["declared"],
        "evidence": counts["pass"] + counts["fail"],
        NO_VOID: counts["declared"],
    }
    population, value = claim.get("population"), claim.get("claim")
    if population != populations[name] or value not in CLAIMS:
        return False
    if population == 0:
        return bool(value == "not-claimable")
    if value != "satisfied":
        return True
    if name == "execution":
        return counts["exercised"] == counts["declared"]
    if name == "evidence":
        return all(_demonstrated(c) for c in checks if c["state"] == "pass")
    if name == NO_VOID:
        return counts["void"] == 0
    return True


def _demonstrated(check: dict[str, Any]) -> bool:
    disc = _get(check, "discrimination")
    return bool(_is_obj(disc) and disc.get("value") == "demonstrated")


def _rows_completeness(
    rollup: dict[str, Any], checks: list[dict[str, Any]], counts: dict[str, int], out: set[str]
) -> None:
    """Rule 23: a completeness claim carries the size of the population it counts over."""
    claims = _get(rollup, "completeness")
    if claims is None:
        return
    if not _is_obj(claims):
        out.add(R[23])
        return
    for name in ("accounting", "execution", "evidence"):
        claim = _get(claims, name)
        if not _is_obj(claim) or not _claim_holds(name, claim, checks, counts):
            out.add(R[23])
            return
    if NO_VOID in claims:
        claim = claims[NO_VOID]
        if not _is_obj(claim) or not _claim_holds(NO_VOID, claim, checks, counts):
            out.add(R[23])


def _carried_referenced(report: dict[str, Any]) -> tuple[int, int]:
    carried = referenced = 0
    for item in report.get("evidence", []):
        for observation in item["observations"]:
            if "carried" in observation:
                carried += 1
            else:
                referenced += 1
    return carried, referenced


def _rows_rollup(
    report: dict[str, Any], checks: list[dict[str, Any]], out: set[str], weaken: frozenset[str]
) -> None:
    counts = _counts(checks)
    rollup = _get(report, "roll-up")
    if rollup is None:
        out.add(R[17])
        return
    if any(rollup.get(key) != value for key, value in counts.items()):
        out.add(R[17])
    carried, referenced = _carried_referenced(report)
    if rollup.get("carried") != carried or rollup.get("referenced") != referenced:
        out.add(R[18])
    _rows_negative_capable(
        rollup, counts, {c["check"] for c in checks}, report.get("fixed"), out, weaken
    )
    _rows_completeness(rollup, checks, counts, out)


def _check_set_finding(
    report: dict[str, Any], checks: list[dict[str, Any]], weaken: frozenset[str]
) -> tuple[str, str | None, str | None] | None:
    """The row the check-set binding is rejected under, its cause and the token.

    None when the binding holds. The cause is a code from CAUSE_CODES, or None
    for a binding refused in words no member names; the token is the number a
    refusal under the jcs-sha256 profile was about, as it was written.
    """
    binding = _get(report, "check-set")
    refusal = _binding_refusal(binding, weaken)
    if refusal is not None:
        return R[15], (UNSUPPORTED_ENCODING if refusal == UNSUPPORTED_ENCODING else None), None
    if binding["leaf-count"] != len(checks):
        return R[15], None, None
    try:
        root = check_set_root(checks, binding["tree-shape"], weaken)
    except DigestRefused as exc:
        return R[20], exc.cause, exc.token
    if binding["sha256"] != root:
        return R[20], DIGESTS_DIFFER, None
    return None


def _rows_check_set(
    report: dict[str, Any], checks: list[dict[str, Any]], out: set[str], weaken: frozenset[str]
) -> None:
    finding = _check_set_finding(report, checks, weaken)
    if finding is not None:
        out.add(finding[0])


def check_set_cause(report: dict[str, Any], weaken: frozenset[str] = NO_WEAKENING) -> str | None:
    """The cause a rejection from the report's check-set binding names, if any.

    A well-shaped report only. The judge compares it with a member's
    ``expected.cause``, so a member is rejected for the reason it states and
    not merely under the row: a float and a root that does not recompute both
    land under W3C-R-020, and only the cause tells them apart. ``weaken`` is
    for the generator's mutation sweep, as in rejections().
    """
    finding = _check_set_finding(report, report["checks"], weaken)
    return None if finding is None else finding[1]


def check_set_refusal(report: dict[str, Any]) -> str | None:
    """The check-set finding in words, row, cause and token, for a reader's output."""
    finding = _check_set_finding(report, report["checks"], NO_WEAKENING)
    if finding is None:
        return None
    row, cause, token = finding
    if cause is None:
        return row
    return f"{row} ({cause}: {token})" if token is not None else f"{row} ({cause})"


def rejections(
    report: dict[str, Any],
    relax: frozenset[str] = frozenset(),
    resolves: dict[str, Any] | None = None,
    weaken: frozenset[str] = NO_WEAKENING,
) -> list[str]:
    """The requirement identifiers this report is rejected under, sorted.

    The report must already have passed ``shape_errors``. An empty list is a
    conforming report. ``relax`` names rows switched off, which is how the
    mutation sweep asks whether only the members naming a row flip when it is.
    ``resolves`` is what this reader can resolve a referenced observation to,
    keyed by the reference's vector locator; a reader with nothing to resolve
    against reads every reference as unchecked and the rows reading moved
    degrade, which is the reading table's third line. ``weaken`` names rules
    of the digest encodings switched off (WEAKENABLE), which is how the
    generator asks which members rest on which rule; a reader passes none.
    """
    out: set[str] = set()
    store: dict[str, Any] = resolves or {}
    checks: list[dict[str, Any]] = report["checks"]
    evidence = {e["id"]: e for e in report.get("evidence", [])}
    for check in checks:
        state = check["state"]
        if state not in STATES:
            out.add(R[19])
            continue
        _row_cause(check, state, out)
        _row_pairs(check, state, out)
        _row_qualifiers(check, state, evidence, store, out)
    for item in evidence.values():
        _rows_evidence(item, store, out)
    _rows_rollup(report, checks, out, weaken)
    _rows_check_set(report, checks, out, weaken)
    _rows_coverage(report, out)
    return sorted(out - set(relax))


def subject_shape_errors(subject_type: str, subject: Any) -> list[str]:
    """Shape errors for a member's subject, by the type the manifest names."""
    if subject_type == "agent-run-metrics":
        return runmetrics.shape_errors(subject)
    if subject_type == "llm-context-discovery":
        return contextdiscovery.shape_errors(subject)
    return shape_errors(subject)


def subject_rejections(
    subject_type: str,
    subject: dict[str, Any],
    relax: frozenset[str] = frozenset(),
    resolves: dict[str, Any] | None = None,
    weaken: frozenset[str] = NO_WEAKENING,
) -> list[str]:
    """Rejections for a member's subject, by the type the manifest names."""
    if subject_type == "agent-run-metrics":
        return sorted(set(runmetrics.rejections(subject)) - set(relax))
    if subject_type == "llm-context-discovery":
        return sorted(set(contextdiscovery.rejections(subject)) - set(relax))
    return rejections(subject, relax, resolves, weaken)


# --------------------------------------------------------------------------
# The judge: vectors-w3c-report/ against this validator.
# --------------------------------------------------------------------------

#: The member fields the identifier digests. ``resolves`` is what the member
#: hands the reader to resolve its referenced observations against, so a
#: changed store changes the member.
ID_FIELDS = ("kind", "family", "requirements", "subjectType", "subject", "resolves", "expected")
KINDS = ("accept", "reject")


def _list(values: list[str]) -> str:
    """The spelling both rails print a list in, so findings diff cleanly."""
    return "[" + ", ".join(values) + "]"


def _render_counts(counts: Any) -> str:
    if not isinstance(counts, dict):
        return "{}"
    return "{" + ", ".join(f"{k}={counts[k]}" for k in sorted(counts)) + "}"


def identify(document: dict[str, Any]) -> str:
    """A member's identifier: v and the first 16 hex digits of SHA-256 over the
    RFC 8785 form of its ID_FIELDS, a missing field read as null."""
    return "v" + sha(rfc8785({k: document.get(k) for k in ID_FIELDS}))[:16]


class Judged:
    """One corpus, judged: members with their findings, and corpus findings."""

    def __init__(self) -> None:
        self.members: list[tuple[str, str, list[str]]] = []
        self.findings: list[str] = []

    def ok(self) -> bool:
        return not self.findings and all(not f for _, _, f in self.members)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, kind, _ in self.members:
            counts[kind] = counts.get(kind, 0) + 1
        return counts


def _requirement(directory: str, row: dict[str, Any], out: list[str]) -> None:
    rid = row["id"]
    path = os.path.join(directory, row["vendored"])
    if not os.path.isfile(path):
        out.append(f"{rid}: names a vendored file {row['vendored']} that is not here")
        return
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    sentence = row["sentence"]
    if any(ord(ch) > 0x7F for ch in sentence):
        out.append(f"{rid}: the pinned sentence is not ASCII")
        return
    if sha(sentence.encode("utf-8")) != row["sentenceDigest"]:
        out.append(f"{rid}: the pinned sentence digest does not recompute from the sentence")
    index = text.find(sentence)
    if index < 0:
        out.append(f"{rid}: quotes a sentence the vendored copy no longer carries")
        return
    if text.find(sentence, index + 1) >= 0:
        out.append(
            f"{rid}: quotes a sentence that appears more than once, so it identifies nothing"
        )
    line = text.count("\n", 0, index) + 1
    if line != row["line"]:
        out.append(f"{rid}: records line {row['line']} and the sentence sits on line {line}")


def _requirements(directory: str, manifest: dict[str, Any], out: list[str]) -> set[str]:
    known: set[str] = set()
    for row in manifest.get("requirements", []):
        if row["id"] in known:
            out.append(f"{row['id']}: duplicate requirement identifier")
        known.add(row["id"])
        _requirement(directory, row, out)
    return known


def _member_vocabulary(
    manifest: dict[str, Any], entry: dict[str, Any], known: set[str], out: list[str]
) -> None:
    if entry.get("kind") not in KINDS:
        out.append(f"declares kind {entry.get('kind')}")
    if entry.get("family") not in manifest.get("families", {}):
        out.append(f"cites family {entry.get('family')} the manifest does not define")
    requirements = entry.get("requirements") or []
    for rid in requirements:
        if rid not in known:
            out.append(f"cites requirement {rid} the manifest does not carry")
    if not requirements:
        out.append("cites no requirement, so a specification change cannot tell it broke")
    if entry.get("specVersion") != manifest.get("specVersion"):
        out.append("declares a specification version the manifest does not pin")
    if entry.get("subjectType") not in SUBJECT_TYPES:
        out.append(f"declares subject type {entry.get('subjectType')}")
    _member_expectation(entry, known, requirements, out)


def _member_expectation(
    entry: dict[str, Any], known: set[str], requirements: list[str], out: list[str]
) -> None:
    expected = entry.get("expected") or {}
    verdict, rejects = expected.get("verdict"), expected.get("rejects")
    if verdict not in KINDS or verdict != entry.get("kind"):
        out.append("expects a verdict that is not its kind")
    if not isinstance(rejects, list):
        out.append("declares no rejects list")
        return
    if verdict == "accept" and rejects:
        out.append("is an accept member that expects a rejection")
    cause = expected.get("cause")
    if cause is not None and (verdict != "reject" or cause not in CAUSE_CODES):
        out.append(f"expects the cause {cause}, which only a reject member names, "
                   "from the closed set")
    if verdict == "reject" and len(rejects) != 1:
        out.append("is a reject member that does not name exactly one row")
    for rid in rejects:
        if rid not in known:
            out.append(f"expects rejection under {rid}, which the manifest does not carry")
        if rid not in requirements:
            out.append(f"expects rejection under {rid} and does not cite it")


def _load_member(directory: str, entry: dict[str, Any], out: list[str]) -> dict[str, Any] | None:
    path = os.path.join(directory, entry["file"])
    if not os.path.isfile(path):
        out.append("the manifest names a vector file that does not exist")
        return None
    try:
        with open(path, "rb") as handle:
            # Every number keeps the token it was written as, so a refusal
            # names it as written, as the Go reader's json.Number does.
            document = load_json(handle.read())
    except (OSError, ValueError) as exc:
        out.append(f"the vector file does not parse: {exc}")
        return None
    if not _is_obj(document):
        out.append("the vector file is not a JSON object")
        return None
    typed: dict[str, Any] = document
    return typed


def _member_identity(document: dict[str, Any], entry: dict[str, Any], out: list[str]) -> None:
    for field in ("kind", "family", "requirements", "expected", "specVersion", "subjectType"):
        if document.get(field) != entry.get(field):
            out.append(f"the vector file and the manifest disagree about {field}")
    if document.get("id") != entry["id"]:
        out.append("the vector file carries a different identifier")
    try:
        recomputed = identify(document)
    except DigestRefused as exc:
        out.append(f"the member has no RFC 8785 form: {exc}")
        return
    if recomputed != entry["id"]:
        out.append("identifier does not recompute from the member's own bytes")


def _member_file(directory: str, entry: dict[str, Any], out: list[str]) -> None:
    document = _load_member(directory, entry, out)
    if document is None:
        return
    _member_identity(document, entry, out)
    subject_type = str(entry.get("subjectType"))
    subject = _get(document, "subject")
    shape = subject_shape_errors(subject_type, subject)
    if shape:
        out.append("the subject is not the shape its definition gives: " + "; ".join(shape))
        return
    resolves: Any = document.get("resolves")
    if resolves is not None and not _is_obj(resolves):
        out.append("resolves is present and is not an object")
        return
    observed = subject_rejections(subject_type, subject, resolves=resolves)
    expected = sorted(entry.get("expected", {}).get("rejects") or [])
    if observed != expected:
        out.append(
            f"the validator rejects under {_list(observed)} "
            f"and the manifest expects {_list(expected)}"
        )
        return
    stated = entry.get("expected", {}).get("cause")
    if stated is not None and subject_type == "report":
        named = check_set_cause(subject)
        if named != stated:
            out.append(f"the validator names the cause {named or 'none'} "
                       f"and the manifest expects {stated}")


def _vendored(directory: str, manifest: dict[str, Any], out: list[str]) -> None:
    for key in sorted(manifest.get("specVendored", {})):
        pin = manifest["specVendored"][key]
        path = os.path.join(directory, pin["path"])
        if not os.path.isfile(path):
            out.append(f"the vendored file for {key} {pin['path']} is missing")
            continue
        with open(path, "rb") as handle:
            if sha(handle.read()) != pin["sha256"]:
                out.append(
                    f"the vendored file for {key} {pin['path']} does not match its pinned digest"
                )


def _pin_finding(directory: str, pin: dict[str, Any]) -> str | None:
    path = os.path.join(directory, pin["path"])
    if not os.path.isfile(path):
        return f"referenceEmitterRuns: {pin['path']} is missing"
    with open(path, "rb") as handle:
        if sha(handle.read()) != pin["sha256"]:
            return f"referenceEmitterRuns: {pin['path']} does not match its pinned digest"
    return None


def _emitted_report_findings(directory: str, rel: str) -> list[str]:
    try:
        with open(os.path.join(directory, rel), "rb") as handle:
            document = load_json(handle.read())
    except (OSError, ValueError):
        return [f"referenceEmitterRuns: {rel} does not parse"]
    if shape := shape_errors(document):
        return [f"referenceEmitterRuns: {rel} is not a v0.1 report: " + "; ".join(shape)]
    if rejected := rejections(document):
        return [f"referenceEmitterRuns: {rel} is rejected under {_list(rejected)}"]
    return []


def _emitter_runs(directory: str, manifest: dict[str, Any], out: list[str]) -> None:
    """Every published run of the reference emitter is on disk as pinned, and conforms."""
    for run in manifest.get("referenceEmitterRuns", []):
        report_holds = True
        for pin in ({"path": run["path"], "sha256": run["sha256"]},
                    run["conformanceReport"], run["run"]):
            if finding := _pin_finding(directory, pin):
                out.append(finding)
                report_holds = report_holds and pin["path"] != run["path"]
        if report_holds:
            out.extend(_emitted_report_findings(directory, run["path"]))


def _corpus(
    directory: str, manifest: dict[str, Any], known: set[str], entries: list[dict[str, Any]]
) -> list[str]:
    out: list[str] = []
    accepted = {e["family"] for e in entries if e.get("kind") == "accept"}
    rejected = {e["family"] for e in entries if e.get("kind") == "reject"}
    if orphan := sorted(rejected - accepted):
        out.append(f"families that reject and never accept: {_list(orphan)}")
    cited = {r for e in entries for r in e.get("requirements") or []}
    if idle := sorted(known - cited):
        out.append(f"requirements minted and cited by no member: {_list(idle)}")
    if unused := sorted(set(manifest.get("families", {})) - accepted - rejected):
        out.append(f"families declared and carried by no member: {_list(unused)}")
    _vendored(directory, manifest, out)
    _emitter_runs(directory, manifest, out)
    measured = {"accept": 0, "reject": 0}
    for entry in entries:
        if entry.get("kind") in measured:
            measured[entry["kind"]] += 1
    if manifest.get("counts") != measured:
        out.append(
            f"counts disagree: manifest {_render_counts(manifest.get('counts'))}, "
            f"measured {_render_counts(measured)}"
        )
    if corpus_digest(manifest, directory) != manifest.get("corpusDigest"):
        out.append("corpusDigest does not match the vector files on disk")
    return out


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """SHA-256 over the member files concatenated in identifier order."""
    digest = hashlib.sha256()
    for entry in sorted(manifest["vectors"], key=lambda e: e["id"]):
        path = os.path.join(root, entry["file"])
        if os.path.isfile(path):
            with open(path, "rb") as handle:
                digest.update(handle.read())
    return digest.hexdigest()


def judge(directory: str) -> Judged:
    with open(os.path.join(directory, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    judged = Judged()
    known = _requirements(directory, manifest, judged.findings)
    seen: set[str] = set()
    entries: list[dict[str, Any]] = manifest.get("vectors", [])
    for entry in entries:
        findings: list[str] = []
        if entry["id"] in seen:
            findings.append("duplicate identifier")
        seen.add(entry["id"])
        _member_vocabulary(manifest, entry, known, findings)
        _member_file(directory, entry, findings)
        judged.members.append((entry["id"], entry.get("kind", ""), findings))
    judged.findings.extend(_corpus(directory, manifest, known, entries))
    return judged


def render(judged: Judged, suite: str) -> str:
    """The same lines the Go reader prints, so the two rails can be diffed."""
    lines = [f"suite: {suite}", f"members: {len(judged.members)}"]
    counts = judged.counts()
    for kind in sorted(counts):
        lines.append(f"  {kind}: {counts[kind]}")
    failed = 0
    for member_id, _, findings in judged.members:
        if not findings:
            continue
        failed += 1
        for finding in findings:
            lines.append(f"FAIL {member_id}: {finding}")
    for finding in judged.findings:
        lines.append(f"FAIL corpus: {finding}")
    if judged.ok():
        lines.append("verdict: every member behaves as MANIFEST.json declares")
    else:
        lines.append(
            f"verdict: {failed} member(s) and {len(judged.findings)} "
            "corpus-level claim(s) do not hold"
        )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# The emitter: the AEE harness report as a v0.1 report.
# --------------------------------------------------------------------------

#: The crosswalk from the harness's observed columns to the five states. The
#: two altitudes are kept apart: ``result`` stays four-valued in the harness,
#: and the per-check record says what a consumer may conclude about the
#: statement the vector carries.
CROSSWALK = {
    "pass": (
        "verdict valid and result pass or pass_indirect; the result is carried "
        "in annotations as the qualifier"
    ),
    "fail": (
        "verdict valid and result fail or degraded, or verdict invalid; the "
        "codes are carried in annotations"
    ),
    "inconclusive": (
        "the indeterminate kind, a vector whose specification admits more than one "
        "reading: cause unsupported_input, the nearest closed disposition, with the "
        "reading the rail committed to or the declared readings as detail; the "
        "vocabulary has no value for an input the specification leaves undetermined, "
        "and that is recorded as a known gap rather than named here"
    ),
    "not-exercised": (
        "a manifest entry declaring expected.unmeasurableBecause, reported with "
        "cause precondition-unsatisfiable and that text; or a report member the "
        "manifest expects and the rail left absent, with cause unavailable"
    ),
    "void": (
        "the harness could not establish a verdict: cause evidence-does-not-hold, "
        "the value for void, with the rail's errors or exit as detail"
    ),
}

#: The domain the emitted report declares once, at run level; every slot that
#: needs it names it by this identifier.
EMITTED_DOMAIN = {
    "id": "d-aee-replay",
    "description": "the AEE corpus replayed by the harness: the artifacts its manifests pin",
}

ABSENT_EXPECTED = {"result": "result", "tiers": "tiers"}


def _record(
    check: str, state: str, cause: dict[str, Any] | None, notes: dict[str, Any]
) -> dict[str, Any]:
    record: dict[str, Any] = {"check": check, "state": state}
    if cause is not None:
        record["cause"] = cause
    if notes:
        record["annotations"] = notes
    return record


def _excluded(check: str, reason: str, notes: dict[str, Any]) -> dict[str, Any]:
    cause = {"code": "precondition-unsatisfiable", "detail": reason}
    record = _record(check, "not-exercised", cause, notes)
    record["declared-exclusion"] = True
    return record


def _inconclusive(row: dict[str, Any], notes: dict[str, Any]) -> dict[str, Any]:
    expected = row.get("expected") or {}
    readings = expected.get("readings") or {}
    primary = (row.get("observed") or {}).get("primaryCode")
    cause: dict[str, Any] = {"code": "unsupported_input"}
    if isinstance(primary, str) and primary:
        cause["detail"] = f"reading committed: {primary}"
    else:
        cause["detail"] = "readings declared, none committed: " + ", ".join(sorted(readings))
    return _record(row["id"], "inconclusive", cause, notes)


def _from_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    """The per-check records one harness row yields, in the crosswalk's terms."""
    observed = row.get("observed") or {}
    expected = row.get("expected") or {}
    notes = {"harness-status": row.get("status"), "kind": row.get("kind")}
    reason = expected.get("unmeasurableBecause")
    if isinstance(reason, str) and reason:
        return [_excluded(row["id"], reason, notes)]
    errors = observed.get("errors") or []
    verdict = observed.get("verdict")
    if errors or verdict not in ("valid", "invalid"):
        cause = {"code": VOID_CAUSE, "detail": "; ".join(errors) or f"verdict {verdict!r}"}
        return [_record(row["id"], "void", cause, notes)]
    if row.get("kind") == "indeterminate":
        return [_inconclusive(row, notes)]
    result = observed.get("result")
    if verdict == "valid" and result in ("pass", "pass_indirect"):
        records = [_record(row["id"], "pass", None, dict(notes, result=result))]
    else:
        annotated = dict(notes, result=result, verdict=verdict, codes=observed.get("codes") or [])
        records = [_record(row["id"], "fail", None, annotated)]
    for member in observed.get("absent") or []:
        if member in ABSENT_EXPECTED and ABSENT_EXPECTED[member] in expected:
            cause = {"code": "unavailable", "detail": f"the rail reported no {member} member"}
            records.append(_record(f"{row['id']}/{member}", "not-exercised", cause, notes))
    return records


def emit(conformance_report: dict[str, Any], shape: str = "flat") -> dict[str, Any]:
    """A v0.1 report from the report ``run_vectors.py`` writes."""
    checks: list[dict[str, Any]] = []
    for row in conformance_report.get("vectors", []):
        checks.extend(_from_row(row))
    counts = _counts(checks)
    rollup: dict[str, Any] = dict(counts, carried=0, referenced=0)
    rollup["negative-capable"] = {"kind": "shown-by-run" if counts["fail"] >= 1 else "nothing"}
    return {
        "format": FORMAT,
        "source": {
            "suite": conformance_report.get("suite"),
            "predicateType": conformance_report.get("predicateType"),
            "rail": conformance_report.get("rail"),
        },
        "crosswalk": CROSSWALK,
        "domain": dict(EMITTED_DOMAIN),
        "checks": checks,
        "evidence": [],
        "roll-up": rollup,
        "check-set": {
            "sha256": check_set_root(checks, shape),
            "leaf-count": len(checks),
            "tree-shape": shape,
        },
    }


def exclusions(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Not-exercised records for every manifest entry that declares an exclusion.

    This is the reader of ``expected.unmeasurableBecause`` that no rail had: a
    member the specification cannot express is reported as not exercised with
    the reason the corpus recorded, rather than dropped from the count.
    """
    records = []
    for entry in manifest.get("vectors", []):
        reason = (entry.get("expected") or {}).get("unmeasurableBecause")
        if isinstance(reason, str) and reason:
            records.append(_excluded(entry["id"], reason, {"kind": entry.get("kind")}))
    return records


# --------------------------------------------------------------------------
# Command line.
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="w3creport", description="judge vectors-w3c-report/ or emit a v0.1 report"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    judge_cmd = sub.add_parser("judge", help="judge a corpus directory against the validator")
    judge_cmd.add_argument("directory")
    emit_cmd = sub.add_parser("emit", help="emit a v0.1 report from a conformance-report.json")
    emit_cmd.add_argument("conformance_report")
    emit_cmd.add_argument("--tree-shape", choices=TREE_SHAPES, default="flat")
    args = parser.parse_args(argv)
    if args.command == "judge":
        judged = judge(args.directory)
        sys.stdout.write(render(judged, SUITE))
        return 0 if judged.ok() else 1
    with open(args.conformance_report, encoding="utf-8") as handle:
        report = emit(json.load(handle), args.tree_shape)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
