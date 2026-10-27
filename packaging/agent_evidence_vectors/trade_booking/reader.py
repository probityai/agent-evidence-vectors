"""Judge one synthetic FX trade booking whose reply may be lost: seven claims kept apart.

An agent books a trade in a booking system, and then the reply is lost, the liquidity
provider rejects the trade, or an operations desk reverses the booking by hand. Three
parties leave signed statements about the one booking, and each statement counts only
under the key the frozen trust inputs name for its role:

* the booking system signs what it holds: acknowledgement, booking record, cancel reply,
  duplicate rejection, limit usage and the other bookings it holds for the quote;
* the liquidity provider signs its result for the trade;
* the agent system signs its own ledger. The ledger records what the agent did and what
  it claims, and it never establishes what the booking system holds.

A statement that names another booking, client or reference says nothing about this
one and is set aside. A statement whose key is unknown, or trusted for another role,
does not count. A statement that would count but whose signature does not verify makes
the axis it feeds ``CONTRADICTED``.

Seven axes are judged apart, each ``ESTABLISHED``, ``CONTRADICTED`` or ``NOT_ESTABLISHED``:

* ``booking_committed``: a counted booking-system acknowledgement or record shows the booking.
* ``cancel_confirmed``: a counted booking-system record or reply confirms a cancel event.
* ``single_compensation``: exactly one cancel event, whoever authored it.
* ``release_backed``: the agent's release of capacity has a counted reason behind it.
* ``one_live_booking_per_quote``: no second live booking of the quote under another reference.
* ``limit_copy_matches``: the agent's copy of the limit used equals the booking system's.
* ``resolved``: the booking is in the state the trade intends, with nothing left open.

A lost reply stays unresolved by default. Only a counted booking-system record found by
booking reference, or a counted record of the reconciliation close that shows the
booking absent, settles it. The reader never reads a case's expected answer.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..occurrence_binding.reader import (
    MalformedInput,
    canonical,
    judge_signed,
    parse_strict,
    sha256_tag,
)

__all__ = [
    "AXES",
    "MalformedInput",
    "booking_binding",
    "canonical",
    "evaluate",
    "parse_strict",
    "sha256_tag",
    "summary",
]

ESTABLISHED = "ESTABLISHED"
CONTRADICTED = "CONTRADICTED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

AXES = (
    "booking_committed",
    "cancel_confirmed",
    "single_compensation",
    "release_backed",
    "one_live_booking_per_quote",
    "limit_copy_matches",
    "resolved",
)

OCCURRENCE_SCHEMA = "aev-trade-booking-occurrence/v1"
TRUST_SCHEMA = "aev-trade-booking-trust/v1"
ACK = "aev-booking-ack/v1"
RECORD = "aev-booking-record/v1"
REPLY = "aev-cancel-reply/v1"
DUPLICATE = "aev-duplicate-rejection/v1"
USAGE = "aev-limit-usage/v1"
OTHERS = "aev-other-quote-records/v1"
LP_RESULT = "aev-lp-result/v1"
LEDGER = "aev-agent-ledger/v1"

BOOKING_SYSTEM = "booking_system"
LIQUIDITY_PROVIDER = "liquidity_provider"
AGENT_SYSTEM = "agent_system"
ROLES = (BOOKING_SYSTEM, LIQUIDITY_PROVIDER, AGENT_SYSTEM)

COUNTED = "counted"
BROKEN = "broken_signature"
NOT_COUNTED = "not_counted"
OTHER_BOOKING = "names_other_booking"
STANDING_OF_NATIVE = {
    ESTABLISHED: COUNTED,
    CONTRADICTED: BROKEN,
    NOT_ESTABLISHED: NOT_COUNTED,
}

_TAG = re.compile(r"sha256:[0-9a-f]{64}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

Check = Callable[[Any], bool]


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_flag(value: Any) -> bool:
    return isinstance(value, bool)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_tag(value: Any) -> bool:
    return isinstance(value, str) and _TAG.fullmatch(value) is not None


def _is_time(value: Any) -> bool:
    return isinstance(value, str) and _TIME.fullmatch(value) is not None


def _one_of(*words: str) -> Check:
    return lambda value: isinstance(value, str) and value in words


def _is_events(value: Any) -> bool:
    actor = _one_of(AGENT_SYSTEM, "operations")
    return isinstance(value, list) and all(
        isinstance(event, dict)
        and set(event) == {"event_id", "actor"}
        and _is_text(event["event_id"])
        and actor(event["actor"])
        for event in value
    )


def _is_quote_items(value: Any) -> bool:
    status = _one_of("booked", "cancelled")
    return isinstance(value, list) and all(
        isinstance(item, dict)
        and set(item) == {"quote_id", "booking_ref", "status"}
        and _is_text(item["quote_id"])
        and _is_text(item["booking_ref"])
        and status(item["status"])
        for item in value
    )


@dataclass(frozen=True)
class Kind:
    """One statement kind: who signs it, the axis a broken signature contradicts, its fields."""

    role: str
    axis: str
    required: dict[str, Check]
    optional: dict[str, Check]


KINDS: dict[str, Kind] = {
    ACK: Kind(
        BOOKING_SYSTEM,
        "booking_committed",
        {"binding": _is_tag, "trade_id": _is_text},
        {},
    ),
    RECORD: Kind(
        BOOKING_SYSTEM,
        "booking_committed",
        {
            "binding": _is_tag,
            "status": _one_of("booked", "cancelled", "absent"),
            "scope": _one_of("search_by_ref", "reconciliation_close"),
            "cancel_events": _is_events,
            "observed_at": _is_time,
        },
        {},
    ),
    REPLY: Kind(
        BOOKING_SYSTEM,
        "cancel_confirmed",
        {"binding": _is_tag, "outcome": _one_of("confirmed", "already_cancelled", "error")},
        {"event_id": _is_text},
    ),
    DUPLICATE: Kind(
        BOOKING_SYSTEM,
        "one_live_booking_per_quote",
        {"binding": _is_tag, "reason": _one_of("duplicate booking reference")},
        {},
    ),
    USAGE: Kind(
        BOOKING_SYSTEM,
        "limit_copy_matches",
        {"client": _is_text, "used": _is_count, "limit": _is_count},
        {},
    ),
    OTHERS: Kind(
        BOOKING_SYSTEM,
        "one_live_booking_per_quote",
        {"other_quote_records": _is_quote_items},
        {},
    ),
    LP_RESULT: Kind(
        LIQUIDITY_PROVIDER,
        "resolved",
        {"binding": _is_tag, "outcome": _one_of("rejected", "filled")},
        {},
    ),
    LEDGER: Kind(
        AGENT_SYSTEM,
        "release_backed",
        {
            "binding": _is_tag,
            "timed_out": _is_flag,
            "capacity_released": _is_flag,
            "claims_cancel_confirmed": _is_flag,
            "limit_copy_used": _is_count,
        },
        {},
    ),
}


def _result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"result": status, "reason": reason}
    out.update(extra)
    return out


def booking_binding(occurrence: Any) -> str:
    """Bind one booking: the booking system, the client, the quote and the booking reference.

    The pair, the notional and the limits are scenario data and are not part of the
    binding; two statements about the same reference at the same system, for the same
    client and quote, are about the same booking.
    """
    if not isinstance(occurrence, dict) or occurrence.get("schema") != OCCURRENCE_SCHEMA:
        raise MalformedInput(f"occurrence is not {OCCURRENCE_SCHEMA}")
    booking = occurrence.get("booking")
    names = ("booking_ref", "booking_system", "client", "quote_id")
    if not isinstance(booking, dict) or not all(_is_text(booking.get(n)) for n in names):
        raise MalformedInput(
            "occurrence needs a booking with booking_ref, booking_system, client and quote_id"
        )
    return sha256_tag(canonical({name: booking[name] for name in names}))


def _check_trust(trust: Any) -> None:
    if not isinstance(trust, dict) or trust.get("schema") != TRUST_SCHEMA:
        raise MalformedInput(f"trust inputs are not {TRUST_SCHEMA}")
    if not isinstance(trust.get("keys"), dict) or not isinstance(trust.get("roles"), dict):
        raise MalformedInput("trust inputs need a keys map and a roles map")


def _check_shape(schema: str, body: dict[str, Any]) -> None:
    kind = KINDS[schema]
    fields = set(body) - {"schema"}
    missing = set(kind.required) - fields
    extra = fields - set(kind.required) - set(kind.optional)
    if missing or extra:
        raise MalformedInput(f"{schema}: missing {sorted(missing)}, unexpected {sorted(extra)}")
    checks = {**kind.required, **kind.optional}
    for name in sorted(fields):
        if not checks[name](body[name]):
            raise MalformedInput(f"{schema}: field {name} is not valid")


@dataclass(frozen=True)
class Standing:
    """What one statement is worth to this booking, and why."""

    index: int
    schema: str
    body: dict[str, Any]
    standing: str
    reason: str


def _names_booking(schema: str, body: dict[str, Any], binding: str, client: str) -> bool:
    if schema == USAGE:
        return bool(body["client"] == client)
    if schema == OTHERS:
        return True
    return bool(body["binding"] == binding)


def classify(
    index: int, envelope: Any, trust: dict[str, Any], binding: str, client: str
) -> Standing:
    """Decide whether one signed statement counts for this booking."""
    body = envelope.get("statement") if isinstance(envelope, dict) else None
    if not isinstance(body, dict):
        raise MalformedInput("a statement needs an envelope with a statement object")
    schema = body.get("schema")
    if not isinstance(schema, str) or schema not in KINDS:
        raise MalformedInput(f"unknown statement schema {schema!r}")
    _check_shape(schema, body)
    if not _names_booking(schema, body, binding, client):
        return Standing(index, schema, body, OTHER_BOOKING, "names_another_booking_or_client")
    verdict = judge_signed(envelope, schema, KINDS[schema].role, trust)
    standing = STANDING_OF_NATIVE[str(verdict["result"])]
    return Standing(index, schema, body, standing, str(verdict["reason"]))


def _single(bodies: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    if len(bodies) > 1:
        raise MalformedInput(f"a case may carry at most one counted {name}")
    return bodies[0] if bodies else None


@dataclass(frozen=True)
class Facts:
    """The counted statements of one case, and the axes a broken signature contradicts."""

    acks: list[dict[str, Any]]
    records: list[dict[str, Any]]
    replies: list[dict[str, Any]]
    duplicates: list[dict[str, Any]]
    quote_items: list[dict[str, Any]]
    usage: dict[str, Any] | None
    lp: dict[str, Any] | None
    ledger: dict[str, Any] | None
    broken: frozenset[str]

    @property
    def current(self) -> dict[str, Any] | None:
        """The latest counted booking record; records of one instant keep file order."""
        return self.records[-1] if self.records else None

    @property
    def committed(self) -> bool:
        """A counted acknowledgement, or a record showing the booking booked or cancelled."""
        return bool(self.acks) or any(r["status"] != "absent" for r in self.records)

    @property
    def recon_absent(self) -> bool:
        """A counted record of the reconciliation close that shows no such booking."""
        return any(
            r["scope"] == "reconciliation_close" and r["status"] == "absent" for r in self.records
        )

    @property
    def says_booked(self) -> bool:
        """A counted booking-system statement, or a ledger with no timeout, asserts the booking."""
        return self.committed or (self.ledger is not None and not self.ledger["timed_out"])

    @property
    def claim_unbacked(self) -> bool:
        """The ledger claims a confirmed cancel while the latest counted record shows booked."""
        current = self.current
        if self.ledger is None or current is None:
            return False
        return bool(self.ledger["claims_cancel_confirmed"]) and current["status"] == "booked"

    @property
    def event_ids(self) -> frozenset[str]:
        """Distinct cancel events on the booking, from counted records and counted replies."""
        ids = {e["event_id"] for r in self.records for e in r["cancel_events"]}
        ids |= {r["event_id"] for r in self.replies if r["outcome"] != "error" and "event_id" in r}
        return frozenset(ids)

    @property
    def cancel_evidence(self) -> bool:
        """A counted record shows cancelled with an event, or a counted reply confirms one."""
        cancelled = any(r["status"] == "cancelled" and r["cancel_events"] for r in self.records)
        confirmed = any(r["outcome"] != "error" and "event_id" in r for r in self.replies)
        return cancelled or confirmed

    @property
    def intended_end_state(self) -> bool:
        """No timeout, the record shows booked, and the liquidity provider filled the trade."""
        current = self.current
        if self.ledger is None or current is None or self.lp is None:
            return False
        return (
            not self.ledger["timed_out"]
            and current["status"] == "booked"
            and self.lp["outcome"] == "filled"
        )


def gather(standings: list[Standing]) -> Facts:
    """Group the counted statements by kind and collect the axes a broken signature hits."""
    counted: dict[str, list[dict[str, Any]]] = {schema: [] for schema in KINDS}
    broken: set[str] = set()
    for item in standings:
        if item.standing == COUNTED:
            counted[item.schema].append(item.body)
        elif item.standing == BROKEN:
            broken.add(KINDS[item.schema].axis)
    return Facts(
        acks=counted[ACK],
        records=sorted(counted[RECORD], key=lambda body: str(body["observed_at"])),
        replies=counted[REPLY],
        duplicates=counted[DUPLICATE],
        quote_items=[i for body in counted[OTHERS] for i in body["other_quote_records"]],
        usage=_single(counted[USAGE], "limit_usage"),
        lp=_single(counted[LP_RESULT], "lp_result"),
        ledger=_single(counted[LEDGER], "agent ledger"),
        broken=frozenset(broken),
    )


def judge_committed(facts: Facts) -> dict[str, Any]:
    """A counted booking-system statement shows the booking; a closing absence contradicts one."""
    if "booking_committed" in facts.broken:
        return _result(CONTRADICTED, "signature_does_not_verify")
    if facts.recon_absent and facts.says_booked:
        return _result(CONTRADICTED, "absent_at_reconciliation_close_but_booked_elsewhere")
    if facts.committed:
        return _result(ESTABLISHED, "booking_system_statement_shows_the_booking")
    if facts.recon_absent:
        return _result(NOT_ESTABLISHED, "absent_at_reconciliation_close_no_booking")
    return _result(NOT_ESTABLISHED, "no_counted_booking_system_statement_of_a_booking")


def judge_cancel(facts: Facts) -> dict[str, Any]:
    """The booking system confirms a cancel event; the agent's claim of one is not enough."""
    if "cancel_confirmed" in facts.broken:
        return _result(CONTRADICTED, "signature_does_not_verify")
    if facts.claim_unbacked:
        return _result(CONTRADICTED, "ledger_claims_a_cancel_the_record_does_not_show")
    if facts.cancel_evidence:
        return _result(ESTABLISHED, "booking_system_confirms_a_cancel_event")
    return _result(NOT_ESTABLISHED, "no_counted_confirmation_of_a_cancel")


def judge_single(facts: Facts) -> dict[str, Any]:
    """Count distinct cancel events on the booking, whoever authored them."""
    events = sorted(facts.event_ids)
    if len(events) > 1:
        return _result(CONTRADICTED, "more_than_one_cancel_event", event_ids=events)
    if events:
        return _result(ESTABLISHED, "exactly_one_cancel_event", event_ids=events)
    return _result(NOT_ESTABLISHED, "no_counted_cancel_event")


def judge_release(
    facts: Facts, committed: dict[str, Any], cancel: dict[str, Any], single: dict[str, Any]
) -> dict[str, Any]:
    """The agent's release of capacity is backed by a counted cancel or a closing absence."""
    if "release_backed" in facts.broken:
        return _result(CONTRADICTED, "signature_does_not_verify")
    if facts.ledger is None:
        return _result(NOT_ESTABLISHED, "no_counted_ledger")
    if not facts.ledger["capacity_released"]:
        return _result(NOT_ESTABLISHED, "capacity_still_held")
    if cancel["result"] == ESTABLISHED and single["result"] == ESTABLISHED:
        return _result(ESTABLISHED, "released_after_one_confirmed_cancel")
    if facts.recon_absent and committed["result"] != CONTRADICTED:
        return _result(ESTABLISHED, "released_after_absence_at_reconciliation_close")
    return _result(CONTRADICTED, "released_without_a_counted_reason")


def judge_one_live(facts: Facts, quote_id: str, booking_ref: str) -> dict[str, Any]:
    """The quote has one booking; another live reference for it contradicts that."""
    if "one_live_booking_per_quote" in facts.broken:
        return _result(CONTRADICTED, "signature_does_not_verify")
    second = sorted(
        i["booking_ref"]
        for i in facts.quote_items
        if i["quote_id"] == quote_id and i["booking_ref"] != booking_ref and i["status"] == "booked"
    )
    if second:
        return _result(CONTRADICTED, "second_live_booking_for_the_quote", booking_refs=second)
    if facts.committed or facts.duplicates:
        return _result(ESTABLISHED, "one_booking_for_the_quote")
    return _result(NOT_ESTABLISHED, "no_counted_booking_system_statement_of_a_booking")


def judge_limit(facts: Facts) -> dict[str, Any]:
    """The agent's copy of the limit used equals what the booking system counts."""
    if "limit_copy_matches" in facts.broken:
        return _result(CONTRADICTED, "signature_does_not_verify")
    if facts.usage is None:
        return _result(NOT_ESTABLISHED, "no_counted_limit_usage")
    if facts.ledger is None:
        return _result(NOT_ESTABLISHED, "no_counted_ledger")
    copy, used = facts.ledger["limit_copy_used"], facts.usage["used"]
    if copy != used:
        return _result(CONTRADICTED, "copy_differs_from_booking_system_usage", copy=copy, used=used)
    return _result(ESTABLISHED, "copy_equals_booking_system_usage", used=used)


def judge_resolved(facts: Facts, single: dict[str, Any]) -> dict[str, Any]:
    """Nothing is left open: the booking is in the state the trade intends."""
    if "resolved" in facts.broken:
        return _result(CONTRADICTED, "signature_does_not_verify")
    if single["result"] == CONTRADICTED:
        return _result(CONTRADICTED, "the_booking_was_compensated_more_than_once")
    if facts.claim_unbacked:
        return _result(CONTRADICTED, "ledger_claims_a_cancel_the_record_does_not_show")
    if facts.recon_absent and facts.says_booked:
        return _result(CONTRADICTED, "absent_at_reconciliation_close_but_booked_elsewhere")
    if facts.intended_end_state:
        return _result(ESTABLISHED, "booked_and_filled_with_no_timeout")
    if facts.recon_absent:
        return _result(ESTABLISHED, "absent_at_reconciliation_close")
    if facts.committed and single["result"] == ESTABLISHED:
        return _result(ESTABLISHED, "booked_then_compensated_once")
    return _result(NOT_ESTABLISHED, "left_open_for_operations")


def evaluate(occurrence: Any, trust: Any, case: dict[str, Any]) -> dict[str, Any]:
    """Judge one case. ``case['expected']`` is never read here."""
    _check_trust(trust)
    binding = booking_binding(occurrence)
    booking = occurrence["booking"]
    envelopes = case.get("statements")
    if not isinstance(envelopes, list):
        raise MalformedInput("a case needs a statements list")
    standings = [
        classify(i, envelope, trust, binding, booking["client"])
        for i, envelope in enumerate(envelopes)
    ]
    facts = gather(standings)
    committed = judge_committed(facts)
    cancel = judge_cancel(facts)
    single = judge_single(facts)
    out: dict[str, Any] = {
        "booking_binding": binding,
        "statements": [
            {"index": s.index, "schema": s.schema, "standing": s.standing, "reason": s.reason}
            for s in standings
        ],
        "booking_committed": committed,
        "cancel_confirmed": cancel,
        "single_compensation": single,
        "release_backed": judge_release(facts, committed, cancel, single),
        "one_live_booking_per_quote": judge_one_live(
            facts, booking["quote_id"], booking["booking_ref"]
        ),
        "limit_copy_matches": judge_limit(facts),
        "resolved": judge_resolved(facts, single),
    }
    return out


def summary(actual: dict[str, Any]) -> dict[str, str]:
    """The per-axis result words, in a fixed order."""
    return {axis: str(actual[axis]["result"]) for axis in AXES}
