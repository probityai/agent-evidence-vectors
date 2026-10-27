#!/usr/bin/env python3
"""Build the frozen trade-booking corpus for one synthetic FX trade booking.

One booking is frozen: the client, the quote, the booking reference and the booking
system. A control and three failure variants are built around it: the booking reply is
lost (variant 1), the liquidity provider rejects after the booking exists (variant 2),
and an operations desk reverses the booking by hand (variant 3). Every case is a set of
signed statements by the booking system, the liquidity provider and the agent system,
under one frozen set of trust inputs, with the answer expected on each of seven axes.

The keys are TEST keys derived from a published recipe, so anyone can rebuild the corpus
byte for byte: ``seed = sha256("aev-trade-booking-test-key/<role>/v1")``.

    python scripts/trade-booking-build.py           # write the corpus
    python scripts/trade-booking-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.trade_booking.reader import (  # noqa: E402
    ACK,
    AXES,
    DUPLICATE,
    LEDGER,
    LP_RESULT,
    OCCURRENCE_SCHEMA,
    OTHERS,
    RECORD,
    REPLY,
    ROLES,
    TRUST_SCHEMA,
    USAGE,
    booking_binding,
    canonical,
    sha256_tag,
)
from run_vectors import ed25519_public_key, ed25519_sign  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/trade_booking/corpus"
E = "ESTABLISHED"
C = "CONTRADICTED"
N = "NOT_ESTABLISHED"
VERIFIER_COMMAND = "agent-evidence-vectors-trade-booking --output <new directory>"
BOOKING_SYSTEM, LIQUIDITY_PROVIDER, AGENT_SYSTEM = ROLES

CONTROL = "control"
V1 = "variant_1_lost_reply"
V2 = "variant_2_liquidity_provider_rejects"
V3 = "variant_3_operations_reverses"
BREAK = "reconciliation_break"
TRUST_CONTROL = "trust_control"


def seed(role: str) -> bytes:
    """The published recipe for the TEST key of one role."""
    return hashlib.sha256(f"aev-trade-booking-test-key/{role}/v1".encode()).digest()


KEYS = {role: ed25519_public_key(seed(role)) for role in ROLES}
KEYIDS = {role: "sha256:" + hashlib.sha256(pub).hexdigest() for role, pub in KEYS.items()}

NOTIONAL = 1_000_000
LIMIT = 5_000_000
USED_BEFORE = 3_000_000
# What the booking system counts: the deal is live or unresolved, cancelled, or booked twice.
LIVE = USED_BEFORE + NOTIONAL
GONE = USED_BEFORE
TWO_LIVE = USED_BEFORE + 2 * NOTIONAL
# An agent that released the deal once for each of two cancel events.
DROPPED_TWICE = USED_BEFORE - NOTIONAL


def occurrence(booking_ref: str = "R1") -> dict[str, Any]:
    """The frozen booking; only the reference changes between bindings."""
    return {
        "schema": OCCURRENCE_SCHEMA,
        "booking": {
            "booking_system": "service:booking-system",
            "client": "CLIENT-A",
            "pair": "EUR/USD",
            "notional": NOTIONAL,
            "quote_id": "Q-1",
            "booking_ref": booking_ref,
        },
        "limit": {"limit": LIMIT, "used_before": USED_BEFORE},
        "trust_inputs": "trust.json",
        "verifier_command": VERIFIER_COMMAND,
    }


OCCURRENCE = occurrence()
BIND = booking_binding(OCCURRENCE)
OTHER_BIND = booking_binding(occurrence("R9"))


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _sign(statement: dict[str, Any], role: str) -> dict[str, Any]:
    return {
        "statement": statement,
        "keyid": KEYIDS[role],
        "signature_hex": ed25519_sign(seed(role), canonical(statement)).hex(),
    }


def _broken(envelope: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(envelope)
    sig = bytearray(bytes.fromhex(out["signature_hex"]))
    sig[5] ^= 0x01
    out["signature_hex"] = sig.hex()
    return out


def _at(minute: int) -> str:
    return f"2026-02-10T14:{minute:02d}:00Z"


def ack(binding: str = BIND) -> dict[str, Any]:
    """The booking system's acknowledgement of the booking."""
    return {"schema": ACK, "binding": binding, "trade_id": "TRD-0001"}


def record(
    status: str,
    scope: str = "search_by_ref",
    events: tuple[tuple[str, str], ...] = (),
    minute: int = 1,
    binding: str = BIND,
) -> dict[str, Any]:
    """A booking record read by reference or at the reconciliation close."""
    return {
        "schema": RECORD,
        "binding": binding,
        "status": status,
        "scope": scope,
        "cancel_events": [{"event_id": eid, "actor": actor} for eid, actor in events],
        "observed_at": _at(minute),
    }


def reply(outcome: str, event_id: str | None = None, binding: str = BIND) -> dict[str, Any]:
    """The booking system's reply to a cancel request."""
    out: dict[str, Any] = {"schema": REPLY, "binding": binding, "outcome": outcome}
    if event_id is not None:
        out["event_id"] = event_id
    return out


def duplicate(binding: str = BIND) -> dict[str, Any]:
    """The booking system's rejection of a resend under the same reference."""
    return {
        "schema": DUPLICATE,
        "binding": binding,
        "reason": "duplicate booking reference",
    }


def usage(used: int) -> dict[str, Any]:
    """The limit the booking system counts for the client."""
    return {"schema": USAGE, "client": "CLIENT-A", "used": used, "limit": LIMIT}


def others(*items: tuple[str, str]) -> dict[str, Any]:
    """The other bookings the booking system holds for quote Q-1: (reference, status)."""
    return {
        "schema": OTHERS,
        "other_quote_records": [
            {"quote_id": "Q-1", "booking_ref": ref, "status": status} for ref, status in items
        ],
    }


def lp(outcome: str, binding: str = BIND) -> dict[str, Any]:
    """The liquidity provider's result for the trade."""
    return {"schema": LP_RESULT, "binding": binding, "outcome": outcome}


def ledger(
    *,
    timed_out: bool,
    released: bool,
    copy_used: int,
    claims: bool = False,
    binding: str = BIND,
) -> dict[str, Any]:
    """The agent system's own account of what it did and what it claims."""
    return {
        "schema": LEDGER,
        "binding": binding,
        "timed_out": timed_out,
        "capacity_released": released,
        "claims_cancel_confirmed": claims,
        "limit_copy_used": copy_used,
    }


def bs(statement: dict[str, Any]) -> dict[str, Any]:
    """Sign as the booking system."""
    return _sign(statement, BOOKING_SYSTEM)


def lps(statement: dict[str, Any]) -> dict[str, Any]:
    """Sign as the liquidity provider."""
    return _sign(statement, LIQUIDITY_PROVIDER)


def ag(statement: dict[str, Any]) -> dict[str, Any]:
    """Sign as the agent system."""
    return _sign(statement, AGENT_SYSTEM)


def _expect(*words: str) -> dict[str, str]:
    return {axis: word for axis, word in zip(AXES, words, strict=True)}


def _cases() -> list[dict[str, Any]]:
    ev1_agent = ("EV-1", "agent_system")
    ev2_agent = ("EV-2", "agent_system")
    ev1_ops = ("EV-1", "operations")
    rows: list[tuple[str, str, str, str, list[dict[str, Any]], dict[str, str]]] = [
        (
            "control_normal_success",
            CONTROL,
            "all",
            "No failure: the booking system acknowledges and shows the booking, the liquidity"
            " provider fills the trade, nothing times out, nothing is released, and the"
            " agent's copy of the limit matches the booking system's.",
            [
                bs(ack()),
                bs(record("booked")),
                lps(lp("filled")),
                bs(usage(LIVE)),
                ag(ledger(timed_out=False, released=False, copy_used=LIVE)),
            ],
            _expect(E, N, N, N, E, E, E),
        ),
        (
            "v1_lost_ack_found_by_search_cancelled_once",
            V1,
            "all",
            "The booking reply is lost and the agent times out. A search by reference finds the"
            " booking, the agent cancels once, the booking system confirms one cancel event,"
            " and only then is capacity released. The copy of the limit matches.",
            [
                bs(record("booked", minute=1)),
                bs(record("cancelled", events=(ev1_agent,), minute=3)),
                bs(reply("confirmed", "EV-1")),
                bs(usage(GONE)),
                ag(ledger(timed_out=True, released=True, copy_used=GONE, claims=True)),
            ],
            _expect(E, E, E, E, E, E, E),
        ),
        (
            "v1_late_booking_held_until_reconciliation_cancelled_once",
            V1,
            "all",
            "The search by reference finds nothing, and the agent holds capacity. The"
            " reconciliation close shows the booking, the agent cancels once, the booking"
            " system confirms one cancel event, and capacity is released afterwards.",
            [
                bs(record("absent", minute=1)),
                bs(record("booked", scope="reconciliation_close", minute=5)),
                bs(record("cancelled", "reconciliation_close", events=(ev1_agent,), minute=7)),
                bs(reply("confirmed", "EV-1")),
                bs(usage(GONE)),
                ag(ledger(timed_out=True, released=True, copy_used=GONE, claims=True)),
            ],
            _expect(E, E, E, E, E, E, E),
        ),
        (
            "v1_search_absent_reconciliation_closes_never_booked",
            V1,
            "resolved",
            "The reply is lost and the agent times out. The search by reference finds nothing, so"
            " the agent holds capacity. The reconciliation close then also shows no booking, and"
            " only after that does the agent release capacity. No statement shows the deal"
            " booked, so it ends as never booked. The copy of the limit matches.",
            [
                bs(record("absent", minute=1)),
                bs(record("absent", "reconciliation_close", minute=5)),
                bs(usage(GONE)),
                ag(ledger(timed_out=True, released=True, copy_used=GONE)),
            ],
            _expect(N, N, N, E, N, E, E),
        ),
        (
            "v1_late_booking_released_at_search_not_found",
            V1,
            "release_backed",
            "The search by reference finds nothing and the agent releases capacity at once."
            " The reconciliation close then shows the booking, uncancelled. The agent's copy"
            " of the limit dropped the deal, and the booking system still counts it.",
            [
                bs(record("absent", minute=1)),
                bs(record("booked", scope="reconciliation_close", minute=5)),
                bs(usage(LIVE)),
                ag(ledger(timed_out=True, released=True, copy_used=GONE)),
            ],
            _expect(E, N, N, C, E, C, N),
        ),
        (
            "v1_lost_ack_released_on_timeout_no_evidence",
            V1,
            "release_backed",
            "The reply is lost and the agent releases capacity at the timeout. No booking-system"
            " statement exists at all, so nothing backs the release.",
            [ag(ledger(timed_out=True, released=True, copy_used=GONE))],
            _expect(N, N, N, C, N, N, N),
        ),
        (
            "v1_resend_same_reference_rejected",
            V1,
            "one_live_booking_per_quote",
            "The agent resends the booking under the same reference. The booking system rejects"
            " it as a duplicate and shows the original booking. Nothing is released and no"
            " cancel has been sent yet.",
            [
                bs(record("booked")),
                bs(duplicate()),
                bs(usage(LIVE)),
                ag(ledger(timed_out=True, released=False, copy_used=LIVE)),
            ],
            _expect(E, N, N, N, E, E, N),
        ),
        (
            "v1_resend_new_reference_duplicate_booking",
            V1,
            "one_live_booking_per_quote",
            "The agent resends the booking under a new reference, R2. The booking system holds"
            " R1 and R2 as live bookings of the same quote. The agent's copy counts one deal"
            " and the booking system counts two.",
            [
                bs(record("booked")),
                bs(others(("R2", "booked"))),
                bs(usage(TWO_LIVE)),
                ag(ledger(timed_out=True, released=False, copy_used=LIVE)),
            ],
            _expect(E, N, N, N, C, C, N),
        ),
        (
            "v1_unresolved_deal_dropped_from_limit_copy",
            V1,
            "limit_copy_matches",
            "The booking is live and unresolved. The agent's copy of the limit left it out, and"
            " the booking system's usage includes it.",
            [
                bs(record("booked")),
                bs(usage(LIVE)),
                ag(ledger(timed_out=True, released=False, copy_used=GONE)),
            ],
            _expect(E, N, N, N, E, C, N),
        ),
        (
            "v1_cancel_claimed_by_agent_only",
            V1,
            "cancel_confirmed",
            "The agent's ledger says a cancel was confirmed and capacity was released. The only"
            " counted booking-system record still shows the booking as booked.",
            [
                bs(record("booked")),
                ag(ledger(timed_out=True, released=True, copy_used=GONE, claims=True)),
            ],
            _expect(E, C, N, C, E, N, C),
        ),
        (
            "v2_lp_reject_cancel_confirmed_once",
            V2,
            "all",
            "The booking is acknowledged and the liquidity provider rejects the trade. The"
            " agent cancels once, the booking system confirms one cancel event, and capacity"
            " is released afterwards. The copy of the limit matches.",
            [
                bs(ack()),
                bs(record("booked", minute=1)),
                lps(lp("rejected")),
                bs(reply("confirmed", "EV-1")),
                bs(record("cancelled", events=(ev1_agent,), minute=3)),
                bs(usage(GONE)),
                ag(ledger(timed_out=False, released=True, copy_used=GONE, claims=True)),
            ],
            _expect(E, E, E, E, E, E, E),
        ),
        (
            "v2_lp_reject_cancel_error_held_for_operations",
            V2,
            "resolved",
            "The liquidity provider rejects the trade and the cancel request returns an error."
            " The agent holds capacity and the booking stays live, so it goes to operations."
            " The copy of the limit still counts the deal.",
            [
                bs(ack()),
                bs(record("booked")),
                lps(lp("rejected")),
                bs(reply("error")),
                bs(usage(LIVE)),
                ag(ledger(timed_out=False, released=False, copy_used=LIVE)),
            ],
            _expect(E, N, N, N, E, E, N),
        ),
        (
            "v2_lp_reject_cancel_retried_two_events",
            V2,
            "single_compensation",
            "The first cancel succeeded but its reply was lost. The agent retried by itself,"
            " and the booking system recorded two cancel events. Capacity is released after the"
            " second, and the agent's copy of the limit dropped the deal twice.",
            [
                bs(ack()),
                bs(record("booked", minute=1)),
                lps(lp("rejected")),
                bs(reply("confirmed", "EV-2")),
                bs(record("cancelled", events=(ev1_agent, ev2_agent), minute=4)),
                bs(usage(GONE)),
                ag(ledger(timed_out=False, released=True, copy_used=DROPPED_TWICE, claims=True)),
            ],
            _expect(E, E, C, C, E, C, C),
        ),
        (
            "v2_lp_reject_cancel_unconfirmed_released_anyway",
            V2,
            "release_backed",
            "The liquidity provider rejects the trade and the cancel request returns an error."
            " The agent releases capacity anyway, and its copy of the limit is below what the"
            " booking system counts.",
            [
                bs(ack()),
                bs(record("booked")),
                lps(lp("rejected")),
                bs(reply("error")),
                bs(usage(LIVE)),
                ag(ledger(timed_out=False, released=True, copy_used=GONE)),
            ],
            _expect(E, N, N, C, E, C, N),
        ),
        (
            "v3_ops_reversed_first_agent_skips_cancel",
            V3,
            "single_compensation",
            "The liquidity provider rejects the trade and operations reverse the booking before"
            " the agent acts. The record shows one cancel event, authored by operations. The"
            " agent sends no cancel and releases capacity after reading the record.",
            [
                bs(ack()),
                bs(record("booked", minute=1)),
                lps(lp("rejected")),
                bs(record("cancelled", events=(ev1_ops,), minute=3)),
                bs(usage(GONE)),
                ag(ledger(timed_out=False, released=True, copy_used=GONE)),
            ],
            _expect(E, E, E, E, E, E, E),
        ),
        (
            "v3_ops_reversed_then_agent_cancel_accepted_two_events",
            V3,
            "single_compensation",
            "Operations reverse the booking, and the agent's cancel is accepted as well. The"
            " record shows two cancel events, one from each. Capacity is released, and the"
            " agent's copy of the limit is below what the booking system counts.",
            [
                bs(ack()),
                bs(record("booked", minute=1)),
                lps(lp("rejected")),
                bs(reply("confirmed", "EV-2")),
                bs(record("cancelled", events=(ev1_ops, ev2_agent), minute=4)),
                bs(usage(GONE)),
                ag(ledger(timed_out=False, released=True, copy_used=DROPPED_TWICE, claims=True)),
            ],
            _expect(E, E, C, C, E, C, C),
        ),
        (
            "v3_agent_cancel_rejected_already_cancelled",
            V3,
            "cancel_confirmed",
            "Operations reverse the booking, and the agent's cancel is answered as already"
            " cancelled, naming the operations event. The record shows one cancel event, and"
            " capacity is released afterwards.",
            [
                bs(ack()),
                bs(record("booked", minute=1)),
                lps(lp("rejected")),
                bs(reply("already_cancelled", "EV-1")),
                bs(record("cancelled", events=(ev1_ops,), minute=3)),
                bs(usage(GONE)),
                ag(ledger(timed_out=False, released=True, copy_used=GONE, claims=True)),
            ],
            _expect(E, E, E, E, E, E, E),
        ),
        (
            "break_agent_booked_booking_system_absent",
            BREAK,
            "booking_committed",
            "The agent's ledger shows the deal as booked: no timeout, capacity held and nothing"
            " released. The booking system's record at the reconciliation close shows no booking"
            " under the reference. The agent system holds a deal the booking system lacks, which"
            " is a break for operations. The booking is not established and is not resolved.",
            [
                bs(record("absent", "reconciliation_close", minute=9)),
                ag(ledger(timed_out=False, released=False, copy_used=LIVE)),
            ],
            _expect(C, N, N, N, N, N, C),
        ),
        (
            "booking_record_signed_by_agent",
            TRUST_CONTROL,
            "booking_committed",
            "A booking record whose fields match the control, signed by the agent system's key."
            " The trust inputs name that key for the agent system, not for the booking system,"
            " so the record does not count. Nothing else is in the case.",
            [ag(record("booked"))],
            _expect(N, N, N, N, N, N, N),
        ),
        (
            "booking_record_names_other_reference",
            TRUST_CONTROL,
            "booking_committed",
            "A booking record with a valid booking-system signature that names reference R9. It"
            " says nothing about R1 and is set aside. Nothing else is in the case.",
            [bs(record("booked", binding=OTHER_BIND))],
            _expect(N, N, N, N, N, N, N),
        ),
        (
            "cancel_reply_signature_broken",
            TRUST_CONTROL,
            "cancel_confirmed",
            "The liquidity provider rejects the trade, and the cancel reply carries one changed"
            " bit in the booking system's signature. The reply does not count, and its broken"
            " signature contradicts the cancel claim. The record still shows booked.",
            [
                bs(ack()),
                bs(record("booked")),
                lps(lp("rejected")),
                _broken(bs(reply("confirmed", "EV-1"))),
                bs(usage(LIVE)),
                ag(ledger(timed_out=False, released=False, copy_used=LIVE)),
            ],
            _expect(E, C, N, N, E, E, N),
        ),
    ]
    return [
        {
            "id": cid,
            "variant": variant,
            "axis": axis,
            "description": desc,
            "statements": statements,
            "expected": expected,
        }
        for cid, variant, axis, desc, statements, expected in rows
    ]


def _trust() -> dict[str, Any]:
    return {
        "schema": TRUST_SCHEMA,
        "key_recipe": "seed = sha256('aev-trade-booking-test-key/<role>/v1'); TEST keys only",
        "keys": {KEYIDS[r]: {"role_label": r, "public_hex": KEYS[r].hex()} for r in ROLES},
        "roles": {role: [KEYIDS[role]] for role in ROLES},
    }


def build() -> dict[str, str]:
    """Return every corpus file's text, manifest last."""
    files = {
        "occurrence.json": _dump(OCCURRENCE),
        "trust.json": _dump(_trust()),
        "cases.json": _dump(
            {
                "schema": "aev-trade-booking-cases/v1",
                "booking_binding": BIND,
                "cases": _cases(),
            }
        ),
    }
    files["manifest.json"] = _dump(
        {
            "schema": "aev-trade-booking-corpus/v1",
            "members": {
                name: sha256_tag(text.encode("utf-8")) for name, text in sorted(files.items())
            },
        }
    )
    return files


def main(argv: list[str] | None = None) -> int:
    """Write the corpus, or with --check exit 1 if the committed files differ."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    files = build()
    if args.check:
        stale = [
            name
            for name, text in files.items()
            if not (CORPUS / name).exists() or (CORPUS / name).read_text() != text
        ]
        if stale:
            print(f"stale corpus members: {stale}", file=sys.stderr)
            return 1
        return 0
    CORPUS.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (CORPUS / name).write_text(text)
    print(f"wrote {len(files)} files, {len(_cases())} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
