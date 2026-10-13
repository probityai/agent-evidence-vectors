"""Reproduce the published AAE v1.4.0 enforce vectors from their input alone.

Each vector is evaluated by the independent kernel, once as published and once with
every object's members in reverse order. A vector is reproduced when the verdict or
status, the core digest, the grant index, every trace predicate it names, the kernel
version and the domain tags all agree, and when the key-order rerun lands on the
same digest. The ``reason_contains`` strings are not compared: the draft makes reason
wording diagnostic and not something two implementations must agree on.
"""

from __future__ import annotations

from typing import Any

import kernel
from strict_json import refuse

# The two caller-error vectors, read from each vector's rationale ("Guard 2", "Guard 3")
# and the Section 6.4 list of caller errors. A raised error must be the named guard.
CALLER_ERROR_GUARDS = {
    "aae-enforce-vector-24": "prior_verdict_permit",
    "aae-enforce-vector-25": "prev_core_digest_mismatch",
}
ENFORCE_TAGS = {"action": "action", "mandate": "mandate", "transaction": "transaction",
                "core": "core"}
RATIFY_TAGS = {"statement": "statement", "core": "ratify_core"}


def require_pinned(mandate: Any, pins: dict[str, str]) -> None:
    """Refuse a mandate naming any authority key outside the pin set (exit 2 upstream)."""
    for did, key, _role in kernel.authorities(mandate):
        pinned = pins.get(did)
        decoded = kernel.strict_hex(key, 32)
        if pinned is None or decoded is None or decoded != bytes.fromhex(pinned):
            refuse("a ratification authority key is not in the trust-key pin set")


def tags_agree(vector: dict[str, Any]) -> bool:
    """The vector's declared domain tags are the draft's tags this kernel uses."""
    names = ENFORCE_TAGS if vector.get("kernel") == "enforce_check" else RATIFY_TAGS
    declared = vector.get("domain_tags")
    if not isinstance(declared, dict) or set(declared) != set(names):
        return False
    return all(
        isinstance(declared[name], str)
        and declared[name].encode("ascii") + b"\x00" == kernel.DOMAIN_TAGS[mine]
        for name, mine in names.items()
    )


def trace_named(expected: list[Any], produced: list[dict[str, Any]]) -> bool:
    """Every named entry appears, in order, with the same result and stated members."""
    cursor = 0
    for want in expected:
        if not isinstance(want, dict):
            return False
        while cursor < len(produced) and produced[cursor]["predicate"] != want.get("predicate"):
            cursor += 1
        if cursor == len(produced):
            return False
        got = produced[cursor]
        cursor += 1
        stated = [key for key in kernel.TRACE_MEMBERS if key in want]
        if any(got[key] != want[key] for key in stated):
            return False
    return True


def enforce_checks(vector: dict[str, Any]) -> dict[str, bool]:
    """Per-claim comparison for one enforce_check vector."""
    given, expected = vector["input"], vector["expected"]
    arguments = (given.get("mandate"), given.get("transaction"), given.get("prev_core_digest"))
    first = kernel.enforce_check(*arguments)
    again = kernel.enforce_check(*(kernel.reversed_keys(value) for value in arguments))
    return {
        "verdict": first.core["verdict"] == expected.get("verdict"),
        "core_digest": first.core_digest == expected.get("core_digest"),
        "grant_index": first.core["grant_index"]
        == expected.get("grant_index", first.core["grant_index"]),
        "trace": trace_named(expected.get("trace", []), first.core["trace"]),
        "kernel_version": first.core["enforce_version"] == vector.get("kernel_version"),
        "key_order_independent": again.core_digest == first.core_digest,
    }


def ratify_arguments(given: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    """The four ratify inputs a vector carries."""
    return (given.get("prior_record"), given.get("decision"), given.get("authority_proof"),
            given.get("prev_core_digest"))


def caller_error(arguments: tuple[Any, Any, Any, Any]) -> str | None:
    """Run ratify and return the caller-error code, or None if a record was produced."""
    try:
        kernel.ratify(*arguments)
    except kernel.CallerError as exc:
        return exc.code
    return None


def ratify_checks(vector: dict[str, Any]) -> dict[str, bool]:
    """Per-claim comparison for one ratify vector, caller errors included."""
    given, expected = vector["input"], vector["expected"]
    arguments = ratify_arguments(given)
    reordered = ratify_arguments(kernel.reversed_keys(given))
    if "error" in expected:
        guard = CALLER_ERROR_GUARDS.get(str(vector.get("id")))
        return {
            "caller_error": guard is not None and caller_error(arguments) == guard,
            "key_order_independent": caller_error(reordered) == guard,
        }
    try:
        first, again = kernel.ratify(*arguments), kernel.ratify(*reordered)
    except kernel.CallerError:
        return {"caller_error_unexpected": False}
    return {
        "status": first.core["status"] == expected.get("status"),
        "core_digest": first.core_digest == expected.get("core_digest"),
        "ratifies": first.core["ratifies"] == expected.get("ratifies"),
        "authority": first.core["authority"] == expected.get("authority", first.core["authority"]),
        "trace": trace_named(expected.get("trace", []), first.core["trace"]),
        "kernel_version": first.core["ratify_version"] == vector.get("kernel_version"),
        "key_order_independent": again.core_digest == first.core_digest,
    }


def reproduce(name: str, vector: dict[str, Any], pins: dict[str, str]) -> dict[str, Any]:
    """Reproduce one vector and return its per-claim result.

    Raises
    ------
    strict_json.InputError
        If the vector's shape is outside the profile or a ratify vector's mandate
        names an authority key that is not pinned.
    """
    if not isinstance(vector.get("input"), dict) or not isinstance(vector.get("expected"), dict):
        refuse("vector lacks input or expected")
    kind = vector.get("kernel")
    if kind == "enforce_check":
        checks = enforce_checks(vector)
    elif kind == "ratify":
        proof = vector["input"].get("authority_proof")
        require_pinned(proof.get("mandate") if isinstance(proof, dict) else None, pins)
        checks = ratify_checks(vector)
    else:
        refuse("vector names an unknown kernel")
    checks["domain_tags"] = tags_agree(vector)
    return {
        "file": name,
        "id": vector.get("id"),
        "kernel": kind,
        "checks": checks,
        "reproduced": all(checks.values()),
    }
